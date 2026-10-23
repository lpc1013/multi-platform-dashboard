# -*- coding: utf-8 -*-
"""高并发自动重连单测（2026-10-22 用户诉求：「应该自动重连 而不是直接弹重试」）。

覆盖：
  - _retryable_err：瞬时错误判定表（纯 429/5xx/并发上限/连接层 → 重连；
    额度耗尽/鉴权失效/参数错误 → 立即透传）
  - _backoff：退避序列
  - _frame_err / _frame_retryable：首帧错误帧识别（限流帧换号、参数帧透传）
  - relay：codearts 429 → 自动重连后成功；恒 429 → 最终错误带「已自动重连 N 次」；
    额度类不重试（call_count==1）；流式重连期间发 SSE 心跳
  - _open_pool：首帧 429 错误帧换下一个号
  - _open_dsflash_pool：全瞬时失败抛可重试错误（429）；全额度失败抛不可重试

测试环境下 _wait_scale=0.001（logstore._under_test 识别 PYTEST_CURRENT_TEST），
重连轮次瞬间完成，不会真睡 90s。
运行：python -m pytest tests/test_auto_reconnect.py -q
"""
import json
import os
import sys
import unittest
from unittest import mock

sys.argv = [sys.argv[0]]  # server/openai_proxy 导入链会把 argv[1] 当端口读
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import openai_proxy as ox   # noqa: E402

_ENT = {"ak": "ak-test", "sk": "sk-test", "sts_token": "sts-test"}


class _FakeHandler:
    """收集 _send/_begin_stream/_write_chunk 调用的假 handler（同 test_proxy）。"""

    def __init__(self):
        self.sent, self.chunks = [], []

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        self.sent.append((code, body))

    def _begin_stream(self, status=200, ctype="text/event-stream; charset=utf-8"):
        self.chunks.append(("HEAD", status))

    def _write_chunk(self, data):
        self.chunks.append(data)


def _sse(*texts):
    """造上游 SSE 行（OpenAI chunk 形状，末帧带 usage）。"""
    lines = []
    for i, t in enumerate(texts):
        lines.append("data:" + json.dumps({
            "id": "r", "created": 1, "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"content": t},
                         "finish_reason": "stop" if i == len(texts) - 1 else None}],
            **({"usage": {"prompt_tokens": 7, "completion_tokens": 3,
                          "total_tokens": 10}} if i == len(texts) - 1 else {}),
        }, ensure_ascii=False))
    lines.append("data:[DONE]")
    return lines


def _seq_opener(seq):
    """按序弹出：异常实例则 raise，否则当 (name, lines) 返回。"""
    def _open(*a):
        item = seq.pop(0)
        if isinstance(item, Exception):
            raise item
        return item
    return _open


class TestRetryableErr(unittest.TestCase):
    """瞬时错误判定：只有「等等能活」的才自动重连。"""

    def test_transient_are_retryable(self):
        for st, msg in [(429, "rate limit exceeded"),
                        (429, '{"code":6004,"msg":"too many requests"}'),
                        (429, '{"error_code":"TM.00001041"}'),
                        (500, "internal"), (502, "bad gateway"),
                        (503, "unavailable"), (504, "gateway timeout"),
                        (408, "request timeout"),
                        (None, "Connection reset by peer"),
                        (None, "Read timed out"),
                        (502, "上游返回空流"),
                        (502, "并发会话数已达上限(3个)")]:
            self.assertTrue(ox._retryable_err(st, msg), "%s %s 应可重连" % (st, msg))

    def test_hard_errors_not_retryable(self):
        for st, msg in [(401, "unauthorized"), (403, "forbidden"),
                        (402, "payment required"), (400, "bad request"),
                        (429, "14018 Credits exhausted"),
                        (429, "积分额度已用尽"),
                        (429, "insufficient balance"),
                        (502, "额度耗尽(14018) xxx"),
                        (502, "quota exceeded")]:
            self.assertFalse(ox._retryable_err(st, msg), "%s %s 不应重连" % (st, msg))

    def test_backoff_sequence(self):
        self.assertEqual([ox._backoff(i) for i in range(1, 6)],
                         [1.0, 2.0, 3.0, 5.0, 8.0])
        self.assertEqual(ox._backoff(9), 8.0)          # 之后维持 8s
        self.assertEqual(ox._backoff(14), 8.0)


class TestFrameErr(unittest.TestCase):
    """首帧错误帧识别（高并发时上游把 429 直接放首帧）。"""

    def test_error_frames_detected(self):
        f = ox._frame_err("data:" + json.dumps({"error_code": 429,
                                                "error_msg": "rate limit"}))
        self.assertEqual(f, (429, "rate limit"))
        f = ox._frame_err("data:" + json.dumps({"error": {"message": "busy"}}))
        self.assertEqual(f, ("err", "busy"))
        f = ox._frame_err("data:" + json.dumps({"code": 503, "msg": "busy"}))
        self.assertEqual(f, (503, "busy"))

    def test_normal_frames_not_errors(self):
        self.assertIsNone(ox._frame_err(_sse("你好")[0]))
        self.assertIsNone(ox._frame_err(": keep-alive comment"))
        self.assertIsNone(ox._frame_err("data:[DONE]"))
        self.assertIsNone(ox._frame_err("data:{\"error_code\":\"0\"}"))

    def test_frame_retryable(self):
        self.assertTrue(ox._frame_retryable(429, "rate limit"))
        self.assertTrue(ox._frame_retryable(503, "busy"))
        self.assertTrue(ox._frame_retryable("14003", "too many requests"))
        self.assertTrue(ox._frame_retryable("x", "rate limit exceeded"))
        # 参数类 4xx：换号也一样错，不重连（锁 test_non_stream_error_chunk_logged 行为）
        self.assertFalse(ox._frame_retryable("InferHub.001001009.400",
                                             "The chat messages is required."))
        self.assertFalse(ox._frame_retryable(400, "tool_choice unsupported"))


class TestRelayAutoReconnect(unittest.TestCase):
    """relay：瞬时错误自动重连，不弹给客户端。"""

    def setUp(self):
        ox._WBAI_ML_COOL.clear()
        ox._POOL_COOL.clear()

    def test_codearts_429_then_success(self):
        """首打 429（并发上限）→ 自动重连 → 第二次成功：客户端只见 200。"""
        h = _FakeHandler()
        seq = [ox.UpstreamError(429, "rate limit exceeded"),
               ("acct", iter(_sse("你", "好")))]
        with mock.patch.object(ox, "_open_pool", side_effect=_seq_opener(seq)), \
             mock.patch("server.log"):
            ox.relay(h, {"model": "x", "messages": []})
        self.assertEqual(h.sent[0][0], 200)
        self.assertEqual(h.sent[0][1]["choices"][0]["message"]["content"], "你好")
        self.assertFalse(seq)                          # 确实重试到了第二个

    def test_persistent_429_final_error_notes_retries(self):
        """一直 429：重连次数打满才回错误，且消息说明已自动重连过。"""
        h = _FakeHandler()
        calls = []

        def boom(*a):
            calls.append(1)
            raise ox.UpstreamError(429, "too many requests")

        with mock.patch.object(ox, "_open_pool", side_effect=boom), \
             mock.patch("server.log"):
            ox.relay(h, {"model": "x", "messages": []})
        self.assertEqual(h.sent[0][0], 429)
        self.assertIn("已自动重连", h.sent[0][1]["error"]["message"])
        self.assertEqual(len(calls), ox.AUTO_RETRY_MAX + 1)   # 首次 + 14 次重连

    def test_quota_error_not_retried(self):
        """真额度耗尽：重试无意义，立即透传（只打一次上游）。"""
        h = _FakeHandler()
        calls = []

        def boom(*a):
            calls.append(1)
            raise ox.UpstreamError(402, "Credits exhausted")

        with mock.patch.object(ox, "_open_pool", side_effect=boom), \
             mock.patch("server.log"):
            ox.relay(h, {"model": "x", "messages": []})
        self.assertEqual(h.sent[0][0], 402)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("已自动重连", h.sent[0][1]["error"]["message"])

    def test_param_error_not_retried(self):
        h = _FakeHandler()
        calls = []

        def boom(*a):
            calls.append(1)
            raise ox.UpstreamError(400, "tool_choice object unsupported")

        with mock.patch.object(ox, "_open_pool", side_effect=boom), \
             mock.patch("server.log"):
            ox.relay(h, {"model": "x", "messages": []})
        self.assertEqual(h.sent[0][0], 400)
        self.assertEqual(len(calls), 1)

    def test_stream_reconnect_sends_heartbeat(self):
        """流式重连等待期必须有 SSE 注释心跳——否则客户端几秒无字节自取消
        （2026-10-20 用户实证）。且心跳开流后只能 SSE 收尾，不能再发状态行。"""
        h = _FakeHandler()
        seq = [ox.UpstreamError(429, "rate limit exceeded"),
               ("acct", iter(_sse("你", "好")))]
        with mock.patch.object(ox, "_open_pool", side_effect=_seq_opener(seq)), \
             mock.patch("server.log"):
            ox.relay(h, {"model": "x", "stream": True, "messages": []})
        self.assertEqual(h.sent, [])                   # 开了流就不再发 HTTP 状态行
        self.assertEqual([c for c in h.chunks if c[0] == "HEAD"], [("HEAD", 200)])
        self.assertTrue(any(isinstance(c, bytes) and b"auto-reconnecting" in c
                            for c in h.chunks), h.chunks)
        body = b"".join(c for c in h.chunks if isinstance(c, bytes))
        text = body.decode("utf-8")
        self.assertIn("你", text)                     # 重连后的内容照常透传
        self.assertIn("好", text)
        self.assertIn("data:[DONE]", text)

    def test_ca_queue_timeout_replies_429(self):
        """槽位占满排队超时：必须给客户端响应（429），不能静默 return。"""
        for _ in range(3):
            ox._CA_SEM.acquire()          # 占满 3 个槽位
        try:
            with mock.patch.object(ox, "_CA_QUEUE_WAIT", 1.5), \
                 mock.patch("server.log"):
                h = _FakeHandler()
                ox.relay(h, {"model": "x", "messages": []})
            self.assertEqual(h.sent[0][0], 429)
            self.assertIn("排队", h.sent[0][1]["error"]["message"])
        finally:
            for _ in range(3):
                ox._CA_SEM.release()

    def test_ca_queue_timeout_stream_ends_as_sse(self):
        """流式排队超时：先开流发心跳，超时后 SSE error 帧收尾（不发状态行）。"""
        for _ in range(3):
            ox._CA_SEM.acquire()
        try:
            with mock.patch.object(ox, "_CA_QUEUE_WAIT", 3.5), \
                 mock.patch("server.log"):
                h = _FakeHandler()
                ox.relay(h, {"model": "x", "stream": True, "messages": []})
            self.assertEqual(h.sent, [])
            self.assertTrue(any(isinstance(c, bytes) and b"queued for CodeArts" in c
                                for c in h.chunks), h.chunks)
            last = h.chunks[-1]
            self.assertIn(b"rate_limit", last)
            self.assertIn(b"data: [DONE]", last)   # 服务端生成帧（带空格，同既有收尾）
        finally:
            for _ in range(3):
                ox._CA_SEM.release()

    def test_connection_layer_exception_retried(self):
        """连接层瞬时异常（requests 家族）也自动重连；非 requests 异常不重试。"""
        import requests
        h = _FakeHandler()
        seq = [requests.exceptions.ReadTimeout("read timeout"),
               ("acct", iter(_sse("好")))]
        with mock.patch.object(ox, "_open_pool", side_effect=_seq_opener(seq)), \
             mock.patch("server.log"):
            ox.relay(h, {"model": "x", "messages": []})
        self.assertEqual(h.sent[0][0], 200)
        self.assertFalse(seq)

        h2 = _FakeHandler()
        calls = []

        def boom(*a):
            calls.append(1)
            raise TypeError("code bug")

        with mock.patch.object(ox, "_open_pool", side_effect=boom), \
             mock.patch("server.log"):
            ox.relay(h2, {"model": "x", "messages": []})
        self.assertEqual(h2.sent[0][0], 502)           # bug 立即暴露，不重试
        self.assertEqual(len(calls), 1)


class TestPoolFirstFrameSwitch(unittest.TestCase):
    """_open_pool 预读：首帧 429 错误帧换下一个号（高并发不弹客户端）。"""

    def setUp(self):
        ox._POOL_COOL.clear()

    def _ents(self):
        return iter([("acctA", _ENT), ("acctB", _ENT)])

    def test_429_first_frame_switches_account(self):
        opened = []

        def fake_open(prov, name, ent, body):
            opened.append(name)
            if name == "acctA":
                # 首帧即 429 错误帧（高并发常见形态）
                return iter(["data:" + json.dumps({"error_code": 429,
                                                   "error_msg": "rate limit"})])
            return iter(_sse("好"))

        with mock.patch.object(ox, "_pool_ents", side_effect=lambda p: self._ents()), \
             mock.patch.object(ox, "_pool_open", side_effect=fake_open), \
             mock.patch("server.log"):
            name, lines = ox._open_pool("codearts", {"model": "x", "messages": []})
        self.assertEqual(name, "acctB")
        self.assertEqual(opened, ["acctA", "acctB"])

    def test_param_error_first_frame_not_switched(self):
        """参数类错误帧不换号（换了也一样错），直接透传。"""
        opened = []

        def fake_open(prov, name, ent, body):
            opened.append(name)
            return iter(["data:" + json.dumps({
                "error_code": "InferHub.001001009.400",
                "error_msg": "The chat messages is required."})])

        with mock.patch.object(ox, "_pool_ents", side_effect=lambda p: self._ents()), \
             mock.patch.object(ox, "_pool_open", side_effect=fake_open), \
             mock.patch("server.log"):
            name, lines = ox._open_pool("codearts", {"model": "x", "messages": []})
        self.assertEqual(opened, ["acctA"])            # 只打了一次：不换号
        first = next(lines)
        self.assertIn("InferHub.001001009.400", first)


class TestDsflashPoolRetryable(unittest.TestCase):
    """_open_dsflash_pool 全失败时：有瞬时错误就抛可重试的（relay 会重连整池）。"""

    def setUp(self):
        ox._POOL_COOL.clear()
        ox._WBAI_ML_COOL.clear()
        # _dsflash_pick 消耗进程级轮转计数器：保存/恢复，避免污染后续测试文件
        # （2026-10-22 实测：test_non_stream_aggregates 曾因计数器位移落到果办
        # 真实通道，收到真实上游响应）。
        self._rr = ox._DSFLASH_RR
        ox._DSFLASH_RR = __import__("itertools").count()

    def tearDown(self):
        ox._DSFLASH_RR = self._rr

    def _ch(self, prov="codearts"):
        return {"prov": prov, "name": "A", "model": "DeepSeek-V4.1-Flash",
                "ent": _ENT, "key": prov + "/A"}

    def test_all_transient_raises_retryable(self):
        with mock.patch.object(ox, "_dsflash_live_channels",
                               return_value=[self._ch()]), \
             mock.patch.object(ox, "_pool_open",
                               side_effect=ox.UpstreamError(429, "too many requests")), \
             mock.patch("server.log"):
            with self.assertRaises(ox.UpstreamError) as cm:
                ox._open_dsflash_pool({"model": "ds-flash", "messages": []})
        self.assertEqual(cm.exception.status, 429)     # 可重试：relay 会退避重连
        self.assertTrue(ox._retryable_err(cm.exception.status, cm.exception.message))

    def test_all_quota_raises_hard_error(self):
        """全是额度耗尽：立即透传，不浪费 90s 重连。"""
        with mock.patch.object(ox, "_dsflash_live_channels",
                               return_value=[self._ch()]), \
             mock.patch.object(ox, "_pool_open",
                               side_effect=ox.UpstreamError(
                                   429, '{"code":14018,"msg":"Credits exhausted"}')), \
             mock.patch("server.log"):
            with self.assertRaises(ox.UpstreamError) as cm:
                ox._open_dsflash_pool({"model": "ds-flash", "messages": []})
        self.assertFalse(ox._retryable_err(cm.exception.status, cm.exception.message))

    def test_empty_pool_raises_retryable_503(self):
        """池空（高并发全通道被短冷却）也是可重试的——等冷却过去就能活。"""
        with mock.patch.object(ox, "_dsflash_live_channels", return_value=[]):
            with self.assertRaises(ox.UpstreamError) as cm:
                ox._open_dsflash_pool({"model": "ds-flash", "messages": []})
        self.assertEqual(cm.exception.status, 503)
        self.assertTrue(ox._retryable_err(cm.exception.status, cm.exception.message))


if __name__ == "__main__":
    unittest.main()
