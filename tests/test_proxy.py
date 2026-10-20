# -*- coding: utf-8 -*-
"""openai_proxy 纯函数单测（不发起任何网络请求）。

覆盖：
  - _upstream_body：上游不支持字段剥离 / 强制 stream / 默认模型 / 附加字段
  - _session_id / _usage_str / _sse_error：确定性输出
  - catalog：缓存命中不重发请求、失败回退种子（mock _get）
  - relay 非流式聚合：mock _chat_stream，验证 OpenAI 响应形状与 usage 记账
运行：python -m unittest tests.test_proxy   （用 pythoncore-3.14-64）
"""
import json
import os
import sys
import unittest
from unittest import mock

sys.argv = [sys.argv[0]]  # server/openai_proxy 导入链会把 argv[1] 当端口读
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import openai_proxy as ox   # noqa: E402  （导入即建缓存/锁，无网络副作用）

_ENT = {"ak": "ak-test", "sk": "sk-test", "sts_token": "sts-test"}


class TestUpstreamBody(unittest.TestCase):
    def test_strips_unsupported_fields(self):
        b = ox._upstream_body({
            "model": "deepseek-v4.1-flash", "messages": [],
            "stream_options": {"include_usage": True}, "user": "u",
            "logit_bias": {}, "logprobs": True, "top_logprobs": 3, "n": 2,
            "presence_penalty": 0.1, "frequency_penalty": 0.2,
            "seed": 42, "response_format": {"type": "json_object"},
            "stop": ["END"], "temperature": 0.7,
        }, "chatid1")
        for k in ("stream_options", "user", "logit_bias", "logprobs",
                  "top_logprobs", "n", "presence_penalty", "frequency_penalty",
                  "seed", "response_format", "stop"):
            self.assertNotIn(k, b)
        self.assertEqual(b["temperature"], 0.7)          # 有用字段保留
        self.assertTrue(b["stream"])                     # 上游恒 SSE
        self.assertEqual(b["chat_id"], "chatid1")
        self.assertEqual(b["prompt_cache_key"], "chatid1")
        self.assertEqual(b["tool_stream"], True)

    def test_default_model_and_keeps_given(self):
        b = ox._upstream_body({"messages": []}, "c")
        self.assertEqual(b["model"], "deepseek-v4.1-flash")   # 缺省 → 免费额度最大
        b2 = ox._upstream_body({"model": "glm-5.3-flash", "messages": []}, "c")
        self.assertEqual(b2["model"], "glm-5.3-flash")        # 指定 → 保留


class TestSmallHelpers(unittest.TestCase):
    def test_session_id_deterministic(self):
        self.assertEqual(ox._session_id("abc"), ox._session_id("abc"))
        self.assertEqual(len(ox._session_id("abc")), 32)
        self.assertNotEqual(ox._session_id("abc"), ox._session_id("abd"))

    def test_usage_str(self):
        self.assertEqual(ox._usage_str({"prompt_tokens": 10, "completion_tokens": 5}),
                         " tokens=10/5/15")
        self.assertEqual(ox._usage_str({"prompt_tokens": 1, "completion_tokens": 2,
                                        "total_tokens": 9}), " tokens=1/2/9")
        self.assertEqual(ox._usage_str(None), "")
        self.assertEqual(ox._usage_str("junk"), "")

    def test_sse_error_shape(self):
        j = json.loads(ox._sse_error(404, "无此模型"))
        self.assertEqual(j["error"]["code"], 404)
        self.assertEqual(j["error"]["message"], "无此模型")
        self.assertEqual(j["error"]["type"], "upstream_error")


class TestCatalog(unittest.TestCase):
    def setUp(self):
        ox._catalog.update(ts=0.0, builtin=[], benefit=set())

    def test_cache_hit_no_refetch(self):
        ox._catalog.update(ts=__import__("time").time(),
                           builtin=["m1"], benefit={"b1"})
        with mock.patch.object(ox, "_get") as g:
            builtin, benefit = ox.catalog(_ENT)
        g.assert_not_called()                       # 缓存有效期内不发请求
        self.assertEqual(builtin, ["m1"])
        self.assertIn("b1", benefit)

    def test_failure_falls_back_to_seed(self):
        with mock.patch.object(ox, "_get", side_effect=Exception("network down")):
            builtin, benefit = ox.catalog(_ENT, force=True)
        self.assertEqual(builtin, [])               # 内置拿不到 → 空
        self.assertTrue({"deepseek-v4.1-flash", "glm-5.3-flash"} <= benefit,
                        "种子福利模型必须在兜底集合里")

    def test_success_populates(self):
        def fake_get(ent, url):
            if "model/builtin" in url:
                return {"builtinModels": [
                    {"model_id": "GLM-5.2", "enable": True},
                    {"model_id": "dead-model", "enable": False},
                ]}
            return {"result": {"models": [{"model_id": "deepseek-v4.1-flash"}]}}
        with mock.patch.object(ox, "_get", side_effect=fake_get):
            builtin, benefit = ox.catalog(_ENT, force=True)
        self.assertEqual(builtin, ["GLM-5.2"])       # disable 的不进目录
        self.assertIn("deepseek-v4.1-flash", benefit)


class TestPickFreshest(unittest.TestCase):
    def test_latest_expiry_wins(self):
        d = {"A": {"expires_at": "2026-10-12T10:00:00Z"},
             "B": {"expires_at": "2026-10-12T23:00:00Z"},
             "C": {"expires_at": "2026-10-11T23:00:00Z"}}
        name, _ = ox._pick_freshest(d)
        self.assertEqual(name, "B")

    def test_missing_expiry_ranks_last(self):
        d = {"A": {}, "B": {"expires_at": "2026-01-01T00:00:00Z"}}
        name, _ = ox._pick_freshest(d)
        self.assertEqual(name, "B")
        name2, _ = ox._pick_freshest({"A": {}, "X": {}})
        self.assertEqual(name2, "A")       # 都没有 → 取 max（字典序兜底，不崩）

    def test_single_account(self):
        name, ent = ox._pick_freshest({"only": {"expires_at": "x", "ak": "a"}})
        self.assertEqual(name, "only")
        self.assertEqual(ent["ak"], "a")


class _FakeHandler:
    """收集 _send/_begin_stream/_write_chunk 调用的假 handler。"""
    def __init__(self):
        self.sent, self.chunks = [], []

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        self.sent.append((code, body))

    def _begin_stream(self, status=200, ctype="text/event-stream; charset=utf-8"):
        self.chunks.append(("HEAD", status))

    def _write_chunk(self, data):
        self.chunks.append(data)


def _sse(*chunks):
    """造上游 SSE 行迭代器（OpenAI chunk 形状）。"""
    lines = []
    for i, c in enumerate(chunks):
        lines.append(json.dumps({
            "id": "resp1", "created": 1700000000, "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": c,
                         "finish_reason": "stop" if i == len(chunks) - 1 else None}],
            **({"usage": {"prompt_tokens": 7, "completion_tokens": 3,
                          "total_tokens": 10}} if i == len(chunks) - 1 else {}),
        }))
    lines.append("data:[DONE]")
    return ["data:" + l for l in lines]


class TestRelayAggregate(unittest.TestCase):
    def setUp(self):
        ox._catalog.update(ts=0.0, builtin=[], benefit=set())

    def test_non_stream_aggregates(self):
        h = _FakeHandler()
        body = {"model": "deepseek-v4.1-flash", "stream": False,
                "messages": [{"role": "user", "content": "hi"}]}
        with mock.patch.object(ox, "_load_ent", return_value=("acct", _ENT)), \
             mock.patch.object(ox, "_chat_stream", return_value=iter(_sse(
                 {"content": "你"}, {"content": "好"}))), \
             mock.patch("server.log") as mlog:
            ox.relay(h, body)
        self.assertEqual(len(h.sent), 1)
        code, out = h.sent[0]
        self.assertEqual(code, 200)
        self.assertEqual(out["choices"][0]["message"]["content"], "你好")
        self.assertEqual(out["choices"][0]["finish_reason"], "stop")
        self.assertEqual(out["usage"]["total_tokens"], 10)
        self.assertEqual(out["model"], "deepseek-v4.1-flash")
        mlog.assert_called_once()                    # 记账必须落一条
        self.assertIn("tokens=7/3/10", mlog.call_args[0][0])

    def test_zero_usage_placeholder_skipped(self):
        """上游首个 chunk 发全 0 usage 占位——记账必须取尾部的真实值。"""
        h = _FakeHandler()
        lines = [
            "data:" + json.dumps({"id": "r", "created": 1, "object": "chat.completion.chunk",
                                  "choices": [{"index": 0, "delta": {"content": "你"}, "finish_reason": None}],
                                  "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}),
            "data:" + json.dumps({"id": "r", "created": 1, "object": "chat.completion.chunk",
                                  "choices": [{"index": 0, "delta": {"content": "好"}, "finish_reason": "stop"}],
                                  "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}}),
            "data:[DONE]",
        ]
        with mock.patch.object(ox, "_load_ent", return_value=("acct", _ENT)), \
             mock.patch.object(ox, "_chat_stream", return_value=iter(lines)), \
             mock.patch("server.log") as mlog:
            ox.relay(h, {"model": "x", "stream": True, "messages": []})
        self.assertIn("tokens=7/3/10", mlog.call_args[0][0])   # 不能是 0/0/0

    def test_upstream_error_passthrough(self):
        h = _FakeHandler()
        with mock.patch.object(ox, "_load_ent", return_value=("acct", _ENT)), \
             mock.patch.object(ox, "_chat_stream",
                               side_effect=ox.UpstreamError(429, "额度用尽")):
            ox.relay(h, {"model": "x", "messages": []})
        self.assertEqual(h.sent[0][0], 429)
        self.assertIn("额度用尽", h.sent[0][1]["error"]["message"])

    def test_non_stream_error_chunk_logged(self):
        """非流式聚合吃到 error chunk（上游 SSE error 事件）→ 必须落审计日志。

        2026-10-19 排查实录：该路径曾只回错误不打日志，故障时 backend_run.log
        零痕迹无法定位（Tabbit InferHub 瞬时拒绝即走此路径 surfaced 为 502）。"""
        h = _FakeHandler()
        err_line = "data:" + json.dumps({
            "id": "r", "created": 1, "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {}, "finish_reason": None}],
            "error": {"message": "The chat messages is required.",
                      "type": "upstream_error"},
            "error_code": "InferHub.001001009.400",
            "error_msg": "The chat messages is required."})
        with mock.patch.object(ox, "_load_ent", return_value=("acct", _ENT)), \
             mock.patch.object(ox, "_chat_stream", return_value=iter([err_line])), \
             mock.patch("server.log") as mlog:
            ox.relay(h, {"model": "x", "stream": False, "messages": []})
        self.assertEqual(h.sent[0][0], 502)
        self.assertIn("The chat messages is required.",
                      h.sent[0][1]["error"]["message"])
        logged = " ".join(c[0][0] for c in mlog.call_args_list)
        self.assertIn("InferHub.001001009.400", logged)   # 审计不能静默

    def test_load_ent_error_no_network(self):
        h = _FakeHandler()
        # 2026-10-19 起 codearts 走统一账号池：凭据过期报错来自 _pool_ents（非 _load_ent）
        with mock.patch.object(ox, "_pool_ents",
                               side_effect=ox.UpstreamError(503, "凭证已过期")):
            ox.relay(h, {"model": "x", "messages": []})
        self.assertEqual(h.sent[0][0], 503)          # 503 原样透传给客户端
        self.assertEqual(h.chunks, [])


class TestWbaiPool(unittest.TestCase):
    """国际版多账号池：一个号额度耗尽自动换下一个。"""

    def setUp(self):
        ox._POOL_COOL.clear()

    def tearDown(self):
        ox._POOL_COOL.clear()

    def test_orders_by_expiry_and_puts_cooldown_last(self):
        accs = {"A": {"token": "t", "expires_at": "2027-01-01 00:00"},
                "B": {"token": "t", "expires_at": "2027-06-01 00:00"}}
        with mock.patch.object(ox.wai, "load_accounts", return_value=accs):
            self.assertEqual([n for n, _ in ox._wbai_ents()], ["B", "A"])
            ox._wbai_cool("B", "test")
            self.assertEqual([n for n, _ in ox._wbai_ents()], ["A", "B"])

    def test_failover_on_credits_exhausted(self):
        accs = {"OLD": {"token": "t1", "expires_at": "2027-01-01 00:00"},
                "NEW": {"token": "t2", "expires_at": "2027-06-01 00:00"}}
        quota = json.dumps({"error": {"data": {"code": 14018,
                                               "msg": "Credits exhausted."}}})
        good = 'data: {"choices":[{"delta":{"content":"hi"}}]}'

        def fake_stream(ent, body, name=None):
            if name == "NEW":
                raise ox.wai.UpstreamErr(402, quota)
            return iter([good])

        with mock.patch.object(ox.wai, "load_accounts", return_value=accs), \
             mock.patch.object(ox.wai, "chat_stream", side_effect=fake_stream), \
             mock.patch("server.log"):
            name, lines = ox._open_wbai({"model": "wb:fast-model", "messages": []})
        self.assertEqual(name, "OLD")            # NEW 先试且失败 → 回落 OLD
        self.assertEqual(list(lines), [good])
        self.assertIn("NEW", ox._POOL_COOL.get("wbai", {}))    # 失败号进入冷却

    def test_model_chain_explicit_and_auto(self):
        # 显式模型：只试它本身 + 同名付费退路（上游按行限流，付费行常仍通）
        self.assertEqual(ox._wbai_chain({}, "deepseek-v4.1-flash"),
                         ["deepseek-v4.1-flash", "deepseek-v4.1-flash-sg"])
        # auto/空：按用户优先级链，目录取不到时用默认链 + default-model 兜底
        with mock.patch.object(ox.wai, "gw_models", side_effect=RuntimeError("no net")):
            self.assertEqual(ox._wbai_chain({}, None),
                             ox.WBAI_AUTO_CHAIN + ["default-model"])

    def test_err_kind_distinguishes_account_and_model(self):
        acct = json.dumps({"error": {"data": {"code": 14018, "msg": "Credits exhausted."}}})
        rl = json.dumps({"error_code": 429, "error_msg": "rate limit exceeded"})
        self.assertEqual(ox._wbai_err_kind("data: " + acct), "account")
        self.assertEqual(ox._wbai_err_kind("data: " + rl), "model")
        self.assertIsNone(ox._wbai_err_kind("data: " + json.dumps({"choices": []})))

    def test_err_kind_gateway_native_6004(self):
        # 2026-10-19 实测：网关原生限流 chunk 是顶层 code/msg，不是 error_code/error_msg
        native = json.dumps({"code": 6004,
                             "msg": "usage exceeds frequency limit, but don't worry, "
                                    "your usage will reset at 2026-10-20 19:41:31 UTC+8, "
                                    "alternatively, you can switch to the other models"})
        self.assertEqual(ox._wbai_err_kind("data: " + native), "model")
        # 模型繁忙（14003）同为行级 → 同号换模型
        busy = json.dumps({"code": 14003, "msg": "too many requests",
                           "displayMsg": {"zh": "模型繁忙，请换模型或稍后重试"}})
        self.assertEqual(ox._wbai_err_kind("data: " + busy), "model")

    def test_all_accounts_exhausted_raises(self):
        accs = {"A": {"token": "t", "expires_at": "2027-01-01 00:00"}}
        quota = json.dumps({"error": {"data": {"code": 14018, "msg": "Credits exhausted."}}})
        with mock.patch.object(ox.wai, "load_accounts", return_value=accs), \
             mock.patch.object(ox.wai, "chat_stream",
                               side_effect=ox.wai.UpstreamErr(402, quota)), \
             mock.patch("server.log"):
            with self.assertRaises(ox.UpstreamError) as cm:
                ox._open_wbai({"model": "wb:x", "messages": []})
        self.assertIn("14018", cm.exception.message)


class TestWbaiModelLimit(unittest.TestCase):
    """6004 行级限流：重置时刻解析、(账号,模型) 冷却、链过滤。"""

    def setUp(self):
        ox._WBAI_ML_COOL.clear()
        ox._POOL_COOL.clear()

    def tearDown(self):
        ox._WBAI_ML_COOL.clear()
        ox._POOL_COOL.clear()

    def test_reset_ts_absolute_en(self):
        # 2026-10-19 实测真实响应（英文文案，北京时间 UTC+8）
        line = json.dumps({"code": 6004, "msg": "usage exceeds frequency limit, "
                           "your usage will reset at 2026-10-20 19:41:31 UTC+8, "
                           "alternatively, you can switch to the other models"})
        ts = ox._wbai_reset_ts(line)
        self.assertIsNotNone(ts)
        import time as _t
        self.assertEqual(_t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(ts)),
                         "2026-10-20 19:41:31")

    def test_reset_ts_absolute_zh(self):
        # magpie#1361 实测中文文案
        ts = ox._wbai_reset_ts("您的使用量已超出频率限制,将在 2026-08-06 15:49:30 UTC+8重置,"
                               "您也可以切换其他模型继续使用。6004 | Trace ID: x")
        self.assertIsNotNone(ts)
        import time as _t
        self.assertEqual(_t.strftime("%H:%M", _t.localtime(ts)), "15:49")

    def test_reset_ts_relative_tomorrow(self):
        ts = ox._wbai_reset_ts("您的使用量已超出频率限制,将在明天早上 9:30 重置")
        self.assertIsNotNone(ts)
        import datetime as _dt
        d = _dt.datetime.fromtimestamp(ts)
        self.assertEqual((d.year, d.month, d.day),
                         (_dt.datetime.now() + _dt.timedelta(days=1)).timetuple()[:3])
        self.assertEqual((d.hour, d.minute), (9, 30))

    def test_reset_ts_unparsable_returns_none(self):
        self.assertIsNone(ox._wbai_reset_ts("usage exceeds frequency limit"))
        self.assertIsNone(ox._wbai_reset_ts(""))

    def test_ml_limit_records_and_annotates(self):
        line = json.dumps({"code": 6004,
                           "msg": "your usage will reset at 2026-10-20 19:41:31 UTC+8"})
        tag = ox._wbai_ml_limit("acct1", "DeepSeek-V4.1-Flash", line)
        self.assertIn("重置", tag)
        self.assertIn("19:41", tag)
        self.assertTrue(ox._wbai_ml_hit("acct1", "deepseek-v4.1-flash"))   # 大小写不敏感
        self.assertFalse(ox._wbai_ml_hit("acct2", "deepseek-v4.1-flash"))  # 其他号不受影响
        # 解析不出时刻 → 退 5h 经验窗口
        tag2 = ox._wbai_ml_limit("acct1", "hy3", "usage exceeds frequency limit")
        self.assertIn("约", tag2)
        self.assertTrue(ox._wbai_ml_hit("acct1", "hy3"))

    def test_chain_skips_limited_rows(self):
        ox._WBAI_ML_COOL[("A", "deepseek-v4.1-flash")] = ox.time.time() + 600
        ox._WBAI_ML_COOL[("A", "deepseek-v4.1-flash-sg")] = ox.time.time() + 600
        with mock.patch.object(ox.wai, "gw_models", side_effect=RuntimeError("no net")):
            chain = ox._wbai_chain({}, None, name="A")
        self.assertNotIn("deepseek-v4.1-flash", chain)
        self.assertNotIn("deepseek-v4.1-flash-sg", chain)
        # 显式点名被限流的模型 → 行过滤后为空，调用方拿到空链换号（不空转上游）
        self.assertEqual(ox._wbai_chain({}, "deepseek-v4.1-flash", name="A"), [])

    def test_pool_model_limited_keeps_account_alive(self):
        # 行级限流（6004）：账号不进整号冷却，同号直接跳到链上下一个模型
        accs = {"A": {"token": "t", "expires_at": "2027-01-01 00:00"}}
        limit = 'data: ' + json.dumps({"code": 6004,
                                       "msg": "your usage will reset at 2026-10-20 19:41:31 UTC+8"})
        good = 'data: {"choices":[{"delta":{"content":"ok"}}]}'
        calls = []

        def fake_stream(ent, body, name=None):
            calls.append(body["model"])
            if body["model"] == "deepseek-v4.1-flash":
                return iter([limit])
            return iter([good])

        with mock.patch.object(ox.wai, "load_accounts", return_value=accs), \
             mock.patch.object(ox.wai, "gw_models", return_value=[
                 {"id": "deepseek-v4.1-flash"}, {"id": "hy3"}, {"id": "default-model"}]), \
             mock.patch.object(ox.wai, "chat_stream", side_effect=fake_stream), \
             mock.patch("server.log"):
            name, lines = ox._open_wbai({"model": "wb:auto", "messages": []})
        self.assertEqual(name, "A")
        self.assertEqual(calls, ["deepseek-v4.1-flash", "hy3"])   # 链上第二个模型顶上
        self.assertEqual(list(lines), [good])
        self.assertNotIn("A", ox._POOL_COOL.get("wbai", {}))      # 整号未被拉黑
        self.assertTrue(ox._wbai_ml_hit("A", "deepseek-v4.1-flash"))

    def test_wbai_model_limits_snapshot(self):
        ox._WBAI_ML_COOL[("A", "hy3")] = ox.time.time() + 600
        ox._WBAI_ML_COOL[("B", "x")] = ox.time.time() - 10        # 已过期 → 清理
        snap = ox.wbai_model_limits()
        self.assertIn("A", snap)
        self.assertNotIn("B", snap)


if __name__ == "__main__":
    unittest.main()
