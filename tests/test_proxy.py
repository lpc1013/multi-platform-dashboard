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
import tempfile as _tempfile
import time
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


def _future_reset(hours=3):
    """夹具用的重置时刻必须相对当前时间：写死日期会让测试在跨过那个点后自己变红
    （2026-10-20 20:12 实测：原夹具的 19:41 已过期，三条用例同时假失败）。"""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + hours * 3600))


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

    def test_tabbit_error_text_non_stream_becomes_502(self):
        """Tabbit 流式路径已不发 error 帧（客户端见 error 帧即撤销气泡显示
        「用户已取消」），错误改为正文 + stop。非流式聚合必须靠正文前缀
        识别并回 502，否则错误会被当成正常回答 200 返回。"""
        h = _FakeHandler()
        lines = [
            "data:" + json.dumps({
                "id": "r", "created": 1, "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"role": "assistant"},
                             "finish_reason": None}]}),
            "data:" + json.dumps({
                "id": "r", "created": 1, "object": "chat.completion.chunk",
                "choices": [{"index": 0,
                             "delta": {"content": "⚠️ Tabbit 上游错误：该模型需要 Pro 会员"},
                             "finish_reason": None}]}),
            "data:" + json.dumps({
                "id": "r", "created": 1, "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
            "data:[DONE]",
        ]
        with mock.patch.object(ox, "_open_pool",
                               return_value=("acct", iter(lines))), \
             mock.patch("server.log") as mlog:
            ox.relay(h, {"model": "tb:DeepSeek-V4.1-Flash", "stream": False,
                         "messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual(h.sent[0][0], 502)
        self.assertIn("Pro 会员", h.sent[0][1]["error"]["message"])
        logged = " ".join(c[0][0] for c in mlog.call_args_list)
        self.assertIn("HTTP502", logged)                 # 审计不能静默

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
        # 14018 只冷当前模型行，不再整号拉黑（整号冷却会导致两个号同时不可用）
        self.assertNotIn("NEW", ox._POOL_COOL.get("wbai", {}))
        self.assertTrue(ox._wbai_ml_hit("NEW", "fast-model"))

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
                           "msg": "your usage will reset at %s UTC+8" % _future_reset()})
        tag = ox._wbai_ml_limit("acct1", "DeepSeek-V4.1-Flash", line)
        self.assertIn("重置", tag)
        self.assertIn(time.strftime("%H:%M", time.localtime(time.time() + 3 * 3600)), tag)
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
                                       "msg": "your usage will reset at %s UTC+8" % _future_reset()})
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

    def test_busy_14003_uses_short_cooldown(self):
        # 14003 是瞬时「模型繁忙」：不能按 6004 的 5 小时窗口拉黑整条链
        tag = ox._wbai_ml_limit("A", "deepseek-v4.1-flash",
                                'data: ' + json.dumps({"code": 14003,
                                                       "msg": "too many requests"}))
        self.assertIn("秒后重试", tag)
        remain = ox._WBAI_ML_COOL[("A", "deepseek-v4.1-flash")] - ox.time.time()
        self.assertGreater(remain, 0)
        self.assertLessEqual(remain, ox._WBAI_BUSY_COOL + 2)

    def test_quota_14018_in_http_429_shell_keeps_account_alive(self):
        # 2026-10-20 实测：上游把 14018 塞在 HTTP 429 外壳里，旧逻辑会按行限流
        # 冷 5 小时；新逻辑只冷当前模型行，同号换下一个模型。
        accs = {"A": {"token": "t", "expires_at": "2027-01-01 00:00"}}
        quota = json.dumps({"error": {"data": {"code": 14018,
                                               "msg": "Credits exhausted."}}})
        good = 'data: {"choices":[{"delta":{"content":"ok"}}]}'
        calls = []

        def fake_stream(ent, body, name=None):
            calls.append(body["model"])
            if body["model"] == "deepseek-v4.1-flash":
                raise ox.wai.UpstreamErr(429, quota)
            return iter([good])

        with mock.patch.object(ox.wai, "load_accounts", return_value=accs), \
             mock.patch.object(ox.wai, "gw_models", return_value=[
                 {"id": "deepseek-v4.1-flash"}, {"id": "hy3"}, {"id": "default-model"}]), \
             mock.patch.object(ox.wai, "chat_stream", side_effect=fake_stream), \
             mock.patch("server.log"):
            name, lines = ox._open_wbai({"model": "wb:auto", "messages": []})
        self.assertEqual(name, "A")
        self.assertEqual(calls, ["deepseek-v4.1-flash", "hy3"])
        self.assertEqual(list(lines), [good])
        self.assertNotIn("A", ox._POOL_COOL.get("wbai", {}))
        self.assertTrue(ox._wbai_ml_hit("A", "deepseek-v4.1-flash"))

    def test_wbai_model_limits_snapshot(self):
        ox._WBAI_ML_COOL[("A", "hy3")] = ox.time.time() + 600
        ox._WBAI_ML_COOL[("B", "x")] = ox.time.time() - 10        # 已过期 → 清理
        snap = ox.wbai_model_limits()
        self.assertIn("A", snap)
        self.assertNotIn("B", snap)


class TestWbaiTrialAndUsage(unittest.TestCase):
    """国际版试用起点必须按账号缓存；反代用量键要去掉 wb:/tb: 前缀。"""

    def setUp(self):
        self._cat = dict(ox.wai._catalog)
        ox.wai._catalog.update(ts=time.time(), models=[{"id": "x"}],
                               promos=[], trial=None)
        ox.wai._trial_starts.clear()

    def tearDown(self):
        ox.wai._catalog.clear()
        ox.wai._catalog.update(self._cat)
        ox.wai._trial_starts.clear()

    def test_trial_start_cached_per_account(self):
        ox.wai._catalog.update(trial={"key": "firstUse", "days": 14,
                                      "model": "hy4-preview", "target": "hy4"})
        ent_a = {"user_id": "u1", "token": "t1"}
        ent_b = {"user_id": "u2", "token": "t2"}
        with mock.patch.object(
                ox.wai, "_fetch_trial_start",
                side_effect=lambda ent, trial: {"u1": 1000.0, "u2": 2000.0}[ent["user_id"]],
        ) as f:
            self.assertEqual(ox.wai.promo_state(ent_a)[2], 1000.0)
            self.assertEqual(ox.wai.promo_state(ent_b)[2], 2000.0)
            # 再读 A 不能被 B 的缓存覆盖（旧实现就是全局单份）
            self.assertEqual(ox.wai.promo_state(ent_a)[2], 1000.0)
            self.assertEqual(f.call_count, 2)

    def test_acct_usage_strips_provider_prefix(self):
        import tempfile
        import data_dir
        today = time.strftime("%Y-%m-%d")
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "proxy_usage.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump({"__acct": {"wbai/A": {today: {
                    "wb:deepseek-v4.1-flash": {"calls": 3}}}}}, fh)
            with mock.patch.object(data_dir, "candidates", return_value=[p]):
                u = ox.wai._acct_usage_today("A")
        self.assertEqual(u["deepseek-v4.1-flash"]["calls"], 3)


if __name__ == "__main__":
    unittest.main()


class TestWbaiFreeChain(unittest.TestCase):
    """2026-10-20：auto 链＝目录里 x0.00 的四个免费行；付费 hy4-preview 不进链。"""

    def setUp(self):
        ox._WBAI_ML_COOL.clear()
        ox._POOL_COOL.clear()

    def test_auto_chain_is_the_four_free_rows(self):
        # 四个免费行都在链上；hy4-preview-f 排最后：它限免 10-10 已结束，
        # 目录仍标 x0.00 但上游按积分门要账（两号实测 14018），垫底才不拖慢前三条。
        self.assertEqual(ox.WBAI_AUTO_CHAIN,
                         ["deepseek-v4.1-flash", "hy3", "step-5-preview", "hy4-preview-f"])
        self.assertNotIn("hy4-preview", ox.WBAI_AUTO_CHAIN)   # x0.29 付费行
        # hy4-preview-f 没有付费变体：不该给它配同名退路（配了只会在积分见底上多撞 14018）
        self.assertNotIn("hy4-preview-f", ox.WBAI_PAID_ALIAS)

    def test_chain_lists_four_rows_without_catalog(self):
        with mock.patch.object(ox.wai, "gw_models", side_effect=RuntimeError("no net")):
            chain = ox._wbai_chain({}, None)
        for m in ox.WBAI_AUTO_CHAIN:
            self.assertIn(m, chain)

    def test_unparsable_6004_cools_24h_not_5h(self):
        # 免费模型的 6004 是 24h token 窗口；5 小时那一档是付费模型的次数窗口
        tag = ox._wbai_ml_limit("A", "hy3", "usage exceeds frequency limit")
        self.assertIn("约", tag)
        remain = ox._WBAI_ML_COOL[("A", "hy3")] - ox.time.time()
        self.assertGreater(remain, 23 * 3600)
        self.assertLessEqual(remain, 24 * 3600 + 5)


class TestWbaiWaitRetry(unittest.TestCase):
    """限流不直接弹错误：最早恢复时刻在预算内就替客户端等（并用心跳喂着它）。"""

    def setUp(self):
        ox._WBAI_ML_COOL.clear()
        ox._POOL_COOL.clear()

    def test_no_cooled_rows_means_no_wait(self):
        self.assertIsNone(ox._wbai_next_avail())
        self.assertFalse(ox._wbai_wait_retry(ox.UpstreamError(429, "x"), 0))

    def test_next_avail_picks_min_of_rows_and_accounts(self):
        now = ox.time.time()
        ox._WBAI_ML_COOL[("A", "hy3")] = now + 400
        ox._WBAI_ML_COOL[("B", "hy3")] = now + 30
        ox._POOL_COOL["wbai"] = {"C": now + 90}
        self.assertAlmostEqual(ox._wbai_next_avail(), now + 30, delta=1)

    def test_far_reset_does_not_wait(self):
        ox._WBAI_ML_COOL[("A", "hy3")] = ox.time.time() + ox._WBAI_WAIT_MAX + 600
        self.assertFalse(ox._wbai_wait_retry(ox.UpstreamError(429, "x"), 0))

    def test_near_reset_waits_and_beats(self):
        ox._WBAI_ML_COOL[("A", "hy3")] = ox.time.time() + 2.0
        beats = []
        t0 = ox.time.time()
        self.assertTrue(ox._wbai_wait_retry(ox.UpstreamError(429, "x"), 0,
                                            beat=lambda rem: beats.append(rem)))
        self.assertGreaterEqual(ox.time.time() - t0, 1.5)   # 真的睡到点，不是立刻返回
        self.assertTrue(beats and beats[0] >= 1)

    def test_dead_client_stops_waiting(self):
        ox._WBAI_ML_COOL[("A", "hy3")] = ox.time.time() + 30

        def boom(rem):
            raise OSError("客户端已断开")

        self.assertFalse(ox._wbai_wait_retry(ox.UpstreamError(429, "x"), 0, beat=boom))

    def test_retry_att_cap(self):
        ox._WBAI_ML_COOL[("A", "hy3")] = ox.time.time() + 5
        self.assertFalse(ox._wbai_wait_retry(ox.UpstreamError(429, "x"), 3))


class TestWbaiRelayWait(unittest.TestCase):
    """relay 层：等待重试期间只开一次流；最终失败要按 SSE 收尾，不能再发 HTTP 状态行。"""

    def setUp(self):
        ox._WBAI_ML_COOL.clear()
        ox._POOL_COOL.clear()

    def test_wait_then_success_opens_stream_once(self):
        h = _FakeHandler()
        ox._WBAI_ML_COOL[("A", "hy3")] = ox.time.time() + 0.3
        seq = [ox.UpstreamError(429, '{"code":14003,"msg":"too many requests"}'),
               ("A", iter(_sse({"content": "好"})))]

        def fake_open(body):
            item = seq.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        with mock.patch.object(ox, "_open_wbai", side_effect=lambda b: fake_open(b)), \
             mock.patch("server.log"):
            ox.relay(h, {"model": "wb:auto", "stream": True, "messages": []})
        self.assertEqual([c for c in h.chunks if c[0] == "HEAD"], [("HEAD", 200)])
        self.assertEqual(len(h.sent), 0)                      # 不该再发一个 HTTP 响应
        self.assertTrue(any(isinstance(c, bytes) and b"retrying in" in c for c in h.chunks))
        self.assertFalse(seq)                                  # 确实重试到了第二个

    def test_all_wait_fails_ends_as_sse_not_status(self):
        h = _FakeHandler()
        ox._WBAI_ML_COOL[("A", "hy3")] = ox.time.time() + 0.3

        def fake_open(body):
            raise ox.UpstreamError(429, "usage exceeds frequency limit")

        with mock.patch.object(ox, "_open_wbai", side_effect=fake_open), \
             mock.patch("server.log"):
            ox.relay(h, {"model": "wb:auto", "stream": True, "messages": []})
        self.assertEqual(len(h.sent), 0)     # 开了流就不能再发状态行
        tail = [c for c in h.chunks if isinstance(c, bytes)]
        self.assertTrue(any(b'"type": "rate_limit"' in c or b'"type":"rate_limit"' in c
                            for c in tail), tail[-1] if tail else h.chunks)
        self.assertIn(b"data: [DONE]", h.chunks[-1])


class TestOfficeaceNoCredentialBorrow(unittest.TestCase):
    """果办：续期不许把别的号的凭据写进本账号键（2026-10-20 两号长成同一条的事故）。"""

    def setUp(self):
        import platforms.officeace as oac
        self.oac = oac
        self.td = _tempfile.TemporaryDirectory()
        self.path = os.path.join(self.td.name, "officeace_accounts.json")
        self._orig = oac._acc_paths
        oac._acc_paths = lambda fn: [self.path]

    def tearDown(self):
        self.oac._acc_paths = self._orig
        self.td.cleanup()

    def _write(self, d):
        from platforms._util import enc_cred
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(enc_cred(d), fh, ensure_ascii=False)

    def test_persist_refuses_identity_switch(self):
        self._write({"A": {"ak": "AKA", "user_id": "uid-A", "project_id": "p-A"},
                     "B": {"ak": "AKB", "user_id": "uid-B", "project_id": "p-B"}})
        # 拿 A 的凭据去落 B 的键（旧路径就是这么把两个号写成一条的）→ 必须整份拒绝
        self.oac._persist_entry("B", {"ak": "AKA", "user_id": "uid-A",
                                      "project_id": "p-A", "sk": "SKA"})
        from platforms._util import dec_cred
        after = dec_cred(json.load(open(self.path, encoding="utf-8")))
        self.assertEqual(after["B"]["ak"], "AKB")
        self.assertEqual(after["B"]["user_id"], "uid-B")

    def test_persist_still_refreshes_same_identity(self):
        # 证伪对面：同一 uid 只换 STS 时刻，必须照写——否则上面那条闸是误伤
        self._write({"A": {"ak": "AKA", "user_id": "uid-A", "expires_at": "2026-10-20T01:00:00"}})
        self.oac._persist_entry("A", {"ak": "AKA", "user_id": "uid-A",
                                      "expires_at": "2026-10-21T09:00:00",
                                      "sts_token": "NEW"})
        from platforms._util import dec_cred
        after = dec_cred(json.load(open(self.path, encoding="utf-8")))
        self.assertEqual(after["A"]["expires_at"], "2026-10-21T09:00:00")
        self.assertEqual(after["A"]["sts_token"], "NEW")


class TestWbaiFreeModelRows(unittest.TestCase):
    """面板「免费模型」要铺四个免费行（含限免已结束的 hy4-preview-f），且用量按号取。"""

    def _fm(self, promos, usage_map):
        # promo_state 出来的 until 是 epoch 秒（read_account 里要 localtime 格式化）
        with mock.patch.object(ox.wai, "ensure_token", return_value="tok"), \
             mock.patch.object(ox.wai, "_headers", return_value={}), \
             mock.patch.object(ox.wai, "promo_state", return_value=(promos, None, None)), \
             mock.patch.object(ox.wai, "_acct_usage_today", return_value=usage_map), \
             mock.patch.object(ox.wai.requests, "Session") as S:
            resp = mock.Mock(status_code=200)
            resp.json.return_value = {"code": 0, "data": {"Response": {"Data": {"Accounts": []}}}}
            S.return_value.post.return_value = resp
            return ox.wai.read_account("A", {"token": "t", "user_id": "u"})["free_models"]

    def test_four_rows_even_after_promo_ends(self):
        e = time.time() + 30 * 3600
        promos = [{"model": "hy3", "days_left": 11, "until": e},
                  {"model": "deepseek-v4.1-flash", "days_left": 11, "until": e},
                  {"model": "step-5-preview", "days_left": 5, "until": e}]
        fm = self._fm(promos, {"hy3": {"calls": 4}})
        self.assertEqual([r["model"] for r in fm],
                         list(ox.wai.WBAI_FREE_ORDER))
        self.assertEqual(len(fm), 4)
        self.assertEqual(fm[1]["calls"], 4)          # 按本号自记账，不是全池合计
        self.assertEqual(fm[0]["calls"], 0)
        self.assertNotIn("hy4-preview-f", [p["model"] for p in promos])   # 限免确实已结束

    def test_promo_only_model_still_listed(self):
        # 目录取不到（离线）也不能把有限免的模型整行抹掉
        fm = self._fm([{"model": "glm-9", "days_left": 2, "until": time.time() + 2 * 3600}], {})
        self.assertIn("glm-9", [r["model"] for r in fm])


class TestOfficeacePickLiveSession(unittest.TestCase):
    """续期取会话：只认同名/同 uid，取不到就 None（不许借别的号）。"""

    def setUp(self):
        import platforms.officeace as oac
        self.oac = oac

    def test_same_key_wins(self):
        accs = {"A": {"user_id": "uid-A", "ak": "AKA"}, "B": {"user_id": "uid-B", "ak": "AKB"}}
        self.assertIs(self.oac.pick_live_session("B", {"user_id": "u-B"}, accs), accs["B"])

    def test_alias_key_matched_by_uid(self):
        accs = {"华为·甲": {"user_id": "domain:uid-B", "ak": "AKB"}}
        got = self.oac.pick_live_session("B", {"user_id": "uid-B"}, accs)
        self.assertEqual(got["ak"], "AKB")

    def test_other_uid_only_returns_none(self):
        # 这条就是那次串号事故的正面证伪：客户端只登了 A，续 B 必须拿不到
        accs = {"A": {"user_id": "uid-A", "ak": "AKA", "project_id": "p-A"}}
        self.assertIsNone(self.oac.pick_live_session("B", {"user_id": "uid-B"}, accs))

    def test_no_uid_returns_none(self):
        accs = {"A": {"user_id": "uid-A"}}
        self.assertIsNone(self.oac.pick_live_session("B", {}, accs))


class TestWbaiCatalogPerAccount(unittest.TestCase):
    """模型目录按账号分键：A 号目录里没有的行，不该因为 B 号后刷新就整条消失。"""

    def setUp(self):
        self._cat = dict(ox.wai._catalog)
        self._by = dict(ox.wai._catalog_by_acct)
        ox.wai._catalog.update(ts=0.0, models=[], promos=[], trial=None)
        ox.wai._catalog_by_acct.clear()

    def tearDown(self):
        ox.wai._catalog.clear()
        ox.wai._catalog.update(self._cat)
        ox.wai._catalog_by_acct.clear()
        ox.wai._catalog_by_acct.update(self._by)

    def _two_accounts(self):
        a = {"token": "tA", "user_id": "uid-A"}
        b = {"token": "tB", "user_id": "uid-B"}
        rows_a = [{"id": "hy3", "credit": "x0.00"}, {"id": "hy4-preview-f", "credit": "x0.00"}]
        rows_b = [{"id": "hy3", "credit": "x0.00"}, {"id": "step-5-preview", "credit": "x0.00"}]
        with mock.patch("requests.Session") as S:
            for ent, rows in ((a, rows_a), (b, rows_b)):
                resp = mock.Mock(status_code=200)
                resp.json.return_value = {"data": {"models": rows, "productFeaturesConfig": {}}}
                S.return_value.get.return_value = resp
                ox.wai.gw_models(ent)

    def test_per_account_lists_do_not_clobber(self):
        a = {"token": "tA", "user_id": "uid-A"}
        self._two_accounts()
        # A 的目录里那一行还在（旧实现：B 后刷新 ⇒ A 只剩 B 的 2 行）
        with mock.patch("requests.Session"):
            ids_a = {m["id"] for m in ox.wai.gw_models(a)}
        self.assertIn("hy4-preview-f", ids_a)

    def test_union_covers_rows_only_one_account_sees(self):
        a = {"token": "tA", "user_id": "uid-A"}
        b = {"token": "tB", "user_id": "uid-B"}
        self._two_accounts()
        with mock.patch.object(ox.wai, "load_accounts", return_value={"A": a, "B": b}),              mock.patch("requests.Session"):
            ids = {m["id"] for m in ox.wai.gw_models_all()}
        self.assertEqual(ids, {"hy3", "hy4-preview-f", "step-5-preview"})

    def test_free_order_has_four_rows(self):
        self.assertEqual(len(set(ox.wai.WBAI_FREE_ORDER)), 4)


class TestWbaiLimitVisibility(unittest.TestCase):
    """限流要能在面板上看见：码 / 号 / 模型 / 重置时刻 / 正在等待的请求。"""

    def setUp(self):
        ox._WBAI_ML_COOL.clear()
        ox._WBAI_EVENTS.clear()
        ox._WBAI_WAITING.clear()

    def test_code_extraction_covers_nested_and_native(self):
        self.assertEqual(ox._wbai_code_of('{"code":6004,"msg":"x"}'), "6004")
        self.assertEqual(ox._wbai_code_of('{"error":{"data":{"code":14018,"msg":"y"}}}'), "14018")
        self.assertEqual(ox._wbai_code_of("plain text with 14003 inside"), "14003")
        self.assertEqual(ox._wbai_code_of("nothing here"), "")

    def test_event_recorded_on_row_limit(self):
        line = json.dumps({"code": 6004, "msg": "will reset at %s UTC+8" % _future_reset()})
        ox._wbai_ml_limit("WB国际·lpc1013", "deepseek-v4.1-flash", line)
        st = ox.wbai_limit_state()
        self.assertEqual(len(st["events"]), 1)
        ev = st["events"][0]
        self.assertEqual(ev["code"], "6004")
        self.assertEqual(ev["acct"], "WB国际·lpc1013")
        self.assertIsNotNone(ev["reset"])
        self.assertIn("deepseek-v4.1-flash", st["rows"]["WB国际·lpc1013"])

    def test_events_are_a_ring_buffer(self):
        for i in range(60):
            ox._wbai_event("6004", "A", "m%d" % i)
        st = ox.wbai_limit_state()
        self.assertLessEqual(len(ox._WBAI_EVENTS), ox._WBAI_EVENTS_MAX)
        self.assertEqual(len(st["events"]), 15)        # 只回最近 15 条

    def test_waiting登记自清理(self):
        ox._WBAI_ML_COOL[("A", "hy3")] = ox.time.time() + 0.3
        self.assertTrue(ox._wbai_wait_retry(ox.UpstreamError(429, "14003 too many requests"),
                                            0, acct="A", model="hy3"))
        self.assertEqual(ox._WBAI_WAITING, {})         # 等完必须清空，不能留僵尸条目


class _NoSleep(object):
    """给 officeace 续期轮询用的 time 替身：真实实现每轮 sleep(1)×24 = 面板卡 24 秒。"""

    @staticmethod
    def sleep(_s):
        return None

    @staticmethod
    def time():
        return time.time()


class TestHuaweiStaleSessionGuard(unittest.TestCase):
    """华为两平台的号只刷新**当前登录**那一条：另一条会停在一整天前。
    客户端会话覆盖库里凭据时必须先比新旧，否则面板把「刚续到明天」的号报成过期。"""

    def setUp(self):
        import local_import
        import platforms.codearts as cat
        import platforms.officeace as oac
        self.li, self.cat, self.oac = local_import, cat, oac
        self.td = _tempfile.TemporaryDirectory()
        self.ca_path = os.path.join(self.td.name, "codearts_accounts.json")
        self.oa_path = os.path.join(self.td.name, "officeace_accounts.json")
        self._ca_files, self._oa_paths = cat._ACC_FILES, oac._acc_paths
        cat._ACC_FILES = (self.ca_path,)
        oac._acc_paths = lambda fn: [self.oa_path]

    def tearDown(self):
        self.cat._ACC_FILES = self._ca_files
        self.oac._acc_paths = self._oa_paths
        self.td.cleanup()

    def _store(self, path, ent):
        from platforms._util import enc_cred
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(enc_cred({"0623号": ent}), fh, ensure_ascii=False)

    def _cred(self, ak, exp):
        return {"ak": ak, "sk": "sk-" + ak, "sts_token": "sts-" + ak,
                "user_id": "uid-0623", "expires_at": exp}

    # ── CodeArts ──
    def test_codearts_keeps_fresher_store_credential(self):
        self._store(self.ca_path, self._cred("AK_STORED", "2026-10-21T12:18:01"))
        live = {"0623号": self._cred("AK_CLIENT", "2026-10-20T08:27:27")}
        with mock.patch.object(self.li, "read_codearts", return_value=(True, "", live)):
            got = self.cat.load_accounts()["0623号"]
        self.assertEqual(got["ak"], "AK_STORED")
        self.assertEqual(got["expires_at"], "2026-10-21T12:18:01")

    def test_codearts_still_adopts_fresher_client_session(self):
        # 对面：闸要是写成「永不覆盖」，客户端新登录的凭据就进不来 —— 必须照收
        self._store(self.ca_path, self._cred("AK_STORED", "2026-10-20T08:27:27"))
        live = {"0623号": self._cred("AK_CLIENT", "2026-10-21T12:18:01")}
        with mock.patch.object(self.li, "read_codearts", return_value=(True, "", live)):
            got = self.cat.load_accounts()["0623号"]
        self.assertEqual(got["ak"], "AK_CLIENT")
        self.assertEqual(got["expires_at"], "2026-10-21T12:18:01")

    # ── OfficeACE ──
    def test_officeace_keeps_fresher_store_credential(self):
        self._store(self.oa_path, self._cred("AK_STORED", "2026-10-21T12:12:52"))
        live = {"0623号": self._cred("AK_CLIENT", "2026-10-20T07:14:47")}
        with mock.patch.object(self.li, "read_officeace", return_value=(True, "", live)):
            got = self.oac.load_accounts()["0623号"]
        self.assertEqual(got["ak"], "AK_STORED")
        self.assertEqual(got["expires_at"], "2026-10-21T12:12:52")

    def test_officeace_still_adopts_fresher_client_session(self):
        self._store(self.oa_path, self._cred("AK_STORED", "2026-10-20T07:14:47"))
        live = {"0623号": self._cred("AK_CLIENT", "2026-10-21T12:12:52")}
        with mock.patch.object(self.li, "read_officeace", return_value=(True, "", live)):
            got = self.oac.load_accounts()["0623号"]
        self.assertEqual(got["ak"], "AK_CLIENT")


class TestOfficeaceExpiredSessionVisible(unittest.TestCase):
    """客户端里过期那条会话也要读出来（打 sts_expired 标记）。
    丢弃 = 本地导入/验证码登录/续期三条路都找不到这个号，号永久不可恢复。"""

    def setUp(self):
        import sqlite3
        import local_import
        self.li = local_import
        self._orig = local_import.OFFICEACE_DATA_DIRS
        self.td = _tempfile.TemporaryDirectory()
        os.makedirs(os.path.join(self.td.name, "data"))
        db = os.path.join(self.td.name, "data", "storage.sqlite")
        con = sqlite3.connect(db)
        con.execute("create table oc_kv_string (key text primary key, value text)")
        now = time.time()
        rows = [("hid_837ylp2ucgnyoxz", "01a1540646c974f18ddd", now - 3 * 3600),
                ("yizhizongchai", "01a080ec36c97031b611", now + 6 * 3600)]
        for nm, uid, ts in rows:
            iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts))
            rec = {"displayName": nm, "expiresAt": iso,
                   "providerState": {
                       "user_id": "iam::%s:user:%s" % (uid, nm),
                       "credential": {"refresh_token": "RT-" + nm},
                       "credentialV3": {"access": "AK-" + nm, "secret": "SK-" + nm,
                                        "sts_token": "STS-" + nm, "project_id": "p",
                                        "expires_at": iso}}}
            con.execute("insert into oc_kv_string values (?, ?)",
                        ("office-claw:oc:session:user:" + uid, json.dumps(rec)))
        con.commit()
        con.close()
        local_import.OFFICEACE_DATA_DIRS = [self.td.name]

    def tearDown(self):
        self.li.OFFICEACE_DATA_DIRS = self._orig
        self.td.cleanup()

    def test_expired_session_is_returned_flagged(self):
        accs = self.li._officeace_read_sqlite()
        self.assertEqual(len(accs), 2)                 # 旧实现在这里 continue ⇒ 只剩 1 条
        self.assertTrue(accs["hid_837ylp2ucgnyoxz"]["sts_expired"])
        self.assertFalse(accs["yizhizongchai"]["sts_expired"])
        self.assertTrue(accs["hid_837ylp2ucgnyoxz"]["refresh_token"])

    def test_expired_session_reaches_refresh_matching(self):
        # 续期侧要的正是这条：过期会话带出来之后，按键名就能命中本号（原来只会说「没有本号会话」）
        accs = self.li._officeace_read_sqlite()
        self.assertIsNotNone(self.oac_pick("hid_837ylp2ucgnyoxz", accs))

    def oac_pick(self, name, accs):
        import platforms.officeace as oac
        return oac.pick_live_session(name, {"user_id": "uid-x"}, accs)


class TestOfficeaceRefreshFailureMessage(unittest.TestCase):
    """续期失败要说清楚「客户端正登录着谁」，而不是只报一句刷新未生效。"""

    def setUp(self):
        import platforms.officeace as oac
        import local_import
        self.oac, self.li = oac, local_import
        self._up, self._sid, self._time = oac._service_up, oac._oc_sid, oac.time

    def tearDown(self):
        self.oac._service_up = self._up
        self.oac._oc_sid = self._sid
        self.oac.time = self._time

    def _run(self, live, old_exp="2026-10-20T07:14:47"):
        self.oac._service_up = lambda: True
        self.oac._oc_sid = lambda: "sid"
        self.oac.time = _NoSleep
        resp = mock.Mock()
        resp.read.return_value = b'{"islogin": true}'
        resp.__enter__ = lambda s: resp
        resp.__exit__ = lambda s, *a: False
        with mock.patch("urllib.request.urlopen", return_value=resp), \
             mock.patch.object(self.li, "read_officeace", return_value=(True, "", live)), \
             mock.patch.object(self.oac, "_persist_entry", lambda *a: None):
            return self.oac._try_refresh_inner("0623号", {"user_id": "uid-0623",
                                                          "expires_at": old_exp})

    def test_names_the_account_the_client_is_using(self):
        live = {"0623号": {"ak": "AK_OLD", "expires_at": "2026-10-20T07:14:47"},
                "yizhizongchai": {"ak": "AK_NEW", "expires_at": "2026-10-20T14:08:45"}}
        ok, msg = self._run(live)
        self.assertFalse(ok)
        self.assertIn("客户端当前登录的是「yizhizongchai」", msg)
        self.assertIn("2026-10-20T14:08:45", msg)

    def test_no_other_session_falls_back_to_plain_message(self):
        # 对面：只有本号那条会话时不许乱指认别人
        live = {"0623号": {"ak": "AK_OLD", "expires_at": "2026-10-20T07:14:47"}}
        ok, msg = self._run(live)
        self.assertFalse(ok)
        self.assertEqual(msg, "刷新未生效（SQLite expires_at 未变化）")

    def test_unreadable_client_db_is_not_reported_as_missing_account(self):
        # 24 轮一条会话都没读到（写锁占用 / 会话表空）时，不许说成「客户端里没有本账号」——
        # 那种措辞把人支去切账号，真正该做的是重开客户端（2026-10-20 实测踩过）
        self.oac._service_up = lambda: True
        self.oac._oc_sid = lambda: "sid"
        self.oac.time = _NoSleep
        resp = mock.Mock()
        resp.read.return_value = b'{"islogin": true}'
        resp.__enter__ = lambda s: resp
        resp.__exit__ = lambda s, *a: False
        with mock.patch("urllib.request.urlopen", return_value=resp), \
             mock.patch.object(self.li, "read_officeace",
                               return_value=(False, "database is locked", {})), \
             mock.patch.object(self.oac, "_persist_entry", lambda *a: None):
            ok, msg = self.oac._try_refresh_inner("0623号", {"user_id": "uid-0623",
                                                            "expires_at": "2026-10-20T07:14:47"})
        self.assertFalse(ok)
        self.assertIn("读不到客户端会话", msg)
        self.assertIn("database is locked", msg)
        self.assertNotIn("不能借用别的号的凭据", msg)

    def test_raises_every_poll_also_reports_unreadable(self):
        def _boom():
            raise OSError("attempt to write a readonly database")
        self.oac._service_up = lambda: True
        self.oac._oc_sid = lambda: "sid"
        self.oac.time = _NoSleep
        resp = mock.Mock()
        resp.read.return_value = b'{"islogin": true}'
        resp.__enter__ = lambda s: resp
        resp.__exit__ = lambda s, *a: False
        with mock.patch("urllib.request.urlopen", return_value=resp), \
             mock.patch.object(self.li, "read_officeace", side_effect=_boom), \
             mock.patch.object(self.oac, "_persist_entry", lambda *a: None):
            ok, msg = self.oac._try_refresh_inner("0623号", {"user_id": "uid-0623",
                                                             "expires_at": "2026-10-20T07:14:47"})
        self.assertFalse(ok)
        self.assertIn("读不到客户端会话", msg)
        self.assertIn("readonly database", msg)


class _StubSend(object):
    """只用来接 Handler._r_* 里 self._send(...) 的假 Handler。"""

    def __init__(self):
        self.sent = []

    def _send(self, code, obj):
        self.sent.append((code, obj))


class TestLocalImportStaleGuard(unittest.TestCase):
    """点「从本地客户端导入」也不许把库里刚续好的凭据换成客户端那条旧会话。
    （两平台 load_accounts 里已各有一道 exp_epoch 闸，导入口是同一个洞的另一半。）"""

    KEY = "hid_837ylp2ucgnyoxz"

    def setUp(self):
        import cred_store
        import webapi
        self.webapi, self.cs = webapi, cred_store
        self.td = _tempfile.TemporaryDirectory()
        self.target = os.path.join(self.td.name, "codearts_accounts.json")
        self._files, self._ident = webapi.CRED_FILES, webapi.ensure_identity
        webapi.CRED_FILES = dict(self._files, codearts=self.target)
        webapi.ensure_identity = lambda pid, rec: None

    def tearDown(self):
        self.webapi.CRED_FILES = self._files
        self.webapi.ensure_identity = self._ident
        self.td.cleanup()

    def _seed(self, exp, ak="AK_STORED"):
        self.cs.write_json(self.target, {self.KEY: {"ak": ak, "sk": "s", "sts_token": "t",
                                                    "expires_at": exp, "user_id": "uid-x"}})

    def _post(self, live_exp):
        live = {self.KEY: {"ak": "AK_CLIENT", "sk": "s", "sts_token": "t",
                           "expires_at": live_exp, "user_id": "uid-x"}}
        stub = _StubSend()
        import local_import
        with mock.patch.object(local_import, "read_local",
                               return_value=(True, "读到 1 个账号", live)):
            self.webapi.Handler._r_api_account_import_local(stub, {"platform": "codearts"})
        return stub.sent[0][1]

    def test_stale_client_session_is_not_written(self):
        self._seed("2026-10-21T12:30:01")
        before = self.cs.read_json(self.target, {})[self.KEY]["expires_at"]
        r = self._post("2026-10-20T08:27:27")
        after = self.cs.read_json(self.target, {})[self.KEY]
        self.assertEqual(after["expires_at"], before)
        self.assertEqual(after["ak"], "AK_STORED")     # 一个字都不许被旧会话顶掉
        self.assertEqual(r["skipped_stale"], [self.KEY])
        self.assertEqual(r["names"], [])
        self.assertIn("更新鲜", r["msg"])

    def test_fresher_client_session_still_imports(self):
        # 对面：闸写成「客户端的一律不收」就等于废掉本地导入 —— 库里更旧时必须照写
        self._seed("2026-10-20T08:27:27")
        r = self._post("2026-10-21T12:30:01")
        after = self.cs.read_json(self.target, {})[self.KEY]
        self.assertEqual(after["ak"], "AK_CLIENT")
        self.assertEqual(after["expires_at"], "2026-10-21T12:30:01")
        self.assertEqual(r["skipped_stale"], [])
        self.assertEqual(r["names"], [self.KEY])

    def test_guard_only_fires_when_store_has_ak(self):
        # 新号（库里没有同名条目）第一次导入必须成功落盘，不能被闸当成「更旧」吞掉
        r = self._post("2026-10-20T08:27:27")
        self.assertEqual(r["names"], [self.KEY])
        self.assertEqual(r["skipped_stale"], [])

    def test_client_record_without_uid_reuses_the_named_card(self):
        # 2026-10-20 实测：客户端会话只有展示名 + account_id，没有 user_id，
        # ident 退化成 AK（每续期就换）→ 点一次本地导入多一张 ·尾号 分身卡。
        # 回填库里同名那条的身份之后，必须认得出是同一个号，并被「更旧不许覆盖」闸拦下。
        self.cs.write_json(self.target, {
            self.KEY: {"ak": "AK_STORED", "sk": "s", "sts_token": "t",
                       "user_id": "uid-real", "user_name": "iam::dom:user:%s" % self.KEY,
                       "expires_at": "2026-10-21T12:30:01"}})
        live = {self.KEY: {"ak": "AK_CLIENT", "sk": "s", "sts_token": "t",
                           "account_id": "acct-1", "expires_at": "2026-10-20T08:27:27"}}
        stub = _StubSend()
        import local_import
        with mock.patch.object(local_import, "read_local", return_value=(True, "m", live)):
            self.webapi.Handler._r_api_account_import_local(stub, {"platform": "codearts"})
        r = stub.sent[0][1]
        after = self.cs.read_json(self.target, {})
        self.assertEqual(sorted(after.keys()), [self.KEY])      # 不许长出分身卡
        self.assertEqual(after[self.KEY]["ak"], "AK_STORED")
        self.assertEqual(r["skipped_stale"], [self.KEY])
        self.assertEqual(r["names"], [])
