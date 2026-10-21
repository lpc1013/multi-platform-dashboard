# -*- coding: utf-8 -*-
"""Tabbit 平台适配器 + 反代路由单测（不发起任何真实网络请求）。

覆盖（2026-10-19 逆向协议，参考 goehou/tabbit-toy 505★ 逐行核对）：
  - 注册表 / cred_store 登记（CRED_FILES / IDENT_FIELDS / DEFAULT_LABEL）
  - JWT 解析与稳定身份（sub 优先，无 JWT 不误判过期）
  - save_cred 身份语义：同身份（换 cookie）沿用键名、不同身份开新卡
  - 签名头 / unique-uuid 指纹 / request_no 生成
  - route_of：tb: 前缀 → tabbit，且不抢 wb:/chat-*/codearts 的路由
  - chat_stream：SSE（event:/data: 双形状）→ OpenAI chunk 转换、
    thinking→reasoning_content（含 reasoning_content 字段）、usage/finish、
    error chunk 中文化、499 自动刷新重试、会话失效换新会话重试
  - 空流防护（2026-10-20 实证 lines=3 = role+stop+[DONE]）：
    首次空流换新会话重试、连续两次空流显式报 502、仅 finish 首帧同为空流、
    只有 thinking 不算空流
  - 会话端点：user-sessions 列表 JSON 解析/正则兜底、/panel/session 建会话、
    列表空现场兜底、_session_stale 特征判定
  - read_account 无 cookie 的可操作报错；read_tabbit 不抛异常
运行：python -m unittest tests.test_tabbit   （用 pythoncore-3.14-64）
"""
import base64
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.argv = [sys.argv[0]]  # server/openai_proxy 导入链会把 argv[1] 当端口读
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import cred_store as cs            # noqa: E402
import openai_proxy as ox          # noqa: E402
import platforms.tabbit as tbt     # noqa: E402
import registry                    # noqa: E402


def _mk_jwt(sub, exp, phone="13800000000"):
    def seg(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return "%s.%s.%s" % (seg({"alg": "HS256", "typ": "JWT"}),
                         seg({"sub": sub, "exp": exp, "phone": phone}), "S" * 43)


JWT = _mk_jwt("u_abc123", int(time.time()) + 3600)


class _FakeResp:
    def __init__(self, lines, status=200, ct="text/event-stream"):
        self.status_code = status
        self.text = "\n".join(lines)
        self.encoding = "utf-8"
        self.headers = {"content-type": ct}
        self._lines = lines

    def iter_lines(self, decode_unicode=False):
        for l in self._lines:
            for sub in str(l).split("\n"):      # 允许一项里混排 event:/data: 两行
                yield sub

    def json(self):
        return json.loads(self.text)

    def close(self):
        pass


class _FakeRequests:
    """拦住 chat_stream 内部的 requests.post（_req 已被单独替换）"""
    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    def post(self, url, **kw):
        self.calls.append(url)
        return self._resp


UPSTREAM = [
    'event: thinking\ndata: {"content":"想想"}',
    'data: {"type":"message_chunk","content":"你"}',
    'event: message_chunk\ndata: {"content":"好"}',
    'data: {"type":"usage","usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}',
    'event: usage\ndata: {"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}',
    'data: {"type":"message_finish"}',
    'event: finish\ndata: {}',
    'data: [DONE]',
]

# 思考块的起止标签按 **ASCII 尖括号**书写（\x3c / \x3e），避免源码里被写成
# 视觉相近的 Unicode 字符导致断言出现「看起来一样却不相等」的假失败。
TAG_OPEN = "\x3cthink\x3e\n"        # 前缀标签 + 换行
TAG_CLOSE = "\n\x3c/think\x3e\n\n"  # 换行 + 闭合标签 + 空行


class TestRegistration(unittest.TestCase):
    def test_registry(self):
        self.assertIn("tabbit", registry.PLATFORMS)
        self.assertIn("tabbit", registry.LOCAL_IMPORT_PLATFORMS)

    def test_cred_store_entries(self):
        self.assertIn("tabbit", cs.CRED_FILES)
        self.assertEqual(cs.IDENT_FIELDS["tabbit"][0], "user_id")
        self.assertEqual(cs.DEFAULT_LABEL["tabbit"], "Tabbit")

    def test_adapter_interface(self):
        self.assertEqual(tbt.LABEL, "Tabbit")
        self.assertEqual([t["key"] for t in tbt.TASKS], ["checkin"])
        for fn in ("load_accounts", "read_account", "run_task", "chat_stream",
                   "models", "fetch_sign_key", "jwt_payload", "stable_uid",
                   "token_exp", "expired", "base_of", "version_of", "gen_request_no"):
            self.assertTrue(callable(getattr(tbt, fn, None)), fn)


class TestJwtIdentity(unittest.TestCase):
    def test_jwt_payload(self):
        j = tbt.jwt_payload("a=1; token=" + JWT + "; b=2")
        self.assertEqual(j["sub"], "u_abc123")
        self.assertIsNone(tbt.jwt_payload("a=1; b=2"))

    def test_stable_uid(self):
        self.assertEqual(tbt.stable_uid("token=" + JWT), "u_abc123")
        self.assertEqual(cs.tabbit_stable_uid("token=" + JWT), "u_abc123")

    def test_expired_states(self):
        self.assertIs(tbt.expired({"cookie": "token=" + JWT}), False)
        self.assertIsNone(tbt.expired({"cookie": "x=1"}))     # 无 JWT 不误判
        old = _mk_jwt("u", int(time.time()) - 10)
        self.assertIs(tbt.expired({"cookie": "token=" + old}), True)

    def test_ensure_identity_backfill(self):
        rec = {"cookie": "token=" + JWT}
        cs.ensure_identity("tabbit", rec)
        self.assertEqual(rec.get("user_id"), "u_abc123")


class TestSaveCredIdentity(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="tabbit_")
        self.path = os.path.join(self.dir, "tabbit_accounts.json")
        self.cf = {"tabbit": self.path}

    def _save(self, sub, ideal):
        rec = {"cookie": "token=" + _mk_jwt(sub, int(time.time()) + 3600)}
        cs.ensure_identity("tabbit", rec)
        return cs.save_cred("tabbit", rec, ideal, cred_files=self.cf)

    def test_same_identity_reuses_key_even_after_cookie_rotation(self):
        k1 = self._save("u_same", "Tabbit·国内版")
        k2 = self._save("u_same", "Tabbit·换个名")
        self.assertEqual(k1, k2)
        self.assertEqual(len(json.load(open(self.path, encoding="utf-8"))), 1)

    def test_different_identity_new_card(self):
        k1 = self._save("u_a", "Tabbit·国内版")
        k2 = self._save("u_b", "Tabbit·国内版")
        self.assertNotEqual(k1, k2)
        self.assertEqual(len(json.load(open(self.path, encoding="utf-8"))), 2)


class TestSignAndFingerprint(unittest.TestCase):
    def test_sign_headers(self):
        h = tbt.sign_headers('{"a":1}', "k" * 32)
        self.assertEqual(set(h), {"x-timestamp", "x-nonce", "x-signature"})
        self.assertEqual(len(h["x-nonce"]), 64)               # HMAC-SHA256 hex
        self.assertRegex(h["x-timestamp"], r"^\d{13}$")

    def test_unique_uuid_marker(self):
        u1 = tbt.make_unique_uuid(True).replace("-", "")
        self.assertEqual(u1[5], "1")                          # 默认浏览器标记位
        u0 = tbt.make_unique_uuid(False).replace("-", "")
        self.assertNotEqual(u0[5], "1")

    def test_request_no(self):
        rn = tbt.gen_request_no(True)
        self.assertEqual(len(rn), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in rn))


class TestRouteOf(unittest.TestCase):
    def test_tb_prefix(self):
        self.assertEqual(ox.route_of("tb:Default"), "tabbit")
        self.assertEqual(ox.route_of("TB:glm"), "tabbit")

    def test_other_prefixes_unchanged(self):
        self.assertEqual(ox.route_of("wb:auto"), "wbai")
        self.assertEqual(ox.route_of("chat-max"), "teleagent")
        self.assertEqual(ox.route_of("deepseek-v4.1-flash"), "codearts")
        self.assertEqual(ox.route_of(""), "codearts")


class TestChatStream(unittest.TestCase):
    def setUp(self):
        self.ent = {"cookie": "token=" + JWT, "base": tbt.BASE_DOM}
        self.body = {"model": "Default", "messages": [{"role": "user", "content": "hi"}]}
        self._real_requests = tbt.requests
        self._real_signkey = tbt.fetch_sign_key
        self._real_session = tbt.get_session_id
        tbt.fetch_sign_key = lambda ent, force=False: "k" * 32
        tbt.get_session_id = lambda ent, force=False: "sess-123"

    def tearDown(self):
        tbt.requests = self._real_requests
        tbt.fetch_sign_key = self._real_signkey
        tbt.get_session_id = self._real_session

    def _chunks(self, lines):
        return [json.loads(l[5:].strip()) for l in lines
                if l.startswith("data:") and "[DONE]" not in l]

    def test_sse_to_openai_chunks(self):
        tbt.requests = _FakeRequests(_FakeResp(UPSTREAM))
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertTrue(tbt.requests.calls[0].endswith("/api/v1/chat/completion"))
        self.assertTrue(lines[-1].startswith("data:") and "[DONE]" in lines[-1])
        chs = self._chunks(lines)
        text = "".join(c["choices"][0]["delta"].get("content", "") for c in chs)
        self.assertEqual(text, "<think>\n想想\n</think>\n\n你好")   # 思考并入正文流
        self.assertNotIn("reasoning_content",
                         "".join(str(c["choices"][0]["delta"]) for c in chs))
        self.assertTrue(any(c.get("usage") for c in chs))
        self.assertTrue(any(c["choices"][0].get("finish_reason") for c in chs))
        self.assertTrue(all(c["object"] == "chat.completion.chunk" for c in chs))

    def test_event_name_not_leaking_across_frames(self):
        # 回归：event: 变量曾跨帧泄漏（首帧 thinking 污染后续无 event: 行的 data 帧）
        tbt.requests = _FakeRequests(_FakeResp(UPSTREAM))
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        # 正文帧不得被思考块污染：chunks[0]=role，[1]="<think>\n"，[2]="想想"，
        # [3]="\n</think>\n\n"，[4]=正文「你」
        second = self._chunks(lines)[4]
        self.assertEqual(second["choices"][0]["delta"].get("content"), "你")
        self.assertNotIn("reasoning_content", second["choices"][0]["delta"])

    def test_thinking_only_still_closes_block(self):
        # 边界：上游只吐思考没有正文 → </think> 也要在 stop 前补上
        up = ['event: thinking\ndata: {"content":"只想不想说"}',
              'data: {"type":"message_finish"}', 'data: [DONE]']
        tbt.requests = _FakeRequests(_FakeResp(up))
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        chs = self._chunks(lines)
        text = "".join(c["choices"][0]["delta"].get("content", "") for c in chs)
        self.assertEqual(text, "<think>\n只想不想说\n</think>\n\n")
        self.assertTrue(any(c["choices"][0].get("finish_reason") == "stop"
                            for c in chs))

    def test_error_event_mapped_to_chinese(self):
        up = ['data: {"type":"error","code":492,"message":"premium only"}', 'data: [DONE]']
        tbt.requests = _FakeRequests(_FakeResp(up))
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        chs = self._chunks(lines)
        # 2026-10-21：错误原因进正文（⚠️ 前缀）且流以 stop 正常收尾，
        # 不发流中 error 帧（客户端见 error 帧即撤销气泡 = 「用户已取消」）。
        text = "".join(c["choices"][0]["delta"].get("content", "") for c in chs)
        self.assertIn("Pro", text)                    # 中文化可操作提示
        self.assertFalse([c for c in chs if c.get("error_code") or "error" in c])
        self.assertTrue(any(c["choices"][0].get("finish_reason") == "stop"
                            for c in chs))

    def test_499_refreshes_sign_key_and_retries(self):
        class _Flaky(_FakeRequests):
            def __init__(self):
                super().__init__(None)
                self.n = 0

            def post(self, url, **kw):
                self.n += 1
                self.calls.append(url)
                return _FakeResp([], status=499) if self.n == 1 else _FakeResp(UPSTREAM)

        tbt.requests = _Flaky()
        with mock.patch.object(tbt, "_invalidate_sign_key") as inv:
            lines = list(tbt.chat_stream(self.ent, dict(self.body)))
            self.assertEqual(inv.call_count, 1)
        self.assertEqual(tbt.requests.n, 2)
        chs = self._chunks(lines)
        text = "".join(c["choices"][0]["delta"].get("content", "") for c in chs)
        self.assertEqual(text, "<think>\n想想\n</think>\n\n你好")

    def test_http_401_maps_to_503_actionable(self):
        tbt.requests = _FakeRequests(_FakeResp([], status=401))
        with self.assertRaises(tbt.UpstreamError) as ctx:
            list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(ctx.exception.status, 503)
        self.assertIn("导入", ctx.exception.message)

    def test_stale_session_retries_with_fresh_one(self):
        # 回归（2026-10-19）：随机/失效 UUID → 上游秒拒「AI服务暂时不可用」（无 code）。
        # 现在每次聊天建新会话 + 该特征错误自动换会话重试，且不吐 error chunk。
        stale = ['event: error\ndata: {"message":"AI服务暂时不可用，请稍后重试"}',
                 'data: [DONE]']

        class _StaleThenOk(_FakeRequests):
            def __init__(self):
                super().__init__(None)
                self.n = 0

            def post(self, url, **kw):
                self.n += 1
                self.calls.append(url)
                return _FakeResp(stale) if self.n == 1 else _FakeResp(UPSTREAM)

        tbt.requests = _StaleThenOk()
        sessions = iter(["sess-stale", "sess-fresh"])
        tbt.get_session_id = lambda ent, force=False: next(sessions)
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(tbt.requests.n, 2)                   # 确实重试了一轮
        chs = self._chunks(lines)
        self.assertFalse([c for c in chs if c.get("error_code")])
        text = "".join(c["choices"][0]["delta"].get("content", "") for c in chs)
        self.assertEqual(text, "<think>\n想想\n</think>\n\n你好")  # 重试后正常出文

    def test_missing_cookie(self):
        with self.assertRaises(tbt.UpstreamError):
            list(tbt.chat_stream({}, dict(self.body)))

    def test_expired_jwt_rejected(self):
        ent = {"cookie": "token=" + _mk_jwt("u", int(time.time()) - 5)}
        with self.assertRaises(tbt.UpstreamError):
            list(tbt.chat_stream(ent, dict(self.body)))

    # ── 空流防护（2026-10-20 实证：后端日志 `tb:… stream 1.3s lines=3`）──
    # 旧行为：上游零内容事件 → 照样产出 role+stop+[DONE]（恰好 3 行）→
    # 客户端收到空回复，显示「用户已取消」。现必须重试，重试仍空必须报错。
    EMPTY = ['event: ready\ndata: {"chat_session_id":"x"}',
             'event: message_start\ndata: {"message_id":"y"}',
             'data: [DONE]']

    def _text(self, lines):
        chs = self._chunks(lines)
        return "".join(c["choices"][0]["delta"].get("content", "") for c in chs)

    def test_empty_stream_retries_with_fresh_session(self):
        """首次空流（无任何产出事件）→ 换新会话重试 → 正常出文，且不吐空回复。"""
        class _EmptyThenOk(_FakeRequests):
            def __init__(self):
                super().__init__(None)
                self.n = 0

            def post(self, url, **kw):
                self.n += 1
                self.calls.append(url)
                return (_FakeResp(TestChatStream.EMPTY) if self.n == 1
                        else _FakeResp(UPSTREAM))

        tbt.requests = _EmptyThenOk()
        sessions = iter(["sess-empty", "sess-fresh"])
        tbt.get_session_id = lambda ent, force=False: next(sessions)
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(tbt.requests.n, 2)                    # 确实重试了一轮
        self.assertFalse([c for c in self._chunks(lines) if c.get("error_code")])
        self.assertEqual(self._text(lines),
                         TAG_OPEN + "想想" + TAG_CLOSE + "你好")   # 重试后正常出文

    def test_empty_stream_twice_raises_actionable(self):
        """连续两次空流 → 必须显式报错，绝不静默产出空回复。"""
        tbt.requests = _FakeRequests(_FakeResp(TestChatStream.EMPTY))
        with self.assertRaises(tbt.UpstreamError) as ctx:
            list(tbt.chat_stream(self.ent, dict(self.body)))
        e = ctx.exception
        self.assertEqual(e.status, 502)
        self.assertIn("空响应", e.message)                      # 用户可读的中文原因
        self.assertIn("重试", e.message)                        # 给出下一步动作

    def test_finish_only_first_frame_treated_as_empty(self):
        """边界：首帧即 message_finish（上游只给结束帧）同为空流，不得当正常回答。"""
        tbt.requests = _FakeRequests(_FakeResp(
            ['data: {"type":"message_finish"}', 'data: [DONE]']))
        with self.assertRaises(tbt.UpstreamError) as ctx:
            list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(ctx.exception.status, 502)
        self.assertIn("空响应", ctx.exception.message)

    def test_codeless_error_retries_then_succeeds(self):
        """无 code 的上游错误 = 疑似瞬时故障/风控 → 换新会话重试一次可自愈。"""
        transient = ['event: error\ndata: {"message":"系统繁忙"}', 'data: [DONE]']

        class _ErrThenOk(_FakeRequests):
            def __init__(self):
                super().__init__(None)
                self.n = 0

            def post(self, url, **kw):
                self.n += 1
                self.calls.append(url)
                return (_FakeResp(transient) if self.n == 1
                        else _FakeResp(UPSTREAM))

        tbt.requests = _ErrThenOk()
        sessions = iter(["s1", "s2"])
        tbt.get_session_id = lambda ent, force=False: next(sessions)
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(tbt.requests.n, 2)                    # 重试了一轮
        chs = self._chunks(lines)
        self.assertFalse([c for c in chs if c.get("error_code")])
        self.assertEqual(self._text(lines), TAG_OPEN + "想想" + TAG_CLOSE + "你好")

    def test_actionable_error_not_retried(self):
        """内容已无法再缩小的 492（本条仅 2 字符）→ 重试无意义：立即中文化返回。
        （2026-10-21 起 492 有了新语义：大 content 的 492 是免费档 ~2 万字符
        体量上限，会减半预算重试——见 tests/test_tabbit_content_budget.py；
        但 content 已 ≤CONTENT_MIN 还 492 说明不是体量问题，不浪费轮次。）"""
        premium = ['data: {"type":"error","code":492,"message":"premium only"}',
                   'data: [DONE]']
        tbt.requests = _FakeRequests(_FakeResp(premium))
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(len(tbt.requests.calls), 1)           # 未重试
        chs = self._chunks(lines)
        # 2026-10-21：错误走正文 + stop，**不发流中 error 帧**——客户端收到
        # error 帧会撤销气泡显示「用户已取消」（15:29 实证）。
        self.assertFalse([c for c in chs if c.get("error_code")])
        self.assertFalse([c for c in chs if "error" in c])
        self.assertIn("Pro", self._text(lines))                 # 原因在正文里
        stops = [c for c in chs if c["choices"][0].get("finish_reason")]
        self.assertEqual(stops[-1]["choices"][0]["finish_reason"], "stop")
        self.assertTrue(lines[-1].strip().endswith("[DONE]"))

    # ── 零文本帧空流（2026-10-20 二次实证：`stream 1.4s lines=3` 仍空）──
    # 首帧事件名是产出型（thinking/message_chunk）但**帧内文本为空**时，
    # 旧判定只看事件名 → 误认为非空 → 照样 role+stop+[DONE] 三行空回复。
    # 必须以「帧内是否真有文本」为准。
    ZEROTEXT = ['event: ready\ndata: {"chat_session_id":"x"}',
                'event: message_start\ndata: {"message_id":"y"}',
                'event: thinking\ndata: {"reasoning_content":""}',
                'event: thinking\ndata: {}',
                'event: message_chunk\ndata: {"content":""}',
                'data: {"type":"message_finish"}', 'data: [DONE]']

    def test_zerotext_frames_treated_as_empty_and_retried(self):
        """零文本 thinking/chunk 帧 + finish = 空流 → 换新会话重试后正常出文。"""
        class _ZeroThenOk(_FakeRequests):
            def __init__(self):
                super().__init__(None)
                self.n = 0

            def post(self, url, **kw):
                self.n += 1
                self.calls.append(url)
                return (_FakeResp(TestChatStream.ZEROTEXT) if self.n == 1
                        else _FakeResp(UPSTREAM))

        tbt.requests = _ZeroThenOk()
        sessions = iter(["sess-zero", "sess-fresh"])
        tbt.get_session_id = lambda ent, force=False: next(sessions)
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(tbt.requests.n, 2)                    # 重试了一轮
        self.assertFalse([c for c in self._chunks(lines) if c.get("error_code")])
        self.assertEqual(self._text(lines), TAG_OPEN + "想想" + TAG_CLOSE + "你好")

    def test_zerotext_frames_twice_raises_actionable(self):
        """连续两次零文本空流 → 502 显式中文化报错，绝不静默空回复。"""
        tbt.requests = _FakeRequests(_FakeResp(TestChatStream.ZEROTEXT))
        with self.assertRaises(tbt.UpstreamError) as ctx:
            list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(ctx.exception.status, 502)
        self.assertIn("空响应", ctx.exception.message)

    def test_zerotext_frames_then_content_same_stream_not_retried(self):
        """同一流内先零文本帧、后有真内容：不得误判空流，也不得多发一轮请求。"""
        mixed = ['event: message_start\ndata: {"message_id":"y"}',
                 'event: thinking\ndata: {"reasoning_content":""}',
                 'event: message_chunk\ndata: {"content":"你好"}',
                 'data: {"type":"message_finish"}', 'data: [DONE]']
        tbt.requests = _FakeRequests(_FakeResp(mixed))
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(len(tbt.requests.calls), 1)           # 未重试
        self.assertEqual(self._text(lines), "你好")
        self.assertFalse([c for c in self._chunks(lines) if c.get("error_code")])

    def test_usage_frame_preserved_when_skipped_before_content(self):
        """usage 是元信息帧（无文本）会被预读跳过，token 统计必须仍能拿到。"""
        up = ['event: usage\ndata: {"usage":{"prompt_tokens":7,"completion_tokens":3}}',
              'event: message_chunk\ndata: {"content":"好"}',
              'data: {"type":"message_finish"}', 'data: [DONE]']
        tbt.requests = _FakeRequests(_FakeResp(up))
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        chs = self._chunks(lines)
        self.assertEqual(self._text(lines), "好")
        usage = [c.get("usage") for c in chs if c.get("usage")]
        self.assertTrue(usage)
        self.assertEqual(usage[-1]["prompt_tokens"], 7)
        self.assertEqual(usage[-1]["total_tokens"], 10)

    # ── 纯空白帧（2026-10-21）：`" "`/`"\n"` 是**真值**，旧实现 `if _frame_text(...)`
    #    会把它当产出 → 不重试、直接发 stop → 客户端一片空白（=「用户已取消」）。
    #    纯空白必须与零文本同路：重试，两次仍空则显式报错。
    BLANK = ['event: message_start\ndata: {"message_id":"y"}',
             'event: message_chunk\ndata: {"content":" "}',
             'event: message_chunk\ndata: {"content":"\\n"}',
             'data: {"type":"message_finish"}', 'data: [DONE]']

    def test_blank_only_frames_treated_as_empty(self):
        """只有空白字符的流 → 判空流并重试，不能当正常结束。"""
        class _BlankThenOk(_FakeRequests):
            def __init__(self):
                super().__init__(None)
                self.n = 0

            def post(self, url, **kw):
                self.n += 1
                self.calls.append(url)
                return (_FakeResp(TestChatStream.BLANK) if self.n == 1
                        else _FakeResp(UPSTREAM))

        tbt.requests = _BlankThenOk()
        sessions = iter(["sess-blank", "sess-fresh"])
        tbt.get_session_id = lambda ent, force=False: next(sessions)
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(tbt.requests.n, 2)                    # 重试了一轮
        self.assertEqual(self._text(lines), TAG_OPEN + "想想" + TAG_CLOSE + "你好")

    def test_blank_only_twice_raises_not_silent_stop(self):
        """连续两次纯空白 → 502 报错（客户端能看见原因），不发空 stop。"""
        tbt.requests = _FakeRequests(_FakeResp(TestChatStream.BLANK))
        with self.assertRaises(tbt.UpstreamError) as ctx:
            list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(ctx.exception.status, 502)
        self.assertIn("空响应", ctx.exception.message)


class TestReadAccountAndLocalImport(unittest.TestCase):
    def test_read_account_no_cookie(self):
        ra = tbt.read_account("x", {})
        self.assertFalse(ra["ok"])
        self.assertIn("导入", ra["error"])

    def test_read_tabbit_never_raises(self):
        import local_import as li
        try:
            ok, msg, accs = li.read_tabbit()
            self.assertIsInstance(ok, bool)
            self.assertIsInstance(msg, str)
        except Exception as e:               # pragma: no cover
            self.fail("read_tabbit 抛了异常：%r" % e)


class TestMapUpstreamError(unittest.TestCase):
    def test_known_codes(self):
        self.assertEqual(tbt._map_upstream_error(401, "x")[0], 503)
        self.assertEqual(tbt._map_upstream_error(492, "premium")[0], 403)
        self.assertIn("默认浏览器", tbt._map_upstream_error(493, "set_default_browser")[1])
        self.assertEqual(tbt._map_upstream_error(429, "x")[0], 429)


class TestSessionEndpoints(unittest.TestCase):
    """会话端点（2026-10-19 新逆向，旧 /newtab Server Action 已 500 失效）：
      GET  /api/v0/chat/md5-key-sessions/user-sessions  历史会话列表
      POST /panel/session                               现场建新空会话
    """

    def setUp(self):
        self.ent = {"cookie": "token=" + JWT, "base": tbt.BASE_DOM}
        tbt._sessions.clear()                # 清进程级会话缓存，避免跨用例串味

    def _resp(self, obj, status=200, ct="application/json"):
        r = _FakeResp([], status=status, ct=ct)
        r.text = json.dumps(obj) if not isinstance(obj, str) else obj
        return r

    def test_fetch_session_list_parses_json(self):
        r = self._resp({"sessions": [
            {"chat_session_id": "s-1", "chat_session_title": "t1"},
            {"chat_session_id": "  ", "chat_session_title": "bad"},
            {"chat_session_id": "s-2", "chat_session_title": "t2"},
        ]})
        with mock.patch.object(tbt, "_req", return_value=r) as rq:
            ids = tbt.fetch_session_list(self.ent)
        self.assertEqual(ids, ["s-1", "s-2"])
        self.assertTrue(rq.call_args[0][1].startswith(
            "/api/v0/chat/md5-key-sessions/user-sessions"))

    def test_fetch_session_list_http_error_returns_empty(self):
        with mock.patch.object(tbt, "_req", return_value=_FakeResp([], status=500)):
            self.assertEqual(tbt.fetch_session_list(self.ent), [])

    def test_fetch_session_list_bad_json_falls_back_to_regex(self):
        r = self._resp('junk 11111111-2222-3333-4444-555555555555 junk',
                       ct="text/html")
        with mock.patch.object(tbt, "_req", return_value=r):
            ids = tbt.fetch_session_list(self.ent)
        self.assertEqual(ids, ["11111111-2222-3333-4444-555555555555"])

    def test_create_session(self):
        r = self._resp({"chat_session_id": "new-sess-1"})
        with mock.patch.object(tbt, "_req", return_value=r) as rq:
            sid = tbt.create_session(self.ent)
        self.assertEqual(sid, "new-sess-1")
        self.assertEqual(rq.call_args[0][1], "/panel/session")
        self.assertEqual(rq.call_args[1].get("method"), "POST")

    def test_create_session_failure_raises(self):
        with mock.patch.object(tbt, "_req", return_value=_FakeResp([], status=500)):
            with self.assertRaises(tbt.UpstreamError):
                tbt.create_session(self.ent)

    def test_create_session_missing_id_raises(self):
        with mock.patch.object(tbt, "_req", return_value=self._resp({"ok": True})):
            with self.assertRaises(tbt.UpstreamError):
                tbt.create_session(self.ent)

    def test_get_session_id_pinned_wins(self):
        self.assertEqual(tbt.get_session_id({"session_id": "pin-1"}), "pin-1")

    def test_get_session_id_force_creates_new(self):
        with mock.patch.object(tbt, "_req", return_value=self._resp(
                {"chat_session_id": "fresh-1"})):
            self.assertEqual(tbt.get_session_id(self.ent, force=True), "fresh-1")

    def test_get_session_id_list_first(self):
        r = self._resp({"sessions": [{"chat_session_id": "hist-1"}]})
        with mock.patch.object(tbt, "_req", return_value=r):
            self.assertEqual(tbt.get_session_id(self.ent), "hist-1")

    def test_get_session_id_empty_list_falls_back_to_create(self):
        # 列表空不再报错引导用户手动开对话——现场 /panel/session 建一个
        empty = self._resp({"sessions": []})
        fresh = self._resp({"chat_session_id": "fresh-2"})

        def _fake_req(ent, path, **kw):
            return empty if "user-sessions" in path else fresh

        with mock.patch.object(tbt, "_req", side_effect=_fake_req):
            self.assertEqual(tbt.get_session_id(self.ent), "fresh-2")


class TestSessionStaleDetection(unittest.TestCase):
    def test_detects_stale(self):
        self.assertTrue(tbt._session_stale(
            {"message": "AI服务暂时不可用，请稍后重试"}))
        self.assertTrue(tbt._session_stale({"details": "AI服务暂时不可用"}))

    def test_coded_errors_are_not_stale(self):
        self.assertFalse(tbt._session_stale(
            {"message": "AI服务暂时不可用", "code": "492"}))
        self.assertFalse(tbt._session_stale({"message": "AI服务暂时不可用",
                                             "status": 500}))

    def test_other_messages_are_not_stale(self):
        self.assertFalse(tbt._session_stale({"message": "模型繁忙"}))
        self.assertFalse(tbt._session_stale(None))
        self.assertFalse(tbt._session_stale("str"))


if __name__ == "__main__":
    unittest.main()
