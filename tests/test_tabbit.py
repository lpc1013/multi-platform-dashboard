# -*- coding: utf-8 -*-
"""Tabbit 平台适配器 + 反代路由单测（不发起任何真实网络请求）。

覆盖（2026-10-19 逆向协议，参考 goehou/tabbit-toy 505★ 逐行核对）：
  - 注册表 / cred_store 登记（CRED_FILES / IDENT_FIELDS / DEFAULT_LABEL）
  - JWT 解析与稳定身份（sub 优先，无 JWT 不误判过期）
  - save_cred 身份语义：同身份（换 cookie）沿用键名、不同身份开新卡
  - 签名头 / unique-uuid 指纹 / request_no 生成
  - route_of：tb: 前缀 → tabbit，且不抢 wb:/chat-*/codearts 的路由
  - chat_stream：SSE（event:/data: 双形状）→ OpenAI chunk 转换、
    thinking→reasoning_content、usage/finish、error chunk 中文化、499 自动刷新重试
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
        reason = "".join(c["choices"][0]["delta"].get("reasoning_content", "") for c in chs)
        self.assertEqual(text, "你好")                    # 正文只聚合 message_chunk
        self.assertEqual(reason, "想想")                  # thinking 进 reasoning_content
        self.assertTrue(any(c.get("usage") for c in chs))
        self.assertTrue(any(c["choices"][0].get("finish_reason") for c in chs))
        self.assertTrue(all(c["object"] == "chat.completion.chunk" for c in chs))

    def test_event_name_not_leaking_across_frames(self):
        # 回归：event: 变量曾跨帧泄漏（首帧 thinking 污染后续无 event: 行的 data 帧）
        tbt.requests = _FakeRequests(_FakeResp(UPSTREAM))
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        # 第二条 data（{"type":"message_chunk","content":"你"}）必须是正文不是思考
        # （chunks[0] 是初始 role 帧，chunks[1]=thinking，chunks[2]=正文「你」）
        second = self._chunks(lines)[2]
        self.assertEqual(second["choices"][0]["delta"].get("content"), "你")
        self.assertNotIn("reasoning_content", second["choices"][0]["delta"])

    def test_error_event_mapped_to_chinese(self):
        up = ['data: {"type":"error","code":492,"message":"premium only"}', 'data: [DONE]']
        tbt.requests = _FakeRequests(_FakeResp(up))
        lines = list(tbt.chat_stream(self.ent, dict(self.body)))
        chs = self._chunks(lines)
        err = [c for c in chs if c.get("error_code")]
        self.assertTrue(err)
        self.assertIn("Pro", err[0]["error_msg"])         # 中文化可操作提示
        self.assertEqual(err[0]["error_code"], "492")

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
        self.assertEqual(text, "你好")

    def test_http_401_maps_to_503_actionable(self):
        tbt.requests = _FakeRequests(_FakeResp([], status=401))
        with self.assertRaises(tbt.UpstreamError) as ctx:
            list(tbt.chat_stream(self.ent, dict(self.body)))
        self.assertEqual(ctx.exception.status, 503)
        self.assertIn("导入", ctx.exception.message)

    def test_missing_cookie(self):
        with self.assertRaises(tbt.UpstreamError):
            list(tbt.chat_stream({}, dict(self.body)))

    def test_expired_jwt_rejected(self):
        ent = {"cookie": "token=" + _mk_jwt("u", int(time.time()) - 5)}
        with self.assertRaises(tbt.UpstreamError):
            list(tbt.chat_stream(ent, dict(self.body)))


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


if __name__ == "__main__":
    unittest.main()
