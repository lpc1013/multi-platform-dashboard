# -*- coding: utf-8 -*-
"""
errors 统一异常体系 + 反代网关（鉴权/限流）回归（2026-10-13）
"""
import os
import sys
import time
import unittest
from unittest import mock

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import errors  # noqa: E402
from errors import DashboardError, StorageError, AuthError, PlatformError, UpstreamError  # noqa: E402


class HierarchyTest(unittest.TestCase):
    def test_hierarchy_and_codes(self):
        for exc in (StorageError, AuthError, PlatformError, UpstreamError):
            self.assertTrue(issubclass(exc, DashboardError))
        self.assertTrue(issubclass(DashboardError, Exception))

    def test_to_dict_shape(self):
        e = StorageError("锁超时")
        d = e.to_dict()
        self.assertEqual(d, {"ok": False, "error": "锁超时", "err_code": "storage_error"})
        self.assertEqual(e.http_status, 500)

    def test_auth_error_status(self):
        e = AuthError("key 无效")
        self.assertEqual(e.http_status, 401)
        self.assertEqual(e.code, "auth_error")

    def test_platform_error_format(self):
        e = PlatformError("minimax", "签到失败")
        self.assertEqual(e.platform, "minimax")
        self.assertIn("[minimax]", e.message)
        self.assertIn("签到失败", e.message)

    def test_upstream_error_legacy_signature(self):
        """旧签名 (status, message) 与 e.status / e.message 必须保持——
        webapi 路由与 openai_proxy.relay 依赖这两个属性。"""
        e = UpstreamError(503, "凭证已过期")
        self.assertEqual(e.status, 503)
        self.assertEqual(e.http_status, 503)
        self.assertEqual(e.message, "凭证已过期")
        e2 = UpstreamError(None, "x")
        self.assertEqual(e2.status, 502)

    def test_cred_store_uses_storage_error(self):
        import cred_store
        self.assertTrue(issubclass(cred_store.StorageError, DashboardError))


@unittest.skipUnless(os.name == "nt", "msvcrt 锁语义仅 Windows")
class LockTimeoutTest(unittest.TestCase):
    def test_lock_timeout_raises_storage_error(self):
        """同进程第二个句柄锁同区域必然 LOCK_VIOLATION——借此构造超时路径。"""
        import tempfile
        import cred_store as cs
        d = tempfile.mkdtemp(prefix="errlock_")
        lp = os.path.join(d, "t_accounts.json.lock")
        import msvcrt
        holder = open(lp, "a+b")
        holder.seek(0)
        msvcrt.locking(holder.fileno(), msvcrt.LK_NBLCK, 1)   # 占住锁
        try:
            with mock.patch.object(cs, "_LOCK_TIMEOUT", 0.3):
                with self.assertRaises(StorageError):
                    cs._os_lock(lp)
        finally:
            holder.close()


class RateLimitTest(unittest.TestCase):
    def setUp(self):
        import openai_proxy as ox
        self.ox = ox
        ox._rl.update(tokens=ox.BURST, ts=time.time())

    def test_burst_then_deny(self):
        ox = self.ox
        with mock.patch.object(ox, "BURST", 3.0), \
             mock.patch.object(ox, "RATE_PER_MIN", 60.0):
            ox._rl.update(tokens=3.0, ts=time.time())
            self.assertTrue(ox.allow_request())
            self.assertTrue(ox.allow_request())
            self.assertTrue(ox.allow_request())
            self.assertFalse(ox.allow_request(), "桶空后必须拒绝")

    def test_refill_over_time(self):
        ox = self.ox
        with mock.patch.object(ox, "BURST", 1.0), \
             mock.patch.object(ox, "RATE_PER_MIN", 60.0):
            ox._rl.update(tokens=0.0, ts=time.time() - 10)   # 10 秒应回填 10 个（封顶 1）
            self.assertTrue(ox.allow_request())


class _FakeHandler:
    def __init__(self, auth=None):
        self.headers = {"Authorization": auth} if auth else {}
        self.sent = []

    def _send(self, code, body):
        self.sent.append((code, body))


class GateAuthTest(unittest.TestCase):
    def setUp(self):
        import openai_proxy as ox
        self.ox = ox
        ox._rl.update(tokens=ox.BURST, ts=time.time())

    def test_no_key_configured_passes(self):
        with mock.patch.object(self.ox, "PROXY_API_KEY", ""):
            h = _FakeHandler()
            self.assertTrue(self.ox.gate(h))
            self.assertEqual(h.sent, [])

    def test_wrong_key_rejected_401(self):
        with mock.patch.object(self.ox, "PROXY_API_KEY", "sk-right"):
            h = _FakeHandler("Bearer sk-wrong")
            self.assertFalse(self.ox.gate(h))
            self.assertEqual(h.sent[0][0], 401)
            self.assertEqual(h.sent[0][1]["error"]["code"], "invalid_api_key")

    def test_right_key_passes(self):
        with mock.patch.object(self.ox, "PROXY_API_KEY", "sk-right"):
            h = _FakeHandler("Bearer sk-right")
            self.assertTrue(self.ox.gate(h))

    def test_rate_limited_429(self):
        with mock.patch.object(self.ox, "PROXY_API_KEY", ""), \
             mock.patch.object(self.ox, "BURST", 1.0), \
             mock.patch.object(self.ox, "RATE_PER_MIN", 0.0001):
            self.ox._rl.update(tokens=1.0, ts=time.time())
            h1 = _FakeHandler()
            self.assertTrue(self.ox.gate(h1))
            h2 = _FakeHandler()
            self.assertFalse(self.ox.gate(h2))
            self.assertEqual(h2.sent[0][0], 429)
            self.assertEqual(h2.sent[0][1]["error"]["code"], "rate_limit_exceeded")


class SanitizeClientMessageTest(unittest.TestCase):
    """客户端可见错误净化：原始上游 JSON / 额度码（14018）绝不透传。"""

    def test_quota_code_hidden(self):
        raw = '{"error":{"data":{"code":14018,"msg":"Credits exhausted"}}}'
        out = errors.sanitize_client_message(429, raw)
        self.assertNotIn("14018", out)
        self.assertNotIn("Credits exhausted", out)
        self.assertIn("额度", out)

    def test_raw_json_generic(self):
        raw = '{"error": {"message": "internal boom"}}'
        out = errors.sanitize_client_message(502, raw)
        self.assertNotIn("internal boom", out)
        self.assertNotIn('"error"', out)

    def test_auth_keyword_hidden(self):
        out = errors.sanitize_client_message(401, "token 已过期且刷新失败")
        self.assertIn("登录态", out)
        self.assertNotIn("token 已过期", out)

    def test_clean_passthrough(self):
        clean = "CodeArts 上游并发会话已达上限（3个），请稍后重试"
        self.assertEqual(errors.sanitize_client_message(429, clean), clean)

    def test_to_dict_sanitizes_upstream_raw(self):
        e = UpstreamError(502, '{"error":{"code":14018,"msg":"x"}}')
        self.assertNotIn("14018", e.to_dict()["error"])


if __name__ == "__main__":
    unittest.main()
