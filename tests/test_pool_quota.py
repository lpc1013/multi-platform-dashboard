# -*- coding: utf-8 -*-
"""/api/pool_quota 参数校验测试（2026-10-20 自检修复的回归测试）。

背景（实证）：`_pool_spec("")` 对未知 provider 会**兜底返回 wbai 账号**，而
`mod` 映射取不到就是 None → 每个号都回 `ok:false, "无额度查询能力"` 且 HTTP 200。
调用方看到的是「有账号但全都查不了额度」的误导性结果，而不是「provider 名写错了」。

运行：python -m pytest tests/test_pool_quota.py -q
"""
import os
import sys
import unittest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)
sys.argv = [sys.argv[0]]          # server.py 会把 argv[1] 当端口，清掉测试参数

import webapi  # noqa: E402


class _FakeHandler:
    """只实现 _r_api_pool_quota 用到的两个成员，避免起真实 socket。"""

    def __init__(self, path):
        self.path = path
        self.sent = None

    def _send(self, code, body):
        self.sent = (code, body)


class TestPoolQuotaProviderValidation(unittest.TestCase):
    def _call(self, path):
        h = _FakeHandler(path)
        webapi.Handler._r_api_pool_quota(h)
        self.assertIsNotNone(h.sent, "处理器没有回包")
        return h.sent

    def test_missing_provider_rejected(self):
        """不带 provider 必须 400，而不是静默返回「无额度查询能力」。"""
        code, body = self._call("/api/pool_quota")
        self.assertEqual(code, 400)
        self.assertEqual(body["accounts"], [])
        self.assertIn("未知上游", body["error"])

    def test_empty_provider_rejected(self):
        code, body = self._call("/api/pool_quota?provider=")
        self.assertEqual(code, 400)
        self.assertIn("未知上游", body["error"])

    def test_unknown_provider_rejected(self):
        """拼错的上游名必须显式报错（曾静默降级成 wbai 的账号列表）。"""
        code, body = self._call("/api/pool_quota?provider=workbuddy_ai")
        self.assertEqual(code, 400)
        self.assertEqual(body["provider"], "workbuddy_ai")
        self.assertIn("workbuddy_intl", body["error"])   # 提示正确别名

    def test_valid_names_pass_validation(self):
        """合法名不应被 400 拦掉（load 用 mock 返回空账号，不打上游）。"""
        from unittest import mock
        for pid in ("codearts", "teleagent", "officeace", "tabbit", "wbai"):
            h = _FakeHandler("/api/pool_quota?provider=" + pid + "&force=1")
            with mock.patch("openai_proxy._pool_spec",
                            return_value=(lambda: {}, None, None, "X")):
                webapi.Handler._r_api_pool_quota(h)
            code, body = h.sent
            self.assertEqual(code, 200, "%s 被误判为未知 provider" % pid)
            self.assertNotIn("未知上游", str(body.get("error") or ""))


if __name__ == "__main__":
    unittest.main()
