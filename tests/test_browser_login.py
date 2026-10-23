# -*- coding: utf-8 -*-
"""browser_login 模块单测（不依赖 playwright，仅覆盖纯逻辑）。

覆盖：
  - _BROWSER_LOGIN_CFG 含 doubao 条目且字段契约正确（capture=full / login_cookie / domains）
  - _build_cookie_string：按域过滤 + 去重保序 + 空值跳过
  - browser_login 对未知平台 / 未配置平台的拒绝分支（不弹浏览器）
运行：python -m unittest tests.test_browser_login
"""
import os
import sys
import unittest

sys.argv = [sys.argv[0]]  # 阻断 server/openai_proxy 导入链把 argv[1] 当端口读
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import browser_login as bl   # noqa: E402


class TestCfg(unittest.TestCase):
    def test_doubao_present(self):
        self.assertIn("doubao", bl._BROWSER_LOGIN_CFG)
        cfg = bl._BROWSER_LOGIN_CFG["doubao"]
        self.assertEqual(cfg.get("capture"), "full")
        self.assertEqual(cfg.get("login_cookie"), "sessionid")
        self.assertIn(".doubao.com", cfg.get("domains", []))
        self.assertTrue(cfg.get("deadline", 0) >= 180)
        self.assertIn("chat", cfg.get("url", ""))

    def test_lingxi_unchanged(self):
        cfg = bl._BROWSER_LOGIN_CFG["lingxi"]
        self.assertEqual(cfg.get("capture"), "single")
        self.assertEqual(cfg.get("cookie_name"), "wps_sid")


class TestBuildCookieString(unittest.TestCase):
    def _cookies(self):
        return [
            {"name": "sessionid", "value": "abc", "domain": ".doubao.com"},
            {"name": "uid_tt", "value": "u1", "domain": "www.doubao.com"},
            {"name": "sid_other", "value": "x", "domain": ".example.com"},  # 应被过滤
            {"name": "sessionid_ss", "value": "def", "domain": ".doubao.com"},
            {"name": "empty_val", "value": "", "domain": ".doubao.com"},     # 空值跳过
            {"name": "sessionid", "value": "abc", "domain": ".doubao.com"},  # 重复去重
        ]

    def test_filters_and_dedup(self):
        s = bl._build_cookie_string(self._cookies(), [".doubao.com", "doubao.com", "www.doubao.com"])
        self.assertIn("sessionid=abc", s)
        self.assertIn("uid_tt=u1", s)
        self.assertIn("sessionid_ss=def", s)
        self.assertNotIn("sid_other", s)
        self.assertNotIn("empty_val", s)
        self.assertEqual(s.count("sessionid=abc"), 1)   # 去重

    def test_empty_domains_returns_empty(self):
        s = bl._build_cookie_string(self._cookies(), [])
        self.assertEqual(s, "")

    def test_no_matching_cookies(self):
        s = bl._build_cookie_string([{"name": "a", "value": "1", "domain": ".x.com"}],
                                     [".doubao.com"])
        self.assertEqual(s, "")


class TestBrowserLoginReject(unittest.TestCase):
    def test_unknown_platform(self):
        ok, msg, cred = bl.browser_login("nope", lambda s, t: None)
        self.assertFalse(ok)
        self.assertIsNone(cred)
        self.assertIn("不支持", msg)

    def test_doubao_config_reachable(self):
        # 仅校验配置可达，不真正拉浏览器（progress 回调空实现）
        self.assertIsNotNone(bl._BROWSER_LOGIN_CFG.get("doubao"))


class TestCheckinCfg(unittest.TestCase):
    def test_doubao_checkin_cfg(self):
        self.assertIn("doubao", bl._BROWSER_CHECKIN_CFG)
        cfg = bl._BROWSER_CHECKIN_CFG["doubao"]
        self.assertIn("pc/agent-explore", cfg.get("url", ""))
        self.assertTrue(cfg.get("success_texts"))
        self.assertIn("签到成功", cfg["success_texts"])
        self.assertIn("200 额度", cfg["success_texts"])
        self.assertTrue(cfg.get("click_texts"))
        self.assertIn(".doubao.com", cfg.get("domains", []))


class TestCheckinPureHelpers(unittest.TestCase):
    def test_parse_cookie_pairs(self):
        pairs = bl._parse_cookie_pairs("a=b; c=d;  e=f ; g")
        self.assertEqual(pairs, [("a", "b"), ("c", "d"), ("e", "f")])  # g 无 = 跳过
        self.assertEqual(bl._parse_cookie_pairs(""), [])
        self.assertEqual(bl._parse_cookie_pairs(None), [])

    def test_build_checkin_cookies(self):
        pairs = [("sessionid", "abc"), ("uid_tt", "u1")]
        ck = bl._build_checkin_cookies(pairs, [".doubao.com", "www.doubao.com"])
        # 每个键值对每个域一份
        self.assertEqual(len(ck), 4)
        for c in ck:
            self.assertEqual(c["path"], "/")
            self.assertIn(c["domain"], [".doubao.com", "www.doubao.com"])
        # 空 name 跳过
        self.assertEqual(bl._build_checkin_cookies([("", "x")], [".doubao.com"]), [])

    def test_contains_any(self):
        self.assertTrue(bl._contains_any("签到成功，获得 200 额度", ["签到成功", "已签到"]))
        self.assertTrue(bl._contains_any("今日已签", ["200 额度", "今日已签"]))
        self.assertFalse(bl._contains_any("活动已结束", ["签到成功", "200 额度"]))
        self.assertFalse(bl._contains_any("", ["签到成功"]))
        self.assertFalse(bl._contains_any(None, ["签到成功"]))


class TestCheckinReject(unittest.TestCase):
    def test_no_cookie(self):
        ok, msg, _ = bl.browser_checkin("doubao", "")
        self.assertFalse(ok)
        self.assertIn("未配置 Cookie", msg)

    def test_unknown_platform(self):
        ok, msg, _ = bl.browser_checkin("nope", "a=b")
        self.assertFalse(ok)
        self.assertIn("不支持", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
