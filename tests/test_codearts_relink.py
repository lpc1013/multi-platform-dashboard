# -*- coding: utf-8 -*-
"""CodeArts 登录态诊断分流：缺刷新令牌（早期票据/客户端导入）vs 有 RT 但续期失败。

不联网、不拉浏览器：把 _refresh_if_needed 打桩成「续期失败」，验证 read_account
的错误文案与 needs_relink 标记正确分流——这是「老是掉登录态」的可操作根因提示。

断言刻意避开 CJK 子串（同一汉字在不同写入路径会被归一化为不同码点，肉眼一致但
in 判定失败）；改用 needs_relink / can_refresh 布尔标志 + ASCII 令牌判定。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import platforms.codearts as codearts


def _ent(refresh_token=""):
    ent = {"ak": "a", "sk": "s", "sts_token": "t",
           "expires_at": "2020-01-01T00:00:00Z"}  # 过去时间 → expired=True
    if refresh_token:
        ent["refresh_token"] = refresh_token
    return ent


class TestCodeArtsRelink(unittest.TestCase):

    def setUp(self):
        # 续期失败：强制走 read_account 的错误分支
        self._orig = codearts._refresh_if_needed
        codearts._refresh_if_needed = lambda name, ent: False

    def tearDown(self):
        codearts._refresh_if_needed = self._orig

    def test_no_refresh_token_branch(self):
        r = codearts.read_account("t", _ent())
        self.assertFalse(r["ok"])
        # 无 RT → 必须携带 refresh_token 文案 + 标记 needs_relink
        self.assertIn("refresh_token", r["error"] or "")
        self.assertIn("无法静默续期", r["error"] or "")
        extra = r["extra"]
        self.assertFalse(extra.get("can_refresh"))
        self.assertTrue(extra.get("needs_relink"))

    def test_has_refresh_token_branch(self):
        r = codearts.read_account("t", _ent(refresh_token="rt-xyz"))
        self.assertFalse(r["ok"])
        # 有 RT 但续期失败 → 不应再提示「缺刷新令牌/需短信重登」，且无 needs_relink
        self.assertNotIn("refresh_token", r["error"] or "")
        self.assertNotIn("无法静默续期", r["error"] or "")
        extra = r["extra"]
        self.assertTrue(extra.get("can_refresh"))
        self.assertFalse(extra.get("needs_relink"))


if __name__ == "__main__":
    unittest.main()
