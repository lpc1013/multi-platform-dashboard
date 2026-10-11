# -*- coding: utf-8 -*-
"""核心纯函数单元测试 —— 多账号「互不覆盖」铁律 + 令牌续期自救。

运行（必须用带 requests/cryptography 的 Python）：
    python -m unittest tests.test_core -v
（在仓库根目录执行；测试只读写临时目录，不碰真实凭据文件。）
"""
import json
import os
import sys
import tempfile
import unittest
import hashlib

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)
sys.argv = [sys.argv[0]]          # server.py 会把 sys.argv[1] 当端口号，清掉 unittest 的参数

import server                      # noqa: E402  （导入即加载平台注册表，不做任何网络请求）
import platforms.minimax as mm     # noqa: E402
import platforms.codearts as ca    # noqa: E402


def _tmp_cred_file():
    fd, path = tempfile.mkstemp(suffix="_accounts.json")
    os.close(fd)
    os.remove(path)                   # 让 _read_json 走「文件不存在」分支
    return path


class TestNameTail(unittest.TestCase):
    def test_phone_uses_last4(self):
        self.assertEqual(server._name_tail({"phone": "13812345678"}), "5678")

    def test_user_id_uses_last4(self):
        self.assertEqual(server._name_tail({"user_id": "88123499"}), "3499")

    def test_token_uses_sha1_head4(self):
        tok = "mmort_abcdef123456"
        self.assertEqual(server._name_tail({"token": tok}),
                         hashlib.sha1(tok.encode()).hexdigest()[:4])

    def test_empty(self):
        self.assertEqual(server._name_tail({}), "")


class TestIdentOf(unittest.TestCase):
    def test_priority_user_id_over_token(self):
        # minimax 刻意把 user_id 排在 access_token 之前：令牌轮换不当指纹
        f, v = server._ident_of("minimax", {"access_token": "mmoat_x", "user_id": "12345"})
        self.assertEqual((f, v), ("user_id", "12345"))

    def test_fallback_to_token(self):
        f, v = server._ident_of("minimax", {"access_token": "mmoat_x"})
        self.assertEqual((f, v), ("access_token", "mmoat_x"))

    def test_none_when_empty(self):
        self.assertIsNone(server._ident_of("minimax", {}))


class TestAllocAccountName(unittest.TestCase):
    """规则：① 同身份沿用旧键名 ② 空名直接用 ③ 冲突追加尾号，绝不覆盖。"""

    def setUp(self):
        self.path = _tmp_cred_file()

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_empty_store_uses_ideal(self):
        self.assertEqual(
            server._alloc_account_name(self.path, "minimax", "小柴", {"user_id": "1111"}),
            "小柴")

    def test_same_identity_reuses_old_key(self):
        # 用户改过显示名后客户端又推来新名字 → 必须沿用旧键（保住备注名）
        server._cred_store_set(self.path, "我的主号", {"user_id": "1111", "access_token": "A"})
        got = server._alloc_account_name(
            self.path, "minimax", "一只总柴0623", {"user_id": "1111", "access_token": "B"})
        self.assertEqual(got, "我的主号")

    def test_conflict_appends_tail(self):
        server._cred_store_set(self.path, "小柴", {"user_id": "1111"})
        got = server._alloc_account_name(self.path, "minimax", "小柴", {"user_id": "2222"})
        self.assertEqual(got, "小柴·2222")

    def test_conflict_twice_numbered(self):
        # 尾号取自**新记录**的身份（3333），与被占用的键名无关；再冲突才加 #2
        server._cred_store_set(self.path, "小柴", {"user_id": "1111"})
        server._cred_store_set(self.path, "小柴·3333", {"user_id": "3333"})
        got = server._alloc_account_name(self.path, "minimax", "小柴", {"user_id": "3333"})
        self.assertEqual(got, "小柴·3333")   # 同身份沿用（规则①优先于尾号）
        got2 = server._alloc_account_name(self.path, "minimax", "小柴", {"user_id": "4444"})
        self.assertEqual(got2, "小柴·4444")


class TestDedupeStore(unittest.TestCase):
    """同身份换了显示名再导入 → 旧键必须清掉，账号数不虚增。"""

    def setUp(self):
        self.path = _tmp_cred_file()

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_drops_old_entries_of_same_identity(self):
        server._cred_store_set(self.path, "旧名", {"user_id": "1111", "access_token": "A"})
        server._cred_store_set(self.path, "别的账号", {"user_id": "9999"})
        # _dedupe_store 只负责清旧键；新键由调用方 _save_cred/_cred_store_set 写入
        dropped = server._dedupe_store(self.path, "minimax", "新名",
                                       {"user_id": "1111", "access_token": "B"})
        self.assertEqual(dropped, ["旧名"])
        server._cred_store_set(self.path, "新名", {"user_id": "1111", "access_token": "B"})
        data = server._read_json(self.path, {})
        self.assertIn("新名", data)
        self.assertIn("别的账号", data)
        self.assertNotIn("旧名", data)

    def test_keeps_target_key_itself(self):
        server._cred_store_set(self.path, "小柴", {"user_id": "1111"})
        dropped = server._dedupe_store(self.path, "minimax", "小柴", {"user_id": "1111"})
        self.assertEqual(dropped, [])
        self.assertIn("小柴", server._read_json(self.path, {}))


class TestMiniMaxRtBackup(unittest.TestCase):
    """RT 一次性轮换的自救副本：写 → 读 回路 + 多账号互不干扰。"""

    def setUp(self):
        fd, self.bak = tempfile.mkstemp(suffix=".rt_backup.json")
        os.close(fd)
        os.remove(self.bak)
        self._orig = mm.RT_BACKUP_FILE
        mm.RT_BACKUP_FILE = self.bak

    def tearDown(self):
        mm.RT_BACKUP_FILE = self._orig
        if os.path.exists(self.bak):
            os.remove(self.bak)

    def test_round_trip(self):
        self.assertTrue(mm._save_rt_backup("1111", "mmort_new", "mmoat_a", 1700000000000))
        self.assertEqual(mm._load_rt_backup("1111"), "mmort_new")

    def test_multi_account_merge(self):
        mm._save_rt_backup("1111", "rt_1", "at_1", 1)
        mm._save_rt_backup("2222", "rt_2", "at_2", 2)
        self.assertEqual(mm._load_rt_backup("1111"), "rt_1")
        self.assertEqual(mm._load_rt_backup("2222"), "rt_2")

    def test_missing_returns_empty(self):
        self.assertEqual(mm._load_rt_backup("no_such_uid"), "")

    def test_invalid_args(self):
        self.assertFalse(mm._save_rt_backup("", "rt", "at", 1))
        self.assertFalse(mm._save_rt_backup("uid", "", "at", 1))
        self.assertEqual(mm._load_rt_backup(""), "")


class TestCodeArtsPreserveMerge(unittest.TestCase):
    """客户端最新会话同键名覆盖自建会话时，续期材料（refresh_token/DPoP）必须保留。

    这是 2026-10-09 修的「客户端导入顶丢自建 refresh_token」缺陷的防回归测试。
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="codearts_test_")
        self.acc_file = os.path.join(self.tmpdir, "codearts_accounts.json")
        server._write_json(self.acc_file, {
            "测试号": {"ak": "AK-OLD", "sk": "SK-OLD", "sts_token": "STS-OLD",
                       "refresh_token": "RT-KEEP", "dpop_priv_pem": "PEM-KEEP",
                       "code_verifier": "VER-KEEP", "user_id": "domain-1"}})
        self._orig_acc, self._orig_tombs = ca._ACC_FILES, ca._TOMB_FILES
        ca._ACC_FILES = (self.acc_file,)
        ca._TOMB_FILES = (os.path.join(self.tmpdir, "codearts_deleted.json"),)

        # 伪造 local_import：客户端发来同键名的新鲜 AK/SK，但不含续期材料
        import types
        fake = types.ModuleType("local_import")
        fake.read_codearts = lambda: (True, "ok", {
            "测试号": {"ak": "AK-NEW", "sk": "SK-NEW", "sts_token": "STS-NEW",
                       "user_id": "domain-1"}})
        self._orig_li = sys.modules.get("local_import")
        sys.modules["local_import"] = fake

    def tearDown(self):
        ca._ACC_FILES, ca._TOMB_FILES = self._orig_acc, self._orig_tombs
        if self._orig_li is not None:
            sys.modules["local_import"] = self._orig_li
        else:
            sys.modules.pop("local_import", None)

    def test_refresh_material_survives_client_override(self):
        accs = ca.load_accounts()
        ent = accs["测试号"]
        self.assertEqual(ent["ak"], "AK-NEW")            # 客户端的新鲜凭据生效
        self.assertEqual(ent["refresh_token"], "RT-KEEP")  # 续期材料保留
        self.assertEqual(ent["dpop_priv_pem"], "PEM-KEEP")
        self.assertEqual(ent["code_verifier"], "VER-KEEP")

    def test_no_client_session_keeps_self_built(self):
        import types
        fake = types.ModuleType("local_import")
        fake.read_codearts = lambda: (True, "ok", {})
        sys.modules["local_import"] = fake
        accs = ca.load_accounts()
        self.assertEqual(accs["测试号"]["ak"], "AK-OLD")
        self.assertEqual(accs["测试号"]["refresh_token"], "RT-KEEP")


if __name__ == "__main__":
    unittest.main(verbosity=2)
