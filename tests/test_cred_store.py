# -*- coding: utf-8 -*-
"""
cred_store 存储层加固回归（2026-10-13）
覆盖：原子写 / 进程内并发不丢写 / 跨进程锁不丢写 / 损坏文件隔离 /
      save_cred 身份语义（同身份沿用键名，不覆盖他人）。
不触碰真实 DATA_DIR：全部读写走 tempfile 目录。
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)
sys.path.insert(0, os.path.join(SRC, "..", "tests"))  # noqa: E402

import cred_store as cs  # noqa: E402


class AtomicWriteTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="credstore_")
        self.path = os.path.join(self.dir, "x_accounts.json")

    def test_write_read_roundtrip(self):
        cs.write_json(self.path, {"a": 1, "b": "中文"})
        self.assertEqual(cs.read_json(self.path, {}), {"a": 1, "b": "中文"})

    def test_no_tmp_leftover(self):
        cs.write_json(self.path, {"a": 1})
        leftovers = [f for f in os.listdir(self.dir) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_corrupt_file_isolated(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write('{"a": 1, "b": ')  # 半截 JSON：模拟写入中途崩溃
        got = cs.read_json(self.path, {"default": True})
        self.assertEqual(got, {"default": True})
        self.assertTrue(any(f.startswith("x_accounts.json.corrupt-")
                            for f in os.listdir(self.dir)),
                        "损坏文件应被隔离为 *.corrupt-*")


class InProcessConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="credstore_")
        self.path = os.path.join(self.dir, "y_accounts.json")

    def test_locked_read_modify_write_no_lost_update(self):
        """8 线程 × 25 次「读-改-写」自增：无锁时必然丢更新，持锁后必须全数保留。"""
        cs.write_json(self.path, {"n": 0})
        errs = []

        def worker():
            try:
                for _ in range(25):
                    with cs.locked(self.path):
                        d = cs.read_json(self.path, {})
                        d["n"] += 1
                        cs.write_json(self.path, d)
            except Exception as e:  # pragma: no cover
                errs.append(e)

        ts = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        self.assertEqual(cs.read_json(self.path, {}).get("n"), 200)

    def test_concurrent_set_distinct_keys_no_lost_writes(self):
        """8 线程各写 10 个不同键：最终 80 键一个不丢（旧实现的覆盖窗口已封死）。"""
        errs = []

        def worker(k):
            try:
                for i in range(10):
                    cs.cred_store_set(self.path, "t%d-%d" % (k, i), {"v": i})
            except Exception as e:  # pragma: no cover
                errs.append(e)

        ts = [threading.Thread(target=worker, args=(k,)) for k in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        self.assertEqual(len(cs.read_json(self.path, {})), 80)


class CrossProcessTest(unittest.TestCase):
    def test_two_processes_no_lost_writes(self):
        """两个独立 Python 进程各写 30 键：跨进程文件锁保证 60 键齐全。"""
        d = tempfile.mkdtemp(prefix="credstore_xproc_")
        path = os.path.join(d, "z_accounts.json")
        script = (
            "import sys\n"
            "sys.path.insert(0, r'%s')\n"
            "import cred_store\n"
            "for i in range(30):\n"
            "    cred_store.cred_store_set(r'%s', sys.argv[1] + str(i), {'v': i})\n"
        ) % (SRC, path)
        procs = [subprocess.Popen([sys.executable, "-c", script, "p%d-" % k])
                 for k in range(2)]
        rcs = [p.wait() for p in procs]
        self.assertEqual(rcs, [0, 0], "子进程应无异常退出")
        data = cs.read_json(path, {})
        self.assertEqual(len(data), 60, "跨进程并发写入不得丢键")


class SaveCredSemanticsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="credstore_sc_")
        self.cred_files = {"minimax": os.path.join(self.dir, "m_accounts.json")}

    def test_same_identity_reuses_key(self):
        k1 = cs.save_cred("minimax", {"user_id": "u1", "access_token": "a1"},
                          "小柴", self.cred_files)
        k2 = cs.save_cred("minimax", {"user_id": "u1", "access_token": "a2"},
                          "小柴", self.cred_files)
        self.assertEqual(k1, k2, "同一身份（user_id 相同）必须沿用旧键名")

    def test_different_identity_same_ideal_no_overwrite(self):
        k1 = cs.save_cred("minimax", {"user_id": "u1", "phone": "13800001111"},
                          "小柴", self.cred_files)
        k2 = cs.save_cred("minimax", {"user_id": "u2", "phone": "13800002222"},
                          "小柴", self.cred_files)
        self.assertNotEqual(k1, k2, "不同身份同名 ideal 必须追加尾号，不得覆盖")
        data = cs.read_json(self.cred_files["minimax"], {})
        self.assertEqual(len(data), 2)
        self.assertEqual(data[k1]["user_id"], "u1")
        self.assertEqual(data[k2]["user_id"], "u2")


class IdentityRotationTest(unittest.TestCase):
    """2026-10-13 重复卡事故回归：dumate 整串 cookie / lingxi 整串 wps_sid
    每次登录必换，曾被当身份指纹 → 3 账号变 6 卡。修复后 IDENT_FIELDS
    以 user_id/phone 等稳定字段优先，令牌轮换不得再开新卡。"""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="credstore_rot_")
        self.cf = {
            "baidu_dumate": os.path.join(self.dir, "dumate_accounts.json"),
            "lingxi": os.path.join(self.dir, "lingxi_accounts.json"),
        }

    def test_dumate_cookie_rotation_no_new_card(self):
        ck1 = "BDUSS=aaa; bce-login-accountid=24a678ecAAAA; STOKEN=x1"
        ck2 = "BDUSS=bbb; bce-login-accountid=24a678ecAAAA; STOKEN=x2; BAIDUID=fresh"
        k1 = cs.save_cred("baidu_dumate", {"cookie": ck1, "user_id": "24a678ecAAAA",
                                           "phone": "18685898566"}, "老名字", self.cf)
        k2 = cs.save_cred("baidu_dumate", {"cookie": ck2, "user_id": "24a678ecAAAA",
                                           "phone": "18685898566"}, "新昵称", self.cf)
        self.assertEqual(k1, k2, "cookie 轮换但 user_id 相同 → 必须沿用旧键名")
        self.assertEqual(len(cs.read_json(self.cf["baidu_dumate"], {})), 1)

    def test_lingxi_sid_rotation_no_new_card(self):
        s1 = "V02SaaaaXYZ00a43ba6900438f6dec"
        s2 = "V02SbbbbQQQ00abb5bf500438f6dec"   # 换 sid，尾 10 位不变（同一用户）
        k1 = cs.save_cred("lingxi", {"wps_sid": s1, "phone": "18685898566"},
                          "灵犀", self.cf)
        k2 = cs.save_cred("lingxi", {"wps_sid": s2, "phone": "18685898566"},
                          "灵犀", self.cf)
        self.assertEqual(k1, k2, "wps_sid 轮换但 phone 相同 → 必须沿用旧键名")
        self.assertEqual(len(cs.read_json(self.cf["lingxi"], {})), 1)

    def test_ensure_identity_backfills_from_cookie(self):
        rec = {"cookie": "BDUSS=zz; bce-login-accountid=abc123"}
        cs.ensure_identity("baidu_dumate", rec)
        self.assertEqual(rec["user_id"], "abc123")
        rec2 = {"wps_sid": "V02Sxyz00438f6decabcdefghij"}
        cs.ensure_identity("lingxi", rec2)
        self.assertEqual(rec2["user_id"], str(rec2["wps_sid"])[-10:])
        # 幂等：已有 user_id 不被覆盖
        rec3 = {"cookie": "bce-login-accountid=aaa", "user_id": "keep"}
        cs.ensure_identity("baidu_dumate", rec3)
        self.assertEqual(rec3["user_id"], "keep")

    def test_ident_fields_stable_first(self):
        self.assertEqual(cs.IDENT_FIELDS["baidu_dumate"][0], "user_id")
        self.assertEqual(cs.IDENT_FIELDS["lingxi"][0], "phone")
        self.assertEqual(cs.IDENT_FIELDS["lingxi"][1], "user_id")


if __name__ == "__main__":
    unittest.main()
