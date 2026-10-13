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


if __name__ == "__main__":
    unittest.main()
