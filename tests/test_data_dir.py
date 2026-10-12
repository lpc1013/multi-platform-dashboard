# -*- coding: utf-8 -*-
"""data_dir（凭据外移到 %LOCALAPPDATA%）单元测试。
不触碰真实 src/ 与真实 DATA_DIR：用 DASHBOARD_DATA_DIR 环境变量 + importlib.reload
隔离，迁移测试通过 _migrate(src_dir=临时目录) 注入。跑完恢复原状。"""
import os
import sys
import json
import shutil
import tempfile
import unittest
import importlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "src"))

import data_dir  # noqa: E402  （以真实环境加载一次；src 下已无数据文件，迁移为 no-op）


class TestDataDir(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.get("DASHBOARD_DATA_DIR")
        self.tmp = tempfile.mkdtemp(prefix="dash_dd_")
        os.environ["DASHBOARD_DATA_DIR"] = self.tmp
        importlib.reload(data_dir)

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("DASHBOARD_DATA_DIR", None)
        else:
            os.environ["DASHBOARD_DATA_DIR"] = self._old_env
        importlib.reload(data_dir)          # 恢复真实 DATA_DIR，避免污染后续测试
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_env_override(self):
        self.assertEqual(data_dir.DATA_DIR, self.tmp)

    def test_path_and_candidates_order(self):
        self.assertEqual(data_dir.path("x_accounts.json"),
                         os.path.join(self.tmp, "x_accounts.json"))
        c = data_dir.candidates("x_accounts.json")
        self.assertEqual(c[0], os.path.join(self.tmp, "x_accounts.json"))
        self.assertEqual(c[1], os.path.join(HERE, "src", "x_accounts.json"))

    def test_migrate_moves_and_deletes_src(self):
        src = tempfile.mkdtemp(prefix="dash_src_")
        payload = {"账号A": {"token": "t"}}
        with open(os.path.join(src, "trae_accounts.json"), "w", encoding="utf-8") as f:
            json.dump(payload, f)
        data_dir._MIGRATE_DONE = False      # 重置幂等闸门
        data_dir._migrate(src_dir=src)
        dst = os.path.join(self.tmp, "trae_accounts.json")
        self.assertTrue(os.path.isfile(dst))
        self.assertFalse(os.path.exists(os.path.join(src, "trae_accounts.json")))
        with open(dst, encoding="utf-8") as f:
            self.assertEqual(json.load(f), payload)

    def test_migrate_idempotent_never_overwrites_dst(self):
        src = tempfile.mkdtemp(prefix="dash_src_")
        with open(os.path.join(src, "trae_accounts.json"), "w", encoding="utf-8") as f:
            f.write('{"new": 1}')
        # dst 已有不同内容（新数据）→ 必须跳过，不覆盖
        dst = os.path.join(self.tmp, "trae_accounts.json")
        with open(dst, "w", encoding="utf-8") as f:
            f.write('{"keep": 1}')
        data_dir._MIGRATE_DONE = False
        data_dir._migrate(src_dir=src)
        with open(dst, encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"keep": 1})
        # src 原件保留（迁移被跳过时不能丢源数据）
        self.assertTrue(os.path.isfile(os.path.join(src, "trae_accounts.json")))

    def test_migrate_failure_keeps_src(self):
        src = tempfile.mkdtemp(prefix="dash_src_")
        # dst 位置预置同名目录 → copy2 失败 → 必须保留 src 原件
        os.mkdir(os.path.join(self.tmp, "qoder_accounts.json"))
        with open(os.path.join(src, "qoder_accounts.json"), "w", encoding="utf-8") as f:
            f.write('{"a": 1}')
        data_dir._MIGRATE_DONE = False
        data_dir._migrate(src_dir=src)      # 不应抛异常
        self.assertTrue(os.path.isfile(os.path.join(src, "qoder_accounts.json")))

    def test_read_json_prefers_data_dir(self):
        src = tempfile.mkdtemp(prefix="dash_src_")
        old_here = data_dir._HERE
        data_dir._HERE = src                # monkeypatch 回落位置（tearDown reload 恢复）
        try:
            with open(os.path.join(src, "wb_login_result.json"), "w", encoding="utf-8") as f:
                f.write('[{"v": "src"}]')
            with open(data_dir.path("wb_login_result.json"), "w", encoding="utf-8") as f:
                f.write('[{"v": "dd"}]')
            self.assertEqual(data_dir.read_json("wb_login_result.json"), [{"v": "dd"}])
            # DATA_DIR 缺失时回落 src 位置
            os.remove(data_dir.path("wb_login_result.json"))
            self.assertEqual(data_dir.read_json("wb_login_result.json"), [{"v": "src"}])
        finally:
            data_dir._HERE = old_here


if __name__ == "__main__":
    unittest.main()
