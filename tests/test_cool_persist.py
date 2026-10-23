# -*- coding: utf-8 -*-
"""冷却态持久化单测（2026-10-22 用户要求「模型重置可使用时间要持久化保留」）。

落盘文件重定向到 tmp 目录（patch ox.COOL_FILE），不碰真实
%LOCALAPPDATA%\\dashboard_analysis\\proxy_cool.json。
_cool_save/_cool_load 在测试进程默认被 _under_test 门控（不落盘/不加载），
需要验证落盘行为的用例显式 patch logstore._under_test → False。
"""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.argv = [sys.argv[0]]  # server/openai_proxy 导入链会把 argv[1] 当端口读
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import openai_proxy as ox  # noqa: E402


class CoolPersistBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cooltest")
        self.file = os.path.join(self.tmp, "proxy_cool.json")
        self._old = ox.COOL_FILE
        ox.COOL_FILE = self.file
        # 清内存态：避免模块导入时的真实恢复 / 其他用例残留干扰断言
        ox._WBAI_ML_COOL.clear()
        ox._POOL_COOL.clear()

    def tearDown(self):
        ox.COOL_FILE = self._old
        ox._WBAI_ML_COOL.clear()
        ox._POOL_COOL.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _not_test(self):
        """让 _cool_save/_cool_load 在测试进程里也真落盘/真加载。"""
        return mock.patch("logstore._under_test", return_value=False)


class TestCoolSaveLoad(CoolPersistBase):
    def test_roundtrip_ml_and_pool(self):
        """模型行冷却 + 账号池冷却 → 落盘 → 模拟重启（清内存）→ 原样恢复。"""
        future = time.time() + 3600
        ox._WBAI_ML_COOL[("WB国际·15149378", "deepseek-v4.1-flash")] = future
        ox._POOL_COOL["codearts"] = {"HST3·8566": time.time() + 1800}
        with self._not_test():
            ox._cool_save()
        self.assertTrue(os.path.exists(self.file))
        ox._WBAI_ML_COOL.clear()
        ox._POOL_COOL.clear()
        with self._not_test():
            ox._cool_load()
        self.assertAlmostEqual(
            ox._WBAI_ML_COOL[("WB国际·15149378", "deepseek-v4.1-flash")],
            future, delta=1)
        self.assertGreater(ox._POOL_COOL.get("codearts", {}).get("HST3·8566", 0),
                           time.time())

    def test_expired_dropped(self):
        """过期项保存时即过滤、加载时不恢复（恢复即清理）。"""
        ox._WBAI_ML_COOL[("A", "m")] = time.time() - 10
        ox._POOL_COOL["wbai"] = {"B": time.time() - 1}
        with self._not_test():
            ox._cool_save()
        d = json.load(open(self.file, encoding="utf-8"))
        self.assertEqual(d["ml"], {})
        self.assertEqual(d["pool"], {})
        ox._WBAI_ML_COOL.clear()
        ox._POOL_COOL.clear()
        with self._not_test():
            ox._cool_load()
        self.assertEqual(ox._WBAI_ML_COOL, {})
        self.assertNotIn("B", ox._POOL_COOL.get("wbai", {}))

    def test_load_missing_or_corrupt_is_noop(self):
        ox._cool_load()                       # 文件不存在
        self.assertEqual(ox._WBAI_ML_COOL, {})
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        with self._not_test():
            ox._cool_load()                   # 损坏文件
        self.assertEqual(ox._WBAI_ML_COOL, {})
        self.assertEqual(ox._POOL_COOL, {})

    def test_key_roundtrip_with_pipe_in_name(self):
        """账号名含 "|" 也能完整 roundtrip（模型段在最后，rpartition 切回）。"""
        ox._WBAI_ML_COOL[("a|b", "M")] = time.time() + 60
        with self._not_test():
            ox._cool_save()
        d = json.load(open(self.file, encoding="utf-8"))
        self.assertIn("a|b|m", d["ml"])       # 模型名落盘时已小写
        ox._WBAI_ML_COOL.clear()
        with self._not_test():
            ox._cool_load()
        self.assertIn(("a|b", "m"), ox._WBAI_ML_COOL)

    def test_snapshot_no_credential_fields(self):
        """落盘内容只允许 v/ml/pool 三个键（无任何凭据字段）。"""
        with self._not_test():
            ox._cool_save()
        d = json.load(open(self.file, encoding="utf-8"))
        self.assertEqual(set(d.keys()), {"v", "ml", "pool"})


class TestSetHooksPersist(CoolPersistBase):
    def test_pool_cool_persists(self):
        with self._not_test():
            ox._pool_cool("wbai", "WB国际·X", "401", sec=600)
        self.assertTrue(os.path.exists(self.file))
        ox._POOL_COOL.clear()
        with self._not_test():
            ox._cool_load()
        self.assertGreater(ox._POOL_COOL.get("wbai", {}).get("WB国际·X", 0),
                           time.time())

    def test_wbai_ml_limit_persists_reset_ts(self):
        """6004 报文带重置时刻 → 解析落盘，重启后仍冷却到这个时刻。"""
        line = ('data:{"error_code":"6004","error_msg":"rate limited, '
                '将在 2099-01-01 08:00:00 UTC+8重置"}')
        with self._not_test():
            tag = ox._wbai_ml_limit("WB国际·Y", "DeepSeek-V4.1-Flash", line)
        self.assertIn("重置", tag)
        ox._WBAI_ML_COOL.clear()
        with self._not_test():
            ox._cool_load()
        self.assertIn(("WB国际·Y", "deepseek-v4.1-flash"), ox._WBAI_ML_COOL)

    def test_save_skipped_under_test(self):
        """铁律：测试进程不落盘——pytest 构造的假冷却不污染线上文件。"""
        with mock.patch("logstore._under_test", return_value=True):
            ox._pool_cool("codearts", "Z", "test", sec=60)
            ox._wbai_ml_limit("WB国际·T", "m", '{"code":6004}')
        self.assertFalse(os.path.exists(self.file))

    def test_dsflash_cool_until_sees_restored_state(self):
        """前端「禁用至 HH:MM:SS 放出」的数据源：恢复后立即可见。"""
        ox._WBAI_ML_COOL[("WB国际·Q", "ds-flash")] = time.time() + 1200
        ox._POOL_COOL["codearts"] = {"HST3·8566": time.time() + 900}
        with self._not_test():
            ox._cool_save()
        ox._WBAI_ML_COOL.clear()
        ox._POOL_COOL.clear()
        with self._not_test():
            ox._cool_load()
        self.assertGreater(ox._dsflash_cool_until("wbai", "WB国际·Q", "ds-flash"), 0)
        self.assertTrue(ox._dsflash_cooling("wbai", "WB国际·Q", "ds-flash"))
        self.assertGreater(
            ox._dsflash_cool_until("codearts", "HST3·8566", "ds-flash"), 0)


if __name__ == "__main__":
    unittest.main()
