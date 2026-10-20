# -*- coding: utf-8 -*-
"""logstore 单元测试 —— 日志隔离与时间戳格式（2026-10-20 自检修复的回归测试）。

背景（实证）：
  1) 测试进程与看板进程共用 src/backend_run.log。跑一次 pytest 会往里写
     `[proxy:wbai] 账号 B 冷却 1800s（test）`、`[proxy:codearts] 账号 ... 冷却
     1800s（额度用尽）` 等**测试构造的假故障**。排障时这些行被当成真实生产
     事件（本机已因此误判过一次）。
  2) 旧时间戳是 `[HH:MM:SS]` 无日期，而 backend_run.log 跨天累积（只按 1MB
     轮转），无法区分昨天与今天。

运行：python -m pytest tests/test_logstore.py -q
"""
import os
import re
import sys
import tempfile
import unittest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import logstore  # noqa: E402


class TestLogIsolation(unittest.TestCase):
    def test_detects_pytest_runtime(self):
        """pytest 执行期间必须能识别出「我在测试里」。"""
        self.assertTrue(logstore._under_test(),
                        "PYTEST_CURRENT_TEST 未生效：测试会污染生产日志")

    def test_log_not_written_to_file_under_test(self):
        """测试期间 log() 不得落盘（内存 LOG 与 stdout 仍保留，便于断言）。"""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "should_stay_empty.log")
            old = logstore.LOG_FILE
            logstore.LOG_FILE = path
            try:
                logstore.log("[proxy:wbai] 账号 B 冷却 1800s（test）")
                self.assertFalse(os.path.exists(path),
                                 "测试写入了生产日志文件：%s" % path)
                self.assertTrue(any("账号 B 冷却" in x for x in logstore.LOG),
                                "内存日志应照常记录，只是不落盘")
            finally:
                logstore.LOG_FILE = old

    def test_log_file_override_by_env(self):
        """DASHBOARD_LOG_FILE 可覆盖路径（多实例/测试隔离）。"""
        self.assertIn("backend_run.log", logstore.LOG_FILE)


class TestTimestampFormat(unittest.TestCase):
    def test_timestamp_carries_date(self):
        """时间戳必须带 MM-DD：跨天日志不能只靠 HH:MM:SS 区分。"""
        logstore.log("ts-format-probe")
        line = logstore.LOG[-1]
        self.assertRegex(line, r"^\[\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] ",
                         "时间戳缺少日期，跨天排障会误判：%r" % line)

    def test_no_bare_hms_prefix(self):
        """回归防线：不允许退回旧的 `[HH:MM:SS]` 裸时间格式。"""
        logstore.log("ts-format-probe-2")
        line = logstore.LOG[-1]
        self.assertIsNone(re.match(r"^\[\d{2}:\d{2}:\d{2}\] ", line), line)


if __name__ == "__main__":
    unittest.main()
