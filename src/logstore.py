# -*- coding: utf-8 -*-
"""
logstore.py —— 运行日志（2026-10-13 从 server.py 抽出）
内存 LOG（前端 /api/log 展示，重启即丢）+ backend_run.log 落盘（重启后可追溯，
超 1MB 轮转 .old 只保留一代）。日志是辅助设施，任何失败都不影响主流程。
"""
import os
import threading
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))

LOG = []

# 运行日志落盘：重启后仍可追溯（内存 LOG 重启即丢）。backend_run.log 已在 .gitignore。
LOG_FILE = os.path.join(HERE, "backend_run.log")
LOG_MAX_BYTES = 1 * 1024 * 1024          # 超过 1MB 轮转为 .old，只保留一代
_log_lock = threading.Lock()


def _log_to_file(line):
    try:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
            try:
                os.replace(LOG_FILE, LOG_FILE + ".old")
            except Exception:
                pass                      # 轮转失败（如被占用）就继续追加，不丢日志
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass                              # 日志是辅助设施，任何失败都不影响主流程


def log(msg):
    line = "[%s] %s" % (datetime.now().strftime("%H:%M:%S"), msg)
    LOG.append(line)
    if len(LOG) > 300:
        del LOG[0]
    try:
        print(line)
    except Exception:
        pass
    with _log_lock:
        _log_to_file(line)
