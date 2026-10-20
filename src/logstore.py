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
# 可用 DASHBOARD_LOG_FILE 覆盖路径（测试/多实例隔离用）。
LOG_FILE = (os.environ.get("DASHBOARD_LOG_FILE")
            or os.path.join(HERE, "backend_run.log"))
LOG_MAX_BYTES = 1 * 1024 * 1024          # 超过 1MB 轮转为 .old，只保留一代
_log_lock = threading.Lock()


def _under_test():
    """是否跑在 pytest 里。
    2026-10-20 实证：测试进程与看板进程共用同一个 backend_run.log，跑一次
    pytest 会往里写 `账号 B 冷却 1800s（test）`、`codearts 额度用尽` 等**测试
    构造的假故障**，排障时被当成真实生产事件（本机已因此误判过一次）。
    PYTEST_CURRENT_TEST 由 pytest 在每个用例执行期间自动设置，导入期与运行期都可靠。"""
    return bool(os.environ.get("PYTEST_CURRENT_TEST"))


def _log_to_file(line):
    if _under_test():
        return                            # 测试不落盘：生产日志只反映真实运行
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
    # 时间戳必须带日期：backend_run.log 跨天累积（只按 1MB 轮转），旧格式 `[HH:MM:SS]`
    # 无法区分昨天与今天——2026-10-20 排障时把往期的 23:29 当成「未来时间」误判。
    line = "[%s] %s" % (datetime.now().strftime("%m-%d %H:%M:%S"), msg)
    LOG.append(line)
    if len(LOG) > 300:
        del LOG[0]
    try:
        print(line)
    except Exception:
        pass
    with _log_lock:
        _log_to_file(line)
