# -*- coding: utf-8 -*-
"""
多平台账号看板 · 本地后端（启动入口）
═════════════════════════════════════════════════════════════════════════
给 index.html 提供真实数据与操作能力：
  GET  /            → 看板页面（index.html）
  GET  /api/state   → 所有平台 / 所有账号状态
  POST /api/run     → 执行操作：按 platform + 账号 + 任务（可异步）
  POST /api/refresh → 强制刷新，忽略缓存

只监听 127.0.0.1，凭据与 token 不出本机。

分层（2026-10-13 起，God Object 拆分完成）：
  registry.py         平台注册表 + 端口
  logstore.py         运行日志（内存 + backend_run.log）
  cred_store.py       凭据存储层（原子写 + 双重锁 + DPAPI 加密 + 身份指纹键名）
  tasks.py            状态汇总（collect_state）+ 任务/浏览器登录调度（JOBS/BLOGINS）
  account_service.py  各登录通道的凭据落盘编排
  webapi.py           HTTP 路由（Handler）+ 本机来源防护
  server.py           本文件：只负责启动（Server / 单实例探测 / main）

平台适配器约定（platforms/<id>.py）：
  PLATFORM / LABEL / TASKS
  load_accounts() -> {name: cred}
  read_account(name, ent) -> 归一化状态 dict
  run_task(name, ent, task_key) -> {ok, msg, ...}

启动：
  python server.py            # 默认 http://127.0.0.1:8799
  python server.py 9000       # 指定端口
"""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import data_dir   # 凭据/运行产物外移到 %LOCALAPPDATA%\dashboard_analysis（import 即自动迁移）

try:
    import requests
except ImportError:
    sys.exit("缺少依赖 requests，请先：pip install requests")

# ── 兼容 re-export（薄壳模式，与 oauth 一期同款）──
# tests/test_core.py 与 openai_proxy.py 经 server.<name> 访问这些符号，保持零改动。
import cred_store
from cred_store import (
    CRED_FILES, IDENT_FIELDS, DEFAULT_LABEL, WB_LOGIN_FILE,
    read_json as _read_json, write_json as _write_json,
    cred_store_set as _cred_store_set, cred_store_remove as _cred_store_remove,
    ident_of as _ident_of, wb_match as _wb_match,
    dedupe_store as _dedupe_store, name_tail as _name_tail,
    alloc_account_name as _alloc_account_name, save_cred as _save_cred,
    locked as _cred_locked,
)
from logstore import log, LOG, LOG_FILE
from registry import PORT, PLATFORMS, PLATFORM_IDS, LOCAL_IMPORT_PLATFORMS
from tasks import (
    collect_state, run_tasks, run_job, start_job, JOBS, BLOGINS,
    _invalidate_state, _new_job, _new_blogin, _blogin_progress,
    _has_playwright, _run_blogin,
    CACHE_TTL, _state_cache, _lock, _blank_acct, _safe_read,
)
from account_service import (
    _wb_store_append, _oauth_save, _dumate_web_save, _lingxi_web_save,
    _codearts_identity, _codearts_oauth_save, _trae_oauth_save,
    _officeace_login_save,
)
from webapi import Handler, _allowed_hosts, _check_host_origin

import socketserver
import urllib.request


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _already_running():
    """探测端口上是否已有看板实例在跑。

    必须主动探测：Server.allow_reuse_address=True 在 Windows 下允许多进程
    同时 bind 同一端口（与 Linux 不同），不探测就会出现两个后端并存、
    跨进程刷新竞争的诡异状态。"""
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/ping" % PORT, timeout=1.5) as r:
            data = json.loads(r.read().decode("utf-8") or "{}")
            return bool(data.get("ok")) and int(data.get("port") or 0) == PORT
    except Exception:
        return False


def main():
    os.chdir(HERE)
    url = "http://127.0.0.1:%d" % PORT
    if _already_running():
        print("=" * 62)
        print(" 端口 %d 已有看板后端在运行，不再启动第二个实例。" % PORT)
        print(" 直接打开浏览器即可：%s" % url)
        print("=" * 62)
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass
        return
    print("=" * 62)
    print(" 多平台账号看板后端已启动：%s" % url)
    print(" 平台：%s" % "、".join(PLATFORMS.keys()))
    print(" 数据目录：%s" % data_dir.DATA_DIR)
    if data_dir.MIGRATED:
        print(" 已自动外移：%s" % "、".join(data_dir.MIGRATED))
    print(" 仅监听本机回环，凭据不出本机。关闭此窗口即停止。")
    print("=" * 62)
    for pid, mod in PLATFORMS.items():
        try:
            n = len(mod.load_accounts())
        except Exception:
            n = 0
        print("  · %s：%s 个凭据" % (getattr(mod, "LABEL", pid), n))
    if not PLATFORMS:
        print("⚠ 没有任何平台适配器加载成功，请检查 platforms/ 目录。")
    print("浏览器打开：%s\n" % url)
    try:
        Server(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    except OSError as e:
        print("\n⚠ 端口 %d 绑定失败：%s" % (PORT, e))
        print("  可能是另一进程占用了端口（netstat -ano | findstr :%d 查看 PID）。" % PORT)


if __name__ == "__main__":
    main()
