# -*- coding: utf-8 -*-
"""
tasks.py —— 状态汇总与任务调度（2026-10-13 从 server.py 抽出）
collect_state（并发读所有平台账号 + 60s 缓存 + 单平台 scope 刷新）、
run_tasks / JOBS 异步任务、BLOGINS 浏览器辅助登录任务。
"""
import os
import sys
import json
import time
import itertools
import threading
import importlib
import importlib.util
import concurrent.futures as cf
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import data_dir
import cred_store
from cred_store import save_cred as _save_cred
from logstore import log, LOG
from registry import PLATFORMS

CACHE_TTL = 60
_state_cache = {"at": 0, "data": None}
_lock = threading.Lock()


def _invalidate_state():
    """凭据变更后只把缓存标脏，立刻返回。
    前端在拿到响应后会自己再发一次 /api/state，无需在这里同步重读全部平台——
    否则「添加账号 / 从本地客户端导入」按钮要等十几秒才有反应（看起来像点了没反应）。"""
    _state_cache.update(at=0, data=None)


# ────────────────────────── 状态读取 ──────────────────────────
def _blank_acct(name, err):
    """读取失败时的占位账号，保证前端卡片结构完整（不会因为一条网络异常整片空白）。"""
    return {"name": name, "ok": False, "error": err,
            "credits": {"remain": 0}, "packages": [], "signed_today": False}


def _safe_read(mod, name, ent):
    try:
        return mod.read_account(name, ent)
    except Exception as e:
        return _blank_acct(name, str(e)[:80])


def collect_state(force=False, scope=None):
    """汇总所有平台状态。

    force=True 忽略缓存重读；scope=<pid> 时只重读该平台并合并进上一份快照
    （用于「添加 / 删除 / 导入账号后只刷新受影响的那一个平台」，秒级返回）。
    账号读取全部并发——原实现是「逐平台逐账号顺序读 + 每条 sleep(0.3)」，
    15 个账号要 10~30 秒，导致点完按钮半分钟没反应，看起来像没生效。
    """
    now = time.time()
    # 普通请求走缓存；带 scope 的请求本来就是为了拿最新值，直接重读
    if not force and not scope and _state_cache["data"] and now - _state_cache["at"] < CACHE_TTL:
        return _state_cache["data"]
    if scope and not _state_cache["data"]:
        scope = None   # 还没有底稿可合并，退回全量首读

    with _lock:
        pids = [scope] if (scope in PLATFORMS) else list(PLATFORMS.keys())

        # 1) 先同步读各平台凭据（本地文件/解密，开销极小）并搭好骨架
        pinfos, loaded = {}, []
        for pid in pids:
            mod = PLATFORMS[pid]
            try:
                accs = mod.load_accounts()
            except Exception as e:
                accs = {}
                log("%s 凭据加载失败：%s" % (pid, e))
            has = bool(accs)
            pinfos[pid] = {"id": pid, "label": getattr(mod, "LABEL", pid),
                           "tasks": getattr(mod, "TASKS", []),
                           "has_credentials": has, "accounts": []}
            for nm, ent in accs.items():
                loaded.append((pid, nm, mod, ent))

        # 2) 所有账号的网络读取并发执行（这是唯一的耗时段）
        got = {}
        if loaded:
            workers = max(4, min(12, len(loaded)))
            with cf.ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(_safe_read, mod, nm, ent): (pid, nm)
                        for pid, nm, mod, ent in loaded}
                for fu in cf.as_completed(futs):
                    got[futs[fu]] = fu.result()
        for pid, nm, mod, ent in loaded:
            # 保持凭据文件中的顺序，卡片不会每次刷新乱跳
            pinfos[pid]["accounts"].append(got.get((pid, nm)) or _blank_acct(nm, "读取失败"))

        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if scope and _state_cache["data"]:
            out = json.loads(json.dumps(_state_cache["data"]))   # 深拷贝，避免污染旧快照
            out["platforms"].update(pinfos)
            out["generated_at"] = stamp
            out["log"] = LOG[-40:]
        else:
            out = {"generated_at": stamp, "platforms": pinfos, "log": LOG[-40:]}

        any_cred = any(p.get("has_credentials") for p in out["platforms"].values())
        out["demo"] = not any_cred
        out["backend"] = True   # 本条响应来自真实后端；与「有无凭据」相互独立
        out["data_dir"] = data_dir.DATA_DIR   # 凭据/数据存放目录（外移后可见可核对）
        if any_cred:
            out.pop("hint", None)
        else:
            out["hint"] = ("未检测到任何平台凭据。最省事的办法：点右上角「添加账号」→"
                           "「从本地客户端导入」，会自动读取你已登录的桌面端登录态"
                           "（WorkBuddy / MiniMax / DuMate / WPS 灵犀 / Trae / Qoder / ZCode / OfficeACE / CodeArts）。")
        _state_cache.update(at=now, data=out)
        return out


# ────────────────────────── 任务执行 ──────────────────────────
def run_tasks(platform, names=None, tasks=("checkin",), chat_text=None, job=None):
    mod = PLATFORMS.get(platform)
    if not mod:
        return {"ok": False, "error": "未知平台 %s" % platform, "results": []}

    def tick(label):
        if job is not None:
            job["current_name"] = name
            job["current_task"] = label

    accs = mod.load_accounts()
    if not accs:
        return {"ok": False, "error": "未找到 %s 凭据" % platform, "results": []}

    targets = [n for n in (names or []) if n in accs] if names else list(accs.keys())
    results = []
    for name in targets:
        ent = accs[name]
        item = {"name": name, "ok": True, "steps": []}
        for tk in tasks:
            tick(mod.TASKS and tk)
            try:
                r = mod.run_task(name, ent, tk)
            except Exception as e:
                r = {"ok": False, "msg": str(e)[:80]}
            st = {"task": tk, "ok": bool(r.get("ok")),
                  "msg": r.get("msg") or ("完成" if r.get("ok") else "失败")}
            item["steps"].append(st)
            log("%s[%s] %s → %s" % (platform, name, tk, st["msg"]))
            if job is not None:
                job["steps"].append(dict(st, name=name))
                job["done"] = job.get("done", 0) + 1
            time.sleep(0.4)
        item["ok"] = all(st.get("ok") for st in item["steps"]) if item["steps"] else False
        results.append(item)
        time.sleep(0.5)

    collect_state(force=True)
    return {"ok": True, "results": results, "state": collect_state(force=False)}


JOBS = {}
_job_seq = itertools.count(1)
_job_lock = threading.Lock()


def _new_job(total, platform, targets):
    with _job_lock:
        jid = str(next(_job_seq))
        JOBS[jid] = {"total": total, "done": 0, "platform": platform, "targets": targets,
                     "current_name": targets[0] if targets else "", "current_task": "准备中",
                     "steps": [], "results": [], "finished": False, "error": None, "started": time.time()}
        return jid


def run_job(jid, platform, names, tasks, chat_text):
    job = JOBS.get(jid)
    if not job:
        return
    try:
        res = run_tasks(platform, names, tasks, chat_text, job=job)
        job["results"] = res.get("results", [])
        job["state"] = res.get("state")
        job["error"] = res.get("error")
    except Exception as e:
        job["error"] = str(e)[:200]
        log("任务异常：%s" % str(e)[:120])
    finally:
        job["finished"] = True
        job["current_task"] = "已完成"
        with _job_lock:
            for k in [k for k, v in JOBS.items()
                      if v.get("finished") and time.time() - v.get("started", 0) > 180]:
                JOBS.pop(k, None)


def start_job(platform, names, tasks, chat_text):
    mod = PLATFORMS.get(platform)
    if not mod:
        return None, 0, 0
    accs = mod.load_accounts()
    if not accs:
        return None, 0, 0
    targets = [n for n in (names or []) if n in accs] if names else list(accs.keys())
    if not targets:
        return None, 0, 0
    valid_tasks = [t["key"] for t in mod.TASKS]
    tasks = [t for t in (tasks or []) if t in valid_tasks]
    if not tasks:
        return None, 0, 0
    jid = _new_job(len(targets) * len(tasks), platform, targets)
    threading.Thread(target=run_job, args=(jid, platform, names, tasks, chat_text), daemon=True).start()
    return jid, len(targets), len(targets) * len(tasks)


# ────────────────────────── 浏览器辅助登录（DuMate / MiniMax） ──────────────────────────
BLOGINS = {}
_blogin_seq = itertools.count(1)
_blogin_lock = threading.Lock()


def _new_blogin(platform, name):
    with _blogin_lock:
        jid = "bl" + str(next(_blogin_seq))
        BLOGINS[jid] = {"platform": platform, "name": name, "status": "starting",
                        "text": "准备中…", "ok": None, "result": None,
                        "finished": False, "started": time.time()}
        return jid


def _blogin_progress(jid, status, text):
    job = BLOGINS.get(jid)
    if job:
        job["status"] = status
        job["text"] = text


def _has_playwright():
    """浏览器登录依赖 playwright 是否可用（仅影响该功能，不影响其余看板功能）。"""
    try:
        return importlib.util.find_spec("playwright") is not None
    except Exception:
        return False


def _run_blogin(jid, platform, name):
    import browser_login as blmod
    job = BLOGINS.get(jid)
    if not job:
        return
    cb = lambda s, t: _blogin_progress(jid, s, t)
    try:
        ok, msg, cred = blmod.browser_login(platform, cb)
        if ok and cred:
            # 浏览器登录目前只服务 lingxi（抓 wps_sid）；与「粘贴添加」同一套落盘规则
            if platform == "lingxi":
                rec = {"wps_sid": cred, "via_browser": True}
            else:
                rec = {"access_token": cred, "via_browser": True}
            use = _save_cred(platform, rec, name)
            job["name"] = use
            _invalidate_state()
            job["ok"], job["result"] = True, "%s（已保存 %s）" % (msg, use)
        else:
            job["ok"], job["result"] = False, msg
    except Exception as e:
        job["ok"], job["result"] = False, "异常：" + str(e)[:160]
    finally:
        job["finished"] = True
        with _blogin_lock:
            for k, v in list(BLOGINS.items()):
                if v.get("finished") and time.time() - v.get("started", 0) > 600:
                    BLOGINS.pop(k, None)
