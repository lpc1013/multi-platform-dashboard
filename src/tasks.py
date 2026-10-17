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
_refreshing = threading.Event()      # 后台刷新去重（stale-while-revalidate）


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


_SNAPSHOT_FILE = "state_snapshot.json"   # data_dir 下的磁盘快照（重启后仍有得显示）


def _load_disk_snapshot():
    try:
        d = json.load(open(data_dir.path(_SNAPSHOT_FILE), encoding="utf-8"))
        if isinstance(d, dict) and d.get("platforms"):
            return d
    except Exception:
        pass
    return None


def _save_disk_snapshot(out):
    try:
        with open(data_dir.path(_SNAPSHOT_FILE), "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False)
    except Exception:
        pass


def _collect_pids(pids):
    """真正执行一轮「读凭据 + 并发读账号」的完整采集，返回 pinfos。"""
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

    got = {}
    if loaded:
        # 纯 I/O 等待型读取，线程开销可忽略：池上限拉到账号数级，
        # 避免「慢账号波次叠队」（25 账号 12 工人时最坏 3 波串行）
        workers = max(4, min(24, len(loaded)))
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_safe_read, mod, nm, ent): (pid, nm)
                    for pid, nm, mod, ent in loaded}
            for fu in cf.as_completed(futs):
                got[futs[fu]] = fu.result()
    for pid, nm, mod, ent in loaded:
        # 保持凭据文件中的顺序，卡片不会每次刷新乱跳
        pinfos[pid]["accounts"].append(got.get((pid, nm)) or _blank_acct(nm, "读取失败"))
    return pinfos


def _finalize(out, pinfos, scope, stamp):
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
                       "（WorkBuddy / MiniMax / DuMate / WPS 灵犀 / Trae / Qoder / ZCode / OfficeACE / CodeArts / TeleAgent）。")
    return out


def _bg_refresh():
    """后台全量刷新（stale-while-revalidate 的 revalidate 半边）。
    完成后更新内存缓存 + 磁盘快照；期间新来的普通请求继续拿旧快照。"""
    try:
        pinfos = _collect_pids(list(PLATFORMS.keys()))
        out = _finalize(None, pinfos, None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        with _lock:
            _state_cache.update(at=time.time(), data=out)
        _save_disk_snapshot(out)
    except Exception as e:
        log("后台刷新状态失败：%s" % str(e)[:120])
    finally:
        _refreshing.clear()


def collect_state(force=False, scope=None):
    """汇总所有平台状态（stale-while-revalidate，2026-10-14）。

    三种路径：
      scope=<pid>  只重读该平台并合并快照（添加/删除/导入账号后用，秒级、必须新值）
      force=True   同步全量重读（手动刷新按钮 / 任务结束后用，行为不变）
      普通请求     缓存命中直接回；缓存过期/为空时——
                   ① 有旧快照（内存过期版或磁盘快照）→ **立即返回旧快照**
                      （打 stale 标记），同时后台线程重读，前端 30s 轮询自动换新；
                   ② 连旧快照都没有（首次启动且从未采集过）→ 同步全量读（仅一次）。

    背景：原先普通请求过期后同步等全平台网络读（最长 25s 超时 × 账号数），
    前端刷新/重启后白屏几秒到十几秒。改为旧值先回、新值后台补，白屏消除。
    """
    now = time.time()
    # 普通请求走缓存；带 scope 的请求本来就是为了拿最新值，直接重读
    if not force and not scope and _state_cache["data"] and now - _state_cache["at"] < CACHE_TTL:
        return _state_cache["data"]
    if scope and not _state_cache["data"]:
        scope = None   # 还没有底稿可合并，退回全量首读

    with _lock:
        pids = [scope] if (scope in PLATFORMS) else list(PLATFORMS.keys())

        # ── stale-while-revalidate：普通请求 + 有旧快照可回 → 先回旧值，后台补新
        if not force and not scope:
            stale = _state_cache["data"] or _load_disk_snapshot()
            if stale is not None:
                if not _refreshing.is_set():
                    _refreshing.set()
                    threading.Thread(target=_bg_refresh, daemon=True,
                                     name="state-swr").start()
                if _state_cache["data"]:
                    out = dict(_state_cache["data"])
                else:
                    out = dict(stale)
                out["stale"] = True          # 前端提示「显示的是上次快照，后台刷新中」
                return out

        # ── 同步路径：force / scope / 磁盘快照也没有的首次启动
        pinfos = _collect_pids(pids)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        out = _finalize(None, pinfos, scope, stamp)
        if not scope:
            _save_disk_snapshot(out)
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
