# -*- coding: utf-8 -*-
"""
token_panel.py —— Token 消耗面板的 Python 桥接层

复用 wb-usage-tracker 的 Node 采集内核（lib/gen.js）+ 官方渲染模板（assets/template.html），
由本 Python 看板统一对外提供：

    GET /tokens         → 注入数据后的完整看板页（官方渲染器，两栏自带导航与过滤器）
    GET /api/tokens     → 三源采集的 DATA JSON

设计要点：
    - 采集内核较重（首扫 12–15s、934 个 jsonl 流式解析），故结果做 TTL 缓存，并由后台线程周期刷新；
    - 对外只给已脱敏的展示名（脱敏自检 assertNoLeak 在 Node 侧执行，凭证不跨进程暴露）；
    - 路径可配：环境变量 WB_USAGE_DIR 指向 wb-usage-tracker/dashboard，默认 E:/AI/AInews/wb-usage-tracker/dashboard；
    - node 可执行文件可配：环境变量 NODE_EXE，否则自动探测。

安全：本模块只读数据源、不写回；凭证库仅在 Node 侧内存解锁，Python 侧只拿到脱敏后的 DATA。
"""
import os
import sys
import json
import time
import glob
import shutil
import sqlite3
import hashlib
import tempfile
import threading
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))

DEFAULT_DIR = "E:/AI/AInews/wb-usage-tracker/dashboard"
WB_USAGE_DIR = os.environ.get("WB_USAGE_DIR", DEFAULT_DIR).replace("\\", "/")
DUMP_JS = os.path.join(HERE, "token_dump.js")
# 模板解析顺序：环境变量显式指定 > 仓库内副本（src/assets/template.html，规范源）> 旧版外部路径。
# 仓库内副本保证克隆即自包含；对看板改样式请改仓库副本，勿再改外部 wb-usage-tracker 的（已停更）。
_TEMPLATE_REPO = os.path.join(HERE, "assets", "template.html")
_TEMPLATE_EXT = os.path.join(WB_USAGE_DIR, "assets", "template.html")
TEMPLATE = _TEMPLATE_REPO if os.path.isfile(_TEMPLATE_REPO) else _TEMPLATE_EXT

TTL = 60  # 缓存刷新周期（秒）
SCAN_TIMEOUT = 150  # 单次采集超时（秒，含首扫）
NODE_CANDIDATES = [
    os.environ.get("NODE_EXE", ""),
    "node",
    "C:/Users/Pengcheng_Li/.workbuddy-ai/binaries/node/versions/22.22.2-6/node.exe",
    "E:/clx/node.exe",
]

_cache = {"data": None, "ts": 0.0, "err": None, "scanning": False}
_lock = threading.Lock()
_started = {"ok": False}


def _find_node():
    for c in NODE_CANDIDATES:
        if not c:
            continue
        if os.path.isfile(c):
            return c
        if shutil.which(c):
            return c
    return None


NODE = _find_node()


def _run_dump():
    if not NODE:
        raise RuntimeError("未找到 node 可执行文件，无法运行 Token 采集内核（可设环境变量 NODE_EXE）")
    if not os.path.isfile(DUMP_JS):
        raise RuntimeError("缺少 token_dump.js：" + DUMP_JS)
    if not os.path.isfile(TEMPLATE):
        raise RuntimeError("未找到官方渲染模板：" + TEMPLATE)
    env = dict(os.environ)
    env["WB_USAGE_DIR"] = WB_USAGE_DIR
    try:
        out = subprocess.run(
            [NODE, DUMP_JS, WB_USAGE_DIR],
            # Node 永远以 UTF-8 写 stdout：必须显式声明，否则中文 Windows 会按 GBK
            # 解码，触发 subprocess _readerthread 的 UnicodeDecodeError 或截断 JSON。
            capture_output=True, encoding="utf-8", errors="replace",
            timeout=SCAN_TIMEOUT, env=env,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Token 采集超时（>%ss）" % SCAN_TIMEOUT)
    if out.returncode != 0:
        raise RuntimeError("采集内核返回错误(%d)：%s" % (
            out.returncode, (out.stderr or out.stdout or "").strip()[:400]))
    return json.loads(out.stdout)


# ── Qoder 用量合并 ───────────────────────────────────────────────────────
# 数据源（GitHub 经验，ChanningYuan/usageBar 与 TokenTracker 同口径）：
#   Qoder IDE → %APPDATA%\Qoder(CN)\SharedClientCache\cache\db\local.db
#               chat_message.token_info = {prompt_tokens, completion_tokens,
#                                          cached_tokens, max_input_tokens}
#   Qoder CLI → ~/.qoder-cn/projects/**/*.jsonl（但该 transcript 的 tokens 恒为 0，
#               只有 credits，故 token 统计以 SQLite 为准；credits 不混入本表）
# 采集内核（wb-usage-tracker）只认 WorkBuddy / Codex，Qoder 在 Python 侧合并。
_QODER_DB_GLOBS = [
    os.path.join(os.environ.get("APPDATA", ""), "QoderCN",
                 "SharedClientCache", "cache", "db", "local.db"),
    os.path.join(os.environ.get("APPDATA", ""), "Qoder",
                 "SharedClientCache", "cache", "db", "local.db"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Qoder CN",
                 "SharedClientCache", "cache", "db", "local.db"),
]


def _qoder_rows():
    """读所有 Qoder 本地库的 chat_message，返回 [{sid,title,proj,model,ts,it,ot,ch}]。
    库可能被运行中的 Qoder 独占 → 先复制到临时目录再只读打开。"""
    rows, seen_msg = [], set()
    for db in _QODER_DB_GLOBS:
        if not db or not os.path.isfile(db):
            continue
        tmp = os.path.join(tempfile.gettempdir(), "_qoder_%s.db" % abs(hash(db)))
        try:
            shutil.copy2(db, tmp)
        except Exception:
            continue
        try:
            con = sqlite3.connect(tmp)
            cur = con.cursor()
            cur.execute("""
                SELECT m.id, m.session_id, m.model_info, m.token_info, m.gmt_create,
                       s.session_title, s.project_name
                  FROM chat_message m
                  LEFT JOIN chat_session s ON s.session_id = m.session_id
                 WHERE m.token_info IS NOT NULL AND m.token_info != ''
            """)
            for mid, sid, mi, ti, ts, title, proj in cur.fetchall():
                if mid in seen_msg:
                    continue
                try:
                    t = json.loads(ti or "{}")
                    it = int(t.get("prompt_tokens") or 0)
                    ot = int(t.get("completion_tokens") or 0)
                    ch = int(t.get("cached_tokens") or 0)
                except Exception:
                    continue
                if it <= 0 and ot <= 0:
                    continue
                try:
                    mk = (json.loads(mi or "{}") or {}).get("model_key") or "qoder"
                except Exception:
                    mk = "qoder"
                seen_msg.add(mid)
                rows.append({"sid": sid, "title": title or "", "proj": proj or "",
                             "model": str(mk), "ts": int(ts or 0),
                             "it": it, "ot": ot, "ch": ch})
            con.close()
        except Exception:
            continue
    return rows


def _merge_qoder(data):
    """把 Qoder 会话并入 DATA（与内核同构：sess/models/ws/accts/_daily/_stat）。"""
    if not isinstance(data, dict):
        return data
    try:
        rows = _qoder_rows()
    except Exception:
        return data
    if not rows:
        return data

    ws = data.setdefault("ws", [])
    models = data.setdefault("models", [])
    sess = data.setdefault("sess", [])
    accts = data.setdefault("accts", [])
    daily = data.setdefault("_daily", [])

    # 账号：Qoder 单独一栏（脱敏，只写产品名）
    if "Qoder" not in accts:
        accts.append("Qoder")
    aidx = accts.index("Qoder")

    def model_idx(name):
        key = "Qoder·" + name
        if key not in models:
            models.append(key)
        return models.index(key)

    def ws_idx(name):
        key = "Qoder · " + (name or "会话")
        if key not in ws:
            ws.append(key)
        return ws.index(key)

    by_sid = {}
    for r in rows:
        by_sid.setdefault(r["sid"], []).append(r)

    daily_map = {d.get("m"): d for d in daily if isinstance(d, dict)}
    n_req = 0
    for sid, rs in by_sid.items():
        recs = []
        for r in rs:
            minute = int(r["ts"] / 60000)
            recs.append([minute, model_idx(r["model"]),
                         r["it"] + r["ot"], r["it"], r["ot"], r["ch"], 0, None])
        if not recs:
            continue
        recs.sort(key=lambda x: x[0])
        n_req += len(recs)
        sess.append({
            "w": ws_idx(rs[0]["proj"] or rs[0]["title"]),
            "id": "qoder" + hashlib.md5(str(sid).encode("utf-8")).hexdigest()[:6],
            "t": (rs[0]["title"] or "(无标题会话)")[:42],
            "st": recs[0][0], "r": recs, "by": 0, "tk": {}, "a": aidx,
        })
        seen_days = set()
        for rec in recs:
            t = time.localtime(rec[0] * 60)
            dk = time.strftime("%Y-%m-%d", t)
            mid = int(time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1)) * 1000)
            d = daily_map.get(mid)
            if d is None:
                d = {"m": mid, "ocred": 0, "tot": 0, "turns": 0, "nsess": 0}
                daily_map[mid] = d
                daily.append(d)
            d["tot"] += rec[2]
            d["turns"] += 1
            seen_days.add(mid)
        for mid in seen_days:
            daily_map[mid]["nsess"] += 1

    sess.sort(key=lambda s: s.get("st") or 0)
    daily.sort(key=lambda d: d.get("m") or 0)

    st = data.setdefault("_stat", {})
    st["sessions"] = st.get("sessions", 0) + len(by_sid)
    st["requests"] = st.get("requests", 0) + n_req
    st["qoderRequests"] = n_req
    sysname = str(data.get("_sys") or "")
    if "Qoder" not in sysname:
        data["_sys"] = (sysname + " + Qoder") if sysname else "Qoder"
    return data


def collect(force=False):
    """取数据：优先返回新鲜缓存；过期/强制则重新扫描（与后台线程去重）。"""
    now = time.time()
    do_scan = False
    with _lock:
        fresh = (_cache["data"] is not None
                 and (now - _cache["ts"]) < TTL
                 and not force)
        if fresh:
            return _cache["data"]
        if _cache["scanning"]:
            do_scan = False  # 交给在跑的扫描
        else:
            _cache["scanning"] = True
            do_scan = True

    if do_scan:
        try:
            data = _merge_qoder(_run_dump())
        except Exception as e:
            with _lock:
                _cache["err"] = str(e)
                _cache["scanning"] = False
            return _cache["data"]
        with _lock:
            _cache["data"] = data
            _cache["ts"] = time.time()
            _cache["err"] = None
            _cache["scanning"] = False
        return data

    # 等待在跑的扫描完成（最多 SCAN_TIMEOUT）
    deadline = time.time() + SCAN_TIMEOUT
    while time.time() < deadline:
        with _lock:
            if _cache["data"] is not None:
                return _cache["data"]
            if not _cache["scanning"]:
                break
        time.sleep(0.5)
    with _lock:
        return _cache["data"]


def render_html():
    data = collect()
    if data is None:
        data = {"_notice": (_cache.get("err") or "Token 采集尚未就绪，请稍候重试")}
    html = open(TEMPLATE, "r", encoding="utf-8").read()
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    if "/*__WBD_DATA__*/null" in html:
        html = html.replace("/*__WBD_DATA__*/null", payload)
    elif "/*__WBD_DATA__*/" in html:
        html = html.replace("/*__WBD_DATA__*/", payload)
    else:
        raise RuntimeError("模板缺少数据注入点（请先运行 build_template.js）")
    return html.encode("utf-8")


def _background_refresh():
    while True:
        try:
            collect()
        except Exception:
            pass
        time.sleep(TTL)


def ensure_started():
    """启动后台刷新线程（幂等）。线程首轮即预热缓存，之后每 TTL 秒刷新一次。"""
    if _started["ok"]:
        return
    t = threading.Thread(target=_background_refresh, daemon=True)
    t.start()
    _started["ok"] = True
