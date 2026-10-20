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
import datetime

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
#   Qoder CN 新版客户端/CLI → ~/.qoder-cn/projects/**/*.jsonl
#               新版把 token 字段恒写 0，但每条 assistant 请求带
#               usage.{credits, context_usage_ratio, request_id}；压缩事件带
#               compactMetadata.preTokens。用 preTokens/ratio 校准上下文窗口
#               （200k/400k/1M），再用 ratio×窗口 估算输入 token；输出按回复
#               文本长度估算。积分/请求数/时间戳为日志原文，不做估算。
# 采集内核（wb-usage-tracker）只认 WorkBuddy / Codex，Qoder 在 Python 侧合并。
_QODER_DB_GLOBS = [
    os.path.join(os.environ.get("APPDATA", ""), "QoderCN",
                 "SharedClientCache", "cache", "db", "local.db"),
    os.path.join(os.environ.get("APPDATA", ""), "Qoder",
                 "SharedClientCache", "cache", "db", "local.db"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Qoder CN",
                 "SharedClientCache", "cache", "db", "local.db"),
]
_QODER_TRANSCRIPT_DIRS = [
    os.path.join(os.path.expanduser("~"), ".qoder-cn", "projects"),
    os.path.join(os.path.expanduser("~"), ".qoder", "projects"),
]
_QODER_WINDOW_DEFAULT = 200000
_QODER_PLATFORM_ORDER = ("WorkBuddy 国内版", "WorkBuddy 国际版", "Qoder", "Codex", "未归属")

# 旧库 398MB、日志 120 个文件：按 mtime/size 缓存，后台每分钟刷新时不重复解析。
_qoder_db_cache = {"sig": None, "rows": []}
_qoder_file_cache = {}

_QODER_SQL = """
    SELECT m.id, m.session_id, m.model_info, m.token_info, m.gmt_create,
           s.session_title, s.project_name
      FROM chat_message m
      LEFT JOIN chat_session s ON s.session_id = m.session_id
     WHERE m.token_info IS NOT NULL AND m.token_info != ''
"""
_QODER_SQL_PLAIN = """
    SELECT m.id, m.session_id, m.model_info, m.token_info, m.gmt_create,
           NULL, NULL
      FROM chat_message m
     WHERE m.token_info IS NOT NULL AND m.token_info != ''
"""


def _qoder_norm_ms(value):
    """时间戳统一成毫秒（旧库 gmt_create 是毫秒，个别版本可能是秒）。"""
    try:
        ts = int(float(value or 0))
    except Exception:
        return 0
    if ts <= 0:
        return 0
    return ts * 1000 if ts < 100000000000 else ts


def _qoder_iso_ms(value):
    if not isinstance(value, str):
        return _qoder_norm_ms(value)
    s = value.strip()
    if not s:
        return 0
    try:
        return int(datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:
        return 0


def _qoder_db_sig():
    sig = []
    for db in _QODER_DB_GLOBS:
        if not db or not os.path.isfile(db):
            continue
        item = [db]
        for suf in ("", "-wal", "-shm"):
            try:
                st = os.stat(db + suf)
                item.extend((st.st_mtime_ns, st.st_size))
            except OSError:
                item.extend((0, 0))
        sig.append(tuple(item))
    return tuple(sig)


def _qoder_db_rows():
    """读所有 Qoder 旧版 IDE 库的 chat_message（真实 token），按库文件签名缓存。
    库可能被运行中的 Qoder 独占 → 主库连同 -wal/-shm 一起复制到临时目录再只读打开。"""
    sig = _qoder_db_sig()
    if sig == _qoder_db_cache["sig"]:
        return _qoder_db_cache["rows"]
    rows, seen_msg = [], set()
    for db in _QODER_DB_GLOBS:
        if not db or not os.path.isfile(db):
            continue
        key = hashlib.md5(db.lower().encode("utf-8")).hexdigest()[:8]
        tmp = os.path.join(tempfile.gettempdir(), "_qoder_%s.db" % key)
        for suf in ("", "-wal", "-shm"):
            src, dst = db + suf, tmp + suf
            try:
                if os.path.isfile(src):
                    shutil.copy2(src, dst)
                elif os.path.isfile(dst):
                    os.remove(dst)
            except Exception:
                pass
        con = None
        try:
            con = sqlite3.connect(tmp)
            try:
                data = con.execute(_QODER_SQL).fetchall()
            except sqlite3.OperationalError:
                # 老版 Qoder CN 没有 chat_session 表
                data = con.execute(_QODER_SQL_PLAIN).fetchall()
        except Exception:
            data = []
        finally:
            if con is not None:
                try:
                    con.close()
                except Exception:
                    pass
        for mid, sid, mi, ti, ts, title, proj in data:
            if mid in seen_msg:
                continue
            try:
                t = json.loads(ti or "{}")
                it = int(t.get("prompt_tokens") or 0)
                ot = int(t.get("completion_tokens") or 0)
                ch = int(t.get("cached_tokens") or 0)
                max_in = int(t.get("max_input_tokens") or 0)
            except Exception:
                continue
            if it <= 0 and ot <= 0:
                continue
            try:
                mk = (json.loads(mi or "{}") or {}).get("model_key") or "qoder"
            except Exception:
                mk = "qoder"
            seen_msg.add(mid)
            rows.append({
                "sid": str(sid or ("db:" + str(mid))),
                "title": str(title or "").strip(), "trank": 1 if title else 0,
                "proj": str(proj or "").strip(),
                "model": str(mk), "ts": _qoder_norm_ms(ts),
                "it": it, "ot": ot, "ch": max(0, min(ch, it)), "cr": None,
                "rid": "db:" + str(mid), "est": False, "win": max_in,
            })
    _qoder_db_cache["sig"] = sig
    _qoder_db_cache["rows"] = rows
    return rows


def _qoder_msg_chars(message):
    """估算一条 assistant 消息的输出体量：ASCII≈4 字符/token，非 ASCII≈1.5 字符/token。"""
    content = message.get("content")
    if isinstance(content, str):
        parts = [content]
    elif isinstance(content, list):
        parts = []
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("text"):
                parts.append(block["text"])
            if block.get("thinking"):
                parts.append(block["thinking"])
            if block.get("input") is not None:
                parts.append(json.dumps(block["input"], ensure_ascii=False))
    else:
        parts = []
    ascii_n = other_n = 0
    for part in parts:
        for ch in part:
            if ord(ch) < 128:
                ascii_n += 1
            else:
                other_n += 1
    return ascii_n, other_n


def _qoder_prompt_text(content):
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
            return ""
        return "".join(b.get("text") or "" for b in content
                       if isinstance(b, dict) and b.get("type") == "text").strip()
    return ""


def _qoder_short(text, n=42):
    return " ".join(str(text or "").split())[:n]


def _qoder_proj(cwd):
    s = str(cwd or "").replace("\\", "/").rstrip("/")
    return s.rsplit("/", 1)[-1].strip() if s else ""


def _qoder_window(cands):
    """压缩点 preTokens / 压缩前 context_usage_ratio = 上下文窗口。
    实测聚成 200k / 400k / 1M 三档，取中位数后吸附到最近的档位。"""
    vals = sorted(v for v in cands if 80000 <= v <= 2000000)
    if not vals:
        return _QODER_WINDOW_DEFAULT, 0
    med = vals[len(vals) // 2] if len(vals) % 2 else (vals[len(vals) // 2 - 1] + vals[len(vals) // 2]) / 2.0
    if med <= 300000:
        return 200000, len(vals)
    if med <= 550000:
        return 400000, len(vals)
    return 1000000, len(vals)


def _parse_qoder_transcript(path):
    """解析一个 Qoder CN jsonl：返回 (rows, info)。rows 已按文件校准窗口估算 token。"""
    stem = os.path.splitext(os.path.basename(path))[0]
    title, trank, cwd, human = "", 0, "", ""
    last_ratio = None
    cands = []
    msg_chars = {}
    reqs = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict):
                    continue
                typ = rec.get("type")
                if typ == "system" and rec.get("subtype") == "compact_boundary":
                    cm = rec.get("compactMetadata") or {}
                    pre = cm.get("preTokens")
                    if pre and last_ratio and last_ratio > 0.03:
                        cands.append(float(pre) / last_ratio)
                    continue
                if typ == "custom-title" and rec.get("customTitle"):
                    title, trank = str(rec["customTitle"]).strip(), 2
                    continue
                if not cwd and rec.get("cwd"):
                    cwd = str(rec["cwd"])
                if typ == "user":
                    if not human:
                        txt = _qoder_prompt_text((rec.get("message") or {}).get("content"))
                        if txt and not txt.startswith("This session is being continued"):
                            human = txt
                    continue
                if typ != "assistant":
                    continue
                msg = rec.get("message")
                if not isinstance(msg, dict):
                    continue
                mid = msg.get("id") or rec.get("uuid") or ("%s:%d" % (path, len(msg_chars)))
                acc = msg_chars.get(mid)
                if acc is None:
                    acc = [0, 0]
                    msg_chars[mid] = acc
                a_n, o_n = _qoder_msg_chars(msg)
                acc[0] += a_n
                acc[1] += o_n
                usage = msg.get("usage")
                if not isinstance(usage, dict):
                    continue
                model = str(msg.get("model") or "")
                if model == "<synthetic>":
                    continue
                ratio = usage.get("context_usage_ratio")
                if isinstance(ratio, (int, float)) and ratio > 0:
                    last_ratio = float(ratio)
                rid = usage.get("request_id") or mid
                real_it = int(usage.get("input_tokens") or 0) + int(usage.get("cache_creation_input_tokens") or 0)
                real_ch = int(usage.get("cache_read_input_tokens") or 0)
                real_ot = int(usage.get("output_tokens") or 0)
                try:
                    credits = float(usage.get("credits"))
                except (TypeError, ValueError):
                    credits = None
                reqs[rid] = {
                    "sid": str(rec.get("sessionId") or rec.get("session_id") or stem),
                    "ts": _qoder_iso_ms(rec.get("timestamp")),
                    "model": model or "qoder",
                    "ratio": float(ratio) if isinstance(ratio, (int, float)) else 0.0,
                    "real_it": real_it, "real_ch": real_ch, "real_ot": real_ot,
                    "chars": (acc[0], acc[1]), "cr": credits, "rid": str(rid),
                }
    except Exception:
        return [], {"window": 0, "calibration": 0}

    win, ncal = _qoder_window(cands)
    proj = _qoder_proj(cwd)
    if not title:
        title = _qoder_short(human) if human else ""
        trank = 1 if title else 0
    rows = []
    for u in reqs.values():
        a_n, o_n = u["chars"]
        if u["real_it"] > 0 or u["real_ot"] > 0:
            it, ot = u["real_it"], u["real_ot"]
            ch = max(0, min(u["real_ch"], it))
            est = False
        else:
            it = int(round(u["ratio"] * win))
            ot = int(round(a_n / 4.0 + o_n / 1.5)) + 8
            ch = 0
            est = (it > 0 or ot > 0)
        if it <= 0 and ot <= 0:
            continue
        rows.append({
            "sid": u["sid"], "title": title, "trank": trank, "proj": proj,
            "model": u["model"], "ts": u["ts"], "it": it, "ot": ot, "ch": ch,
            "cr": u["cr"], "rid": u["rid"], "est": est, "win": win,
        })
    return rows, {"window": win, "calibration": ncal}


def _qoder_transcript_rows():
    files = []
    for root in _QODER_TRANSCRIPT_DIRS:
        if os.path.isdir(root):
            files.extend(glob.glob(os.path.join(root, "**", "*.jsonl"), recursive=True))
    files = sorted(set(files))
    rows, seen_req = [], set()
    meta = {"files": 0, "estReq": 0, "exactReq": 0, "credits": 0.0,
            "windows": {}, "filesByWindow": {}}
    live = set(files)
    for path in files:
        try:
            st = os.stat(path)
        except OSError:
            continue
        sig = (st.st_mtime_ns, st.st_size)
        ent = _qoder_file_cache.get(path)
        if not ent or ent[0] != sig:
            ent = (sig,) + _parse_qoder_transcript(path)
            _qoder_file_cache[path] = ent
        parsed, info = ent[1], ent[2]
        meta["files"] += 1
        wk = str(info.get("window") or 0)
        meta["filesByWindow"][wk] = meta["filesByWindow"].get(wk, 0) + 1
        for r in parsed:
            rid = r.get("rid")
            if rid:
                if rid in seen_req:
                    continue
                seen_req.add(rid)
            rows.append(r)
            if r.get("cr") is not None:
                meta["credits"] += r["cr"]
            meta["estReq" if r.get("est") else "exactReq"] += 1
            rk = str(r.get("win") or 0)
            meta["windows"][rk] = meta["windows"].get(rk, 0) + 1
    for path in list(_qoder_file_cache):
        if path not in live:
            _qoder_file_cache.pop(path, None)
    return rows, meta


def _qoder_gate_enabled():
    """新版客户端是否已打开 token 落盘开关（写用户环境变量，需重启 Qoder 生效）。"""
    if os.environ.get("QODERCN_EXPOSE_TOKEN_USAGE") == "1":
        return True
    if os.environ.get("QODER_EXPOSE_TOKEN_USAGE") == "1":
        return True
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            for name in ("QODERCN_EXPOSE_TOKEN_USAGE", "QODER_EXPOSE_TOKEN_USAGE"):
                try:
                    val, _ = winreg.QueryValueEx(key, name)
                    if str(val).strip().lower() in ("1", "true"):
                        return True
                except OSError:
                    pass
    except Exception:
        pass
    return False


def _qoder_rows_all():
    try:
        exact = _qoder_db_rows()
    except Exception:
        exact = []
    try:
        est, meta = _qoder_transcript_rows()
    except Exception:
        est, meta = [], {"files": 0, "estReq": 0, "exactReq": 0, "credits": 0.0,
                         "windows": {}, "filesByWindow": {}}
    meta["exactReq"] = meta.get("exactReq", 0) + len(exact)
    return exact + est, meta


def _stamp_platforms(data):
    """给每个会话标注平台（平台是会话属性：同一账号可能横跨国内/国际版），
    并为账号生成主平台回退值。Codex 的 workspace 不带国际标记，按账号名判定。"""
    accts = data.get("accts") or []
    wss = data.get("ws") or []
    sess = data.get("sess") or []
    for s in sess:
        if s.get("p"):
            continue
        a = s.get("a", -1)
        name = str(accts[a]) if isinstance(a, int) and 0 <= a < len(accts) else ""
        if name == "Qoder":
            p = "Qoder"
        elif "Codex" in name:
            p = "Codex"
        else:
            w = s.get("w")
            wn = str(wss[w]) if isinstance(w, int) and 0 <= w < len(wss) else ""
            p = "WorkBuddy 国际版" if "★国际" in wn else ("未归属" if a < 0 else "WorkBuddy 国内版")
        s["p"] = p
    present = set(s.get("p") for s in sess)
    platforms = [p for p in _QODER_PLATFORM_ORDER
                 if p in present or p in ("WorkBuddy 国内版", "WorkBuddy 国际版", "Qoder")]
    for p in sorted(present):
        if p and p not in platforms:
            platforms.append(p)
    data["_platforms"] = platforms

    counts = {}
    for s in sess:
        a = s.get("a", -1)
        if not isinstance(a, int) or a < 0:
            continue
        bucket = counts.setdefault(a, {})
        bucket[s["p"]] = bucket.get(s["p"], 0) + 1
    acct_plat = []
    for i, name in enumerate(accts):
        c = counts.get(i) or {}
        if c:
            best = sorted(c.items(), key=lambda kv: (-kv[1], 0 if kv[0] == "WorkBuddy 国际版" else 1))[0][0]
            acct_plat.append(best)
        else:
            nm = str(name)
            acct_plat.append("Codex" if "Codex" in nm else ("Qoder" if nm == "Qoder" else "WorkBuddy 国内版"))
    data["acctPlatform"] = acct_plat


def _merge_qoder(data):
    """把 Qoder 会话并入 DATA（与内核同构：sess/models/ws/accts/_daily/_stat）。"""
    if not isinstance(data, dict):
        return data
    rows, qmeta = _qoder_rows_all()

    if rows:
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
                             r["it"] + r["ot"], r["it"], r["ot"],
                             max(0, min(r["ch"], r["it"])), 0, r.get("cr")])
            if not recs:
                continue
            recs.sort(key=lambda x: x[0])
            n_req += len(recs)
            best = max(rs, key=lambda r: (r.get("trank") or 0, len(r.get("title") or "")))
            title = (best.get("title") or "").strip()
            proj = next((r.get("proj") for r in rs if r.get("proj")), "")
            # AI 耗时：请求间隔 ≤5 分钟合并（与内核同口径）
            times = sorted(set(int(r["ts"] / 1000) for r in rs if r.get("ts")))
            busy = sum(b - a for a, b in zip(times, times[1:]) if 0 < b - a <= 300)
            sess.append({
                "w": ws_idx(proj or title),
                "id": "qoder" + hashlib.md5(str(sid).encode("utf-8")).hexdigest()[:6],
                "t": (title or proj or "(无标题会话)")[:42],
                "st": recs[0][0], "r": recs, "by": busy, "tk": {}, "a": aidx,
                "p": "Qoder",
            })
            seen_days = set()
            for rec in recs:
                t = time.localtime(rec[0] * 60)
                mid = int(time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1)) * 1000)
                d = daily_map.get(mid)
                if d is None:
                    d = {"m": mid, "ocred": 0, "tot": 0, "turns": 0, "nsess": 0}
                    daily_map[mid] = d
                    daily.append(d)
                d["tot"] += rec[2]
                d["turns"] += 1
                if rec[7] is not None:
                    d["ocred"] = d.get("ocred", 0) + rec[7]
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

    est_req = qmeta.get("estReq", 0)
    exact_req = qmeta.get("exactReq", 0)
    mode = "none" if not (est_req or exact_req) else ("exact" if est_req == 0 else ("estimate" if exact_req == 0 else "mixed"))
    data["_qoderMeta"] = {
        "mode": mode,
        "estReq": est_req,
        "exactReq": exact_req,
        "credits": round(qmeta.get("credits", 0.0), 2),
        "windows": {k: v for k, v in sorted(qmeta.get("windows", {}).items(), key=lambda kv: int(kv[0]))},
        "filesByWindow": {k: v for k, v in sorted(qmeta.get("filesByWindow", {}).items(), key=lambda kv: int(kv[0]))},
        "files": qmeta.get("files", 0),
        "gate": _qoder_gate_enabled(),
        "source": "Qoder IDE local.db + ~/.qoder-cn/projects/**/*.jsonl",
    }
    _stamp_platforms(data)
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
