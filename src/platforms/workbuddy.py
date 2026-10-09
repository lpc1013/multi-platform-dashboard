# -*- coding: utf-8 -*-
"""
WorkBuddy · 看板平台适配器
═════════════════════════════════════════════════════════════════════════
复用现有 fetch_state.py 的凭据加载 / token 刷新 / session 构造 / 积分包解析，
把原 server.py 里的 WorkBuddy 专属逻辑（签到 / 派小猫 / 打招呼 / 读状态）
封装成本看板统一的 load_accounts / read_account / run_task 接口。

凭据：WORKBUDDY_REFRESH_TOKEN 环境变量，或 ../WorkBuddy-Daily/wb_refresh_tokens.json、
      wb_login_result.json（fetch_state.load_accounts 已兼容 dict/list 两种格式）。
"""
import json, os, sys, time, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

try:
    import requests
except ImportError:
    sys.exit("缺少依赖 requests，请先：pip install requests")

import fetch_state as fs

PLATFORM = "workbuddy"
LABEL = "WorkBuddy"
TASKS = [
    {"key": "checkin", "label": "每日签到", "daily": True},
    {"key": "travel", "label": "派小猫出行", "daily": True},
    {"key": "chat", "label": "给 AI 打招呼", "daily": True},
]


# ───────────────────────── 官方接口操作 ─────────────────────────
def api_json(s, method, path, body=None, retries=2, timeout=20):
    url = fs.BASE + path
    for i in range(1, retries + 1):
        try:
            r = s.post(url, json=body or {}, timeout=timeout, verify=False) \
                if method == "POST" else s.get(url, timeout=timeout, verify=False)
            if 500 <= r.status_code < 600 and i < retries:
                time.sleep(1.5 * i)
                continue
            return r.json() if r.status_code == 200 else {}
        except Exception:
            if i < retries:
                time.sleep(1.5 * i)
    return {}


def do_sign(s):
    d = api_json(s, "POST", "/v2/billing/meter/daily-checkin", {}, retries=3)
    if d.get("code") in (0, 200):
        credit = (d.get("data") or {}).get("credit")
        return True, ("签到成功 +%s 积分" % credit if credit else "签到成功"), credit
    msg = (d.get("msg") or "").strip()
    if not d:
        return False, "签到失败（网络异常）", None
    low = msg.lower()
    if "已签到" in msg or "already" in low or "重复" in msg:
        return True, "今天已签到（无需重复）", None
    return False, (msg[:60] or "签到被拒绝"), None


def do_travel(s):
    vis = api_json(s, "GET", "/v2/activity/growth/buddy/visible")
    if vis and vis.get("code") == 0:
        vd = vis.get("data") or {}
        if not vd.get("buddy_visible", True) or not vd.get("has_buddy", True):
            return {"ok": False, "state": "no_buddy", "msg": "该账号尚未领养 Buddy，跳过"}

    st = api_json(s, "GET", "/v2/activity/growth/buddy/travel/status")
    if not st or st.get("code") != 0:
        return {"ok": False, "state": "unknown", "msg": "旅行状态获取失败"}
    sd = st.get("data") or {}
    state = sd.get("state", "idle")
    parts = []

    if state == "arrived":
        rr = api_json(s, "POST", "/v2/activity/growth/buddy/travel/claim", {})
        if rr.get("code") == 0:
            rw = (rr.get("data") or {}).get("reward_credit", 0)
            parts.append("领取旅行礼物 +%s 积分" % rw)
        else:
            parts.append("礼物领取失败：%s" % str(rr.get("msg", ""))[:40])
        st = api_json(s, "GET", "/v2/activity/growth/buddy/travel/status")
        sd = (st or {}).get("data") or {}
        state = sd.get("state", "idle")

    if state == "traveling":
        mins = max(0, (int(sd.get("arrive_at", 0)) - int(sd.get("server_now", 0))) // 60)
        if parts:
            parts.append("仍在旅行中，约 %s 分钟后到达" % mins)
            return {"ok": True, "state": "traveling", "msg": "；".join(parts), "arrive_in_min": mins}
        return {"ok": True, "state": "traveling", "msg": "旅行中，约 %s 分钟后到达" % mins, "arrive_in_min": mins}

    if sd.get("daily_limit_reached"):
        parts.append("今日已完成（每日仅一次出行，礼物已领取）")
        return {"ok": True, "state": "done", "msg": "；".join(parts)}

    cfg = api_json(s, "GET", "/v2/activity/growth/buddy/travel/config")
    locs = ((cfg.get("data") or {}).get("locations") or [])
    if not locs:
        parts.append("未取到旅行目的地")
        return {"ok": not any("失败" in p for p in parts), "state": "idle", "msg": "；".join(parts)}

    rr = api_json(s, "POST", "/v2/activity/growth/buddy/travel/depart", {"location_id": locs[0].get("id")})
    if rr.get("code") == 0:
        rd = rr.get("data") or {}
        secs = int(rd.get("arrive_at", 0)) - int(rd.get("server_now", 0))
        hrs = max(0, secs // 3600)
        parts.append("已派出小猫，约 %s 小时后到达" % hrs)
        return {"ok": True, "state": "departed", "msg": "；".join(parts), "arrive_in_min": max(0, secs // 60)}
    parts.append("出发失败：%s" % str(rr.get("msg", ""))[:40])
    return {"ok": False, "state": "idle", "msg": "；".join(parts)}


def do_chat(s, text=None, model="glm-5.2"):
    text = text or os.environ.get("WORKBUDDY_CHAT_TEXT", "你好")
    conv = api_json(s, "POST", "/console/webchat/conversations", {"name": "看板打卡-%s" % uuid.uuid4().hex[:8]})
    conv_id = (conv.get("data") or {}).get("conversationId", "")
    if not conv_id:
        return {"ok": False, "msg": "会话创建失败：%s" % str(conv.get("msg", ""))[:40]}

    payload = {"messages": [{"role": "user", "content": text}],
               "model": model, "stream": True, "conversationId": conv_id}
    headers = dict(s.headers)
    headers["Accept"] = "text/event-stream"
    try:
        r = s.post(fs.BASE + "/console/chat/completions", json=payload, headers=headers,
                   timeout=60, verify=False, stream=True)
        if r.status_code >= 400:
            r.close()
            return {"ok": False, "msg": "消息发送失败（HTTP %s）" % r.status_code}
        # text/event-stream 无 charset，requests 默认按 ISO-8859-1 解码 → UTF-8 中文全乱码，强制改 UTF-8
        r.encoding = "utf-8"
        srv_mid, txt, n, pending = "", "", 0, ""
        for line in r.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            d = pending + line[6:] if pending else line[6:]
            if d.strip() in ("[DONE]", "[完成]", "[✅完成]"):
                break
            try:
                jj = json.loads(d)
            except Exception:
                # 分块边界可能把一条 data 行截断，留到下一行拼起来再解一次
                pending = d if len(d) < 65536 else ""
                continue
            pending = ""
            if not srv_mid and jj.get("id"):
                srv_mid = str(jj["id"])
            for c in jj.get("choices", []):
                txt += (c.get("delta") or {}).get("content", "") or ""
            n += 1
            if srv_mid and n >= 6:
                break
        r.close()
        if srv_mid:
            return {"ok": True, "msg": "已发送「%s」，AI 已回复（%s…）" % (text, txt.strip()[:24]), "message_id": srv_mid}
        return {"ok": bool(txt), "msg": ("已发送消息「%s」（未取到服务端 id）" % text) if txt else "消息已发送但无响应内容"}
    except Exception as e:
        return {"ok": False, "msg": "对话异常：%s" % str(e)[:50]}


# ───────────────────────── 统一接口 ─────────────────────────
def load_accounts():
    return fs.load_accounts()


def _ensure_token(ent):
    at, rt = ent.get("access_token", ""), ent.get("refresh_token", "")
    if not at and rt:
        at, _ = fs.refresh(rt)
    return at


def _loc_name(loc):
    """旅行目的地：接口给的是对象 {id,code,name,...}，前端只显示名字。"""
    if isinstance(loc, dict):
        return loc.get("name") or loc.get("code") or ""
    return str(loc or "")


def read_account(name, ent):
    at = _ensure_token(ent)
    if not at:
        return {"name": name, "ok": False,
                "error": "凭据缺失或已失效，请重新运行 workbuddy_login.py 登录",
                "level": "?", "energy": None, "streak_days": None,
                "signed_today": False, "credits": {"remain": 0, "total": 0, "used": 0},
                "packages": [], "buddy": {"state": "unknown"}}

    s = fs.sess(at)
    resource = fs.getj(s, "/v2/billing/meter/get-user-resource", "POST")
    summary = fs.getj(s, "/billing/meter/get-user-resource-summary", "POST")
    status = fs.getj(s, "/v2/billing/meter/checkin-activity-status", "POST")
    prof = fs.getj(s, "/v2/activity/growth/profile")
    energy = fs.getj(s, "/v2/activity/growth/energy")
    travel = fs.getj(s, "/v2/activity/growth/buddy/travel/status")

    sd = (status or {}).get("data") or {}
    td = (travel or {}).get("data") or {}
    pd = (prof or {}).get("data") or {}

    state = td.get("state", "unknown")
    limit_reached = bool(td.get("daily_limit_reached"))
    arrive_in = 0
    if state == "traveling":
        arrive_in = max(0, (int(td.get("arrive_at", 0)) - int(td.get("server_now", 0))) // 60)
    # 关键修正：出行+领礼物都做完后，接口把 state 退回 "idle"（location=null, buddy_id=0），
    # 但 daily_limit_reached 仍为 true。此时不能显示成「在家待命」（那意味着还能再派一次），
    # 应显示「今日已完成」。
    if state == "idle" and limit_reached:
        state = "done"

    pkgs = fs.build_packages(resource)
    if not pkgs:
        pkgs = fs.build_packages_legacy(summary)
    remain = sum(p["remain"] for p in pkgs) if pkgs else int(sd.get("total_credits") or 0)
    total = sum(p["amount"] for p in pkgs) if pkgs else remain

    return {
        "name": name, "ok": True,
        "level": ("Lv.%s" % pd["level"]) if pd.get("level") is not None else "?",
        "energy": ((energy or {}).get("data") or {}).get("balance"),
        "streak_days": sd.get("streak_days"),
        "signed_today": bool(sd.get("today_checked_in")),
        "credits": {"remain": remain, "total": total, "used": max(0, total - remain)},
        "packages": pkgs,
        "buddy": {"state": state, "arrive_in_min": arrive_in,
                  "location": _loc_name(td.get("location")),
                  "daily_limit_reached": limit_reached,
                  "can_travel": (state == "idle"),
                  "letter": ((td.get("letter") or {}) or {}).get("guide_text") if state == "arrived" else None},
    }


def run_task(name, ent, task_key):
    at = _ensure_token(ent)
    if not at:
        return {"ok": False, "msg": "凭据失效，请重新登录"}
    s = fs.sess(at)
    if task_key == "checkin":
        ok, msg, _c = do_sign(s)
        return {"ok": ok, "msg": msg}
    if task_key == "travel":
        tr = do_travel(s)
        return {"ok": tr.get("ok"), "msg": tr.get("msg"), "state": tr.get("state")}
    if task_key == "chat":
        ch = do_chat(s)
        return {"ok": ch.get("ok"), "msg": ch.get("msg")}
    return {"ok": False, "msg": "未知任务"}
