# -*- coding: utf-8 -*-
"""
Qoder CN（阿里 Qoder 国内版）每日领取 100 Credits · 看板平台适配器
════════════════════════════════════════════════════════════════════════
接口口径（逆向自客户端 + 本机实测，2026-10 验证）：
    活动列表  GET  https://openapi.qoder.com.cn/sash/api/v1/me/campaigns
    领取      POST https://openapi.qoder.com.cn/sash/api/v1/me/campaigns/{campaignId}/claim
    额度      GET  https://openapi.qoder.com.cn/api/v2/quota/usage

鉴权：Authorization: Bearer <dt-…>（token 来自客户端 auth.v1.dat，见 local_import.read_qoder）

要点（踩坑）：
  * 2026-09 官方从旧 daily-check-in 迁到 campaigns 框架：必须先 GET 当日列表拿到
    当天的 campaignId，再 POST claim；用旧 id 重放只会得到 409 AlreadyExists。
  * 必须打 openapi.qoder.com.cn；打 qoder.com.cn 会 401 missing cookie header。
  * 领取是幂等的（重复跑不会重复发币）。
  * 每日 10:00（UTC+8）刷新，领取后 30 天有效。
"""
import os
import sys
import json
import time

try:
    import requests
except ImportError:
    sys.exit("缺少依赖 requests，请先：pip install requests")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

PLATFORM = "qoder"
LABEL = "Qoder CN"
TASKS = [{"key": "checkin", "label": "每日领取 100 Credits", "daily": True}]

BASE = (os.environ.get("QODER_HOST") or "https://openapi.qoder.com.cn").rstrip("/")
CAMPAIGNS_PATH = "/sash/api/v1/me/campaigns"
CLAIM_PATH = "/sash/api/v1/me/campaigns/%s/claim"
USAGE_PATH = "/api/v2/quota/usage"
USERINFO_PATH = "/api/v1/userinfo"

UA = "Qoder"


def _hdr(token):
    return {
        "Authorization": "Bearer " + token,
        "Cosy-ClientType": "10",
        "User-Agent": UA,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _req(token, path, method="GET", body=None, timeout=25):
    """返回 (status_code, parsed_json_or_text)"""
    try:
        r = requests.request(method.upper(), BASE + path,
                             headers=_hdr(token),
                             data=(json.dumps(body) if body is not None else None),
                             timeout=timeout, verify=False)
    except Exception as e:
        return 0, {"error": str(e)[:160]}
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"raw": r.text[:300]}


# ───────────────────────── 身份反查 ─────────────────────────
def fetch_user_info(token, mode="bearer"):
    """GET /api/v1/userinfo（Bearer）反查账号身份 —— 客户端 fetchUser 用的同一接口。
    字段口径逆向自 0.4.3 app.asar：id/user_id/uid、name/username/user_name、
    security_mobile（手机号）、email。返回 None 表示令牌无效/接口不可用。
    OAuth 授权落盘时用它填 user_id/phone，身份指纹稳定（令牌轮换也不丢身份）。"""
    st, j = _req(token, USERINFO_PATH)
    if st != 200 or not isinstance(j, dict):
        return None
    d = j.get("data") if isinstance(j.get("data"), dict) else j
    uid = d.get("id") or d.get("user_id") or d.get("uid")
    if not uid:
        return None
    return {
        "user_id": str(uid),
        "name": str(d.get("name") or d.get("username") or d.get("user_name") or ""),
        "phone": str(d.get("security_mobile") or "").strip() or "",
        "email": str(d.get("email") or ""),
    }


# ───────────────────────── 凭据 ─────────────────────────
def load_accounts():
    """凭据来源（优先级从高到低）：
       1) 环境变量 QODER_TOKEN（+ QODER_REFRESH_TOKEN 可选）
       2) 凭据文件 ROOT/qoder_accounts.json 或 HERE/qoder_accounts.json
    """
    accs = {}
    tok = (os.environ.get("QODER_TOKEN", "") or "").strip()
    if tok:
        accs["Qoder"] = {"token": tok,
                         "refresh_token": (os.environ.get("QODER_REFRESH_TOKEN", "") or "").strip()}
    for path in (os.path.join(ROOT, "qoder_accounts.json"),
                 os.path.join(HERE, "qoder_accounts.json")):
        if not os.path.exists(path):
            continue
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            items = [(str(k), v) for k, v in data.items()]
        elif isinstance(data, list):
            items = [(str(it.get("name") or "Qoder%d" % (i + 1)), it) for i, it in enumerate(data)]
        else:
            items = []
        for nm, v in items:
            if isinstance(v, dict) and v.get("token"):
                accs[nm] = {"token": v["token"].strip(),
                            "refresh_token": (v.get("refresh_token") or "").strip(),
                            "expires_at": v.get("expires_at"),
                            "user_id": v.get("user_id"),
                            "phone": v.get("phone")}
    return accs


def _campaigns(token):
    st, j = _req(token, CAMPAIGNS_PATH)
    if st != 200 or not isinstance(j, dict):
        return None, "活动列表查询失败（HTTP %s）：%s" % (st, str(j)[:120])
    return j, None


def _usage(token):
    st, j = _req(token, USAGE_PATH)
    if st != 200 or not isinstance(j, dict):
        return None
    return j


def _claimable(camps):
    """可领的活动：CLAIMABLE 且未过期"""
    now = time.time()
    out = []
    for c in (camps.get("campaigns") or []):
        if c.get("actionType") != "CLAIM_BENEFIT":
            continue
        if c.get("claimStatus") != "CLAIMABLE":
            continue
        end = c.get("endAt")
        if end and float(end) < now:
            continue
        out.append(c)
    return out


def _benefit_of(c):
    b = c.get("benefit") or {}
    amt = b.get("amount")
    kind = b.get("kind") or "CREDITS"
    return kind, amt


# ───────────────────────── 读取 ─────────────────────────
def read_account(name, ent):
    empty = {"name": name, "ok": False, "error": None, "level": "Qoder",
             "signed_today": False,
             "credits": {"remain": 0, "total": 0, "used": 0},
             "packages": [], "extra": {}}
    token = (ent.get("token") or "").strip()
    if not token:
        empty["error"] = "未配置 token（请点「从本地客户端导入」）"
        return empty

    camps, err = _campaigns(token)
    if camps is None:
        if "401" in str(err) or "403" in str(err):
            empty["error"] = "登录态已失效，请在 Qoder CN 客户端重新登录后再次导入"
        else:
            empty["error"] = err
        return empty

    avail = _claimable(camps)
    packages, remain, total, used = [], 0, 0, 0
    usage = _usage(token)
    if usage:
        for key, label in (("addOnQuota", "活动赠送额度"), ("userQuota", "订阅额度")):
            q = usage.get(key) or {}
            t = float(q.get("total") or 0)
            u = float(q.get("used") or 0)
            r = float(q.get("remaining") or 0)
            total += t
            used += u
            remain += r
            if t > 0:
                packages.append({
                    "name": label, "amount": t, "remain": r, "used": u,
                    "expire": None, "source": "measured", "perpetual": False,
                    "kind": "Credits",
                })
        user_type = usage.get("userType")
    else:
        user_type = None

    today = avail[0] if avail else None
    kind, amt = _benefit_of(today) if today else (None, None)

    return {
        "name": name, "ok": True, "error": None,
        "level": ("Qoder CN · " + str(user_type)) if user_type else "Qoder CN",
        "signed_today": not avail,
        "credits": {"remain": round(remain), "total": round(total), "used": round(used)},
        "packages": packages,
        "extra": {
            "can_sign_in": bool(avail),
            "today_reward": amt,
            "today_kind": kind,
            "campaign_count": len(camps.get("campaigns") or []),
            "claimable_count": len(avail),
            "user_id": camps.get("uid"),
            "phone": ent.get("phone"),
            "expires_at": ent.get("expires_at"),
        },
    }


# ───────────────────────── 领取 ─────────────────────────
def run_task(name, ent, task_key):
    if task_key != "checkin":
        return {"ok": False, "msg": "未知任务"}
    token = (ent.get("token") or "").strip()
    if not token:
        return {"ok": False, "msg": "未配置 token"}

    camps, err = _campaigns(token)
    if camps is None:
        return {"ok": False, "msg": err}

    avail = _claimable(camps)
    if not avail:
        return {"ok": True, "msg": "今日无可领活动（已领取或未到刷新时间）"}

    msgs = []
    allok = True
    for c in avail:
        cid = c.get("campaignId")
        kind, amt = _benefit_of(c)
        st, j = _req(token, CLAIM_PATH % cid, method="POST", body={})
        if st == 200:
            got = ""
            if isinstance(j, dict):
                d = j.get("data") or {}
                got = d.get("amount") or d.get("credits") or amt
            msgs.append("已领取 +%s %s" % (got or amt or "", kind or "积分"))
        elif st in (400, 409):
            txt = json.dumps(j, ensure_ascii=False) if not isinstance(j, str) else j
            if "AlreadyExists" in txt or "已领取" in txt or "already" in txt.lower():
                msgs.append("该活动今日已领取")
            else:
                allok = False
                msgs.append("领取失败（HTTP %s）：%s" % (st, txt[:80]))
        elif st in (401, 403):
            return {"ok": False, "msg": "登录态已失效，请在 Qoder CN 客户端重新登录后再次导入"}
        else:
            allok = False
            msgs.append("领取失败（HTTP %s）：%s" % (st, str(j)[:80]))
        time.sleep(0.4)

    return {"ok": allok, "msg": "；".join(msgs), "state": "claimed" if allok else "partial"}
