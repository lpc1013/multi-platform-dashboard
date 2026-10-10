# -*- coding: utf-8 -*-
"""
ZCode（z.ai 官方客户端）· 看板平台适配器
════════════════════════════════════════════════════════════════════════
接口口径（逆向自客户端 asar + 本机实测，2026-10 验证）：

  登录态    ~/.zcode/v2/credentials.json → 键 `zcodejwttoken`
            （enc:v1:<iv>.<tag>.<ct>，AES-256-GCM，key = sha256(回退串)，见 local_import.read_zcode）
  当前计划  GET  /api/v1/zcode-plan/billing/current      （实测 200）
  可领计划  GET  /api/v1/zcode-plan/billing/preview?app_version=&platform=   （实测 200）
  手动领取  POST /api/v1/zcode-plan/billing/claim          body {"plan_id": "..."}
  活动发放  GET  /api/v1/marketing/touch?seq=N             （实测 200，返回 deliveries[]）
  活动动作  POST /api/v1/marketing/touch/action            body {"campaign_id": "...", "action_type": "..."}

踩坑（重要）：
  * 必须打 `https://zcode.z.ai`。
  * **必须带 `X-Client-Language`（缺失时接口一律返回 400 parameter error，极具误导性）**；
    另需 `X-ZCode-App-Version` / `X-Platform` / `X-Device-Mid`。
  * `billing/claim` 需要阿里云滑块验证参数 `X-Aliyun-Captcha-Verify-Param`，
    纯 HTTP 无法生成 → 看板能监测、能提示，但**领取需在客户端点一下**。
  * 赠送额度是「不定时发放」，平时 `plans` / `deliveries` 都是空数组，属正常。

读取到的「额度」语义：读的是活动/计划的可领状态，不是 token 余额（z.ai 未公开余额接口）。
"""
import os
import sys
import json
import time
import uuid

try:
    import requests
except ImportError:
    sys.exit("缺少依赖 requests，请先：pip install requests")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

PLATFORM = "zcode"
LABEL = "ZCode（z.ai）"
TASKS = [{"key": "checkin", "label": "领取赠送额度", "daily": True}]

BASE = (os.environ.get("ZCODE_HOST") or "https://zcode.z.ai").rstrip("/")
CURRENT_PATH = "/api/v1/zcode-plan/billing/current"
PREVIEW_PATH = "/api/v1/zcode-plan/billing/preview"
CLAIM_PATH = "/api/v1/zcode-plan/billing/claim"
TOUCH_PATH = "/api/v1/marketing/touch"
TOUCH_ACTION_PATH = "/api/v1/marketing/touch/action"

APP_VERSION = os.environ.get("ZCODE_APP_VERSION") or "3.14.3"
PLATFORM_KEY = "win32-x64" if os.name == "nt" else "darwin-arm64"


def _device_mid(secret):
    """客户端会带一个稳定的 X-Device-Mid（uuid）。这里由凭据派生，保证跨次运行一致。"""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "zcode-device-%s" % (secret or "anon")))


def _hdr(token, secret=""):
    return {
        "Authorization": "Bearer " + token,
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "X-ZCode-App-Version": APP_VERSION,
        "X-Platform": PLATFORM_KEY,
        "X-Client-Language": "zh-CN",
        "X-Device-Mid": _device_mid(secret),
        "Origin": BASE,
        "Referer": BASE + "/",
    }


_seq = [0]


def _req(token, path, method="GET", body=None, secret="", timeout=25):
    """返回 (status_code, parsed_json_or_text)"""
    hdr = _hdr(token, secret)
    data = json.dumps(body) if body is not None else None
    try:
        r = requests.request(method.upper(), BASE + path, headers=hdr, data=data,
                             timeout=timeout, verify=False)
    except Exception as e:
        return 0, {"error": str(e)[:160]}
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"raw": r.text[:300]}


def _ok(j):
    return isinstance(j, dict) and j.get("code") == 0


def _data(j):
    return (j or {}).get("data") or {}


# ───────────────────────── 凭据 ─────────────────────────
def load_accounts():
    """凭据来源（优先级从高到低）：
       1) 环境变量 ZCODE_TOKEN（+ ZCODE_SECRET 可选，用于派生 Device-Mid）
       2) ROOT/zcode_accounts.json 或 HERE/zcode_accounts.json
    """
    accs = {}
    tok = (os.environ.get("ZCODE_TOKEN", "") or "").strip()
    if tok:
        accs["ZCode"] = {"token": tok, "secret": (os.environ.get("ZCODE_SECRET") or "").strip()}
    for path in (os.path.join(ROOT, "zcode_accounts.json"),
                 os.path.join(HERE, "zcode_accounts.json")):
        if not os.path.exists(path):
            continue
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            items = [(str(k), v) for k, v in data.items()]
        elif isinstance(data, list):
            items = [(str(it.get("name") or "ZCode%d" % (i + 1)), it) for i, it in enumerate(data)]
        else:
            items = []
        for nm, v in items:
            if isinstance(v, dict) and v.get("token"):
                accs[nm] = {"token": v["token"].strip(),
                            "secret": (v.get("secret") or "").strip(),
                            "user_id": v.get("user_id")}
    return accs


# ───────────────────────── 读取 ─────────────────────────
def read_account(name, ent):
    # 续期按钮预填用：ZCode 凭据无手机号，键名是 11 位手机号时兑底（用户以手机号备注命名）
    _phone = str(ent.get("phone") or (name if name.isdigit() and len(name) == 11 else "") or "")
    empty = {"name": name, "ok": False, "error": None, "level": "ZCode",
             "signed_today": False,
             "credits": {"remain": 0, "total": 0, "used": 0},
             "packages": [], "extra": {"phone": _phone}}
    token = (ent.get("token") or "").strip()
    if not token:
        empty["error"] = "未配置 token（请点「从本地客户端导入」）"
        return empty
    secret = (ent.get("secret") or "").strip()

    st, j = _req(token, CURRENT_PATH, secret=secret)
    if st == 401 or st == 403:
        empty["error"] = "登录态已失效，请在 ZCode 客户端重新登录后再次导入"
        return empty
    if not _ok(j):
        empty["error"] = "计划查询失败（HTTP %s）：%s" % (st, str(j)[:110])
        return empty
    d = _data(j)
    plans = d.get("plans") or []

    # 可手动领取的计划
    st2, j2 = _req(token, "%s?app_version=%s&platform=%s" % (PREVIEW_PATH, APP_VERSION, PLATFORM_KEY),
                   secret=secret)
    claimable = _data(j2).get("plans") or [] if _ok(j2) else []

    # 活动发放（不定时推送礼物）
    _seq[0] += 1
    st3, j3 = _req(token, "%s?seq=%d" % (TOUCH_PATH, _seq[0]), secret=secret)
    deliveries = _data(j3).get("deliveries") or [] if _ok(j3) else []

    grant = 0
    for c in claimable:
        for l in (c.get("entitlements") or c.get("entitlement") or []):
            grant += int(l.get("grant_units") or l.get("grantUnits") or 0)

    today = claimable[0] if claimable else None
    extra = {
        "phone": _phone,
        "can_sign_in": bool(claimable) or bool(deliveries),
        "plan_count": len(plans),
        "claimable_count": len(claimable),
        "delivery_count": len(deliveries),
        "today_reward": grant or None,
        "today_kind": "Token" if grant else None,
        "captcha_required": bool(claimable),
        "user_id": ent.get("user_id"),
        "plans": [{"id": c.get("plan_id") or c.get("planId"),
                   "name": c.get("name") or c.get("plan_id")} for c in (plans + claimable)][:8],
        "deliveries": [{"campaign_id": x.get("campaignId") or x.get("campaign_id"),
                        "action_type": x.get("actionType") or x.get("action_type"),
                        "title": x.get("title") or x.get("name") or ""} for x in deliveries][:8],
    }
    lv = "ZCode"
    if plans:
        lv = "ZCode · " + (plans[0].get("name") or plans[0].get("plan_id") or "已订阅")
    return {
        "name": name, "ok": True, "error": None, "level": lv,
        "signed_today": not (claimable or deliveries),
        "credits": {"remain": 0, "total": 0, "used": 0},   # z.ai 未公开余额接口
        "packages": [],
        "extra": extra,
    }


# ───────────────────────── 领取 ─────────────────────────
def run_task(name, ent, task_key):
    if task_key != "checkin":
        return {"ok": False, "msg": "未知任务"}
    token = (ent.get("token") or "").strip()
    if not token:
        return {"ok": False, "msg": "未配置 token"}
    secret = (ent.get("secret") or "").strip()

    msgs, acted, failed = [], 0, False

    # ① 活动发放：可直接点「领取」
    _seq[0] += 1
    st, j = _req(token, "%s?seq=%d" % (TOUCH_PATH, _seq[0]), secret=secret)
    deliveries = _data(j).get("deliveries") or [] if _ok(j) else []
    for x in deliveries:
        cid = x.get("campaignId") or x.get("campaign_id")
        act = x.get("actionType") or x.get("action_type")
        if not (cid and act):
            continue
        st2, j2 = _req(token, TOUCH_ACTION_PATH, method="POST",
                       body={"campaign_id": cid, "action_type": act}, secret=secret)
        if _ok(j2):
            acted += 1
            msgs.append("已领取活动奖励「%s」" % (x.get("title") or x.get("name") or cid))
        else:
            msgs.append("活动 %s 领取失败：%s" % (cid, str(j2)[:70]))
        time.sleep(0.4)

    # ② 计划赠送：需要阿里云滑块验证 → 纯 HTTP 领不了
    st3, j3 = _req(token, "%s?app_version=%s&platform=%s" % (PREVIEW_PATH, APP_VERSION, PLATFORM_KEY),
                   secret=secret)
    claimable = _data(j3).get("plans") or [] if _ok(j3) else []
    if claimable:
        names = "、".join(str(c.get("name") or c.get("plan_id")) for c in claimable[:3])
        msgs.append("有 %d 个待领计划（%s），领取需阿里云滑块验证："
                    "请打开 ZCode 客户端 → 计划页点「领取」按钮" % (len(claimable), names))
        failed = True

    if not msgs:
        return {"ok": True, "msg": "暂无可领额度（赠送为不定时发放，稍后再试）", "state": "none"}
    return {"ok": (not failed), "msg": "；".join(msgs),
            "state": "claimed" if acted else "manual"}
