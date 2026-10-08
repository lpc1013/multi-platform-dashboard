# -*- coding: utf-8 -*-
"""
WPS 灵犀（智点）平台适配器
════════════════════════════════════════════════════════════════════════
凭据：wps_sid cookie（从本机 WPS 灵犀客户端解密得到，见 local_import.read_lingxi）

接口（全部来自灵犀客户端 app.asar 内的真实调用，非猜测）：
  GET  /api/public/v1/tasks                     任务列表（含 daily_check_in）
  POST /api/public/v1/tasks/{task_key}/claim    领取（签到 task_key = daily_check_in）
  GET  /api/public/v1/credits/balance           智点余额（按批次列出）

客户端的领取逻辑（asar 中原文）：
  const kZ="/api/public/v1/tasks";
  function dVe(t){return Et.get(kZ, TZ({params:t}))}
  function Bne(t,e){return Et.post(`${kZ}/${t}/claim`, void 0, TZ(...))}
  const Ble="daily_check_in";
均带 withCredentials:true → 即靠 wps_sid cookie 鉴权。
"""
import os
import sys
import json
import time
import urllib.request
import urllib.error
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

LABEL = "WPS 灵犀"
TASKS = [{"key": "checkin", "label": "每日签到"}]

BASE = "https://lingxi.wps.cn"
CHECKIN_KEY = "daily_check_in"
TASKS_PATH = "/api/public/v1/tasks"
BALANCE_PATH = "/api/public/v1/credits/balance"

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) WPS-LingXi/1.3.13 Chrome/146.0.7680.177 Safari/537.36")


# ───────────────────────── 凭据 ─────────────────────────
def load_accounts():
    """凭据来源（优先级从高到低）：
       1) 环境变量 LINGXI_WPS_SID（单账号）
       2) 凭据文件 ROOT/lingxi_accounts.json 或 HERE/lingxi_accounts.json
          dict: {"灵犀·A": {"wps_sid": "V02S..."}}
          list: [{"name": "灵犀·A", "wps_sid": "..."}]
    """
    accs = {}
    sid = (os.environ.get("LINGXI_WPS_SID", "") or "").strip()
    if sid:
        accs["灵犀"] = {"wps_sid": sid}
    for path in (os.path.join(ROOT, "lingxi_accounts.json"),
                 os.path.join(HERE, "lingxi_accounts.json")):
        if not os.path.exists(path):
            continue
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, dict) and v.get("wps_sid"):
                    accs[str(k)] = {"wps_sid": v["wps_sid"].strip()}
        elif isinstance(data, list):
            for i, it in enumerate(data):
                if isinstance(it, dict) and it.get("wps_sid"):
                    nm = str(it.get("name") or "灵犀%d" % (i + 1))
                    accs[nm] = {"wps_sid": it["wps_sid"].strip()}
    return accs


# ───────────────────────── HTTP ─────────────────────────
def _req(ent, path, method="GET", body=None, timeout=25):
    """返回 (http_status, parsed_json_or_text)"""
    sid = (ent.get("wps_sid") or "").strip()
    if not sid:
        raise RuntimeError("未配置 wps_sid")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={
            "Cookie": "wps_sid=" + sid,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": BASE,
            "Referer": BASE + "/",
            "User-Agent": _UA,
        })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return -1, str(e)[:160]


def _tasks(ent):
    st, j = _req(ent, TASKS_PATH)
    if st != 200 or not isinstance(j, dict):
        return None, "任务列表查询失败（HTTP %s）：%s" % (st, str(j)[:100])
    return (j.get("data") or {}), None


def _balance(ent):
    st, j = _req(ent, BALANCE_PATH)
    if st != 200 or not isinstance(j, dict):
        return None, "智点余额查询失败（HTTP %s）：%s" % (st, str(j)[:100])
    return (j.get("data") or {}), None


def _find_daily(tasks_data):
    for t in (tasks_data.get("tasks") or []):
        if t.get("task_key") == CHECKIN_KEY:
            return t
    return None


# ───────────────────────── 读取 ─────────────────────────
def read_account(name, ent):
    empty = {"name": name, "ok": False, "error": None, "level": "?",
             "signed_today": False,
             "credits": {"remain": 0, "total": 0, "used": 0},
             "packages": [], "extra": {}}
    if not (ent.get("wps_sid") or "").strip():
        empty["error"] = "未配置 wps_sid（请点「从本地客户端导入」）"
        return empty

    td, err = _tasks(ent)
    if td is None:
        # 登录态失效的典型表述
        if "401" in str(err) or "403" in str(err) or "未登录" in str(err):
            empty["error"] = "wps_sid 已失效，请在灵犀客户端重新登录后再次导入"
        else:
            empty["error"] = err
        return empty

    daily = _find_daily(td)
    signed = bool(daily and daily.get("status") == "claimed")
    ex = (daily or {}).get("extra") or {}
    days = ex.get("check_in_days") or []
    today_day = ex.get("today_day")
    today_item = next((d for d in days if d.get("day") == today_day), None)
    # 今日可领 / 已领
    can_sign = bool(daily and daily.get("status") in ("incomplete", "claimable"))

    bd, berr = _balance(ent)
    total = used = remain = 0
    packages = []
    if bd:
        # 赠送批（bonus_credits）+ 购买批（purchased_credits）都要列，
        # 只取前者会漏掉付费购买的智点。
        for key, kind in (("bonus_credits", "赠送"), ("purchased_credits", "购买")):
            for b in (bd.get(key) or []):
                v = _num(b.get("value"))
                c = _num(b.get("consumed"))
                r = _num(b.get("balance"))
                if r == 0 and v == 0:
                    continue
                packages.append({
                    "name": b.get("sku_key") or "智点",
                    "amount": v,
                    "remain": r,
                    "used": c,
                    "expire": _fmt_time(b.get("expire_time")),
                    "source": "measured",
                    "kind": kind,
                    "perpetual": False,
                })
        # 批次求和（作为兜底）
        total = sum(p["amount"] for p in packages)
        used = sum(p["used"] for p in packages)
        remain = sum(p["remain"] for p in packages)

        # 接口聚合字段更权威，用它校准：
        #   total_balance / total_bonus / total_purchased / total_contract 都是「剩余」口径，
        #   不能当「总量」；总量要取 bonus_summary/purchased_summary 的 total_value。
        if bd.get("total_balance") is not None:
            remain = _num(bd.get("total_balance"))
        agg_total = 0.0
        for sk in ("bonus_summary", "purchased_summary"):
            s = bd.get(sk)
            if isinstance(s, dict):
                agg_total += _num(s.get("total_value"))
        if agg_total:
            total = agg_total
        # 合约/订阅类积分没有 total_value 可查，只知「剩余」→ 保证总量不小于剩余
        if remain > total:
            total = remain
        used = max(0.0, total - remain)

    # 按到期时间排序（最近的在前）；不截断——前端会按到期日分组并自带「更晚到期」汇总，
    # 后端若先截断会让那部分汇总少算。
    packages.sort(key=lambda p: (p.get("expire") or "9999"))
    pending = [t for t in (td.get("tasks") or []) if t.get("status") == "claimable"]

    return {
        "name": name, "ok": True, "error": None,
        "level": "灵犀专业版" if bd and bd.get("enabled") else "灵犀",
        "signed_today": signed,
        "credits": {"remain": round(remain), "total": round(total), "used": round(used)},
        "packages": packages,
        "extra": {
            "can_sign_in": can_sign,
            "today_day": today_day,
            "streak_days": len(days),
            "total_claimed": _num(td.get("total_claimed_credits")),
            "today_reward": (today_item or {}).get("reward") or (daily or {}).get("reward_amount"),
            "pending_claims": len(pending) + (1 if can_sign else 0),
            "one_time_pending": [t.get("title") for t in pending][:4],
            "pkg_count": len(packages),
        },
    }


def _num(v):
    try:
        return float(v)
    except Exception:
        return 0.0


def _fmt_time(s):
    """ISO8601 → 本地 yyyy-mm-dd hh:mm（解析失败返回 None）"""
    if not s:
        return None
    try:
        t = str(s).replace("Z", "+00:00")
        import datetime as _dt
        d = _dt.datetime.fromisoformat(t)
        return d.astimezone().strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(s)[:16] if isinstance(s, str) else None


# ───────────────────────── 任务 ─────────────────────────
def run_task(name, ent, task_key):
    if task_key != "checkin":
        return {"ok": False, "msg": "未知任务"}
    if not (ent.get("wps_sid") or "").strip():
        return {"ok": False, "msg": "未配置 wps_sid"}

    # 先查状态，已签到就不重复请求
    td, err = _tasks(ent)
    if td is None:
        return {"ok": False, "msg": err}
    daily = _find_daily(td)
    if daily and daily.get("status") == "claimed":
        return {"ok": True, "msg": "今日已签到（灵犀智点）", "flag": "ALREADY_TODAY"}
    if daily is None:
        return {"ok": False, "msg": "任务列表中未找到「每日签到」任务"}

    st, j = _req(ent, "%s/%s/claim" % (TASKS_PATH, CHECKIN_KEY), method="POST")
    if st != 200 or not isinstance(j, dict):
        return {"ok": False, "msg": "签到请求失败（HTTP %s）：%s" % (st, str(j)[:120])}
    if j.get("result") != "ok":
        return {"ok": False, "msg": str(j.get("hint") or j.get("message") or str(j)[:120])}

    d = j.get("data") or {}
    gain = None
    if isinstance(d.get("extra"), dict):
        gain = d["extra"].get("today_reward")
    if gain is None:
        gain = (daily or {}).get("reward_amount")
    total_claimed = d.get("total_claimed_credits")
    msg = "签到成功，+%s 智点" % (int(gain) if gain else "?")
    if total_claimed is not None:
        msg += "（累计已领 %s）" % int(_num(total_claimed))
    return {"ok": True, "msg": msg, "flag": "SUCCESS", "gain": gain}


if __name__ == "__main__":
    accs = load_accounts()
    print("账号:", list(accs.keys()))
    for nm, ent in accs.items():
        r = read_account(nm, ent)
        print("[%s] ok=%s signed=%s 剩余=%s/%s 连续=%s 可签=%s err=%s"
              % (nm, r["ok"], r["signed_today"], r["credits"]["remain"], r["credits"]["total"],
                 (r["extra"] or {}).get("streak_days"), (r["extra"] or {}).get("can_sign_in"),
                 r["error"]))
