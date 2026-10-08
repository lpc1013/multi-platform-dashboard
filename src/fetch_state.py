# -*- coding: utf-8 -*-
"""
WorkBuddy 看板数据生成器  ->  dashboard_data.json

做什么：
  调官方接口读取真实数据（积分包 / 签到状态 / 成长等级 / 能量 / Buddy 旅行状态），
  「到期日」直接取官方接口 /v2/billing/meter/get-user-resource 的真实字段（CycleEndTime /
  DeductionEndTime），不做任何推算；解析口径取自开源项目 CreditDaddy。
  输出 JSON 给 workbuddy-dashboard.html 导入查看。

用法：
  python fetch_state.py

凭据来源（任选其一，优先级从高到低）：
  1) 环境变量 WORKBUDDY_REFRESH_TOKEN = 每行 "手机号:AT:RT"
  2) ../WorkBuddy-Daily/wb_refresh_tokens.json（L0NE-6 脚本维护）
  获取凭据：在 WorkBuddy-Daily 目录跑  python workbuddy_login.py
"""
import os, sys, json, time, base64, calendar
from datetime import datetime, timedelta

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("缺少依赖 requests，请先：pip install requests")

BASE = "https://www.workbuddy.cn"
REFRESH_URL = "https://copilot.tencent.com/v2/plugin/auth/token/refresh"
UA = "WorkBuddy/5.5.2 WorkBuddy AI/5.5.2 CLI/2.137.1"

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
# 凭据候选文件（两种来源都要认，避免"登录成功却读不到"）：
#   1) wb_refresh_tokens.json —— L0NE-6 主脚本维护，dict 格式
#   2) wb_login_result.json   —— workbuddy_login.py 登录工具写出，list 格式
STORE = os.path.join(TOOLS, "WorkBuddy-Daily", "wb_refresh_tokens.json")
LOGIN_STORE = os.path.join(TOOLS, "WorkBuddy-Daily", "wb_login_result.json")
OUT = os.path.join(HERE, "dashboard_data.json")


def jw(tok):
    """本地解 JWT payload（不验签），用于取 uid / 手机号 / 过期时间。"""
    try:
        s = tok.split(".")[1]
        s += "=" * (4 - len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))
    except Exception:
        return {}


def _from_file(path):
    """解析一个凭据文件，返回 {账号标识: {access_token, refresh_token}}。

    兼容两种格式：
      dict: {"手机号": {"access_token":.., "refresh_token":..}}   （L0NE-6 主脚本）
      list: [{"phone":.., "access_token":.., "refresh_token":..}] （workbuddy_login.py）
    """
    out = {}
    if not os.path.exists(path):
        return out
    try:
        raw = json.load(open(path, encoding="utf-8"))
    except Exception:
        return out

    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(v, dict):
                out[str(k)] = {"access_token": v.get("access_token", ""),
                               "refresh_token": v.get("refresh_token", "")}
    elif isinstance(raw, list):
        for it in raw:                      # 同一手机号重复登录时，后一条（更新）覆盖
            if not isinstance(it, dict):
                continue
            key = str(it.get("alias") or it.get("phone") or it.get("name") or "")
            if not key:
                continue
            out[key] = {"access_token": it.get("access_token", ""),
                        "refresh_token": it.get("refresh_token", "")}
    return out


def _store_candidates():
    """凭据文件候选位置（按优先级）。

    同时兼容两种目录布局：
      标准布局：dashboard/ 与 WorkBuddy-Daily/ 同级（上级目录）
      扁平布局：凭据文件直接放在 dashboard/ 本目录（便于分发后独立使用）
    """
    return [STORE, LOGIN_STORE,
            os.path.join(HERE, "wb_refresh_tokens.json"),
            os.path.join(HERE, "wb_login_result.json")]


def load_accounts():
    accs = {}
    env = os.environ.get("WORKBUDDY_REFRESH_TOKEN", "").strip()
    if env:
        for line in env.replace("@", "\n").splitlines():
            line = line.strip().strip('"').strip("'")
            if not line or "$wbEncrypted" in line:
                continue
            p = line.split(":", 2)
            if len(p) == 3:
                u, at, rt = p[0].strip(), p[1].strip(), p[2].strip()
            elif len(p) == 2:
                u, at, rt = p[0].strip(), p[1].strip(), ""
            else:
                continue
            accs[u or ("acc%d" % (len(accs) + 1))] = {"access_token": at, "refresh_token": rt}
    # 文件兜底：两个来源都读，已存在的键不覆盖（环境变量优先级最高）
    for path in _store_candidates():
        for k, v in _from_file(path).items():
            if k not in accs:
                accs[k] = v
    return accs


def refresh(rt):
    """用 refresh token 换 access token。"""
    s = requests.Session()
    s.trust_env = False
    try:
        r = s.post(REFRESH_URL, json={}, timeout=20, verify=False,
                   headers={"X-Refresh-Token": rt, "X-Auth-Refresh-Source": "plugin",
                            "Content-Type": "application/json"})
        d = r.json()
        inner = d.get("data") or {}
        if d.get("code") == 0 and inner.get("accessToken"):
            return inner["accessToken"], inner.get("refreshToken") or rt
        return None, str(d.get("msg", ""))[:80]
    except Exception as e:
        return None, str(e)[:80]


def sess(tok):
    s = requests.Session()
    s.trust_env = False
    uid = str(jw(tok).get("sub", ""))
    s.headers.update({
        "Authorization": "Bearer " + tok,
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Origin": BASE, "Referer": BASE + "/profile/growth-center",
        "User-Agent": UA, "X-User-Id": uid,
    })
    return s


def getj(s, path, method="GET"):
    url = BASE + path
    try:
        r = s.get(url, timeout=20, verify=False) if method == "GET" \
            else s.post(url, json={}, timeout=20, verify=False)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}


REFILL_GAP_SEC = 2 * 24 * 3600      # 判定"循环包"的阈值：扣减截止时间比周期结束晚 2 天以上


def _parse_dt(v):
    """到期时间归一：上游可能给毫秒整数 / 秒整数 / 'YYYY-MM-DD HH:MM:SS' 字符串。"""
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)):
        n = float(v)
        n = n / 1000.0 if n > 1e12 else n
        try:
            return datetime.fromtimestamp(n)
        except Exception:
            return None
    s = str(v).strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19], fmt)
        except Exception:
            continue
    return None


def _first_num(d, *keys):
    """按优先级取第一个可解析为数字的非空字段（Precise 优先）。"""
    for k in keys:
        if k not in d:
            continue
        v = d.get(k)
        if v in (None, ""):
            continue
        try:
            return float(v)
        except Exception:
            continue
    return 0.0


def build_packages(resource):
    """按官方口径解析积分包与**真实到期时间**。

    数据来源：POST /v2/billing/meter/get-user-resource → data.Response.Data.Accounts[]
    字段与判定口径取自开源项目 CreditDaddy（src/workbuddyClient.js fetchWorkbuddyQuota），
    非自行推算：
      · 循环包（体验版月度额度）：用 Cycle* 字段，到期看 CycleEndTime
      · 一次性赠送/活动包：用 Capacity* 字段，到期看 DeductionEndTime
      · recurring 判定：DeductionEndTime 比 CycleEndTime 晚 2 天以上
    """
    data = (resource or {}).get("data") or {}
    accounts = (((data.get("Response") or {}).get("Data") or {}).get("Accounts")) or []
    now = datetime.now()
    pkgs = []

    for a in accounts:
        cycle_end = _parse_dt(a.get("CycleEndTime"))
        deduct_end = _parse_dt(a.get("DeductionEndTime"))
        recurring = bool(cycle_end and deduct_end and
                         (deduct_end - cycle_end).total_seconds() > REFILL_GAP_SEC)

        if recurring:
            total = _first_num(a, "CycleCapacitySizePrecise", "CycleCapacitySize")
            used = _first_num(a, "CycleCapacityUsedPrecise", "CycleCapacityUsed")
            remain = _first_num(a, "CycleCapacityRemainPrecise", "CycleCapacityRemain")
        else:
            total = _first_num(a, "CapacitySizePrecise", "CapacitySize")
            used = _first_num(a, "CapacityUsedPrecise", "CapacityUsed")
            remain = _first_num(a, "CapacityRemainPrecise", "CapacityRemain")

        if total <= 0:
            continue
        expire_dt = cycle_end if recurring else (deduct_end or cycle_end)
        if expire_dt and expire_dt < now:      # 已过期的不再展示
            continue

        name = a.get("PackageName") or a.get("SubProductName") or "积分包"
        pkgs.append({
            "name": name,
            "amount": round(total, 2),
            "remain": round(remain, 2),
            "used": round(used, 2),
            "expire": expire_dt.strftime("%Y-%m-%d %H:%M") if expire_dt else None,
            "source": "measured",               # 官方接口真实值
            "perpetual": False,
            "recurring": recurring,
        })

    # 有用完与否优先，再按到期先后
    pkgs.sort(key=lambda p: (0 if p["remain"] > 0 else 1, p["expire"] or "9999"))
    return pkgs


def build_packages_legacy(summary):
    """兜底：老接口 /billing/meter/get-user-resource-summary 只给余量、不返回到期日。

    仅在 v2 接口不可用时使用，到期日留空并标注 estimate（不推算）。
    """
    data = (summary or {}).get("data") or {}
    pkgs = []
    for i, p in enumerate(data.get("Packages", []) or []):
        try:
            total = float(p.get("CycleTotalCapacity") or 0)
            remain = float(p.get("CycleRemainCapacity") or 0)
            used = float(p.get("CycleUsedCapacity") or 0)
        except Exception:
            continue
        if total <= 0:
            continue
        pkgs.append({
            "name": p.get("PackageName") or ("主套餐" if i == 0 else "加量包%d" % i),
            "amount": round(total, 2), "remain": round(remain, 2), "used": round(used, 2),
            "expire": None, "source": "estimate", "perpetual": False, "recurring": False,
        })
    return pkgs


def main():
    accs = load_accounts()
    if not accs:
        print("未找到任何凭据，无法拉取真实数据。请先准备凭据：")
        print("  方式1（推荐）：在 WorkBuddy-Daily 目录执行  python workbuddy_login.py")
        print("                 短信登录后会输出一行「手机号:AT:RT」")
        print("  方式2：设置环境变量 WORKBUDDY_REFRESH_TOKEN（多账号换行分隔）")
        print("  方式3：脚本也会自动读取 %s" % STORE)
        print("\n（现在打开 workbuddy-dashboard.html 可先看演示数据效果）")
        return

    out = {"generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "accounts": []}

    for name, ent in accs.items():
        at, rt = ent.get("access_token", ""), ent.get("refresh_token", "")
        if not at and rt:
            at, _ = refresh(rt)
        if not at:
            out["accounts"].append({
                "name": name, "level": "?", "energy": None, "streak_days": None,
                "signed_today": False, "credits": {"remain": 0, "total": 0, "used": 0},
                "packages": [], "buddy": {"state": "idle"}, "error": "凭据缺失，请重新登录获取"
            })
            continue

        s = sess(at)
        resource = getj(s, "/v2/billing/meter/get-user-resource", "POST")
        summary = getj(s, "/billing/meter/get-user-resource-summary", "POST")
        status = getj(s, "/v2/billing/meter/checkin-activity-status", "POST")
        prof = getj(s, "/v2/activity/growth/profile")
        energy = getj(s, "/v2/activity/growth/energy")
        travel = getj(s, "/v2/activity/growth/buddy/travel/status")

        sd = (status or {}).get("data") or {}
        td = (travel or {}).get("data") or {}
        pdata = (prof or {}).get("data") or {}

        state = td.get("state", "idle")
        arrive_in = 0
        if state == "traveling":
            arrive_in = max(0, (int(td.get("arrive_at", 0)) - int(td.get("server_now", 0))) // 60)

        pk = build_packages(resource)
        if not pk:
            pk = build_packages_legacy(summary)
        remain = sum(p["remain"] for p in pk) if pk else int(sd.get("total_credits") or 0)
        total = sum(p["amount"] for p in pk) if pk else remain

        out["accounts"].append({
            "name": name,
            "level": ("Lv.%s" % pdata["level"]) if pdata.get("level") is not None else "?",
            "energy": ((energy or {}).get("data") or {}).get("balance"),
            "streak_days": sd.get("streak_days"),
            "signed_today": bool(sd.get("today_checked_in")),
            "credits": {"remain": remain, "total": total, "used": max(0, total - remain)},
            "packages": pk,
            "buddy": {"state": state, "arrive_in_min": arrive_in, "location": td.get("location", "")},
        })
        time.sleep(0.6)

    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("已生成：%s" % OUT)
    print("账号数：%d" % len(out["accounts"]))
    for a in out["accounts"]:
        soon = [p for p in a["packages"] if not p.get("perpetual") and p.get("expire")]
        print("  %-14s 剩余 %-7s分  积分包 %d 个  buddy=%s%s" % (
            a["name"], a["credits"]["remain"], len(a["packages"]),
            a["buddy"]["state"],
            ("  ⚠️ %s" % a["error"]) if a.get("error") else ""))
    print("\n下一步：打开 workbuddy-dashboard.html → 点「导入数据 JSON」选择 dashboard_data.json")


if __name__ == "__main__":
    main()
