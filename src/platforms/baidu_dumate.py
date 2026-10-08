# -*- coding: utf-8 -*-
"""
百度搭子 DuMate · 看板平台适配器
═════════════════════════════════════════════════════════════════════════
移植自开源方案 wearetheone777/dumate2api 的 src/dumate-web.js
（该仓库完整逆向了 DuMate 网页端「签到/抽奖/任务/积分」接口，端点逐条实测）。

端点（base = https://www.dumate.cn，前缀 /api/dumate/）：
    签到        POST /api/dumate/points/loginBonus
    签到信息    GET  /api/dumate/points/loginBonusInfo
    抽奖状态    GET  /api/dumate/activity/growth-plan/draw/status
    抽奖        POST /api/dumate/activity/growth-plan/draw
    领奖        POST /api/dumate/activity/growth-plan/prize/claim
    任务列表    GET  /api/dumate/activity/growth-plan/tasks
    完成任务    POST /api/dumate/activity/growth-plan/task/complete
    积分明细    GET  /api/dumate/points/quota_overview

鉴权：浏览器同源 cookie（BDUSS 等）。桌面端把请求交给 Go 后端的 cookie-proxy 转发，
      我们这里直接带 cookie 请求云端，并带 X-Dumate-Client-Type: web 头。

凭据获取：点看板「📱 从本地客户端导入」解密本机已登录的 DuMate 桌面端 Cookie（含 BDUSS），
          或手动粘贴 Cookie 字符串，存入凭据文件 dumate_accounts.json。
          （DuMate 无网页版，浏览器登录入口已移除——dumate.cn 仅是下载页，拿不到登录态。）
"""
import os, sys, time, uuid, json, urllib.parse

try:
    import requests
except ImportError:
    sys.exit("缺少依赖 requests，请先：pip install requests")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

BASE = os.environ.get("DUMATE_WEB_BASE", "https://www.dumate.cn").rstrip("/")
TIMEOUT = int(os.environ.get("DUMATE_WEB_TIMEOUT", "20000"))

PLATFORM = "baidu_dumate"
LABEL = "百度搭子 DuMate"
TASKS = [
    {"key": "checkin", "label": "每日签到", "daily": True},
    {"key": "draw", "label": "每日抽奖", "daily": True},
]

# 本会话内抽到的中奖记录（API 的 my_prizes 之外，抽奖后立即可见）
_WIN_LOG = {}


# ───────────────────────── 请求封装 ─────────────────────────
def _request(cookie, method, url_path, body=None):
    url = url_path if url_path.startswith("http") else BASE + url_path
    payload = None if body is None else json.dumps(body, ensure_ascii=False)
    headers = {
        "Cookie": cookie,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "X-Dumate-Client-Type": "web",
        "Referer": BASE + "/app",
        "Origin": BASE,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    }
    if payload:
        headers["Content-Type"] = "application/json"
    try:
        r = requests.request(method, url, headers=headers, data=payload,
                              timeout=TIMEOUT / 1000.0, verify=False)
        try:
            parsed = r.json()
        except Exception:
            parsed = None
        expired = (r.status_code == 401) or (parsed and parsed.get("code") in (10001, 10006))
        ok = (200 <= r.status_code < 300) and (not parsed or parsed.get("code") in (0, None) or parsed.get("success") is not False)
        return {"ok": ok, "status": r.status_code, "expired": bool(expired),
                "data": parsed, "raw": (None if parsed is not None else r.text[:300])}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _pick(res):
    if not res.get("ok"):
        return None
    d = res.get("data")
    if not isinstance(d, dict):
        return d
    if "result" in d:
        return d["result"]
    if "data" in d:
        return d["data"]
    return d


def _err_of(res):
    if res.get("error"):
        return res["error"]
    if res.get("expired"):
        return "登录态已失效，请重新登录 dumate.cn 并更新 Cookie"
    d = res.get("data") or {}
    return d.get("message") or d.get("msg") or d.get("error_message") or ("HTTP %s" % res.get("status"))


def _prize_name(d):
    """从抽奖结果字典里尽量取出奖品名（接口字段名不固定，逐键兜底）。"""
    if not isinstance(d, dict):
        return None
    for k in ("prizeName", "prize_name", "name", "title", "prize", "prizeName_text"):
        v = d.get(k)
        if v:
            return str(v)
    return None


# ───────────────────────── 凭据 ─────────────────────────
def load_accounts():
    """凭据来源（优先级从高到低）：
       1) 环境变量 DUMATE_COOKIE（单账号）
       2) 凭据文件 ROOT/dumate_accounts.json 或 HERE/dumate_accounts.json
          dict: {"搭子A": {"cookie": "BDUSS=...; ..."}}
          list: [{"name": "搭子A", "cookie": "..."}]
    """
    accs = {}
    ck = (os.environ.get("DUMATE_COOKIE", "") or "").strip()
    if ck:
        accs["DuMate"] = {"cookie": ck}
    for path in (os.path.join(ROOT, "dumate_accounts.json"),
                 os.path.join(HERE, "dumate_accounts.json")):
        if not os.path.exists(path):
            continue
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, dict) and v.get("cookie"):
                    accs[str(k)] = {"cookie": v["cookie"].strip()}
        elif isinstance(data, list):
            for i, it in enumerate(data):
                if isinstance(it, dict) and it.get("cookie"):
                    nm = str(it.get("name") or "DuMate%d" % (i + 1))
                    accs[nm] = {"cookie": it["cookie"].strip()}
    return accs


# ───────────────────────── 业务接口 ─────────────────────────
def _login_bonus_info(cookie):
    res = _request(cookie, "GET", "/api/dumate/points/loginBonusInfo")
    if not res.get("ok"):
        return None, _err_of(res)
    r = _pick(res) or {}
    return {"has_issued": bool(r.get("hasIssued") or r.get("has_issued")),
            "sign_in_days": r.get("signInDays") or r.get("sign_in_days") or []}, None


def _claim_login_bonus(cookie):
    res = _request(cookie, "POST", "/api/dumate/points/loginBonus")
    if not res.get("ok"):
        return False, _err_of(res)
    return True, "签到成功"


def _quota_overview(cookie):
    res = _request(cookie, "GET", "/api/dumate/points/quota_overview?clientType=desktop&timezone=Asia%2FShanghai")
    if not res.get("ok"):
        return None, _err_of(res)
    r = _pick(res) or {}
    total = Number(r.get("totalPoints") or 0)
    used = Number(r.get("usedPoints") or 0)
    subscribed = bool(r.get("isSubscribed"))
    packages = []
    for p in (list(r.get("subscription") or []) + list(r.get("incremental") or [])):
        exp = p.get("expireDate")
        expire = None
        if isinstance(exp, (int, float)) and exp:
            # expireDate 可能是秒或毫秒时间戳，统一折算成秒再格式化；
            # 超范围/非法值不让它把整个查询带崩（Windows 上 localtime 会抛 OSError 22）
            sec = exp / 1000.0 if exp > 1e12 else float(exp)
            try:
                expire = time.strftime("%Y-%m-%d %H:%M", time.localtime(sec))
            except (OSError, ValueError, OverflowError):
                expire = None
        packages.append({
            "name": p.get("packageType") or "积分包",
            "amount": Number(p.get("totalPoints") or 0),
            "remain": Number(p.get("totalPoints") or 0) - Number(p.get("usedPoints") or 0),
            "used": Number(p.get("usedPoints") or 0),
            "expire": expire,
            "source": "measured",
            "perpetual": False,
        })
    return {"total": total, "used": used, "left": max(0, total - used),
            "subscribed": subscribed, "packages": packages}, None


def _draw_status(cookie):
    res = _request(cookie, "GET", "/api/dumate/activity/growth-plan/draw/status")
    if not res.get("ok"):
        return None, _err_of(res)
    r = _pick(res) or {}
    return {"remaining_draws": r.get("remaining_draws") or r.get("remainingDraws") or 0,
            "prizes": r.get("prizes") or [],
            "my_prizes": r.get("my_prizes") or []}, None


def _draw(cookie):
    """抽奖需要幂等键 request_id：每次生成新的，防服务端重复扣次数。"""
    res = _request(cookie, "POST", "/api/dumate/activity/growth-plan/draw",
                   {"request_id": uuid.uuid4().hex})
    if not res.get("ok"):
        return None, _err_of(res)
    r = _pick(res) or {}
    return {"remaining_draws": r.get("remaining_draws") or r.get("remainingDraws"),
            "result": r, "prize_name": _prize_name(r)}, None


# ───────────────────────── 统一接口 ─────────────────────────
def _build_win_records(name, ds):
    """合并「官方中奖记录(my_prizes)」与「本会话抽到(_WIN_LOG)」。"""
    recs = []
    api = (ds or {}).get("my_prizes") or []
    if isinstance(api, list):
        for p in api:
            if isinstance(p, dict):
                recs.append({"name": _prize_name(p) or "奖励",
                             "at": p.get("createTime") or p.get("create_time") or "",
                             "source": "官方"})
    for w in (_WIN_LOG.get(name) or []):
        recs.append({"name": w.get("prize") or "奖励",
                     "at": w.get("at") or "",
                     "source": "本会话"})
    return recs


def read_account(name, ent):
    cookie = (ent.get("cookie") or "").strip()
    if not cookie:
        return {"name": name, "ok": False, "error": "未配置 DuMate Cookie",
                "level": "?", "signed_today": False,
                "credits": {"remain": 0, "total": 0, "used": 0}, "packages": [],
                "extra": {"remaining_draws": 0, "win_records": []}}
    # 签到信息
    bi, bi_err = _login_bonus_info(cookie)
    signed = bool(bi and bi.get("has_issued"))
    # 积分
    q, q_err = _quota_overview(cookie)
    if q is None:
        return {"name": name, "ok": False,
                "error": q_err or "积分查询失败",
                "level": "?", "signed_today": signed,
                "credits": {"remain": 0, "total": 0, "used": 0}, "packages": [],
                "extra": {"remaining_draws": 0, "win_records": []}}
    # 抽奖状态
    ds, _ = _draw_status(cookie)
    remaining = (ds or {}).get("remaining_draws", 0)
    win_records = _build_win_records(name, ds)
    last_draw = (_WIN_LOG.get(name) or [])
    last_draw = (last_draw[-1].get("prize") if last_draw else None)
    return {
        "name": name, "ok": True, "error": None,
        "level": ("Pro" if q.get("subscribed") else "免费版"),
        "signed_today": signed,
        "credits": {"remain": q["left"], "total": q["total"], "used": q["used"]},
        "packages": q["packages"],
        "extra": {"remaining_draws": remaining,
                  "sign_in_days": (bi or {}).get("sign_in_days", []),
                  "win_records": win_records,
                  "last_draw": last_draw},
    }


def run_task(name, ent, task_key):
    cookie = (ent.get("cookie") or "").strip()
    if not cookie:
        return {"ok": False, "msg": "未配置 DuMate Cookie"}
    if task_key == "checkin":
        ok, msg = _claim_login_bonus(cookie)
        return {"ok": ok, "msg": msg}
    if task_key == "draw":
        ds, err = _draw_status(cookie)
        if ds and (ds.get("remaining_draws") or 0) <= 0:
            return {"ok": False, "msg": "今日抽奖次数已用完（剩余 %s 次）" % (ds.get("remaining_draws"))}
        r, err = _draw(cookie)
        if r is None:
            return {"ok": False, "msg": err or "抽奖失败"}
        rem = r.get("remaining_draws")
        prize = r.get("prize_name")
        if prize:
            _WIN_LOG.setdefault(name, [])
            _WIN_LOG[name].append({"prize": prize,
                                   "at": time.strftime("%Y-%m-%d %H:%M:%S")})
            return {"ok": True, "msg": "抽到：%s（剩余 %s 次）" % (prize, rem)}
        return {"ok": True, "msg": "抽奖完成（剩余 %s 次）" % rem}
    return {"ok": False, "msg": "未知任务"}


def Number(v):
    try:
        return float(v)
    except Exception:
        return 0.0
