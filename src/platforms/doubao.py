# -*- coding: utf-8 -*-
"""
豆包（字节跳动 AI 助手）平台适配器
════════════════════════════════════════════════════════════════════════
凭据：www.doubao.com 登录 Cookie（整条粘贴，模式同 tabbit / codearts）。
      认证核心 cookie 是 sessionid / sessionid_ss（登录态判定用）。

接口（2026-10-22 从豆包网页版/电脑端前端 bundle 逆向提取，非猜测）：
  POST /alice/basic/launch                     启动配置
      → data.ug_campaign_info.campaign_group_code = 签到活动码（scene 入参）
  POST /alice/ug/campaign/landing/get          签到落地页状态 {scene}
      → data.chosen_type：1=MainPage（今日未签，展示签到卡）
                          2=CompleteCheckinPage（今日已签，展示完成页）
      → data.main_page_info / complete_page_info：{title, content, buttons}
  POST /alice/ug/campaign/landing/checkin      执行签到 {scene, biz_params?}
      → data.checked_in == true 即签到成功（前端原文判定）

错误码：710012001 = 登录已过期；成功码 0 / 200（前端 AXQ 模块白名单）。
签到奖励（如「今日签到领 200 额度」）写在落地页 title/content 里，
本适配器用正则尽力解析；解析不到只报「签到成功」不编造数字。
"""
import os
import json
import re
import time
import hashlib
import threading
import urllib.request
import urllib.error

try:
    from ._util import dec_cred, enc_cred
except ImportError:  # 被独立脚本直接加载时的兜底
    dec_cred = enc_cred = (lambda o: o)

try:                       # 包内导入（server.py: import platforms.doubao）
    from ._util import to_float as _num
except ImportError:        # 直接以脚本运行（python platforms/doubao.py）时的兜底
    def _num(v, default=0.0):
        try:
            return float(v)
        except (TypeError, ValueError):
            return default

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

try:                       # 凭据数据目录（2026-10-12 外移到 %LOCALAPPDATA%）
    from .. import data_dir as _dd
except ImportError:        # platforms 被当顶层包导入（server.py 方式）→ 平铺导入
    try:
        import data_dir as _dd
    except ImportError:
        _dd = None

# 浏览器签到兜底（API 失败降级用）。包内/脚本两种导入兜底，保持与上面的 data_dir 一致。
try:
    from ..browser_login import browser_checkin
except ImportError:
    try:
        from browser_login import browser_checkin
    except ImportError:
        browser_checkin = None


def _acc_paths(name):
    """凭据文件读点候选：DATA_DIR → ROOT → HERE。"""
    if _dd is not None:
        return _dd.candidates(name)
    return [os.path.join(ROOT, name), os.path.join(HERE, name)]


LABEL = "豆包"
TASKS = [{"key": "checkin", "label": "每日签到"}]

BASE = "https://www.doubao.com"
EP_LAUNCH = "/alice/basic/launch"
EP_LANDING_GET = "/alice/ug/campaign/landing/get"
EP_LANDING_CHECKIN = "/alice/ug/campaign/landing/checkin"

ERR_LOGIN = 710012001                       # 登录已过期（前端 msg：登录已过期，请重新登录）
OK_CODES = {0, 200, "0", "200"}             # 前端 AXQ 成功码白名单

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36")

# chosen_type 枚举（前端原文）
CH_NONE, CH_MAIN, CH_DONE = 0, 1, 2

# 活动码缓存：cookie 指纹 → (code, ts)。启动配置每次读账号都拉一次没必要，
# 与 tabbit 的 sign_key 缓存同思路（进程级，TTL 30 分钟）。
_CODE_TTL = 1800
_code_cache = {}
_code_lock = threading.Lock()

# 奖励数字解析：「200 额度」「100 积分」等
_REWARD_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(?:个)?(额度|积分|积分点|豆)")
# 登录态判定：sessionid / sessionid_ss（豆包认证核心 cookie）
_LOGIN_COOKIE_RE = re.compile(r"(?:^|;\s*)sessionid(?:_ss)?\s*=\s*\S", re.I)
# 稳定身份：ByteDance 系用户 id cookie（跨登录会话不变）
_UID_RE = re.compile(r"(?:^|;\s*)(?:uid_tt|uid_tt_ss|odin_tt)\s*=\s*([^;\s]+)", re.I)


# ───────────────────────── 凭据 ─────────────────────────
def load_accounts():
    """凭据来源（优先级从高到低）：
       1) 环境变量 DOUBAO_COOKIE（单账号，整条 cookie 串）
       2) 凭据文件 ROOT/doubao_accounts.json 或 HERE/doubao_accounts.json
          dict: {"豆包·A": {"cookie": "sessionid=...; ..."}}
          list: [{"name": "豆包·A", "cookie": "..."}]
       可选字段：campaign_group_code（手填活动码，留空则自动从启动配置获取）。
    """
    accs = {}
    env = (os.environ.get("DOUBAO_COOKIE", "") or "").strip()
    if env:
        accs["豆包"] = {"cookie": env}
    for path in _acc_paths("doubao_accounts.json"):
        if not os.path.exists(path):
            continue
        try:
            data = dec_cred(json.load(open(path, encoding="utf-8")))
        except Exception:
            continue
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, dict) and cookie_of(v):
                    accs[str(k)] = v
        elif isinstance(data, list):
            for i, it in enumerate(data):
                if isinstance(it, dict) and cookie_of(it):
                    nm = str(it.get("name") or "豆包%d" % (i + 1))
                    accs[nm] = it
    return accs


def cookie_of(ent):
    """账号记录 → cookie 串。整条 cookie 优先；只给了 sessionid 时自动拼。"""
    c = str((ent or {}).get("cookie") or "").strip()
    if c:
        return c
    sid = str((ent or {}).get("sessionid") or "").strip()
    if sid:
        return "sessionid=" + sid
    return ""


def has_login(cookie_str):
    """登录态判定：cookie 串里有没有 sessionid（保存账号时校验用）。"""
    return bool(_LOGIN_COOKIE_RE.search(str(cookie_str or "")))


def stable_uid(cookie_str):
    """稳定身份：uid_tt / odin_tt（ByteDance 系用户 id，换登录会话不变）。
    取不到返回空串——此时身份退化为整串 cookie（同 codearts 的降级路径）。"""
    m = _UID_RE.search(str(cookie_str or ""))
    return m.group(1).strip() if m else ""


# ───────────────────────── HTTP ─────────────────────────
def _req(ent, path, body=None, timeout=25):
    """POST JSON，返回 (http_status, parsed_json_or_text)。
    豆包业务错误也走 HTTP 200 + code 字段，与其它平台一致。"""
    cookie = cookie_of(ent)
    if not cookie:
        raise RuntimeError("未配置豆包 Cookie")
    data = json.dumps(body or {}).encode("utf-8")
    req = urllib.request.Request(
        BASE + path, data=data, method="POST",
        headers={
            "Cookie": cookie,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": BASE,
            "Referer": BASE + "/chat/",
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


def _ok_code(v):
    return v in OK_CODES


def _login_text(j):
    """登录过期的统一文案；不是登录问题返回 None。"""
    if not isinstance(j, dict):
        return None
    if j.get("code") == ERR_LOGIN or "登录" in str(j.get("msg") or ""):
        return "Cookie 已失效，请在豆包网页版（doubao.com）重新登录后再次粘贴"
    return None


def _dig_campaign_code(data):
    """从启动配置 data 里挖 campaign_group_code（字段路径多处容错）。"""
    if not isinstance(data, dict):
        return ""
    for path in (("ug_campaign_info", "campaign_group_code"),
                 ("campaign_group_code",),
                 ("ugCampaignInfo", "campaignGroupCode"),
                 ("ug_campaign_info", "campaignGroupCode")):
        cur = data
        for k in path:
            cur = cur.get(k) if isinstance(cur, dict) else None
            if cur is None:
                break
        if isinstance(cur, str) and cur.strip():
            return cur.strip()
    return ""


def _launch(ent):
    """拉启动配置取活动码。返回 (code, err)；
    err: "" 成功 / "login" 登录过期 / "nocampaign" 无进行中活动 / "net" 网络或异常。"""
    try:
        st, j = _req(ent, EP_LAUNCH, {})
    except Exception:
        return "", "net"
    if st == -1 or not isinstance(j, dict):
        return "", "net"
    if not _ok_code(j.get("code")):
        return "", ("login" if _login_text(j) else "net")
    cg = _dig_campaign_code(j.get("data"))
    if not cg:
        return "", "nocampaign"
    return cg, ""


def _resolve_code(ent):
    """活动码解析：账号记录手填 > 启动配置自动获取（30 分钟缓存）。"""
    manual = str((ent or {}).get("campaign_group_code") or "").strip()
    if manual:
        return manual, ""
    fp = hashlib.md5(cookie_of(ent).encode("utf-8", "replace")).hexdigest()[:12]
    now = time.time()
    with _code_lock:
        hit = _code_cache.get(fp)
        if hit and now - hit[1] < _CODE_TTL:
            return hit[0], ""
    code, err = _launch(ent)
    if code:
        with _code_lock:
            _code_cache[fp] = (code, now)
    return code, err


def _landing(ent, code):
    """落地页状态。返回 (data_dict, err_text)；err_text 为空即成功。"""
    st, j = _req(ent, EP_LANDING_GET, {"scene": code})
    if st == -1 or not isinstance(j, dict):
        return None, "签到状态查询失败（HTTP %s）：%s" % (st, str(j)[:100])
    if not _ok_code(j.get("code")):
        return None, _login_text(j) or str(j.get("msg") or str(j)[:100])
    data = j.get("data")
    if not isinstance(data, dict):
        return None, "签到状态查询返回为空（活动码可能已失效）"
    return data, ""


def _parse_reward(text):
    """从「今日签到领 200 额度」这类文案里解析奖励数；解析不到返回 None。"""
    m = _REWARD_RE.search(str(text or ""))
    if not m:
        return None
    v = _num(m.group(1))
    return int(v) if v == int(v) else v


def _page_text(data):
    """按 chosen_type 取当前应展示的落地页文案。"""
    if not isinstance(data, dict):
        return "", "", []
    if data.get("chosen_type") == CH_DONE:
        page = data.get("complete_page_info") or {}
    else:
        page = data.get("main_page_info") or {}
    if not isinstance(page, dict):
        page = {}
    title = str(page.get("title") or "")
    content = str(page.get("content") or "")
    buttons = [str(b.get("title") or "") for b in (page.get("buttons") or [])
               if isinstance(b, dict) and b.get("title")]
    return title, content, buttons


# ───────────────────────── 读取 ─────────────────────────
def read_account(name, ent):
    # 续期按钮预填用：ent.phone 优先，键名本身是 11 位手机号时兑底
    _phone = str(ent.get("phone") or (name if name.isdigit() and len(name) == 11 else "") or "")
    empty = {"name": name, "ok": False, "error": None, "level": "豆包",
             "signed_today": False,
             "credits": {"remain": 0, "total": 0, "used": 0},
             "packages": [], "extra": {"phone": _phone}}
    if not cookie_of(ent):
        empty["error"] = "未配置豆包 Cookie（请点「添加账号」粘贴网页版登录 Cookie）"
        return empty

    code, err = _resolve_code(ent)
    if err == "login":
        empty["error"] = "Cookie 已失效，请在豆包网页版（doubao.com）重新登录后再次粘贴"
        return empty
    if err == "nocampaign":
        empty["error"] = "当前没有进行中的签到活动（活动可能已结束）"
        return empty
    if err:
        empty["error"] = "获取签到活动配置失败（网络异常），请稍后重试"
        return empty

    data, derr = _landing(ent, code)
    if data is None:
        empty["error"] = derr
        return empty

    signed = data.get("chosen_type") == CH_DONE
    title, content, buttons = _page_text(data)
    reward = _parse_reward(title)
    if reward is None:
        reward = _parse_reward(content)

    return {
        "name": name, "ok": True, "error": None,
        "level": "豆包",
        "signed_today": signed,
        # 豆包没有对外开放的余额查询接口（签到额度在活动页内），
        # credits 保持 0——奖励信息走 extra，不编造数字。
        "credits": {"remain": 0, "total": 0, "used": 0},
        "packages": [],
        "extra": {
            "phone": _phone,
            "can_sign_in": not signed,
            "campaign_group_code": code,
            "checkin_title": title,
            "checkin_content": content,
            "checkin_buttons": buttons,
            "today_reward": reward,
        },
    }


# ───────────────────────── 任务 ─────────────────────────
def _checkin_via_browser(ent, reason):
    """API 失败后降级到浏览器签到：注入已保存 Cookie 打开签到页（pc/agent-explore）。"""
    if browser_checkin is None:
        return {"ok": False, "msg": (reason or "签到失败") + "（且无浏览器兜底模块）"}
    ok, msg, _ = browser_checkin("doubao", cookie_of(ent))
    if ok:
        return {"ok": True, "msg": msg, "flag": "SUCCESS_BROWSER"}
    return {"ok": False, "msg": (reason or "签到失败") + "；浏览器兜底：" + msg}


def run_task(name, ent, task_key):
    if task_key != "checkin":
        return {"ok": False, "msg": "未知任务"}
    if not cookie_of(ent):
        return {"ok": False, "msg": "未配置豆包 Cookie"}

    code, err = _resolve_code(ent)
    if err == "login":
        # Cookie 失效：API 与浏览器兜底都救不了，直接让用户重登
        return {"ok": False, "msg": "Cookie 已失效，请在豆包网页版（doubao.com）重新登录后再次粘贴"}
    if err == "nocampaign":
        return {"ok": False, "msg": "当前没有进行中的签到活动（活动可能已结束）"}
    if err:
        # 网络/反爬类异常：降级浏览器兜底
        return _checkin_via_browser(ent, "获取签到活动配置失败（%s）" % err)

    # 先查状态，已签到就不重复请求
    data, derr = _landing(ent, code)
    if data is None:
        return _checkin_via_browser(ent, derr)
    if data.get("chosen_type") == CH_DONE:
        title = str((data.get("complete_page_info") or {}).get("title") or "")
        return {"ok": True, "msg": "今日已签到（豆包）" + ("· " + title if title else ""),
                "flag": "ALREADY_TODAY"}

    st, j = _req(ent, EP_LANDING_CHECKIN, {"scene": code})
    if st == -1 or not isinstance(j, dict):
        return _checkin_via_browser(ent, "签到请求失败（HTTP %s）" % st)
    if not _ok_code(j.get("code")):
        login_msg = _login_text(j)
        if login_msg:
            # 登录态问题：浏览器兜底也救不了，直接报
            return {"ok": False, "msg": login_msg}
        # 其它（反爬 710022002 / 未知码）→ 浏览器兜底
        return _checkin_via_browser(
            ent, "API 签到失败（%s），尝试浏览器兜底" % (str(j.get("msg") or j.get("code"))[:80]))
    rdata = j.get("data") or {}
    if not (isinstance(rdata, dict) and rdata.get("checked_in")):
        return _checkin_via_browser(ent, "API 返回未完成，尝试浏览器兜底")

    # 成功后补一次落地页读取，拿「已完成」页的奖励文案（失败不影响成功判定）
    reward = _parse_reward(str((rdata.get("complete_page_info") or {}).get("title") or ""))
    if reward is None:
        data2, _ = _landing(ent, code)
        if data2 is not None and data2.get("chosen_type") == CH_DONE:
            reward = _parse_reward(str((data2.get("complete_page_info") or {}).get("title") or ""))
    msg = "签到成功" + ("，+%s 额度" % (int(reward) if isinstance(reward, float) and reward == int(reward) else reward)
                       if reward is not None else "（豆包）")
    return {"ok": True, "msg": msg, "flag": "SUCCESS", "gain": reward}


if __name__ == "__main__":
    accs = load_accounts()
    print("账号:", list(accs.keys()))
    for nm, ent in accs.items():
        r = read_account(nm, ent)
        print("[%s] ok=%s signed=%s 活动码=%s 标题=%r err=%s"
              % (nm, r["ok"], r["signed_today"],
                 (r["extra"] or {}).get("campaign_group_code"),
                 (r["extra"] or {}).get("checkin_title"), r["error"]))
