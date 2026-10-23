# -*- coding: utf-8 -*-
"""
受控浏览器辅助登录（可选依赖：playwright）
═════════════════════════════════════════════════════════════════════════
为什么需要它：
  部分平台没有对本地脚本开放的「短信验证码」登录接口，它们的登录态本质是
  「网页端登录后的 cookie」。这里改用「受控浏览器」方案：后端拉起一个可见的
  Chromium，用户在真实登录页用手机验证码完成登录，我们自动抓取登录后的凭据并落盘。

  · lingxi：打开 account.wps.cn → WPS（手机号+短信验证码）登录 → 抓 wps_sid

  为什么【没有】DuMate 的浏览器登录入口（用户反馈后已删除）：
  百度搭子 DuMate **没有网页版**，只有桌面客户端；登录时走的是「客户端内嵌的
  百度 passport 网页视图」，登录态落在 dumate 域会话里。独立浏览器打开 dumate.cn
  只能看到「下载客户端」页，拿不到 dumate 域会话——早期版本那个入口是死链。
  所以 DuMate 的可靠路径是「从本地客户端导入」（解密桌面端 Cookie，含 BDUSS），
  而不是浏览器登录。

playwright 仅在调用本模块时才 import，未安装不影响看板其余功能；
普通「粘贴 token/cookie」/「从本地客户端导入」添加方式也不依赖它。

注：MiniMax / ZCode / Qoder 走各自的 OAuth 设备码（看板内「一键登录」），
不在这里——它们的登录页是各平台真实授权页（account.minimax.cn /
zcode.z.ai / qoder.cn），与桌面端同源，比受控浏览器抓 cookie 更稳。
"""
import json
import os
import re
import time

# ── WorkBuddy AI（国际版）：网页 OAuth 登录 ────────────────────────────────
# 流程（2026-10-19 实测打通）：
#   /login/?platform=website&state=2&product=workbuddy
#     → Keycloak SSO（Google / GitHub / X）→ /login/select
#     → SPA 调 GET /console/login/enterprise?state=2
#     → 响应体 {"data":{"accessToken":..,"refreshToken":..,"expiresIn":..}}
# 注意：/v3/config 是公开接口，拿它验证会假阳性；必须用鉴权接口
#      POST /v2/billing/meter/get-user-resource（code=0 才算真可用）。
WBAI_LOGIN_URL = "https://www.workbuddy.ai/login/?platform=website&state=2&product=workbuddy"
WBAI_RES_URL = "https://www.workbuddy.ai/v2/billing/meter/get-user-resource"
WBAI_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}")
WBAI_HEAD = {"Content-Type": "application/json",
             "Accept": "application/json, text/plain, */*",
             "X-Domain": "https://www.workbuddy.ai", "X-Product": "SaaS",
             "X-Env-ID": "production",
             "User-Agent": "VSCode/1.119.0 WorkBuddy/4.9.29177644"}


def _install_hint():
    return ("缺少 playwright，无法使用浏览器登录。请先安装：\n"
            "  pip install playwright\n"
            "  playwright install chromium\n"
            "（仅浏览器登录功能需要；也可直接「粘贴 token/cookie」或「从本地客户端导入」添加）")


def _cookie_named(context, name):
    """跨域抓取某个名字的 cookie 值（WPS 的 wps_sid 可能在 .wps.cn / account.wps.cn 等域）。"""
    try:
        for c in context.cookies():
            if c.get("name") == name and c.get("value"):
                return c["value"]
    except Exception:
        pass
    return None


def _build_cookie_string(cookies, domains):
    """从 cookie 列表里挑出属于指定域的，拼成 'a=b; c=d' 串（去重保序）。

    纯函数（不依赖 playwright），便于单测。domains 按 endswith 匹配，
    故 ".doubao.com" 能同时命中 ".doubao.com" 与 "www.doubao.com"。
    """
    out = []
    seen = set()
    for c in cookies:
        dom = (c.get("domain") or "").lower()
        if not any(dom == d or dom.endswith(d) for d in domains):
            continue
        if not c.get("value"):
            continue
        kv = "%s=%s" % (c["name"], c["value"])
        if kv not in seen:
            seen.add(kv)
            out.append(kv)
    return "; ".join(out)


def _cookie_string_for_domains(context, domains):
    """包一层 context.cookies() 的安全调用（供浏览器登录主循环使用）。"""
    try:
        return _build_cookie_string(context.cookies(), domains)
    except Exception:
        return ""


# 各平台浏览器登录配置：新增平台只需加一项，不必再写一份几乎相同的函数
#   capture:
#     "single" —— 抓单个命名 cookie（如 wps_sid），记为该字段值
#     "full"   —— 抓整条 Cookie 串（如豆包 sessionid 体系），登录标志 cookie
#                 落地后才算数，取指定域下全部 cookie 拼成 'a=b; c=d'
#   login_cookie: 登录成功的标志 cookie 名（"full" 模式用；兼容其 _ss 变体）
#   domains: "full" 模式取哪些域的 cookie（按 endswith 匹配）
_BROWSER_LOGIN_CFG = {
    "lingxi": {
        "url": "https://account.wps.cn/",
        "tip": "WPS（手机号 + 短信验证码）",
        "capture": "single",         # 抓单个命名 cookie（wps_sid）
        "locale": "zh-CN",
        "cookie_name": "wps_sid",
        "ok_msg": "已抓取并保存 WPS 灵犀登录态（wps_sid）",
    },
    # 豆包：弹可见浏览器 → 用户在真实登录页手动登录（看板**不代点**任何按钮）
    #   → 检测 sessionid / sessionid_ss 落地 → 抓整条 Cookie 串落盘。
    #   与普通「粘贴 Cookie」等价，但省去用户 F12 复制；全程手动，规避滑块风控。
    "doubao": {
        "url": "https://www.doubao.com/chat/",
        "tip": "豆包（手机号 + 验证码 / 扫码，全程你手动操作）",
        "capture": "full",           # 抓整条 Cookie 串
        "locale": "zh-CN",
        "login_cookie": "sessionid", # 落地即视为已登录（兼容 sessionid_ss）
        "domains": [".doubao.com", "doubao.com", "www.doubao.com"],
        "deadline": 360,             # 手动登录给足时间
        "ok_msg": "已抓取并保存豆包登录态（Cookie）",
    },
}


# ── 浏览器签到兜底（2026-10-22 增补）──────────────────────────────────────
# 背景：豆包 REST API 在 shark_admin 反爬下对自动化请求返回 710022002 / 滑块
# 验证码（DoubaoCLI、doubao2api 均有记载），纯 HTTP 签到不稳。但「在已登录的
# 浏览器会话里访问签到页」却能稳定领奖（doubao-manager 的 checkinType:'visit'
# 即「访问即得」）。故签到采用「API 主 + 浏览器兜底」：平台适配器先试 HTTP
# API，失败再降级到这里——注入已保存的登录 Cookie 打开签到页，检测到成功文案
# 即算领到（必要时按用户授权自动点「签到」按钮）。
_BROWSER_CHECKIN_CFG = {
    "doubao": {
        "url": "https://www.doubao.com/pc/agent-explore",
        "domains": [".doubao.com", "doubao.com", "www.doubao.com"],
        "locale": "zh-CN",
        # 成功判定：页面 DOM 出现以下任一文案（截图已确认「签到成功，获得 200 额度」）
        "success_texts": ["签到成功", "已签到", "领取成功", "200 额度", "今日已签"],
        # 若页面有「签到」按钮且尚未自动发奖，则自动点（用户已授权自动点）
        "click_texts": ["签到", "立即签到", "去签到", "马上签到", "点击签到"],
        "deadline": 120,
        "ok_msg": "浏览器访问豆包 agent-explore 已完成签到（200 额度）",
    },
}


def _parse_cookie_pairs(cookie_str):
    """'a=b; c=d' → [('a','b'),('c','d')]。纯函数，便于单测。"""
    out = []
    for part in (cookie_str or "").split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out.append((k.strip(), v.strip()))
    return out


def _build_checkin_cookies(pairs, domains):
    """把 cookie 键值对展开成 playwright add_cookies 所需的 dict 列表
    （每个域一份）。纯函数。"""
    cookies = []
    for k, v in pairs:
        if not k:
            continue
        for d in (domains or []):
            cookies.append({"name": k, "value": v, "domain": d, "path": "/"})
    return cookies


def _contains_any(text, subs):
    """纯函数：text 是否包含 subs 中任一子串。"""
    t = text or ""
    return any(s and s in t for s in subs)


def browser_checkin(platform, cookie, progress=None):
    """注入已保存的登录 Cookie 打开签到页，检测成功文案（必要时自动点「签到」）。

    progress(status, text)：可选进度回传，status ∈ {opening,clicking,capturing,error}
    返回 (ok:bool, msg:str, cred:str|None)
    """
    cfg = _BROWSER_CHECKIN_CFG.get(platform)
    if not cfg:
        return False, "该平台暂不支持浏览器签到（仅 %s）" % "、".join(_BROWSER_CHECKIN_CFG), None
    pairs = _parse_cookie_pairs(cookie)
    if not pairs:
        return False, "未配置 Cookie，无法注入登录态", None
    ck = _build_checkin_cookies(pairs, cfg.get("domains"))
    if not ck:
        return False, "Cookie 解析为空，无法注入登录态", None

    try:
        from playwright.sync_api import sync_playwright  # noqa
    except Exception:
        return False, _install_hint(), None

    if progress:
        progress("opening", "已打开浏览器，正在注入登录态并访问签到页…")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=False,
                args=["--disable-blink-features=AutomationControlled"])
            ctx = browser.new_context(**({"locale": cfg["locale"]} if cfg.get("locale") else {}))
            try:
                ctx.add_cookies(ck)
            except Exception as e:
                try:
                    browser.close()
                except Exception:
                    pass
                return False, "注入 Cookie 失败：" + str(e)[:120], None
            page = ctx.new_page()
            try:
                page.goto(cfg["url"], wait_until="domcontentloaded", timeout=30000)
            except Exception:
                pass  # 页面可能重定向/有壳，继续轮询

            deadline = time.time() + (cfg.get("deadline") or 120)
            clicked = False
            ok = False
            while time.time() < deadline:
                html = _safe_html(page)
                if _contains_any(html, cfg["success_texts"]):
                    ok = True
                    break
                if not clicked and not _contains_any(html, ["签到成功", "已签到"]):
                    if _click_signin_btn(page, cfg["click_texts"]):
                        clicked = True
                        if progress:
                            progress("clicking", "已点击签到按钮，等待领取…")
                time.sleep(2)

            try:
                browser.close()
            except Exception:
                pass
            if ok:
                if progress:
                    progress("capturing", "检测到签到成功")
                return True, cfg["ok_msg"], None
            return False, "浏览器访问签到页超时，未检测到签到成功文案（请手动确认）", None
    except Exception as e:
        return False, "浏览器签到异常：" + str(e)[:160], None


def _safe_html(page):
    try:
        return page.content() or ""
    except Exception:
        return ""


def _click_signin_btn(page, texts):
    """在页面里找一个含签到文案的可点击元素并点。返回是否点到。"""
    for t in (texts or []):
        try:
            loc = page.locator(
                "button, [role='button'], a, .sign-btn, .checkin-btn").filter(has_text=t)
            if loc.count() > 0:
                loc.first.click(timeout=4000, force=False)
                return True
        except Exception:
            continue
    return False


def _wbai_profile_dir():
    """浏览器登录专用持久 profile：登录态留在这里，下次点登录可免密直接过 SSO。"""
    try:
        import data_dir
        return data_dir.path("wbai_browser_profile")
    except Exception:
        return os.path.join(os.path.expanduser("~"), ".wbai_browser_profile")


def _wbai_validate(tok):
    """鉴权接口验证（/v3/config 是公开接口，不能用它验）。"""
    try:
        import requests
        r = requests.post(WBAI_RES_URL, headers=dict(WBAI_HEAD, Authorization="Bearer " + tok),
                          json={}, timeout=25, verify=False,
                          proxies={"http": None, "https": None})
        if r.status_code == 200:
            return r.json().get("code") == 0
        return False
    except Exception:
        return False


def _wbai_claims(tok):
    import base64
    try:
        seg = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception:
        return {}


def _wbai_login(progress):
    """WorkBuddy AI 网页登录：弹可见 Chromium → 用户点 GitHub 授权 →
    拦截 /console/login/enterprise 的 accessToken/refreshToken 响应。
    返回 (ok, msg, json 字符串凭据)。"""
    try:
        from playwright.sync_api import sync_playwright  # noqa
    except Exception:
        return False, _install_hint(), None

    progress("opening", "已打开浏览器，请点「GitHub」完成授权（窗口里操作，最多等 5 分钟）…")
    hit = None
    seen = set()
    last_url = [""]

    def log_url(u):
        if u != last_url[0]:
            last_url[0] = u
            progress("opening", "登录中…（%s）" % (u.split("?")[0][:60]))

    try:
        with sync_playwright() as p:
            ctx = p.chromium.launch_persistent_context(
                _wbai_profile_dir(), headless=False,
                viewport={"width": 1180, "height": 860},
                args=["--disable-blink-features=AutomationControlled"])
            page = ctx.pages[0] if ctx.pages else ctx.new_page()

            def on_resp(resp):
                nonlocal hit
                if hit:
                    return
                u = resp.url
                try:
                    ct = (resp.headers or {}).get("content-type", "")
                except Exception:
                    ct = ""
                if "json" not in ct:
                    return
                if not any(k in u for k in ("login", "auth", "token", "oauth")):
                    return
                try:
                    body = resp.text()
                except Exception:
                    return
                if "ccessToken" not in body and "refreshToken" not in body:
                    return
                try:
                    j = json.loads(body)
                except Exception:
                    return
                d = (j.get("data") or {}) if isinstance(j, dict) else {}
                at = d.get("accessToken") or d.get("access_token") or ""
                if not at or at in seen:
                    return
                seen.add(at)
                if _wbai_validate(at):
                    hit = {"token": at,
                           "refresh_token": d.get("refreshToken") or d.get("refresh_token") or "",
                           "src": u[:90]}
                    progress("capturing", "检测到登录成功，正在保存…")

            page.on("response", on_resp)
            page.on("framenavigated",
                    lambda f: log_url(f.url) if f == page.main_frame else None)

            page.goto(WBAI_LOGIN_URL, wait_until="domcontentloaded", timeout=45000)
            deadline = time.time() + 300
            while time.time() < deadline and not hit:
                page.wait_for_timeout(1500)

            try:
                ctx.close()
            except Exception:
                pass
    except Exception as e:
        return False, "浏览器登录异常：" + str(e)[:160], None

    if not hit:
        return False, "等待登录超时（5 分钟）。请在弹出的浏览器里点 GitHub 完成授权后重试。", None

    cl = _wbai_claims(hit["token"])
    cred = {"token": hit["token"], "refresh_token": hit["refresh_token"],
            "user_id": str(cl.get("sub") or ""), "domain": "www.workbuddy.ai",
            "via_browser": True,
            "expires_at": time.strftime("%Y-%m-%d %H:%M",
                                        time.localtime(cl.get("exp") or time.time() + 30 * 86400))}
    return True, "已抓取 WorkBuddy AI 登录态（%s）" % (cl.get("preferred_username") or "已登录"), \
        json.dumps(cred, ensure_ascii=False)


def browser_login(platform, progress):
    """启动受控 Chromium 打开对应登录页，等用户登录后抓凭据。

    progress(status, text)：回传进度，status ∈ {opening,capturing,error}
    返回 (ok:bool, msg:str, cred:str|None)
    """
    if platform == "workbuddy_ai":
        return _wbai_login(progress)

    cfg = _BROWSER_LOGIN_CFG.get(platform)
    if not cfg:
        return False, "不支持的平台（浏览器登录仅支持 %s）" % \
            "、".join(list(_BROWSER_LOGIN_CFG) + ["workbuddy_ai"]), None

    progress("opening", "已打开浏览器，请在弹出的登录页用「%s」登录"
                        "（若弹出滑块验证，手动过一下）…" % cfg["tip"])
    try:
        from playwright.sync_api import sync_playwright  # noqa
    except Exception:
        progress("error", "未安装 playwright")
        return False, _install_hint(), None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            ctx = browser.new_context(**({"locale": cfg["locale"]} if cfg.get("locale") else {}))
            page = ctx.new_page()
            page.goto(cfg["url"], wait_until="domcontentloaded", timeout=30000)

            deadline = time.time() + (cfg.get("deadline") or 180)
            login_name = cfg.get("login_cookie", "")
            cred = None
            while time.time() < deadline:
                if cfg.get("capture") == "full":
                    # 抓整条 Cookie：登录标志 cookie（及其 _ss 变体）落地后才算捕获成功
                    ok_login = (_cookie_named(ctx, login_name) or
                                _cookie_named(ctx, login_name + "_ss")) if login_name else True
                    cred = _cookie_string_for_domains(ctx, cfg.get("domains") or []) if ok_login else None
                else:
                    cred = _cookie_named(ctx, cfg.get("cookie_name", ""))
                if cred:
                    break
                time.sleep(2)

            try:
                browser.close()
            except Exception:
                pass

            if not cred:
                return False, "等待登录超时（%d 秒）。请在弹出的浏览器完成登录后重试。" \
                              % (cfg.get("deadline") or 180), None
            progress("capturing", "检测到登录成功，正在保存…")
            return True, cfg["ok_msg"], cred
    except Exception as e:
        return False, "浏览器登录异常：" + str(e)[:160], None
