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


# 各平台浏览器登录配置：新增平台只需加一项，不必再写一份几乎相同的函数
_BROWSER_LOGIN_CFG = {
    "lingxi": {
        "url": "https://account.wps.cn/",
        "tip": "WPS（手机号 + 短信验证码）",
        "capture": "single",         # 抓单个命名 cookie（wps_sid）
        "locale": "zh-CN",
        "cookie_name": "wps_sid",
        "ok_msg": "已抓取并保存 WPS 灵犀登录态（wps_sid）",
    },
}


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

            deadline = time.time() + 180
            cred = None
            while time.time() < deadline:
                cred = _cookie_named(ctx, cfg.get("cookie_name", ""))
                if cred:
                    break
                time.sleep(2)

            try:
                browser.close()
            except Exception:
                pass

            if not cred:
                return False, "等待登录超时（180 秒）。请在弹出的浏览器完成登录后重试。", None
            progress("capturing", "检测到登录成功，正在保存…")
            return True, cfg["ok_msg"], cred
    except Exception as e:
        return False, "浏览器登录异常：" + str(e)[:160], None
