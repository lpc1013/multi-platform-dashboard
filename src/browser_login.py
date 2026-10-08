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
import time


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


def browser_login(platform, progress):
    """启动受控 Chromium 打开对应登录页，等用户登录后抓凭据。

    progress(status, text)：回传进度，status ∈ {opening,capturing,error}
    返回 (ok:bool, msg:str, cred:str|None)
    """
    cfg = _BROWSER_LOGIN_CFG.get(platform)
    if not cfg:
        return False, "不支持的平台（浏览器登录仅支持 %s）" % "、".join(_BROWSER_LOGIN_CFG), None

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
