# -*- coding: utf-8 -*-
"""ZCode（z.ai）短信直登：cli/init 流 + 弹窗代点（2026-10-08 侦察实测 DOM）—— 二期拆分。"""
import json
import time
import os
import uuid
import base64
import hashlib
import secrets
import threading
import subprocess
import urllib.parse
import http.server
import re

try:
    import requests
except ImportError:
    requests = None

try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass
from oauth_common import (
    DEVICE_GRANT_TYPE, PROVIDERS, UA, _CODE_SEL, _JOBS, _OFFSCREEN_ARGS, _PHONE_SEL, _click_consent, _click_text, _consent_checked, _first_sel, _has_captcha, _job_lock, _login_submitted, _new_job, _origin, _pkce, _post_form, _provider, _pull_window_front, _view, get_job, submit_code,
)
from oauth_shared import _CODEARTS_DEBUG_LOCK, _CODEARTS_DEBUG_LOG, _codearts_debug, _qoder_has_captcha, _trae_find_token
from oauth_device import _cli_poll_start, device_poll


# ──────────── ZCode（z.ai）短信直登：cli/init 流 + 弹窗代点（2026-10-08 侦察实测 DOM）────────────
# zai（chat.z.ai/auth）：input[type=tel] 手机号 / input[placeholder*=验证码] /
#   「发送验证码」DIV /「登录」DIV，无协议复选框（文案即同意）。
# bigmodel（bigmodel.cn/login）：#tab-sms 默认激活 / input[placeholder*=手机号] /
#   「获取验证码」/「登录 / 注册」；发送时可能弹腾讯滑块（tcaptcha 容器常驻 DOM，
#   必须按尺寸判可见，否则每次都误判成弹了验证码）。
# 令牌走既有 cli_poll 轮询（device_poll → _cli_poll_once），与「打开授权网页」同源。

_ZCODE_PAGE_SEL = {
    "zai": {"phone": "input[type='tel']",
            "code": "input[placeholder*='验证码']",
            "send": ["发送验证码"], "login": ["登录"]},
    "bigmodel": {"phone": "input[placeholder*='手机号']",
                 "code": "input[placeholder*='验证码']",
                 "send": ["获取验证码"], "login": ["登录 / 注册", "登录"]},
}


def start_zcode_sms_job(phone, sub, on_success, name=""):
    """ZCode 手机号+短信直登入口（server.py sms_start 的 zcode 分支调用）。"""
    phone = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if len(phone) != 11:
        return False, "请填写 11 位手机号（当前：%s）" % (phone or "空"), None
    sub = sub if sub in _ZCODE_PAGE_SEL else "zai"
    ok, msg, flow = _cli_poll_start("zcode", sub)
    if not ok:
        return False, msg, None
    job = _new_job("zcode", flow)
    job.update(mode="sms", phone=phone, name=name or "")
    with _job_lock:
        _JOBS[job["job"]] = job
    threading.Thread(target=_run_zcode_sms_job,
                     args=(job, flow, phone, on_success), daemon=True).start()
    return True, "已发起 ZCode 短信登录", _view(job)


def _zcode_captcha_visible(ctx):
    """登录页滑块/图片验证码是否真的弹出。tcaptcha 容器常驻 DOM，须按尺寸/透明度判可见。"""
    js_vis = ("() => { const e = document.getElementById('tcaptcha_transform_dy')"
              " || document.querySelector('[id*=tcaptcha],[class*=tcaptcha]');"
              " if (!e) return false;"
              " const r = e.getBoundingClientRect();"
              " const st = getComputedStyle(e);"
              " return r.width > 120 && r.height > 60 && st.display !== 'none'"
              " && st.visibility !== 'hidden' && parseFloat(st.opacity || '1') > 0.1; }")
    try:
        for pg in ctx.pages:
            try:
                if pg.evaluate(js_vis):
                    return True
            except Exception:
                pass
            try:
                if pg.evaluate("() => !!document.querySelector("
                               "'[class*=geetest_panel], [class*=geetest_widget]')"):
                    return True
            except Exception:
                pass
            for f in pg.frames:
                u = (f.url or "")
                if ("captcha" in u or "geetest" in u or "punish" in u) \
                        and "bigmodel" not in u:
                    return True
    except Exception:
        pass
    return False


def _zcode_click_authorize(ctx):
    """Z.ai 授权页（chat.z.ai/auth/oauth/authorize）的最后一步：勾协议 + 点「继续」。

    2026-10-08 用户实测：验证码登录成功后跳到该页，必须先勾选「用户协议和隐私政策」
    复选框，再点【继续】，令牌才会下发。两个动作缺一不可，否则轮询永远 pending。

    注意：
      · 只在 URL 含 authorize/oauth/consent 的页面动作，避免误点登录表单页；
        但「oauth」过于宽泛（CLI 登录链路本身也走 /oauth/... 路径），因此改为要求
        同时命中「授权页特征」：路径含 authorize/consent，或主机属 chat.z.ai 且路径含 oauth；
      · 复选框可能是自定义元素（非原生 input），先试原生 check()，再 JS 兜底置 checked
        并派发 change/click 事件（很多前端框架靠事件监听刷新按钮可用态）；
      · 按钮点「继续」优先，其次「同意 / 授权 / 确认」。
    返回 True 表示本轮至少完成了一次「勾选 + 点击」。
    """
    def _is_authorize_page(u):
        ul = u.lower()
        if "authorize" in ul or "consent" in ul:
            return True
        # chat.z.ai 的授权页形如 /auth/oauth/authorize?...；单凭 "oauth" 不算，避免误伤
        return ("chat.z.ai" in ul and "/oauth/" in ul and "authorize" in ul)

    did = False
    for pg in ctx.pages:
        u = (pg.url or "")
        if not _is_authorize_page(u):
            continue
        for target in [pg] + [f for f in pg.frames if f is not pg.main_frame]:
            # ① 勾选协议复选框：先用原生 input[type=checkbox]
            try:
                cbs = target.locator("input[type='checkbox']")
                for i in range(min(cbs.count(), 4)):
                    cb = cbs.nth(i)
                    try:
                        if not cb.is_checked():
                            cb.check(timeout=1200)
                            did = True
                    except Exception:
                        try:
                            cb.click(timeout=1000)
                            did = True
                        except Exception:
                            pass
            except Exception:
                pass
            # ①b JS 兜底：自定义 checkbox / 被样式隐藏的原生框，强制勾选并派发事件
            try:
                target.evaluate(
                    "() => {"
                    " const boxes = Array.from(document.querySelectorAll("
                    "   'input[type=checkbox],[role=checkbox],[class*=checkbox],"
                    "   [class*=agree],[class*=consent],[class*=protocol]'));"
                    " for (const b of boxes) {"
                    "   const isInput = b.tagName === 'INPUT';"
                    "   const on = isInput ? b.checked : (b.getAttribute('aria-checked') === 'true');"
                    "   if (!on) {"
                    "     if (isInput) { b.checked = true; }"
                    "     else { b.setAttribute('aria-checked','true'); }"
                    "     b.dispatchEvent(new Event('input',  {bubbles:true}));"
                    "     b.dispatchEvent(new Event('change', {bubbles:true}));"
                    "     b.click && b.click();"
                    "   }"
                    " } }")
            except Exception:
                pass
            # ② 点「继续 / 同意 / 授权 / 确认」
            #    归一化匹配优先（去空白）：antd 等框架会把「继续」渲染成「继 续」，
            #    用 :has-text('继续') 会失配（2026-10-08 Qoder 同款坑）。
            try:
                el = target.evaluate_handle(
                    "(targets) => {"
                    " const norm = s => (s || '').replace(/\\s+/g, '').replace(/\\u3000/g, '');"
                    " const els = Array.from(document.querySelectorAll('button,a,[role=button]'));"
                    " for (const t of targets) {"
                    "   const hit = els.find(e => norm(e.innerText) === t || norm(e.textContent) === t);"
                    "   if (hit) return hit;"
                    " }"
                    " return null;"
                    "}",
                    ["继续", "同意并继续", "同意授权", "同意", "授权", "确认", "Authorize", "Continue"])
                jsd = el.as_element() if el else None
                if jsd:
                    try:
                        jsd.click(timeout=900)
                        did = True
                    except Exception:
                        try:
                            jsd.evaluate("e => e.click()")
                            did = True
                        except Exception:
                            pass
            except Exception:
                pass
            if did:
                return True
            for txt in ("继续", "同意并继续", "同意授权", "同意", "授权", "确认", "Authorize", "Continue"):
                for sel in ("button", "a", "[role=button]"):
                    try:
                        loc = target.locator("%s:has-text('%s')" % (sel, txt))
                        if loc.count():
                            loc.first.click(timeout=900)
                            did = True
                            break
                    except Exception:
                        continue
                if did:
                    break
            if did:
                return True
    return False


def _run_zcode_sms_job(job, flow, phone, on_success):
    try:
        from playwright.sync_api import sync_playwright  # 延迟导入
    except Exception:
        job.update(status="done", finished=True, ok=False,
                   result="缺少 playwright，无法拉起登录窗口。请 pip install playwright")
        return

    sub = flow.get("sub") if flow.get("sub") in _ZCODE_PAGE_SEL else "zai"
    sel = _ZCODE_PAGE_SEL[sub]
    deadline = time.time() + flow["expires_in"] + 150
    interval = 2.0
    browser = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False, args=_OFFSCREEN_ARGS)
            ctx = browser.new_context(locale="zh-CN",
                                      viewport={"width": 560, "height": 840})
            page = ctx.new_page()
            job["status"] = "opening"
            job["result"] = "已打开登录窗口，正在进入 %s 登录页…" % (
                "Z.ai" if sub == "zai" else "智谱 BigModel")
            page.goto(flow["verify_url"], wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(1500)

            # ① 填手机号（bigmodel 短信 tab 默认激活；保险起见未激活就点一下）
            form_ok = True
            try:
                t = page.locator("#tab-sms")
                if t.count() and "is-active" not in (t.get_attribute("class") or ""):
                    t.click(timeout=2000)
                    page.wait_for_timeout(600)
            except Exception:
                pass
            try:
                page.wait_for_selector(sel["phone"], state="visible", timeout=10000)
                page.fill(sel["phone"], phone, timeout=5000)
            except Exception:
                form_ok = False
                job["result"] = ("没找到手机号输入框（页面可能改版），已把窗口拉回屏幕；"
                                 "请在窗口里手动完成登录，看板会继续自动接管令牌")
                _pull_window_front(ctx)
                job.update(sms_sent=True, need_code=False)

            if form_ok:
                job["result"] = "手机号已填入，正在点「%s」…" % sel["send"][0]
                # ② 点发送验证码（弹滑块时把窗口拉回让人工完成）
                if not _click_text(page, sel["send"], timeout=3500):
                    job["result"] = ("没点动「%s」，请在窗口里手动点一下发送。"
                                     % sel["send"][0])
                    _pull_window_front(ctx)
                page.wait_for_timeout(1200)
                cap = (_zcode_captcha_visible(ctx) or _qoder_has_captcha(ctx))
                if cap:
                    _pull_window_front(ctx)
                job.update(status="waiting_code", sms_sent=True, need_code=True,
                           captcha=cap,
                           result=("窗口弹出了滑块/图片验证码，请先在窗口里完成，短信才会发出。"
                                   if cap else
                                   "验证码已发送 📩 请在下方填入短信验证码"
                                   "（若没收到，看看窗口是否弹了验证码）"))

            # ③ 主循环：等验证码 → 提交 → 轮询令牌（cli_poll 与「打开授权网页」共用）
            last_poll = 0.0
            while time.time() < deadline:
                now = time.time()
                if form_ok and job.get("code") and not job.get("code_submitted"):
                    try:
                        page.fill(sel["code"], str(job["code"]), timeout=4000)
                        page.wait_for_timeout(300)
                        if _click_text(page, sel["login"], timeout=2500):
                            job["code_submitted"] = True
                            job["need_code"] = False
                            job["result"] = "已提交验证码，正在登录…"
                    except Exception:
                        pass  # 表单可能已随登录跳转销毁，交给轮询
                if form_ok and job.get("code_submitted"):
                    cap2 = _zcode_captcha_visible(ctx)
                    if cap2 and not job.get("captcha"):
                        _pull_window_front(ctx)
                        job["result"] = "登录时弹出滑块/图片验证码，请先在窗口里完成…"
                    job["captcha"] = cap2
                    # ④ 登录成功后 Z.ai 会跳到授权页（chat.z.ai/auth/oauth/authorize）：
                    #    必须【勾选「用户协议和隐私政策」复选框】再点【继续】才会下发令牌，
                    #    否则页面一直停着、轮询永远 pending —— 2026-10-08 用户实测。
                    #    该页在 chat.z.ai 域；登录表单所在的 zcode.z.ai 页不含此步，因此
                    #    仅在「当前 URL 含 authorize/oauth/consent」时才动作，避免误点登录页。
                    if _zcode_click_authorize(ctx) and not job.get("auth_clicked"):
                        job["auth_clicked"] = True
                        job["result"] = "已勾选协议并点「继续」，等待令牌下发…"
                    elif job.get("auth_clicked"):
                        job["result"] = "已点「继续」，等待令牌下发…"
                if now - last_poll >= interval:
                    last_poll = now
                    state, d = device_poll(flow)
                    if state == "ok":
                        grant = {
                            "access_token": str(d.get("access_token") or ""),
                            "refresh_token": str(d.get("refresh_token") or ""),
                            "token_type": str(d.get("token_type") or "Bearer"),
                            "expires_in": d.get("expires_in"),
                            "scope": "",
                            "zai": d.get("zai") or {},
                        }
                        try:
                            ok2, name, msg2 = on_success(grant)
                        except Exception as e:
                            ok2, name, msg2 = False, "", "保存登录态异常：%s" % str(e)[:150]
                        job.update(status="done", finished=True, ok=bool(ok2),
                                   result=msg2 or ("已保存 %s" % name), name=name or "")
                        try:
                            browser.close()
                        except Exception:
                            pass
                        return
                    if state == "slow_down":
                        interval += 2
                    # error（偶发网络/未完成）不中断，继续轮询
                page.wait_for_timeout(700)

            if not job.get("finished"):
                job.update(status="done", finished=True, ok=False,
                           result="登录超时，请重新发起（登录链接已过期）")
            try:
                browser.close()
            except Exception:
                pass
    except Exception as e:
        job.update(status="done", finished=True, ok=False,
                   result="短信登录异常：%s" % str(e)[:200])
        try:
            if browser:
                browser.close()
        except Exception:
            pass
