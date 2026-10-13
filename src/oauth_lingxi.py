# -*- coding: utf-8 -*-
"""灵犀（WPS）网页短信直登 —— 二期拆分自 oauth_login.py。"""
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


# ═══════════════ 灵犀（WPS）网页短信直登 ═══════════════
# account.wps.cn 默认微信扫码页 → 点「手机」tab → #phone / #smartCaptchaBtn（发码）
# → #code / #confirmCode（立即登录/注册）→ 抓 wps_sid cookie。
# 用户只在看板填手机号 + 验证码，弹窗只是自动代点（与 MiniMax/Qoder/DuMate 同模式）。

_LINGXI_LOGIN_URL = "https://account.wps.cn/"


def _lingxi_new_job(name):
    job = {
        "job": uuid.uuid4().hex[:12], "platform": "lingxi",
        "mode": "sms", "status": "waiting", "finished": False,
        "ok": None, "result": "", "name": name, "started": time.time(),
        "user_code": "", "verify_url": _LINGXI_LOGIN_URL,
        "expires_in": 360,
        "hint": "在弹出的窗口里完成 WPS 手机号短信登录，看板自动抓取 wps_sid",
        "phone": "", "need_code": False, "code": None, "code_submitted": False,
        "sms_sent": False,
    }
    with _job_lock:
        _JOBS[job["job"]] = job
    return job


def start_lingxi_sms_job(phone, name, on_success):
    """灵犀网页短信直登入口（server.py sms_start 的 lingxi 分支调用）。"""
    phone = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if len(phone) != 11:
        return False, "请填写 11 位手机号（当前：%s）" % (phone or "空"), None
    job = _lingxi_new_job(name or "")
    job["phone"] = phone
    threading.Thread(target=_run_lingxi_sms_job,
                     args=(job, phone, on_success), daemon=True).start()
    return True, "已发起灵犀网页登录", _view(job)


def _lingxi_wait_sid(ctx, deadline):
    """轮询浏览器上下文，等 wps_sid cookie 出现（可能落在 .wps.cn / account.wps.cn 域）。"""
    while time.time() < deadline:
        try:
            for c in ctx.cookies():
                if c.get("name") == "wps_sid" and c.get("value"):
                    return c["value"]
        except Exception:
            pass
        time.sleep(1.0)
    return ""


def _lingxi_finish(job, on_success, sid):
    try:
        ok, _use, msg = on_success({"wps_sid": sid, "phone": job.get("phone", "")})
        job.update(status="done", finished=True, ok=bool(ok), result=msg)
    except Exception as e:
        job.update(status="done", finished=True, ok=False,
                   result="保存凭据失败：%s" % str(e)[:150])


def _run_lingxi_sms_job(job, phone, on_success):
    try:
        from playwright.sync_api import sync_playwright  # 延迟导入
    except Exception:
        job.update(status="done", finished=True, ok=False,
                   result="缺少 playwright，无法拉起登录窗口。请 pip install playwright")
        return

    deadline = time.time() + job["expires_in"] + 180
    browser = None
    try:
        with sync_playwright() as p:
            # 去自动化特征 + 窗口移出屏幕（用户无感）；WPS 智能验证弹出时拉回
            browser = p.chromium.launch(headless=False, args=_OFFSCREEN_ARGS)
            ctx = browser.new_context(locale="zh-CN",
                                      viewport={"width": 560, "height": 840})
            page = ctx.new_page()
            job["status"] = "opening"
            job["result"] = "已打开 WPS 登录窗口，正在进入登录页…"
            page.goto(_LINGXI_LOGIN_URL, wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(1500)

            # ① 默认微信扫码页 → 切「手机」tab。侦察实测（2026-10-08）：点「手机」
            #    (a.js_toProtocolDialog) 会先弹「提示」协议对话框，必须点「同意」
            #    (.dialog-footer-ok) 才渲染手机号表单 —— 旧版缺这步导致 #phone 永远找不到。
            try:
                page.locator("a", has_text="手机").first.click(timeout=5000)
            except Exception:
                try:
                    page.get_by_text("手机", exact=True).first.click(timeout=3000)
                except Exception:
                    pass  # 可能已在手机 tab
            try:   # 协议确认弹窗（此前同意过可能不出现）
                page.wait_for_selector(".dialog-footer-ok", timeout=3500)
                page.click(".dialog-footer-ok", timeout=2000)
                job["result"] = "已在弹窗点「同意」协议，正在进入手机号登录…"
            except Exception:
                pass

            # ② 填手机号（事件驱动等输入框出现；短信登录视图没有 #loginProtocal，
            #    协议已由上面弹窗一步解决）
            try:
                page.wait_for_selector("#phone", state="visible", timeout=10000)
                page.fill("#phone", phone, timeout=5000)
            except Exception:
                job["result"] = ("没找到手机号输入框，请在窗口里手动完成登录，"
                                 "看板会自动抓取 wps_sid…")
                sid = _lingxi_wait_sid(ctx, deadline)
                if sid:
                    _lingxi_finish(job, on_success, sid)
                else:
                    job.update(status="done", finished=True, ok=False,
                               result="未抓到 wps_sid（登录未完成或已超时）")
                return
            try:
                page.evaluate(
                    "() => { const c = document.querySelector('#loginProtocal');"
                    " if (c && !c.checked) c.click(); }")
            except Exception:
                pass

            # ③ 点「发送验证码」（侦察实测：.sendBtnWrap 就是发送按钮；
            #    旧版等 8 秒 #smartCaptchaBtn 是在等一个不存在的元素，纯浪费）
            sent = False
            try:
                page.wait_for_selector(".sendBtnWrap", state="visible", timeout=6000)
            except Exception:
                pass
            for sel in (".sendBtnWrap", "#smartCaptchaBtn"):
                try:
                    page.locator(sel).first.click(timeout=3000)
                    sent = True
                    break
                except Exception:
                    continue
            if not sent:
                sent = _click_text(page, ["发送验证码"], timeout=2500)
            if not sent:
                job["result"] = ("没点动「发送验证码」（可能有滑块），请直接在窗口里点；"
                                 "短信发出后回看板填验证码即可。")
            page.wait_for_timeout(1500)
            if _qoder_has_captcha(ctx):
                _pull_window_front(ctx)   # WPS 智能验证弹出：把屏幕外窗口拉回让人工完成
            job["need_code"] = True
            job["sms_sent"] = True
            job["result"] = ("验证码已发送至 %s（若窗口弹出了滑块/图片验证码，"
                             "请先在窗口里完成），请回看板填入。" % phone)

            # ④ 等用户在看板填验证码
            while time.time() < deadline and not job.get("code"):
                time.sleep(0.5)
            code = (job.get("code") or "").strip()
            if not code:
                sid = _lingxi_wait_sid(ctx, deadline)  # 用户可能改在窗口手动登录
                if sid:
                    _lingxi_finish(job, on_success, sid)
                else:
                    job.update(status="done", finished=True, ok=False,
                               result="超时：未收到验证码，登录未完成")
                return

            # ⑤ 填验证码 → 点「立即登录/注册」
            job["code_submitted"] = True
            job["result"] = "已提交验证码，正在登录…"
            try:
                page.fill("#code", code, timeout=8000)
            except Exception:
                pass
            try:
                page.click("#confirmCode", timeout=8000)
            except Exception:
                try:
                    page.get_by_text("立即登录", exact=False).first.click(timeout=5000)
                except Exception:
                    pass

            # ⑥ 等 wps_sid（12 秒未到且检测到验证弹层 → 拉回窗口让人工完成）
            sid = _lingxi_wait_sid(ctx, min(deadline, time.time() + 12))
            if not sid and _qoder_has_captcha(ctx):
                _pull_window_front(ctx)
                job["result"] = "登录时出现了滑块/验证，请先在窗口里完成，正在继续等待登录态…"
            sid = sid or _lingxi_wait_sid(ctx, deadline)
            if sid:
                _lingxi_finish(job, on_success, sid)
            else:
                job.update(status="done", finished=True, ok=False,
                           result="登录后未抓到 wps_sid（登录可能失败，"
                                  "或窗口里有未完成的验证），请重试")
    except Exception as e:
        job.update(status="done", finished=True, ok=False,
                   result="灵犀网页登录异常：%s" % str(e)[:150])
    finally:
        try:
            if browser:
                browser.close()
        except Exception:
            pass
