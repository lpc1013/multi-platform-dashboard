# -*- coding: utf-8 -*-
"""DuMate（百度搭子）网页直登：弹窗代点（2026-10-08 实测 DOM）—— 二期拆分。"""
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


# ──────────── DuMate（百度搭子）网页直登：弹窗代点（2026-10-08 实测 DOM）────────────
# 链路（实测 + 参考开源 wearetheone777/dumate2api）：
#   dumate.baidu.com/app 点「立即登录」→ 内嵌 passport iframe
#   （login.bce.baidu.com/?passport_phone=true&from=dumate&loginScene=dumate，
#   短信 tab 默认激活）→ 填手机号 → 点「发送验证码」→ 回填验证码 → 点「登录」
#   → BDUSS（.baidu.com）落地 → 用 cookie 调 /api/dumate/user/info 拿身份。
# 选择器用 [id$=...] 后缀匹配：TANGRAM__PSP_N__ 的 N 会随页面状态变化。

_DUMATE_APP_URL = "https://www.dumate.cn/app"   # 302 → dumate.baidu.com/app


def _dumate_new_job(name):
    job = {
        "job": uuid.uuid4().hex[:12], "platform": "baidu_dumate",
        "mode": "sms", "status": "waiting", "finished": False,
        "ok": None, "result": "", "name": name, "started": time.time(),
        "user_code": "", "verify_url": _DUMATE_APP_URL,
        "expires_in": 360,
        "hint": "在弹出的窗口里完成百度账号短信登录，看板自动抓取登录态",
        "phone": "", "need_code": False, "code": None, "code_submitted": False,
        "sms_sent": False,
    }
    with _job_lock:
        _JOBS[job["job"]] = job
    return job


def _dumate_find_login_surface(ctx, budget=40):
    """定位百度登录表单的操作表面，返回 Frame 或 Page（两者 fill/locator 接口兼容）。

    实测（2026-10-08）同一入口有两种渲染形态：
    ① passport iframe（login.bce.baidu.com / passport.baidu.com）；
    ② 登录组件直接内嵌在主页 DOM（无任何子 iframe）——旧实现只找 iframe，
       遇到形态②就永远「等待百度登录表单」，手机号不填、验证码发不出。
    统一以 [id$='smsPhone'] 元素实际出现为准，两种形态都能命中。
    """
    t0 = time.time()
    while time.time() - t0 < budget:
        for pg in ctx.pages:
            # ① iframe 形态：passport 域 frame 且里面已有短信手机号框
            for f in pg.frames:
                if f is pg.main_frame:
                    continue
                u = f.url or ""
                if "login.bce.baidu.com" not in u and "passport.baidu.com" not in u:
                    continue
                try:
                    if f.locator("[id$='smsPhone']").count():
                        return f
                except Exception:
                    pass
            # ② 主页内嵌形态：主文档里直接有短信手机号框
            try:
                if pg.locator("[id$='smsPhone']").count():
                    return pg
            except Exception:
                pass
        time.sleep(1.0)
    return None


def _dumate_cookie_string(ctx):
    """抓登录态 cookie：.baidu.com（BDUSS 等）+ dumate.baidu.com + dumate.cn。
    同名 cookie 取域更具体的那个。"""
    all_ck = []
    for pg in ctx.pages:
        try:
            all_ck = ctx.cookies()   # context 级全量
            break
        except Exception:
            continue
    if not all_ck:
        return ""
    keep_domains = (".baidu.com", "baidu.com", "dumate.baidu.com",
                    ".dumate.baidu.com", "dumate.cn", ".dumate.cn", "www.dumate.cn")
    best = {}
    for c in all_ck:
        dom = (c.get("domain") or "").lower()
        if not any(dom == d or dom.endswith(d) for d in keep_domains):
            continue
        if not c.get("value"):
            continue
        prev = best.get(c["name"])
        if not prev or len(dom) > len(prev[0]):
            best[c["name"]] = (dom, c["value"])
    return "; ".join("%s=%s" % (k, v[1]) for k, v in best.items())


def _dumate_fetch_user(cookie_str):
    """用登录态 cookie 反查身份（logged-in 才有数据）。

    实测返回（2026-10-08）：{"code":0,"success":true,"result":{"bceAccountId",
    "bceUserId","displayName","userId",...}} —— 早期预期的 uid/userName/nickname
    字段并不存在，字段名不匹配曾导致登录成功却永远判不出身份、卡到超时。
    """
    if not cookie_str:
        return None
    try:
        r = requests.get("https://dumate.baidu.com/api/dumate/user/info",
                         headers={"Cookie": cookie_str, "Accept": "application/json",
                                  "Referer": "https://dumate.baidu.com/app",
                                  "User-Agent": UA},
                         timeout=15, verify=False)
        d = r.json()
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    id_keys = ("uid", "userId", "userID", "bceUserId", "bceAccountId")
    nm_keys = ("nickname", "userName", "displayName", "name")
    for k in ("result", "data"):
        v = d.get(k)
        if isinstance(v, dict):
            user = v.get("user") if isinstance(v.get("user"), dict) else v
            if any(user.get(kk) for kk in id_keys):
                return {"user_id": str(next(user[kk] for kk in id_keys if user.get(kk))),
                        "name": str(next((user[kk] for kk in nm_keys if user.get(kk)), ""))}
    return None


def start_dumate_web_job(phone, name, on_success):
    """DuMate 网页直登：弹可见窗口代点百度账号短信登录，成功后抓 cookie 落盘。"""
    phone = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if len(phone) != 11:
        return False, "请填写 11 位手机号（当前：%s）" % (phone or "空"), None
    job = _dumate_new_job(name or "")
    job["phone"] = phone
    threading.Thread(target=_run_dumate_web_job,
                     args=(job, phone, name, on_success), daemon=True).start()
    return True, "已发起 DuMate 网页登录", _view(job)


def _run_dumate_web_job(job, phone, name, on_success):
    try:
        from playwright.sync_api import sync_playwright  # 延迟导入
    except Exception:
        job.update(status="done", finished=True, ok=False,
                   result="缺少 playwright，无法拉起登录窗口。请 pip install playwright")
        return

    deadline = time.time() + job["expires_in"] + 120
    browser = None
    try:
        with sync_playwright() as p:
            # 去掉自动化特征 + 窗口移出屏幕（用户无感）；百度风控滑块出现时拉回
            browser = p.chromium.launch(headless=False, args=_OFFSCREEN_ARGS)
            ctx = browser.new_context(locale="zh-CN",
                                      viewport={"width": 560, "height": 840})
            page = ctx.new_page()
            job["status"] = "opening"
            job["result"] = "已打开登录窗口，正在进入 DuMate 网页版…"
            page.goto(_DUMATE_APP_URL, wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(1500)

            # ① 点「立即登录」（若已带登录态会直接进入应用，视为成功）
            try:
                page.get_by_text("立即登录", exact=False).first.click(timeout=5000)
            except Exception:
                pass
            job["result"] = "已点「立即登录」，正在等待百度登录表单…"

            # ② 等登录表单出现（iframe 或主页内嵌两种形态，见 _dumate_find_login_surface）
            job["result"] = "正在等待百度登录表单…"
            fr = _dumate_find_login_surface(ctx, budget=45)
            if not fr:
                job.update(status="done", finished=True, ok=False,
                           result="没等到百度登录表单（页面可能改版或加载慢），"
                                  "请重试；若窗口里表单已出来，直接手动登录，看板会自动抓取登录态")
                # 不立即关窗：给人工登录留后路，继续走下面的 cookie 轮询兜底
                fr = None
            else:
                job["result"] = "已定位登录表单，正在填入手机号…"

            # ③ 短信 tab 默认激活；填手机号 + 勾协议 + 点「发送验证码」
            if fr is not None:
                try:
                    fr.fill("[id$='smsPhone']", phone, timeout=6000)
                except Exception:
                    job.update(status="done", finished=True, ok=False,
                               result="没找到手机号输入框（passport 可能改版），请在窗口里手动登录，"
                                      "看板会自动抓取登录态")
                    # 不关窗：降级为纯人工登录，继续轮询 cookie
                    fr = None
            if fr is not None:
                try:
                    ag = fr.locator("[id$='smsIsAgree']")
                    if ag.count() and not ag.first.is_checked():
                        ag.first.click(timeout=1500)
                except Exception:
                    try:
                        fr.evaluate("() => { const e = document.querySelector(\"[id$='smsIsAgree']\");"
                                    " if (e && !e.checked) { e.checked = true;"
                                    " e.dispatchEvent(new Event('change', {bubbles: true})); } }")
                    except Exception:
                        pass
                try:
                    fr.locator("[id$='smsTimer']").first.click(timeout=4000)
                    job["sms_sent"] = True
                except Exception:
                    job["result"] = "没点到「发送验证码」，请在窗口里手动点一下"
                job["need_code"] = True
                job["result"] = ("验证码已发送至 %s（若窗口弹出滑块/图片验证码，请先在窗口里完成）"
                                 % phone)

            # ④ 等验证码回填 → 代填并提交；期间同时轮询 cookie（人工登录也兜得住）
            code_used = False
            t_submit = None
            pulled = False
            while time.time() < deadline and not job.get("finished"):
                time.sleep(1.0)
                code = job.get("code")
                if code and not code_used and fr is not None:
                    code_used = True
                    t_submit = time.time()
                    job["code_submitted"] = True
                    job["result"] = "已收到验证码，正在提交登录…"
                    try:
                        fr.fill("[id$='smsVerifyCode']", code, timeout=5000)
                        try:
                            ag = fr.locator("[id$='smsIsAgree']")
                            if ag.count() and not ag.first.is_checked():
                                ag.first.click(timeout=1200)
                        except Exception:
                            pass
                        fr.locator("[id$='smsSubmit']").first.click(timeout=4000)
                    except Exception:
                        job["result"] = ("自动提交没成功，请直接在窗口里把验证码填进"
                                         "「短信验证码」框并点「登录」")

                # 登录成功判定：BDUSS（百度账号登录态，签到凭证本体）出现即成功；
                # user/info 只用来取身份昵称，拿不到不再阻塞（曾因字段名不匹配
                # 导致登录成功却空转到超时）。
                ck = _dumate_cookie_string(ctx)
                if "BDUSS=" not in ck:
                    if (code_used and not pulled and t_submit
                            and time.time() - t_submit > 15):
                        # 提交 15 秒仍无登录态：可能有二次滑块验证，拉回窗口让人工看一眼
                        _pull_window_front(ctx)
                        job["result"] = ("提交后迟迟未登录成功——若窗口里出现滑块/二次验证，"
                                         "请完成它；也可以直接在窗口里手动登录。")
                        pulled = True
                    continue
                info = _dumate_fetch_user(ck)
                if not info:
                    time.sleep(1.5)             # cookie 可能刚落地，稍候重试一次
                    ck = _dumate_cookie_string(ctx)
                    info = _dumate_fetch_user(ck)
                grant = {"cookie": ck, "user": info or {}, "phone": phone}
                try:
                    ok2, name2, msg2 = on_success(grant)
                except Exception as e:
                    ok2, name2, msg2 = False, "", "保存登录态异常：%s" % str(e)[:150]
                job.update(status="done", finished=True, ok=bool(ok2),
                           result=msg2 or ("已保存 %s" % name2), name=name2 or "")
                try:
                    browser.close()
                except Exception:
                    pass
                return

            if not job.get("finished"):
                job.update(status="done", finished=True, ok=False,
                           result="登录超时，请重新发起")
            try:
                browser.close()
            except Exception:
                pass
    except Exception as e:
        job.update(status="done", finished=True, ok=False,
                   result="DuMate 网页登录异常：%s" % str(e)[:200])
        try:
            if browser:
                browser.close()
        except Exception:
            pass
