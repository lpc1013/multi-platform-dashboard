# -*- coding: utf-8 -*-
"""Qoder 短信直登：弹窗代点（阿里云登录，2026-10-08 实测 DOM）—— 二期拆分。"""
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
from oauth_device import device_poll


# ────────────────── Qoder 短信直登：弹窗代点（阿里云登录，2026-10-08 实测 DOM）──────────────────
# 链路（无头侦察实测）：qoder.cn/users/sign-in → 点「使用阿里云登录」<A> 链接 →
#   account.aliyun.com/sso/login.htm?biz_variant=qoder → 内嵌 iframe
#   passport.aliyun.com/havanaone/login/login.htm（appEntrance=qoder_sms）：
#     #fm-sms-login-id 手机号 / #fm-smscode 验证码 / #fm-agreement-checkbox 协议 /
#     button.fm-submit.sms-login「登录 / 注册」（未填时 fm-button-disabled）
#   提交验证码 → 阿里云侧确认步【继续】（2026-10-08 用户实测：不点它就一直停着）→
#   qoder.com.cn/sso/callback/aliyun → 设备确认页 → 点「授权」→ 轮询拿令牌。
# 滑块/图片验证码无法自动化 —— 弹真人可见窗口，用户顺手拖一下/填一下。

_QODER_AUTH_TEXTS = ["授权登录", "确认授权", "同意授权", "授权", "允许", "确认", "同意", "Authorize"]
# 阿里云侧验证码提交后的确认步按钮（用户实测【继续】；按优先级排序）
_QODER_ALIYUN_NEXT_TEXTS = ["继续", "同意授权", "授权登录", "同意", "确认", "Authorize"]
# Qoder 自家「设备确认页」(qoder.cn/device/selectAccounts) 的按钮文案实测是【继续】
# （页面标题「允许登录 / 继续使用此账户吗?」），不是「授权」——2026-10-08 用户实测。
# 之前只按 _QODER_AUTH_TEXTS 匹配，点不到这个绿色「继续」，只能干等 30 秒拉窗口人工点。
_QODER_SELECT_TEXTS = ["继续", "授权", "允许", "确认", "同意", "Authorize"]

def _qoder_find_sms_frame(ctx, budget=35):
    """在所有页面的所有 frame（含主文档）里找阿里云短信登录表单（#fm-sms-login-id）。
    直接探测元素本身，不依赖 iframe URL 特征（havanaone 路径可能随页面状态变化）。"""
    t0 = time.time()
    while time.time() - t0 < budget:
        for pg in ctx.pages:
            for f in pg.frames:
                try:
                    if f.locator("#fm-sms-login-id").count():
                        return f
                except Exception:
                    pass
        time.sleep(0.8)
    return None


def _qoder_stage(ctx):
    """验证码提交后的页面阶段：select（Qoder 授权确认页）/ qoder（qoder 域回调/中转）/
    aliyun（还在阿里云侧）/ other。用于给用户可见的进度状态。
    注意先判 qoder 再判 aliyun：回调页 qoder.com.cn/sso/callback/aliyun 路径里也含 aliyun。"""
    try:
        urls = [(pg.url or "") for pg in ctx.pages]
    except Exception:
        return "other"
    if any("selectAccounts" in u for u in urls):
        return "select"
    if any("qoder" in u for u in urls):
        return "qoder"
    if any(("aliyun" in u or "havana" in u or "taobao" in u) for u in urls):
        return "aliyun"
    return "other"


def _qoder_click_where(ctx, domains, texts, exclude=None):
    """在匹配域的页面（含 frame）里按文本点按钮。

    两条路径：
      ① 归一化匹配（主）：JS 遍历 button/a/[role=button]，把 innerText 去掉所有空白后
         与目标文案比对，命中即返回该元素并点击。
         —— 必须归一化：antd 会在两个汉字之间自动插空格（`继续`→`继 续`、`登录`→`登 录`），
         用 `:has-text('继续')` 会 count=0 点不到（2026-10-08 用户实测「就再点一下」点不动的根因）。
      ② CSS `:has-text` 联合选择器（兜底）：兼容非 antd/无空格场景。

    按钮没渲染时毫秒级返回 False，不拖慢主循环的令牌轮询。"""
    norm = [(t, t.replace(" ", "").replace("\u3000", "")) for t in texts]
    # 选择器兜底（原逻辑）
    sels = []
    for n in texts:
        sels.append("button:has-text('%s')" % n)
        sels.append("a:has-text('%s')" % n)
        sels.append("[role='button']:has-text('%s')" % n)
    big = ",".join(sels)
    js = (
        "(targets) => {"
        " const norm = s => (s || '').replace(/\\s+/g, '').replace(/\\u3000/g, '');"
        " const els = Array.from(document.querySelectorAll('button,a,[role=button]'));"
        " for (const t of targets) {"
        "   const hit = els.find(e => norm(e.innerText) === t || norm(e.textContent) === t);"
        "   if (hit) return hit;"
        " }"
        " return null;"
        "}"
    )
    for pg in ctx.pages:
        u = (pg.url or "")
        if not any(d in u for d in domains):
            continue
        if exclude and any(x in u for x in exclude):
            continue
        targets = [n for _, n in norm]
        for target in [pg] + [f for f in pg.frames if f is not pg.main_frame]:
            # ① 归一化匹配（主路径）：命中后由 Playwright 点，失败再退回 CSS
            try:
                el = target.evaluate_handle(js, targets)
                jsd = el.as_element() if el else None
                if jsd:
                    try:
                        jsd.click(timeout=800)
                        return True
                    except Exception:
                        try:
                            jsd.evaluate("e => e.click()")
                            return True
                        except Exception:
                            pass
            except Exception:
                pass
            # ② CSS 兜底
            try:
                loc = target.locator(big)
                if loc.count():
                    loc.first.click(timeout=800)
                    return True
            except Exception:
                pass
    return False


def _qoder_click_authorize(ctx):
    """回到 Qoder 域（设备确认页 / 授权页）后，代点确认按钮。

    两类页面都要覆盖：
      · /device/selectAccounts（「允许登录 / 继续使用此账户吗?」）→ 按钮文案【继续】
      · SSO 授权确认页 → 文案「授权登录 / 同意授权 / 允许」等
    因此合并 _QODER_SELECT_TEXTS 与 _QODER_AUTH_TEXTS，并按「继续」优先。
    只点 qoder 域页面（含 frame）。"""
    return _qoder_click_where(ctx, ("qoder",),
                              _QODER_SELECT_TEXTS + _QODER_AUTH_TEXTS)


def _qoder_click_aliyun_next(ctx):
    """阿里云侧验证码提交后的确认步：代点【继续/同意授权】等（2026-10-08 用户实测：
    表单提交后若不点这一步，页面就一直停着不跳转）。跳过 qoder 域页面（回调页
    路径里含 aliyun 字样，避免与授权点击重复/误点）。"""
    return _qoder_click_where(ctx, ("aliyun", "havana", "taobao"),
                              _QODER_ALIYUN_NEXT_TEXTS, exclude=("qoder",))


def _run_qoder_sms_job(job, flow, phone, on_success):
    try:
        from playwright.sync_api import sync_playwright  # 延迟导入
    except Exception:
        job.update(status="done", finished=True, ok=False,
                   result="缺少 playwright，无法拉起登录窗口。请 pip install playwright")
        return

    deadline = time.time() + flow["expires_in"] + 150
    interval = 2.0
    browser = None
    try:
        with sync_playwright() as p:
            # 去掉 navigator.webdriver 自动化特征（阿里云风控会盯这个），
            # 实测无头+带特征时 SSO 内嵌登录 iframe 概率性不加载；
            # 窗口移到屏幕外（用户无感），滑块出现时 _pull_window_front 拉回
            browser = p.chromium.launch(headless=False, args=_OFFSCREEN_ARGS)
            ctx = browser.new_context(locale="zh-CN", viewport={"width": 560, "height": 840})
            page = ctx.new_page()
            job["status"] = "opening"
            job["result"] = "已打开登录窗口，正在进入阿里云登录页…"
            page.goto(flow["verify_url"], wait_until="domcontentloaded", timeout=60000)

            # ① 点「使用阿里云登录」——事件驱动：入口一渲染出来立刻点（不再固定 sleep）。
            # 必须用【精确文本】匹配入口：has_text='阿里云' 子串会抓到页脚「阿里云协议/官网」
            # 等链接并 goto 到错误页面，登录表单永远等不到（2026-10-08 踩坑回归）。
            clicked = False
            for txt, tmo in (("使用阿里云登录", 8000), ("阿里云登录", 2500)):
                try:
                    loc = page.get_by_text(txt, exact=True).first
                    loc.wait_for(state="visible", timeout=tmo)
                    href = ""
                    try:  # 入口若是 <a>，读真实 href；确认指向阿里云登录域才直跳（省一次 SPA 路由）
                        href = loc.evaluate(
                            "e => { const a = e.closest && e.closest('a');"
                            " return a ? (a.getAttribute('href') || '') : ''; }") or ""
                    except Exception:
                        pass
                    href = str(href).strip()
                    if href.startswith("//"):
                        href = "https:" + href
                    if href.startswith("http") and any(
                            k in href for k in ("aliyun", "havana")):
                        page.goto(href, wait_until="domcontentloaded", timeout=30000)
                    else:
                        loc.click(timeout=3000)
                    clicked = True
                    break
                except Exception:
                    continue
            if not clicked:
                clicked = _click_text(page, ["使用阿里云登录", "阿里云登录"], timeout=2500)
            if not clicked:
                job.update(status="done", finished=True, ok=False,
                           result="没在登录页找到「使用阿里云登录」入口（页面可能改版），"
                                  "请改用「打开授权网页」方式手动登录")
                browser.close()
                return
            page.wait_for_timeout(300)

            # ② 等阿里云短信表单 iframe（带进度反馈；页面偶尔加载慢）
            fr = None
            t0 = time.time()
            while time.time() - t0 < 45:
                fr = _qoder_find_sms_frame(ctx, budget=2)
                if fr:
                    break
                job["result"] = "正在等待阿里云登录表单加载…（%d 秒）" % int(time.time() - t0)
            if not fr:
                try:
                    urls = " ｜ ".join((pg.url or "")[:90] for pg in ctx.pages)
                except Exception:
                    urls = ""
                job.update(status="done", finished=True, ok=False,
                           result="没找到阿里云手机号登录表单（等待 45 秒超时）。当前页面：%s"
                                  " —— 请重试一次；若仍失败请截图登录窗口反馈" % (urls or "未知"))
                browser.close()
                return
            fr.fill("#fm-sms-login-id", phone)
            job["result"] = "手机号已填入，正在勾选协议并点「获取验证码」…"

            # ③ 勾「我已阅读并同意」协议（input 可能被样式隐藏，JS 兜底）
            try:
                fr.locator("#fm-agreement-checkbox").click(timeout=1500)
            except Exception:
                try:
                    fr.evaluate("() => { const e = document.querySelector('#fm-agreement-checkbox');"
                                " if (e) { e.checked = true;"
                                " e.dispatchEvent(new Event('change', {bubbles: true})); } }")
                except Exception:
                    pass

            # ④ 点「获取验证码」（弹滑块/图片验证码时请用户在窗口里完成）
            for txt in ("获取验证码", "发送验证码", "免费获取", "获取短信验证码"):
                try:
                    fr.get_by_text(txt, exact=False).first.click(timeout=2000)
                    break
                except Exception:
                    continue
            page.wait_for_timeout(1000)
            captcha = _qoder_has_captcha(ctx)
            try:
                if fr.locator("#fm-login-checkcode").is_visible():
                    captcha = True
            except Exception:
                pass
            if captcha:
                _pull_window_front(ctx)   # 滑块/图片验证码：把屏幕外窗口拉回让人工完成
            job.update(status="waiting_code", sms_sent=True, need_code=True, captcha=captcha,
                       result="验证码已发送 📩 请在下方填入短信验证码"
                              + ("（⚠ 登录窗口出现了滑块/图片验证码，请先在窗口里完成）"
                                 if captcha else ""))

            # ⑤ 主循环：回填验证码 → 提交 → 代点授权 → 轮询令牌
            last_poll = 0.0
            submit_t = None      # 验证码提交时刻
            auth_click_t = None  # 首次点到 Qoder「授权」的时刻
            aliyun_click_t = None  # 首次点到阿里云侧【继续】确认步的时刻
            pulled = False       # 长时间无进展时把窗口拉回屏幕（只做一次）
            while time.time() < deadline:
                now = time.time()
                if job.get("code") and not job.get("code_submitted"):
                    try:
                        fr.fill("#fm-smscode", str(job["code"]))
                        page.wait_for_timeout(300)
                        try:
                            fr.locator("button.fm-submit.sms-login").first.click(timeout=2000)
                            submitted = True
                        except Exception:
                            submitted = _click_text(page, ["登录 / 注册", "登录"], timeout=1500)
                        if submitted:
                            job["code_submitted"] = True
                            job["need_code"] = False
                            submit_t = now
                            job["result"] = "已提交验证码，正在登录…"
                    except Exception:
                        pass  # frame 可能已随登录跳转销毁，交给轮询
                if not job.get("code_submitted"):
                    cap = _qoder_has_captcha(ctx)
                    if cap and not job.get("captcha"):
                        _pull_window_front(ctx)   # 边沿触发：新弹出的验证码把窗口拉回
                    job["captcha"] = cap
                if job.get("code_submitted"):
                    # —— 细粒度进度：让每一秒的等待都可见，不再冻结在「已提交验证码」——
                    if submit_t is None:
                        submit_t = now
                    waited = int(now - submit_t)
                    if _qoder_click_authorize(ctx) and auth_click_t is None:
                        auth_click_t = now
                    if _qoder_click_aliyun_next(ctx) and aliyun_click_t is None:
                        aliyun_click_t = now
                    if auth_click_t is not None:
                        job["result"] = "已点「授权」，等待令牌下发…（%d 秒）" % int(now - auth_click_t)
                    elif aliyun_click_t is not None:
                        job["result"] = "已点「继续」，等待跳回 Qoder…（%d 秒）" % int(now - aliyun_click_t)
                    else:
                        stage = _qoder_stage(ctx)
                        if stage == "aliyun":
                            job["result"] = "阿里云侧登录处理中…（%d 秒）" % waited
                            try:  # best-effort：验证码填错时阿里云会有红色报错
                                for bad in ("验证码错误", "验证码有误", "校验码错误"):
                                    if fr.get_by_text(bad).count():
                                        job["result"] = "阿里云提示验证码有误，请重新发起登录"
                                        break
                            except Exception:
                                pass
                        elif stage == "select":
                            job["result"] = "已到 Qoder 授权确认页，正在代点「授权」…（%d 秒）" % waited
                        else:
                            job["result"] = "登录成功，正在跳转…（%d 秒）" % waited
                    # 兜底：提交后 30 秒仍未拿到令牌（自动点击没生效/确认页需要人工），
                    # 把窗口拉回屏幕，用户可直接手动点「授权」，轮询照样会成功
                    if waited >= 30 and not pulled:
                        pulled = True
                        _pull_window_front(ctx)
                    if pulled:
                        job["result"] += "；已把窗口拉回屏幕，可在窗口里手动点「授权」加速"
                if now - last_poll >= interval:
                    last_poll = now
                    state, d = device_poll(flow)
                    if state == "ok":
                        grant = {
                            "access_token": str(d.get("access_token") or ""),
                            "refresh_token": str(d.get("refresh_token") or ""),
                            "token_type": str(d.get("token_type") or "Bearer"),
                            "expires_in": d.get("expires_in"),
                            "expires_at": str(d.get("expires_at") or ""),
                            "scope": "",
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
                    elif state == "denied":
                        job.update(status="done", finished=True, ok=False, result="授权被拒绝")
                        break
                    elif state == "expired":
                        job.update(status="done", finished=True, ok=False,
                                   result="授权码已过期（5 分钟），请重新发起登录")
                        break
                page.wait_for_timeout(700)

            if not job.get("finished"):
                job.update(status="done", finished=True, ok=False,
                           result="登录超时，请重新发起（授权码 5 分钟内有效）")
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
