# -*- coding: utf-8 -*-
"""登录任务调度（供前端轮询）—— 二期拆分自 oauth_login.py。

start_job：纯设备流任务；start_sms_job：短信直登入口（按 provider kind 分发
到 qoder 专用主循环或通用 _run_sms_job）。"""
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
from oauth_device import device_poll, device_start
from oauth_qoder import _run_qoder_sms_job


# ────────────────────────── 登录任务（供前端轮询）──────────────────────────
def start_job(platform, on_success, region="cn", sub=None):
    """起一个后台任务：申请设备码 → 开网页 → 轮询 → 成功后回调落盘。

    on_success(grant) 需返回 (ok, name, msg)；name 用于前端提示。
    sub：部分平台（ZCode）需要选登录通道（zai / bigmodel）。
    返回 (ok, msg, job_view)。
    """
    ok, msg, flow = device_start(platform, region, sub=sub)
    if not ok:
        return False, msg, None
    job = _new_job(platform, flow)
    with _job_lock:
        _JOBS[job["job"]] = job
    threading.Thread(target=_run_job, args=(job, flow, on_success), daemon=True).start()
    return True, msg, _view(job)






def _run_job(job, flow, on_success):
    deadline = time.time() + flow["expires_in"]
    interval = flow["interval"]
    job["status"] = "waiting"
    job["result"] = "等待你在网页上完成授权…"
    while time.time() < deadline:
        time.sleep(interval)
        state, d = device_poll(flow)
        if state == "pending":
            continue
        if state == "slow_down":
            interval += 5
            continue
        if state == "denied":
            job.update(status="done", finished=True, ok=False, result="你在授权网页上点了「拒绝」")
            return
        if state == "expired":
            job.update(status="done", finished=True, ok=False, result="授权超时，请重新发起登录")
            return
        if state == "error":
            job.update(status="done", finished=True, ok=False,
                       result="授权失败：%s" % json.dumps(d, ensure_ascii=False)[:180])
            return
        # ok
        grant = {
            "access_token": str(d.get("access_token") or ""),
            "refresh_token": str(d.get("refresh_token") or ""),
            "token_type": str(d.get("token_type") or "Bearer"),
            "expires_in": d.get("expires_in"),
            "expires_at": str(d.get("expires_at") or ""),
            "scope": str(d.get("scope") or " ".join(
                (_provider(flow["platform"]).get("scopes") or []))),
        }
        try:
            ok, name, msg = on_success(grant)
        except Exception as e:
            ok, name, msg = False, "", "保存登录态异常：%s" % str(e)[:150]
        job.update(status="done", finished=True, ok=bool(ok),
                   result=msg if msg else ("已保存 %s" % name), name=name or "")
        return
    job.update(status="done", finished=True, ok=False,
               result="授权超时（%d 秒内未完成），请重新发起登录" % flow["expires_in"])
















def start_sms_job(platform, phone, on_success, region="cn"):
    """手机号 + 短信验证码登录。返回 (ok, msg, job_view)。

    流程：申请设备码 → 拉起可见 Chromium 打开登录页 → 自动切「手机号登录」并填手机号
    → 自动点「获取验证码」→ 前端弹验证码输入框 → submit_code() 注入验证码并点登录
    → 自动点「授权」→ 轮询拿到正式令牌 → on_success 落盘 → 关浏览器。
    """
    raw = str(phone or "")
    if "*" in raw:
        # 设备流登录的账号只存得到脱敏号（如 180******23），完整号从未落盘
        return False, ("该账号记录的是脱敏手机号（%s），完整号码未保存过——"
                       "请手动输入 11 位手机号后重新续期" % raw), None
    phone = "".join(ch for ch in raw if ch.isdigit())
    if len(phone) != 11:
        return False, "请填写 11 位手机号（当前：%s）" % (phone or "空"), None
    ok, msg, flow = device_start(platform, region)
    if not ok:
        return False, msg, None
    job = _new_job(platform, flow)
    job.update(mode="sms", phone=phone)
    with _job_lock:
        _JOBS[job["job"]] = job
    kind = _provider(platform).get("kind")
    target = _run_qoder_sms_job if kind == "qoder_device" else _run_sms_job
    threading.Thread(target=target, args=(job, flow, phone, on_success),
                     daemon=True).start()
    return True, "已发起短信登录", _view(job)




def _run_sms_job(job, flow, phone, on_success):
    try:
        from playwright.sync_api import sync_playwright  # 延迟导入
    except Exception:
        job.update(status="done", finished=True, ok=False,
                   result="缺少 playwright，无法拉起登录窗口。请 pip install playwright")
        return

    deadline = time.time() + flow["expires_in"] + 60
    interval = max(2.0, float(flow["interval"]))
    browser = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False, args=_OFFSCREEN_ARGS)
            ctx = browser.new_context(locale="zh-CN", viewport={"width": 520, "height": 780})
            page = ctx.new_page()
            job["status"] = "opening"
            job["result"] = "已打开登录窗口，正在填入手机号…"
            page.goto(flow["verify_url"], wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(800)

            # ① 切到「手机号登录」并填手机号
            _click_text(page, ["手机号登录", "手机登录"])
            page.wait_for_timeout(800)
            # ⚠ 协议必须先勾：未勾时点「立即登录」前端会**静默不响应**（不发登录请求、不报错），
            #   表现为「按钮点了没反应」。这里勾一次（幂等），下面点登录前还会再兜一次。
            _click_consent(page)
            ph = _first_sel(page, _PHONE_SEL)
            if not ph:
                job.update(status="done", finished=True, ok=False,
                           result="没在登录页找到手机号输入框，请改用「弹出授权网页」方式")
                browser.close()
                return
            ph.fill(phone)
            page.wait_for_timeout(300)
            _click_consent(page)   # 填号后再兜一次（部分渲染较慢的批次此刻才出现协议行）
            job["result"] = "手机号已填入，正在点击「获取验证码」…"

            # ② 点「获取验证码」（若平台弹滑块，请在窗口里手动拖一下）
            _click_text(page, ["获取验证码", "发送验证码", "获取短信验证码"], timeout=3000)
            page.wait_for_timeout(1000)
            # ②b MiniMax 点「获取验证码」后可能先弹协议确认框，要点「确认」短信才真正
            #    发出（2026-10-13 真机回归实测）。点掉确认框后补点一次发送；其它平台
            #    无此框时两次点击都空跑（_click_text 找不到文本直接返回 False），无副作用。
            if _click_text(page, ["确认", "确定", "同意"], timeout=1200):
                page.wait_for_timeout(600)
                _click_text(page, ["获取验证码", "发送验证码", "获取短信验证码"], timeout=2500)
            if _has_captcha(page):
                _pull_window_front(ctx)   # 滑块弹出：把屏幕外窗口拉回让人工拖
            job.update(status="waiting_code", sms_sent=True, need_code=True,
                       captcha=_has_captcha(page),
                       result="验证码已发送 📩 请在下方填入短信验证码"
                              "（若登录窗口弹出滑块验证，先在窗口里拖一下）")

            # ③ 主循环：注入验证码 → 点登录 → 点授权 → 轮询令牌
            last_poll = 0.0
            while time.time() < deadline:
                now = time.time()
                if job.get("code") and not job.get("code_submitted"):
                    cd = _first_sel(page, _CODE_SEL, timeout=3000)
                    if cd:
                        cd.fill(str(job["code"]))
                        page.wait_for_timeout(300)
                        # ⚠ 点「立即登录」前必须确认协议已勾：未勾时点击会被前端静默拦截
                        #   （无 network、无 toast），只表现为「按钮没反应」。故这里：
                        #   ① 未勾 → 补勾；② 点登录；③ 若仍未发出 /oauth2/login 请求 → 再补勾重试。
                        if _consent_checked(page) is not True:
                            _click_consent(page)
                        _login_submitted(page, ["立即登录", "登录", "登 录"], ctx)
                        job["code_submitted"] = True
                        job["need_code"] = False
                        job["result"] = "已提交验证码，正在登录…"
                # 滑块风控状态回传前端：每轮都刷新（验证码消失后 flag 自动归 False，
                # 前端状态文案随之恢复真实内容——旧实现只在未提交验证码时更新，
                # 提交后 flag 永久滞留 true，假警告盖住「正在登录」直到结束）
                cap = _has_captcha(page)
                if cap and not job.get("captcha"):
                    _pull_window_front(ctx)   # 边沿触发：新弹出的滑块把窗口拉回
                job["captcha"] = cap
                if job.get("code_submitted"):
                    # 登录成功后设备授权页会出现确认按钮
                    _click_text(page, ["授权", "确认授权", "同意授权", "允许", "Authorize"],
                                timeout=800)
                if now - last_poll >= interval:
                    last_poll = now
                    state, d = device_poll(flow)
                    if state == "ok":
                        grant = {
                            "access_token": str(d.get("access_token") or ""),
                            "refresh_token": str(d.get("refresh_token") or ""),
                            "token_type": str(d.get("token_type") or "Bearer"),
                            "expires_in": d.get("expires_in"),
                            "scope": str(d.get("scope") or " ".join(
                                _provider(flow["platform"])["scopes"])),
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
                        job.update(status="done", finished=True, ok=False,
                                   result="授权被拒绝")
                        break
                    elif state == "expired":
                        job.update(status="done", finished=True, ok=False,
                                   result="授权码已过期（5 分钟），请重新点击「获取验证码」")
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
