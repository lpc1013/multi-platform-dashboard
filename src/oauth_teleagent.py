# -*- coding: utf-8 -*-
"""电信 TeleAgent（星辰超级智能体）网页登录 —— 抓 web console 会话。

背景（2026-10-14 全部实测，勿凭记忆改写）：
  桌面客户端的 sapi 签名网关只有 chat / web_search / instruction 三个端点；
  积分余额与每日打卡在 web console 侧（/console/api/*，天翼 upms OAuth 保护，
  client_id=uDqtlP82nJZqIduN3BDUBtxM6ijAttov）。
  web 会话 = localStorage 的 console_token(access) + refresh_token，SPA 静默续期；
  本机 leveldb 全盘扫描确认客户端不落盘 web 会话 → 唯一路径：真实浏览器登录一次。

流程：
  ① 弹可见 Chromium 打开 upms authorize → 302 到 master-auth 统一登录页
  ② 用户在窗口里完成登录（手机号+短信验证码 或 密码；滑块/拼图验证码按提示完成）
     —— MasterAuth 是自绘 UI + 滑块风控，验证码必须在真人可见的窗口里完成，
        代填只做「尽力而为」，失败不阻塞（窗口里手输即可）
  ③ 登录成功 → 302 回 agent.teleai.com.cn/super-agent?code=... → SPA 自动兑换
     → localStorage 出现 console_token / refresh_token
  ④ 任务轮询各页面 localStorage 抓取 → on_success 落盘（webapi 侧 _teleagent_login_save）
  ⑤ 无人值守续期：refresh_token 换新（platforms/teleagent.py 侧实现）
"""
import json
import time
import uuid
import threading
import urllib.parse

from oauth_common import (
    _JOBS, _job_lock, _view, _pull_window_front,
)

# 天翼 upms OAuth：client_id 取自 /console/api/* 401 响应体（2026-10-14 实测）
AUTHORIZE_URL = (
    "https://www.teleai.com.cn/aicloud-api/upms/public/auth/authorize"
    "?client_id=uDqtlP82nJZqIduN3BDUBtxM6ijAttov"
    "&redirect_uri=" + urllib.parse.quote(
        "https://agent.teleai.com.cn/super-agent", safe="")
)
# SPA 会话落点（ta_index.js 实测：setItem("console_token"...) / eA() 清单）
LS_KEYS = ("console_token", "refresh_token", "token", "sso_token",
           "consone_token", "operToken", "USER_INFO")


def _grab_session(page):
    """从页面抓 web 会话。拿到 console_token 或 refresh_token 才算数，返回 dict/None。"""
    try:
        url = page.url or ""
        if "teleai.com.cn" not in url:
            return None
        ls = page.evaluate(
            "() => { const o = {}; for (let i = 0; i < localStorage.length; i++)"
            " { const k = localStorage.key(i); o[k] = localStorage.getItem(k); }"
            " return o; }")
        if not isinstance(ls, dict):
            return None
        if not (ls.get("console_token") or ls.get("refresh_token")):
            return None
        out = {}
        for k in LS_KEYS:
            v = ls.get(k)
            if v:
                out[k] = v
        out["_url"] = url
        return out
    except Exception:
        return None


def _wait_session(ctx, deadline, job=None):
    """轮询上下文所有页面直到抓到会话。"""
    while time.time() < deadline:
        pages = []
        try:
            pages = list(ctx.pages)
        except Exception:
            pass
        for pg in pages:
            s = _grab_session(pg)
            if s:
                return s
        if job is not None:
            job["seconds_left"] = int(deadline - time.time())
        time.sleep(1.0)
    return None


def _prefill_phone(page, phone):
    """尽力在 master-auth 页填手机号并点「获取验证码」。任一步失败静默返回 False。"""
    try:
        sel = ('input[type="tel"], input[placeholder*="手机"], '
               'input[placeholder*="号码"], input[name*="phone" i]')
        box = page.locator(sel).first
        box.wait_for(state="visible", timeout=6000)
        box.fill(phone, timeout=3000)
        page.wait_for_timeout(400)
        for txt in ("获取验证码", "获取短信验证码", "发送验证码"):
            try:
                page.get_by_text(txt, exact=False).first.click(timeout=1800)
                return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def run_login_blocking(phone, on_status, on_success, timeout=600):
    """阻塞式网页登录（供 start_teleagent_login 的线程与独立驱动共用）。

    on_status(text)      进度回传（job result / 驱动状态文件）
    on_success(session)  成功回调，返回 (ok, msg)
    返回 (ok, msg)。
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        msg = "缺少 playwright，无法拉起登录窗口"
        on_status(msg)
        return False, msg

    browser = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            ctx = browser.new_context(locale="zh-CN",
                                      viewport={"width": 520, "height": 820})
            page = ctx.new_page()
            page.set_default_timeout(8000)
            on_status("正在打开天翼统一登录页…")
            page.goto(AUTHORIZE_URL, wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(1200)
            _pull_window_front(ctx)

            prefill = False
            if phone:
                prefill = _prefill_phone(page, phone)
            if prefill:
                on_status("已填入手机号并点击「获取验证码」；若窗口弹出滑块/拼图验证码，"
                          "请在窗口里完成，然后输入收到的短信验证码完成登录。")
            else:
                on_status("请在弹出的窗口里完成登录（手机号+短信验证码 或 密码）；"
                          "出现滑块/拼图验证码时在窗口里完成即可。")

            deadline = time.time() + timeout
            sess = _wait_session(ctx, deadline, job=None)
            if not sess:
                msg = "超时：未等到 web 会话（登录未完成或已取消）"
                on_status(msg)
                return False, msg
            on_status("已抓到 web 会话，正在保存…")
            try:
                res = on_success(sess)
                if isinstance(res, tuple) and len(res) == 3:
                    ok, msg = bool(res[0]), str(res[2])   # (ok, 键名, 提示)
                else:
                    ok, msg = bool(res[0]), str(res[1])
            except Exception as e:
                ok, msg = False, "保存异常：%s" % str(e)[:150]
            on_status(msg)
            return bool(ok), msg
    except Exception as e:
        msg = "网页登录异常：%s" % str(e)[:200]
        on_status(msg)
        return False, msg
    finally:
        try:
            if browser:
                browser.close()
        except Exception:
            pass


# ─────────────────────── 看板登录任务（供前端轮询） ───────────────────────
def start_teleagent_login(phone, name, on_success):
    """TeleAgent 网页登录入口（webapi /api/account/sms_start 的 teleagent 分支调用）。

    phone 可空：填了就尽力代填+代点发码；不填/代填失败由用户在窗口手输。
    返回 (ok, msg, job_view)。
    """
    phone = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if phone and len(phone) != 11:
        return False, "手机号需 11 位（当前：%s），或留空直接在窗口里登录" % phone, None

    job = {
        "job": uuid.uuid4().hex[:12], "platform": "teleagent",
        "mode": "web", "status": "waiting", "finished": False,
        "ok": None, "result": "", "name": name or "", "started": time.time(),
        "user_code": "", "verify_url": AUTHORIZE_URL,
        "expires_in": timeout_sec(),
        "hint": "在弹出的窗口里完成天翼账号登录（短信验证码或密码），"
                "看板自动抓取 web 会话（积分余额/每日打卡用）",
        "phone": phone, "need_code": False, "code": None,
        "code_submitted": False, "sms_sent": False,
    }
    with _job_lock:
        _JOBS[job["job"]] = job

    def _on_status(text):
        job["status"] = "done" if job.get("finished") else "waiting_login"
        job["result"] = text

    def _runner():
        ok, msg = run_login_blocking(
            phone, _on_status,
            lambda sess: on_success(dict(sess, phone=phone, name=name)))
        job.update(status="done", finished=True, ok=bool(ok), result=msg)

    threading.Thread(target=_runner, daemon=True).start()
    return True, "已打开 TeleAgent 登录窗口", _view(job)


def timeout_sec():
    return 600
