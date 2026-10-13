# -*- coding: utf-8 -*-
"""OfficeACE 手机号短信直登 + 本地服务探测/拉起 —— 二期拆分。"""
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
from oauth_device import device_poll, device_start
from oauth_hw import _hw_fill_and_send, _hw_stage, _hw_submit_code


# ────────────────────────────── OfficeACE ──────────────────────────────
# 桌面端本地 API（自签名 HTTPS）。默认 3004，但打包形态下端口可能被随机化
# （asar 内注释：UseRandomFrontendApiPorts），权威来源是 App 自己写的
# runtime-state.json（含 ApiUrl/ApiPort）。候选路径（asar runtimeStateCandidates）：
#   1) %USERPROFILE%\.office-claw\run\windows\runtime-state.json   （打包安装，需 .office-claw-release.json）
#   2) <installRoot>\.office-claw\run\windows\runtime-state.json
#   3) <installRoot>\.office-claw\run\runtime-state.json
_OFFICEACE_API = "https://127.0.0.1:3004"   # 兜底默认
_OFFICEACE_EXE_CANDIDATES = [
    r"E:\OfficeAce\OfficeAce.exe",
]
_OFFICEACE_INSTALL_HINTS = [r"E:\OfficeAce", r"C:\Program Files\OfficeAce"]

# 本进程是否直启过 ServiceHost（2026-10-12）：流程结束时要回收（见 _officeace_maybe_teardown）
_OFFICEACE_SPAWNED = False


def _officeace_runtime_state_paths():
    """按 App 自己的 runtimeStateCandidates 顺序给出 runtime-state.json 候选路径。
    注意安装形态是 <installRoot>\\.office-claw\\run\\windows\\runtime-state.json
    （.office-claw 段不能省）。"""
    home = os.path.expanduser("~")
    roots = [os.path.join(home, ".office-claw")]
    roots += [os.path.join(h, ".office-claw") for h in _OFFICEACE_INSTALL_HINTS]
    cands = []
    for root in roots:
        cands.append(os.path.join(root, "run", "windows", "runtime-state.json"))
        cands.append(os.path.join(root, "run", "runtime-state.json"))
    return cands


def _officeace_gui_running():
    """GUI 壳（OfficeAce.exe）是否在跑：在跑说明服务可能正被它共用，绝不回收。
    注意 tasklist 输出是 GBK（中文 Windows），不能用 text=True（UTF-8 解码会炸）——
    按字节匹配进程名（纯 ASCII），对任何代码页都稳。"""
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq OfficeAce.exe"],
                             capture_output=True, timeout=10)
        return b"OfficeAce.exe" in (out.stdout or b"")
    except Exception:
        return False


def _officeace_maybe_teardown():
    """回收本流程直启的 ServiceHost（幂等：只有本进程 spawn 过才动手）。
    ⚠ 2026-10-12 实测教训：无头实例常驻会独占 runtime-state 的 HostPid 归属，
    用户之后打开 GUI 客户端时报 NATIVE_SERVICE_STATE_INVALID 拒绝启动
    （expected pid=25208, actual pid=44892）。用完必须还。"""
    global _OFFICEACE_SPAWNED
    if not _OFFICEACE_SPAWNED:
        return False
    _OFFICEACE_SPAWNED = False
    if _officeace_gui_running():
        return False                       # GUI 在共用这套服务，不能杀
    try:
        for st in _officeace_runtime_state_paths():
            try:
                pid = int(json.load(open(st, encoding="utf-8")).get("HostPid") or 0)
            except Exception:
                continue
            if pid:
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                               capture_output=True)
                return True
    except Exception:
        pass
    return False


def _officeace_resolve_api():
    """返回 (base_url, source)。优先读 runtime-state.json 的 ApiUrl（防端口随机化），
    失败再回退 192.0.0.1:3004。source 用于诊断文案。"""
    for p in _officeace_runtime_state_paths():
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        url = str(d.get("ApiUrl") or "").strip()
        port = d.get("ApiPort")
        state = str(d.get("State") or "").strip()
        if not url and isinstance(port, int) and port > 0:
            url = "https://127.0.0.1:%d" % port
        if url:
            return url.rstrip("/"), "runtime-state.json(%s%s)" % (
                p, ("; State=%s" % state) if state else "")
    return _OFFICEACE_API, "默认 3004"


def _officeace_exe_path():
    """定位 OfficeAce.exe（本机已装时）。"""
    for p in _OFFICEACE_EXE_CANDIDATES:
        if os.path.exists(p):
            return p
    for root in _OFFICEACE_INSTALL_HINTS:
        p = os.path.join(root, "OfficeAce.exe")
        if os.path.exists(p):
            return p
    return None


def _officeace_api(path, method="GET", body=None, timeout=8, base=None):
    base = base or _OFFICEACE_API
    try:
        # 关键：本地回环必须绕过系统代理（否则 sandbox/公司代理会把 127.0.0.1 也拦下来报 ProxyError）
        r = requests.request(method, base + path,
                             json=body if body is not None else None,
                             headers={"Content-Type": "application/json"},
                             timeout=timeout, verify=False,
                             proxies={"http": None, "https": None})
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"raw": r.text[:200]}
    except Exception as e:
        return 0, {"error": str(e)[:120]}


def _officeace_probe(timeout=5):
    """探活：返回 (ok, base_url, info)。读 runtime-state 拿真实端口后打 /api/islogin。"""
    base, src = _officeace_resolve_api()
    st, j = _officeace_api("/api/islogin", timeout=timeout, base=base)
    if st == 0 and base != _OFFICEACE_API:
        st, j = _officeace_api("/api/islogin", timeout=timeout, base=_OFFICEACE_API)
        if st != 0:
            base = _OFFICEACE_API
    return (st != 0), base, {"status": st, "info": j, "source": src}


def _officeace_autostart(wait=75):
    """确保本地 API 就绪：probe 优先 → 直启 ServiceHost（无 watchdog）→ launcher 兜底。
    返回 (ok, base_url, note)。

    ⚠⚠ 2026-10-09 架构（勿回退）：
      · `OfficeAce.exe`（桌面壳 launcher）spawn ServiceHost 时带 `--stop-on-launcher-exit`
        → launcher 一死（沙箱/无桌面会话 ~0.5s exit 0）整个栈连锁自停。
      · **正确姿势 = 直启 `OfficeAceServiceHost.exe`（不带 stop 标志，剥掉代理环境变量，
        检测到 HTTP_PROXY 会秒拒）**，与看板进程解耦，可常驻。
      · 第二实例问题：服务已在跑时再拉 OfficeAce.exe 会因单实例锁秒退 exit=0 ——
        **这不是失败**，必须先 probe、秒退后复查 probe。
    """
    import subprocess
    # ⓪ 入口先 probe：服务已在跑就直接用（第二实例锁会让 launcher 秒退，先避免误判）
    ok, base, _ = _officeace_probe(timeout=4)
    if ok:
        return True, base, "本地 API 已就绪（服务本就在跑）"

    # ① 直启 ServiceHost（detached，剥代理变量）
    sh = None
    sh_exe = os.path.join(os.path.dirname(_officeace_exe_path()
                          or r"E:\OfficeAce\OfficeAce.exe"),
                          "OfficeAceServiceHost.exe")
    if os.path.isfile(sh_exe):
        env = dict(os.environ)
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                  "ALL_PROXY", "all_proxy"):
            env.pop(k, None)
        try:
            flags = 0
            if hasattr(subprocess, "DETACHED_PROCESS"):
                flags = (subprocess.DETACHED_PROCESS
                         | subprocess.CREATE_NEW_PROCESS_GROUP)
            sh = subprocess.Popen(
                [sh_exe, "--mode", "serve", "--enable-native-runtime",
                 "--packaged-production",
                 "--project-root", os.path.dirname(sh_exe)],
                cwd=os.path.dirname(sh_exe), env=env,
                creationflags=flags, close_fds=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            sh = None

    # ② 兜底拉 launcher（真实桌面会话下可用）
    exe = _officeace_exe_path()
    proc = None
    if exe:
        try:
            flags = 0
            if hasattr(subprocess, "DETACHED_PROCESS"):
                flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            proc = subprocess.Popen([exe], cwd=os.path.dirname(exe),
                                    creationflags=flags, close_fds=True)
        except Exception:
            proc = None

    # ③ 轮询等 API 就绪（无论哪个路径拉起的，API 起来就算成功）
    t0 = time.time()
    while time.time() - t0 < wait:
        ok, base, _ = _officeace_probe(timeout=3)
        if ok:
            if sh is not None:
                # 直启 ServiceHost 成功 → 标记为本流程所有，结束后 _officeace_maybe_teardown 回收
                globals()["_OFFICEACE_SPAWNED"] = True
            how = "ServiceHost" if sh else "客户端"
            return True, base, "已自动启动 OfficeACE 服务（%s，用时 %.0fs）" % (how, time.time() - t0)
        time.sleep(2)
    why = []
    if sh is not None and sh.poll() is not None:
        why.append("ServiceHost 退出(exit=%s)" % sh.returncode)
    if proc is not None and proc.poll() is not None:
        why.append("launcher 退出(exit=%s)" % proc.returncode)
    return (False, _OFFICEACE_API,
            "已尝试自动启动（直启 ServiceHost + 客户端）但 %ds 内本地 API 仍未就绪%s。"
            "请在真实桌面会话里手动双击 OfficeAce.exe 后重试。"
            % (wait, ("（%s）" % "；".join(why)) if why else ""))


def start_officeace_sms_job(phone, name, on_success):
    """OfficeACE 手机号+短信直登：驱动桌面端本地 API 完成华为云 OAuth（App 落盘凭据）。
    客户端没在跑时**自动拉起**（用户 2026-10-08 选定的行为）。"""
    _officeace_maybe_teardown()   # 清掉上一次流程可能残留的直启实例（幂等，非本流程拉起则no-op）
    phone = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if len(phone) != 11:
        return False, "请填写 11 位手机号（当前：%s）" % (phone or "空"), None
    ok, base, info = _officeace_probe(timeout=5)
    note = ""
    if not ok:
        # wait=25：正常启动 host+redis+api 约 10~20s 够用；若桌面壳秒退会立即返回，不傻等
        ok, base, note = _officeace_autostart(wait=25)
        if not ok:
            return False, ("%s 本地 API 未就绪。已尝试自动启动 OfficeACE 客户端但失败：%s。"
                           "请手动双击 %s 启动（托盘里在跑即可），再点本按钮。"
                           % (base, note,
                              _officeace_exe_path() or r"E:\OfficeAce\OfficeAce.exe")), None
    flow = {"user_code": "", "verify_url": "", "expires_in": 600,
            "interval": 2, "platform": "officeace", "sub": None, "api": base}
    job = _new_job("officeace", flow)
    job.update(mode="sms", phone=phone, name=name or "",
               hint="华为云统一登录（手机号+验证码），完成后 App 自动保存新凭据")
    if note:
        job["result"] = note
    with _job_lock:
        _JOBS[job["job"]] = job
    threading.Thread(target=_run_officeace_sms_job,
                     args=(job, phone, name, on_success), daemon=True).start()
    return True, ("已发起 OfficeACE 短信登录" + ("（%s）" % note if note else "")), _view(job)


def _officeace_scan_captured(cdp, captured):
    """在已捕获的 https 响应里找 officeclaw://oauth/callback?code=…（Location 头优先，
    其次 authui/oauth 相关响应体）。返回 (code, state) 或 (None, None)。"""

    def parse(u):
        m = re.search(r"[?&]code=([^&]+)", u or "")
        m2 = re.search(r"[?&]state=([^&]+)", u or "")
        if m:
            return m.group(1), (m2.group(1) if m2 else "")
        return None, None

    for it in captured:
        for u in (it.get("loc"), it.get("url")):
            code, stt = parse(u)
            if code:
                return code, stt
    for it in captured:
        if it.get("body_done") or not it.get("want_body"):
            continue
        try:
            resp = cdp.send("Network.getResponseBody", {"requestId": it["rid"]})
            body = resp.get("body") or ""
            it["body_done"] = True
            if "oauth/callback" in body or "officeclaw" in body:
                code, stt = parse(body)
                if code:
                    return code, stt
        except Exception:
            it["body_done"] = True
    return None, None


def _run_officeace_sms_job(job, phone, name, on_success):
    try:
        return _run_officeace_sms_job_inner(job, phone, name, on_success)
    finally:
        # 无论成功/失败/用户中途放弃，本流程直启的服务都回收（GUI 在跑时自动跳过）
        _officeace_maybe_teardown()


def _run_officeace_sms_job_inner(job, phone, name, on_success):
    base = job.get("api") or _OFFICEACE_API
    st, j = _officeace_api("/api/login/authorize", "POST", {"persist": True},
                           timeout=12, base=base)
    url = (j or {}).get("authorizeUrl") or ""
    state = (j or {}).get("state") or ""
    if st != 200 or not url or not state:
        job.update(status="done", finished=True, ok=False,
                   result="App 未返回授权链接（HTTP %s）：%s" % (st, str(j)[:150]))
        return
    browser = None
    ok_saved = False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False, args=_OFFSCREEN_ARGS)
            ctx = browser.new_context(locale="zh-CN",
                                      viewport={"width": 520, "height": 800},
                                      ignore_https_errors=True)
            page = ctx.new_page()
            cdp = ctx.new_cdp_session(page)
            cdp.send("Network.enable")
            captured = []

            def _on_resp(e):
                try:
                    resp = e.get("response") or {}
                    hdrs = resp.get("headers") or {}
                    loc = hdrs.get("location") or hdrs.get("Location") or ""
                    u = resp.get("url") or ""
                    captured.append({"rid": e.get("requestId"), "url": u, "loc": loc,
                                     "want_body": any(k in u for k in
                                                      ("authui", "oauth", "login")),
                                     "body_done": False})
                    if len(captured) > 240:
                        del captured[:80]
                except Exception:
                    pass
            cdp.on("Network.responseReceived", _on_resp)

            job["status"] = "opening"
            job["result"] = "已打开华为云登录窗口（OfficeACE 授权链路）…"
            page.goto(url, wait_until="domcontentloaded", timeout=60000)
            form_ok = False
            for _ in range(28):
                if _hw_stage(page):
                    form_ok = True
                    break
                page.wait_for_timeout(800)
            if form_ok:
                page.wait_for_timeout(700)
                filled = False
                for attempt in range(3):
                    if _hw_fill_and_send(page, ctx, job, phone):
                        filled = True
                        break
                    page.wait_for_timeout(900)
                if not filled:
                    _pull_window_front(ctx)
                    job["result"] = ("手机号输入框找到了但自动填报失败，已把窗口拉回屏幕；"
                                     "请手动完成登录，看板自动接 code。")
            else:
                _pull_window_front(ctx)
                job["result"] = "没等到华为云登录页，请在窗口里手动完成登录。"
                job.update(sms_sent=True, need_code=False)

            deadline = time.time() + 620
            while time.time() < deadline:
                if form_ok and job.get("code") and not job.get("code_submitted"):
                    _hw_submit_code(page, ctx, job, job["code"])
                code, cb_state = _officeace_scan_captured(cdp, captured)
                if code:
                    st2, j2 = _officeace_api("/api/login/callback", "POST",
                                             {"code": code, "state": cb_state or state},
                                             timeout=20, base=base)
                    uid = (j2 or {}).get("userId") or ""
                    if (j2 or {}).get("success") and uid:
                        grant = {"user_id": str(uid),
                                 "user_name": (j2 or {}).get("userName") or "",
                                 "phone": phone,
                                 "via_oauth": True}
                        try:
                            ok2, nm, msg2 = on_success(grant)
                        except Exception as e:
                            ok2, nm, msg2 = False, "", "保存登录态异常：%s" % str(e)[:150]
                        job.update(status="done", finished=True, ok=bool(ok2),
                                   result=msg2 or ("已保存 %s" % nm), name=nm or "")
                        ok_saved = True
                    elif (j2 or {}).get("needCode"):
                        job.update(status="done", finished=True, ok=False,
                                   result="App 要求二次验证（needCode），"
                                          "请在 OfficeACE 窗口里完成后再导入。")
                    else:
                        job.update(status="done", finished=True, ok=False,
                                   result="App 交换 code 失败（HTTP %s）：%s"
                                          % (st2, str(j2)[:160]))
                    break
                page.wait_for_timeout(700)
            if not ok_saved and not job.get("finished"):
                job.update(status="done", finished=True, ok=False,
                           result="登录超时（620 秒内未捕获到回调 code），请重试")
    except Exception as e:
        job.update(status="done", finished=True, ok=False,
                   result="OfficeACE 短信登录异常：%s" % str(e)[:200])
    finally:
        try:
            if browser:
                browser.close()
        except Exception:
            pass


if __name__ == "__main__":
    ok, msg, flow = device_start("minimax")
    print("device_start:", ok, msg)
    if ok:
        print(json.dumps(flow, ensure_ascii=False, indent=1))
        print("\n请在浏览器打开：", flow["verify_url"])
        print("授权码：", flow["user_code"])
        for _ in range(3):
            time.sleep(1)
            print("poll ->", device_poll(flow)[0])
