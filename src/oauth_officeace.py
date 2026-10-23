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
import officeace_guard


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
                # 2026-10-19：光杀进程不够——状态文件仍记着死 pid，客户端下次启动
                # 会抛 NATIVE_SERVICE_STATE_INVALID（expected/actual 不匹配）。
                try:
                    if int(json.load(open(st, encoding="utf-8")).get("HostPid") or 0) == pid:
                        os.remove(st)
                except Exception:
                    pass
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


def _officeace_pid_is_host(pid):
    """校验 pid 确实是 OfficeAceServiceHost.exe（防 pid 复用误杀）。"""
    try:
        out = subprocess.run(["tasklist", "/FI", "PID eq %d" % int(pid)],
                             capture_output=True, timeout=10)
        return b"OfficeAceServiceHost.exe" in (out.stdout or b"")
    except Exception:
        return False


def _officeace_host_pids():
    """tasklist 全盘扫 OfficeAceServiceHost.exe 的全部 pid（/FO CSV /NH 逐行解析）。

    ⚠⚠ 2026-10-22 二次修复：旧实现只认 runtime-state.json 的 HostPid —— 状态文件
    缺失/被删/还没来得及写时，孤儿 host 照样占着 3004 端口和租约，GUI 一起就被
    顶退（startup-failure.json 13:49 实证）。tasklist 扫描不依赖任何状态文件。"""
    pids = []
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq OfficeAceServiceHost.exe",
             "/FO", "CSV", "/NH"],
            capture_output=True, timeout=10)
        text = (out.stdout or b"").decode("gbk", "replace")
        for line in text.splitlines():
            line = line.strip()
            if "OfficeAceServiceHost.exe" not in line:
                continue
            m = re.match(r'^"?OfficeAceServiceHost\.exe"?\s*,\s*"?(\d+)"?', line)
            if m:
                pids.append(int(m.group(1)))
    except Exception:
        pass
    return pids


def _officeace_port_free(port=3004):
    """端口是否已释放（连不上 = 已释放）。taskkill 后 TCP 可能有逗留，
    GUI 的 ServiceHost 立刻起会撞 "Another host already running"。"""
    import socket
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", port))
        return False
    except Exception:
        return True
    finally:
        s.close()


def _officeace_kill_orphan_host():
    """杀掉「没有 GUI 在跑」的全部遗留 ServiceHost，并清掉指向死 pid 的状态文件。
    返回杀掉的 pid 列表（空列表 = 无可杀/有 GUI 在跑）。

    ⚠⚠ 2026-10-22 问题2 根因：看板（含上一轮看板进程 / 刷新周期）拉起的裸 host
    常驻不退，用户双击 OfficeAce.exe 时客户端检测到
    「Another OfficeAce native service host is already running」
    （startup-failure.json 实证 11:44 / 13:49）→ 客户端打不开。
    GUI 要能启动，必须先把这个占茅坑的 host 杀掉 + 删状态文件
    （状态文件留着死 pid 也会让客户端抛 expected/actual 不匹配拒启）。

    双通道找 host：tasklist 全盘扫 + 状态文件 HostPid 兜底（pid 复用校验）。
    仅在没有 GUI 运行时调用（GUI 在跑 = 服务归它所有，绝不能动）。"""
    if _officeace_gui_running():
        return []
    pids = _officeace_host_pids()
    for st in _officeace_runtime_state_paths():
        try:
            pid = int(json.load(open(st, encoding="utf-8")).get("HostPid") or 0)
        except Exception:
            continue
        if pid and pid not in pids and _officeace_pid_is_host(pid):
            pids.append(pid)
    for pid in pids:
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, timeout=15)
        except Exception:
            pass
    # 杀完必须删状态文件，否则客户端读到死 pid 拒启（2026-10-19 实证）
    for st in _officeace_runtime_state_paths():
        try:
            pid = int(json.load(open(st, encoding="utf-8")).get("HostPid") or 0)
        except Exception:
            continue
        if pid in pids or (pid and not _officeace_pid_is_host(pid)):
            try:
                os.remove(st)
            except Exception:
                pass
    return pids


def _officeace_autostart(wait=45, need_gui=True):
    """确保「GUI 客户端 + 本地 API」就绪。返回 (ok, base_url, note)。

    ⚠⚠ 2026-10-22 二次根因修复（勿回退，用户四连问题的最后一环）：
    officeclaw:// 回调只能由 GUI 进程接收（OS 按 HKCR\\officeclaw 投递给
    OfficeAce.exe）。裸 ServiceHost 能 serve authorize/poll，但**永远拿不到
    code** → 旧代码的「裸 host 兜底」对登录流程等于保证 620s 超时，还会占着
    端口/租约把用户双击的客户端顶退。所以本函数**只拉 GUI，不做裸 host 兜底**；
    起不来就明说，让用户手动双击（裸 host 只用于 platforms.officeace 的
    当前账号无人值守续期，且有登录互斥闸）。

    重试至多 3 次的原因：taskkill 后端口/租约释放有延迟，GUI 首启会撞
    "Another OfficeAce native service host is already running" 而秒退
    （startup-failure.json 13:49 实证：刷新周期的裸 host 与 GUI 抢占）。
    每轮重试前都清孤儿 + 等端口真正释放，把抢占窗口压到零。"""
    # ⓪ 入口先 probe：客户端已在跑就直接用
    ok, base, _ = _officeace_probe(timeout=4)
    if ok and _officeace_gui_running():
        return True, base, "本地 API 已就绪（OfficeACE 客户端正在运行）"
    exe = _officeace_exe_path()
    if not exe:
        return (False, _OFFICEACE_API,
                "未找到 OfficeACE 安装（%s）。请先安装 OfficeACE 桌面端再登录。"
                % r"E:\OfficeAce\OfficeAce.exe")
    per = max(12, min(25, wait // 2 or 20))
    notes = []
    for attempt in range(1, 4):
        # ① 每轮先清掉没有 GUI 在跑的遗留 host，再等端口真正释放
        killed = _officeace_kill_orphan_host()
        for _ in range(20):
            if _officeace_port_free():
                break
            time.sleep(0.5)
        if attempt > 1:
            time.sleep(2.0)
        # ② 拉起桌面客户端（剥代理变量：ServiceHost 检测到 *PROXY* 会拒绝启动）
        try:
            env = dict(os.environ)
            for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                      "ALL_PROXY", "all_proxy"):
                env.pop(k, None)
            flags = 0
            if hasattr(subprocess, "DETACHED_PROCESS"):
                flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            gui = subprocess.Popen([exe], cwd=os.path.dirname(exe), env=env,
                                   creationflags=flags, close_fds=True)
        except Exception as e:
            notes.append("第%d次拉起客户端失败：%s" % (attempt, str(e)[:80]))
            continue
        # ③ 等 GUI 把自己的 ServiceHost 拉起来（冷启约 10~25s）
        t0 = time.time()
        other_running = False
        while time.time() - t0 < per:
            ok, base, _ = _officeace_probe(timeout=3)
            if ok and _officeace_gui_running():
                note = ("已拉起 OfficeACE 客户端，本地 API 就绪"
                        "（第%d次尝试，用时 %.0fs）" % (attempt, time.time() - t0))
                if killed:
                    note += "（已清理遗留服务进程 %s）" % ",".join(
                        str(p) for p in killed)
                return True, base, note
            if gui.poll() is not None:
                # 我们的实例退了：还有别的 GUI 在跑（单实例锁）→ 等主实例的 API
                other_running = _officeace_gui_running()
                break
            time.sleep(1.5)
        if other_running:
            t1 = time.time()
            while time.time() - t1 < per:
                ok, base, _ = _officeace_probe(timeout=3)
                if ok:
                    return True, base, ("OfficeACE 客户端本就在运行，本地 API 已就绪"
                                        "（用时 %.0fs）" % (time.time() - t1))
                time.sleep(1.5)
            return (False, _OFFICEACE_API,
                    "OfficeACE 客户端已在运行，但 %ds 内本地 API 仍未就绪。"
                    "请从托盘完全退出客户端，重新双击 %s 后再试。" % (per, exe))
        if gui.poll() is None:
            notes.append("第%d次：%ds 内本地 API 未就绪（客户端进程仍在，可能还在初始化）"
                         % (attempt, per))
        else:
            notes.append("第%d次：客户端启动即退出（exit=%s，多为主实例锁/服务被抢占）"
                         % (attempt, gui.returncode))
    return (False, _OFFICEACE_API,
            "已重试 3 次拉起 OfficeACE 客户端均失败（%s）。请手动双击 %s，"
            "等客户端窗口/托盘图标出现后再点「发送验证码」。"
            % ("；".join(notes)[:220], exe))


def start_officeace_sms_job(phone, name, on_success):
    """OfficeACE 手机号+短信直登：驱动桌面端本地 API 完成华为云 OAuth（App 落盘凭据）。
    客户端没在跑时**自动拉起**（用户 2026-10-08 选定的行为）。

    ⚠ 2026-10-22：全程持登录互斥闸（officeace_guard）—— 短信登录独占 GUI，
    刷新周期（try_refresh）在登录期间不碰本地服务，否则它的裸 host 起停会把
    客户端顶退、authorize 撞上服务起停窗口报 HTTP 0（用户四连问题实证）。"""
    if not officeace_guard.begin_login():
        return False, "已有一个果办登录流程正在进行，请先完成或等待其结束后再试", None
    started = False
    try:
        _officeace_maybe_teardown()   # 清掉上一次流程可能残留的直启实例（幂等，非本流程拉起则no-op）
        phone = "".join(ch for ch in str(phone or "") if ch.isdigit())
        if len(phone) != 11:
            return False, "请填写 11 位手机号（当前：%s）" % (phone or "空"), None
        ok, base, info = _officeace_probe(timeout=5)
        note = ""
        if not (ok and _officeace_gui_running()):
            # 短信登录的回调（officeclaw://）必须由 GUI 客户端接收。即使 API 已被
            # 看板刷新周期的裸 host 拉起来，也要先把客户端拉起来
            #（autostart 会清掉占茅坑的裸 host 再拉 GUI，且绝不回退裸 host）。
            # wait=45：等 Electron 客户端把自己的 ServiceHost 拉起来（冷启约 10~25s）。
            ok, base, note = _officeace_autostart(wait=45, need_gui=True)
            if not ok:
                return False, ("本地 API 未就绪。已尝试自动拉起 OfficeACE 客户端但失败：%s。"
                               "请手动双击 %s 启动（托盘里在跑即可），再点本按钮。"
                               % (note,
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
        started = True
        return True, ("已发起 OfficeACE 短信登录" + ("（%s）" % note if note else "")), _view(job)
    finally:
        if not started:
            # 线程没起来（参数错/拉客户端失败/异常）→ 立即还闸，别把刷新周期锁死
            officeace_guard.end_login()


def _officeace_scan_captured(cdp, captured):
    """在已捕获的 https 响应里找 officeclaw://oauth/callback?code=…&state=…。
    返回 (code, state) 或 (None, None)。

    ⚠ 2026-10-22 修复：华为 OAuth 重定向链里，中间跳板
    https://…/oauth/callback?code=HUAWEI&state=… 也会被 Network 捕获，且比最终
    officeclaw:// 原生跳转更早出现。旧逻辑「取第一个带 code 的 URL」会拿到华为侧的
    code/state，POST 给 App 的 /api/login/callback 即报 oauth_state_invalid。
    → 只认最终 officeclaw://oauth/callback（原生 scheme），其余跳过；原生跳转
      Playwright 捕获不到时，退而从 XHR 响应体里捞 officeclaw 串（排除 https 中间跳板）。
    """

    def parse(u):
        m = re.search(r"[?&]code=([^&]+)", u or "")
        m2 = re.search(r"[?&]state=([^&]+)", u or "")
        if m:
            return m.group(1), (m2.group(1) if m2 else "")
        return None, None

    # ① 直接捕获到 officeclaw://oauth/callback 原生跳转（只认该 scheme，排除华为中间跳板）
    for it in captured:
        for u in (it.get("loc"), it.get("url")):
            if not u or "officeclaw://oauth/callback" not in u:
                continue
            code, stt = parse(u)
            if code:
                return code, stt

    # ② 退而从 XHR 响应体里捞（原生跳转 Playwright 捕获不到，但 App 交换前 XHR 体里带 officeclaw 串）
    _hint = ("officeclaw", "oauth", "callback", "login", "token", "auth", "exchange")
    for it in captured:
        if it.get("body_done"):
            continue
        url = it.get("url") or ""
        if not it.get("want_body") and not any(k in url for k in _hint):
            continue
        try:
            resp = cdp.send("Network.getResponseBody", {"requestId": it["rid"]})
            body = resp.get("body") or ""
            it["body_done"] = True
            if "officeclaw" in body:
                code, stt = parse(body)
                if code:
                    return code, stt
        except Exception:
            it["body_done"] = True
    return None, None


# 从 officeclaw://oauth/callback?code=…&state=… 里取 (code, state)
def _officeace_cb_params(u):
    m = re.search(r"[?&]code=([^&]+)", u or "")
    m2 = re.search(r"[?&]state=([^&]+)", u or "")
    if m:
        return m.group(1), (m2.group(1) if m2 else "")
    return None, None


# ⚠⚠ 2026-10-22 根因修复：OfficeACE 的 redirect_uri 是**标准 HTTPS 回调页**
#   （https://agentarts.cn-southwest-2.myhuaweicloud.com/v1/claw/auth/callback?code=HUAWEI&state=…），
#   真正的 officeclaw://oauth/callback?code=CLAW&state=… 是该 HTTPS 页面**再用 JS 客户端跳转**
#   抛出的自定义 scheme —— 不产生任何 HTTP 响应，Playwright/CDP 的 Network 层根本捕获不到
#   （旧实现只扫 HTTP 302 Location / XHR body → 永远落空 → 卡到 620s 超时，/api/login/callback 从未被调用）。
#   解法：document_start 注入钩子，在任何页面脚本跑之前挂好：
#     · location.assign / location.replace / window.open 收 raw URL（未 HTML 编码，首选）
#     · 锚点点击 capture 段收 a[href^=officeclaw://]
#     · MutationObserver + 定时扫 documentElement.outerHTML 兜底（URL 以属性/脚本字符串出现时）
#   统一存进 window.__oc_cb，轮询 page.evaluate 读出。
_OFFICEACE_CAPTURE_JS = r"""(() => {
  if (window.__oc_hooked) return;
  window.__oc_hooked = true;
  window.__oc_cb = null;
  const grab = (u) => { try { u = '' + u;
    if (u && u.indexOf('officeclaw://') === 0 && !window.__oc_cb) window.__oc_cb = u; } catch (e) {} };
  const dec = (s) => s.replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#39;/g,"'")
                      .replace(/&lt;/g,'<').replace(/&gt;/g,'>');
  const parseCb = () => {
    if (window.__oc_cb) return window.__oc_cb;
    try {
      const html = document.documentElement ? document.documentElement.outerHTML : '';
      const m = html.match(/officeclaw:\/\/oauth\/callback[^"'<>\s)]*/);
      if (m) { window.__oc_cb = dec(m[0]); return window.__oc_cb; }
    } catch (e) {}
    return null;
  };
  window.__oc_parse = parseCb;
  try {
    if (window.location.assign) { const la = window.location.assign.bind(window.location);
      window.location.assign = (u) => { grab(u); return la(u); }; }
    if (window.location.replace) { const lr = window.location.replace.bind(window.location);
      window.location.replace = (u) => { grab(u); return lr(u); }; }
  } catch (e) {}
  try { if (window.open) { const wo = window.open.bind(window);
    window.open = (u, ...r) => { grab(u); return wo(u, ...r); }; } } catch (e) {}
  document.addEventListener('click', (e) => { try {
    let a = e.target; while (a && a.tagName !== 'A') a = a.parentElement;
    if (a && a.href) grab(a.href); } catch (err) {} }, true);
  const scan = () => { try { parseCb(); } catch (e) {} };
  scan();
  try { new MutationObserver(scan).observe(document.documentElement,
       {childList:true, subtree:true, attributes:true}); } catch (e) {}
  try { setInterval(scan, 400); } catch (e) {}
})();"""


# 官方回调链路（asar 逆向实证，2026-10-22 起为主路径）：
#   authorize 返回 state → 浏览器登录 → 华为回调页 JS 客户端跳转抛
#   officeclaw://oauth/callback?code=CLAW&state=S → **OS 按 HKCR\officeclaw 把该
#   scheme 投递给 GUI 进程**（OfficeAce.exe）→ GUI 主进程把 code 登记到 host 侧 →
#   轮询 GET /api/login/oauth/poll?state=S 取 {code} → POST /api/login/callback 落凭据。
#   实测（裸 host，2026-10-22）：无 code 时 poll 返 HTTP 202 +
#   {"error_code":"AgentArts.11000009","error_msg":"Authorization code is not ready..."}；
#   垃圾 state 返 400 + 11000004（state 必须 32 位 [0-9a-f]）。
#   error_code 带 AgentArts. 前缀，用后缀匹配防前缀变动。
_OFFICEACE_POLL_NOT_READY = "11000009"


def _officeace_poll_code(base, state, timeout=8):
    """官方 poll：返回 (code, note)。code 非空 = GUI 已收到 officeclaw:// 回调。"""
    if not state:
        return None, "无 state"
    st, j = _officeace_api("/api/login/oauth/poll?state=%s" % urllib.parse.quote(state),
                           timeout=timeout, base=base)
    if st == 200 and isinstance(j, dict) and j.get("code"):
        return str(j.get("code")), "poll 拿到 code"
    if st == 202:
        ec = str((j or {}).get("error_code") or "") if isinstance(j, dict) else ""
        if ec.endswith(_OFFICEACE_POLL_NOT_READY):
            return None, ""            # 正常未就绪，不算异常
        return None, "poll 202: %s" % str(j)[:80]
    if st == 0:
        return None, "poll 连接失败（本地 API 不在跑？）"
    return None, "poll HTTP %s: %s" % (st, str(j)[:80])


def _officeace_relay_file_params(max_age=180):
    """读 activation relay 中转文件：secondary GUI 实例收到 officeclaw:// 后
    会把原文写进 %TEMP%\\officeclaw-toast-activation.txt 再退出，primary 每 500ms
    轮询它。primary 没来得及处理时，看板可以直接从这里捞 (code, state)。
    只认刚写过的（mtime 在 max_age 秒内），避免捡到几天前的残留。"""
    p = os.path.join(os.environ.get("TEMP", ""), "officeclaw-toast-activation.txt")
    try:
        if not os.path.isfile(p):
            return None, None
        if time.time() - os.path.getmtime(p) > max_age:
            return None, None
        txt = open(p, encoding="utf-8", errors="replace").read()
        m = re.search(r"officeclaw://oauth/callback[^\"'\s)]*", txt)
        if m:
            return _officeace_cb_params(m.group(0))
    except Exception:
        pass
    return None, None


def _run_officeace_sms_job(job, phone, name, on_success):
    try:
        return _run_officeace_sms_job_inner(job, phone, name, on_success)
    finally:
        # 无论成功/失败/用户中途放弃，本流程直启的服务都回收（GUI 在跑时自动跳过）
        _officeace_maybe_teardown()
        # 还登录互斥闸：刷新周期可以恢复无人值守续期了
        officeace_guard.end_login()


def _run_officeace_sms_job_inner(job, phone, name, on_success):
    base = job.get("api") or _OFFICEACE_API
    # 授权前复检：autostart 成功后到这一步之间服务可能被掉（起停窗口）——
    # 先给明确诊断，别让用户看到一句裸的 "HTTP 0 Max retries exceeded"
    ok0, base0, _ = _officeace_probe(timeout=4)
    if not ok0:
        job.update(status="done", finished=True, ok=False,
                   result=("本地 API 在发起授权前掉线（OfficeACE 服务没在跑）。"
                           "请确认客户端正在运行后重试。"))
        return
    base = base0 or base
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
            # document_start 注入：在任何页面脚本前挂好 officeclaw:// 捕获钩子
            # （HTTPS 回调页的 JS 客户端跳转，HTTP Network 层抓不到，必须浏览器侧拦）
            try:
                ctx.add_init_script(_OFFICEACE_CAPTURE_JS)
            except Exception:
                pass
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
            t_start = time.time()
            poll_n = 0
            startfile_tried = False
            last_poll_note = ""
            gui_warned = False
            while time.time() < deadline:
                if form_ok and job.get("code") and not job.get("code_submitted"):
                    _hw_submit_code(page, ctx, job, job["code"])
                # ① 官方 poll（主路径，2026-10-22）：GUI 收到 officeclaw:// 后 host 侧
                #    登记 code，轮询 /api/login/oauth/poll 取。~每 1.4s 一次。
                code = cb_state = None
                if poll_n % 2 == 0:
                    c, note = _officeace_poll_code(base, state)
                    last_poll_note = note
                    if c:
                        code, cb_state = c, state
                poll_n += 1
                # ② 兜底 A：JS 钩子 + DOM 观测（浏览器侧直接抓到 officeclaw:// URL）
                oc_url = None
                try:
                    oc_url = page.evaluate(
                        "() => (window.__oc_parse ? window.__oc_parse() : (window.__oc_cb || null))")
                except Exception:
                    oc_url = None
                if not code and oc_url:
                    code, cb_state = _officeace_cb_params(oc_url)
                # ③ 兜底 B：CDP HTTP 层 302 Location / XHR body（极少数服务端 302 直跳场景）
                if not code:
                    code, cb_state = _officeace_scan_captured(cdp, captured)
                # ④ 兜底 C：activation relay 中转文件（secondary 实例写的 officeclaw:// 原文）
                if not code:
                    code, cb_state = _officeace_relay_file_params()
                if oc_url and code:
                    _codearts_debug("officeace", "JS 捕获 officeclaw 回调: %s" % str(oc_url)[:140])
                # ⑤ 兜底 D：浏览器已跳到 officeclaw:// 但官方 poll 迟迟不返回
                #    （OS 投递失败/handler 未注册）→ 主动 startfile 把 URL 投给 GUI
                if not code and oc_url and not startfile_tried and time.time() - t_start > 20:
                    startfile_tried = True
                    try:
                        os.startfile(oc_url)
                        _codearts_debug("officeace", "已 startfile 主动投递 officeclaw 回调")
                    except Exception as e:
                        _codearts_debug("officeace", "startfile 投递失败: %s" % str(e)[:100])
                # ⑥ 诊断提示：客户端没在跑时 poll 永远 202，说清楚免得干等
                if not code and not gui_warned and time.time() - t_start > 60 \
                        and not _officeace_gui_running():
                    gui_warned = True
                    job["result"] = ("已打开登录窗口，但 OfficeACE 客户端没在运行 —— "
                                     "回调无人接收。请双击 OfficeAce.exe 把客户端拉起来，"
                                     "再回到本窗口完成登录。")
                # ⑥b 快退：客户端退出且本地 API 也不在跑 → 回调无人接收，
                #     本次登录不可能完成，别干等 620s
                if not code and time.time() - t_start > 45 \
                        and not _officeace_gui_running():
                    ok3, _b3, _i3 = _officeace_probe(timeout=3)
                    if not ok3:
                        job.update(status="done", finished=True, ok=False,
                                   result=("OfficeACE 客户端已退出、本地 API 也不在跑 —— "
                                           "回调无人接收，本次登录无法完成。请重新发起登录，"
                                           "并保持客户端运行直到登录完成。"))
                        return
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
                           result=("登录超时（620 秒内未拿到回调 code）%s。"
                                   "请确认 OfficeACE 客户端正在运行（回调要靠它接收），再重试。"
                                   % (("；最后一次 poll：%s" % last_poll_note)
                                      if last_poll_note else "")))
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
