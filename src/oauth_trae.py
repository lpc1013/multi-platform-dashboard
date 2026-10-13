# -*- coding: utf-8 -*-
"""Trae 手机号短信直登 + 客户端指纹 / 设备流（2026-10-08 协议逆向落地）—— 二期拆分。"""
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


# ─────────────────────────────── Trae ───────────────────────────────
# ⚠⚠ 2026-10-08 实地取证（推翻旧假设，勿回退）：
#   · 旧注释称「回调端口必须固定 17388，官网靠探测它判断客户端在线」——**实测为假**。
#     客户端源码（main.js:1477302）OAuthLocalServer 用 `r.listen(0,"127.0.0.1")`，
#     即 **操作系随机分配端口**，日志 `Found available port` / `Listening on port 64553`
#     分别是 Supabase 线（固定候选表）与 Trae 线（随机）。固定端口反而可能被占用/混淆。
#   · 旧常量 _TRAE_PLUGIN_VERSION="2.3.83560"、_TRAE_APP_VERSION="3.3.100" 是**过期硬编码**；
#     真值来自客户端 manifest（E:\Trae\Trae CN\debug.log）：
#       appVersion=3.3.104   buildVersion=2.3.87416
#     且 storage.json 的 `iCubeLastVersion = 2.3.87416`（= buildVersion），可动态读取。
#   · 旧 _trae_oauth_device() 直接取 TRAE_DIRS[0]（=TRAE SOLO CN）→ **拿错客户端身份**：
#       SOLO CN : machineId=20d2bede…  publicKey=…/KmDUr8iB7DPs…
#       Trae CN : machineId=8de60a37…  publicKey=…HGZdSX+1il9z…
#     IDE 线（auth_from=trae）对应 **Trae CN**；SOLO 线对应 TRAE SOLO CN。必须按线取。
_TRAE_CONSOLE = "https://www.trae.cn"
_TRAE_API = "https://api.trae.cn"
# 参考值（逆向自客户端，当前流程未使用，保留备查）：
#   iCube 域名 = https://api.trae.com.cn
#   OAuth app_id = 6eefa01c-1036-4c7e-9ca5-d891f63bfcd8
_TRAE_APP_VERSION = "3.3.104"        # 兜底；运行时优先读客户端真值
_TRAE_PLUGIN_VERSION = "2.3.87416"   # = buildVersion（兜底值，运行时优先读 iCubeLastVersion）
_TRAE_LINES = {
    "trae": {"auth_from": "trae", "client_id": "ono9krqynydwx5",
             "platform": "IDE_PC", "hide_saas": False, "label": "Trae (IDE)",
             # IDE 线对应的客户端数据目录名（用于挑对 machineId / publicKey / 版本）
             "dirs": ["Trae CN", "Trae", "TRAE SOLO CN"]},
    "solo": {"auth_from": "solo", "client_id": "en1oxy7wnw8j9n",
             "platform": "SOLO_PC", "hide_saas": True, "label": "TRAE SOLO",
             "dirs": ["TRAE SOLO CN", "Trae CN", "Trae"]},
}
_TRAE_CRED_MARKERS = ("authCodeInfo", "code", "accessToken", "access_token",
                      "refreshToken", "refresh_token")


def _trae_client_running():
    """本机 Trae/TRAE 客户端是否在运行（运行中它的 OAuthLocalServer 会抢先兑换 AuthCode → 10101）。"""
    try:
        import subprocess
        r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, timeout=12)
        out = (r.stdout or "").lower()
        for kw in ("trae cn.exe", "trae.exe", "trae solo cn.exe", "traecode.exe"):
            if kw in out:
                return True
    except Exception:
        return False
    return False


def _trae_line_dirs(line):
    """按线路返回优先顺序的客户端数据目录列表（IDE→Trae CN，SOLO→TRAE SOLO CN）。"""
    cfg = _TRAE_LINES.get(line) or _TRAE_LINES["trae"]
    try:
        import local_import as li
        base = getattr(li, "TRAE_DIRS", []) or []
    except Exception:
        base = []
    order = cfg.get("dirs") or []
    out = []
    for name in order:
        for d in base:
            if os.path.basename(d).lower() == name.lower() and d not in out:
                out.append(d)
    for d in base:                     # 兜底：未列出的也保留在末尾
        if d not in out:
            out.append(d)
    return out


def _trae_read_build_version(app_dir):
    """从客户端 storage.json 读真实 buildVersion（= plugin_version）。"""
    try:
        import local_import as li
        sf = os.path.join(app_dir, "User", "globalStorage", "storage.json")
        st = li._load_json(sf)
        if isinstance(st, dict):
            v = str(st.get("iCubeLastVersion") or "").strip()
            if v:
                return v
    except Exception:
        pass
    return ""


def _trae_oauth_device(line="trae"):
    """读本机 Trae 客户端 storage.json 的 icube-dc 设备身份（OAuth 授权/兑换必须）。

    按 `line` 选对客户端（IDE→Trae CN，SOLO→TRAE SOLO CN）——两套 machineId/publicKey
    不同，用错会与授权/兑换侧不一致。返回 dict 含 device_id/public_key/machine_id/
    app_version/build_version/app_dir。"""
    try:
        import local_import as li
    except Exception:
        return None
    for app_dir in _trae_line_dirs(line):
        sf = os.path.join(app_dir, "User", "globalStorage", "storage.json")
        if not os.path.isfile(sf):
            continue
        try:
            st = li._load_json(sf)
        except Exception:
            continue
        if not isinstance(st, dict):
            continue
        did = ""
        for k in st:
            if k.startswith("iCubeAuthInfo://icube-dc:"):
                d = k.split(":")[-1]
                if d.isdigit():
                    did = d
                    break
        if not did:
            continue
        enc = st.get("iCubeAuthInfo://icube-dc:%s" % did)
        if not enc:
            continue
        try:
            dev = li._trae_decrypt_auth(str(enc).strip())
        except Exception:
            continue
        pub = (dev.get("publicKeyPEM") or "").strip()
        if not pub:
            continue
        return {"device_id": did, "public_key": pub,
                "machine_id": (st.get("telemetry.machineId") or "").strip(),
                "build_version": _trae_read_build_version(app_dir),
                "app_dir": app_dir}
    return None


def _trae_reg_str(path, name):
    """从 HKLM 读字符串（沙箱内 reg.exe 被禁 → 用 winreg）。"""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            v, _ = winreg.QueryValueEx(k, name)
            return str(v or "").strip()
    except Exception:
        return ""


def _trae_account_full_name():
    """读 Windows 账户「全名」（对齐客户端 CTe() 的 net.exe 分支）。

    ⚠ 2026-10-08 实地取证（本机账户全名**为空**，见下）：
      `net.exe user <USERNAME>` 中文系统输出的是本地化的「全名」标签，
      客户端正则 `/Full Name\\s+(.*)/` 只匹配英文 → **匹配不到 → 走兜底**。
      因此本机真值 = USERNAME（"Pengcheng_Li"），不是账户全名。
      我们按行解析（避免 \\s* 吞换行误匹配到下一行的「注释」）并兼容中英两种标签；
      读不到一律返回 ""（与客户端本机行为一致）。
    """
    try:
        import subprocess
        user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
        if not user:
            return ""
        r = subprocess.run(["net.exe", "user", user],
                           capture_output=True, timeout=15)
        raw = r.stdout or b""
        txt = ""
        for enc in ("gbk", "cp936", "utf-8"):
            try:
                txt = raw.decode(enc)
                break
            except Exception:
                continue
        if not txt:
            return ""
        for line in txt.splitlines():
            s = line.rstrip()
            for tag in ("Full Name", "全名"):
                if s.startswith(tag):
                    return s[len(tag):].strip()
    except Exception:
        return ""
    return ""


def _trae_device_suffix():
    """DeviceName 后缀：客户端 `ETe()` 里 `suffix = f(200, null)`，取自 nls 资源。

    nls.messages.json(en)      [200] = "'s computer"
    nls.zh-cn.messages.json(zh)[200] = "的电脑"
    本机实测客户端发的 DeviceName = "Pengcheng_Li的电脑" → 中文后缀。
    优先按 Trae 安装目录里是否存在 nls.zh-cn.messages.json 判定语言（与客户端界面一致）。
    """
    for d in _trae_out_dirs():
        try:
            if os.path.isfile(os.path.join(d, "nls.zh-cn.messages.json")):
                return "的电脑"
            if os.path.isfile(os.path.join(d, "nls.messages.json")):
                return "'s computer"
        except Exception:
            continue
    return "的电脑"


def _trae_out_dirs():
    """Trae 客户端的 resources/app/out 目录候选（读 nls/i18n 用）。"""
    cands = [
        r"E:\Trae\TRAE SOLO CN\resources\app\out",
        r"E:\Trae\Trae CN\resources\app\out",
        os.path.join(os.environ.get("LOCALAPPDATA") or "", "Programs", "Trae CN",
                     "resources", "app", "out"),
        os.path.join(os.environ.get("LOCALAPPDATA") or "", "Programs", "TRAE SOLO CN",
                     "resources", "app", "out"),
    ]
    return [d for d in cands if d and os.path.isdir(d)]


def _trae_device_name():
    """对齐客户端 `ETe()`：`DeviceName = CTe() + i18nSuffix`。

    客户端原始逻辑（main.js:1281803，2026-10-08 实地取证）：
      CTe(): win32 → `net.exe user <USERNAME>` 的 Full Name；空 → Electron os.userInfo().username;
             再空 → process.env.USER || USERNAME
      ETe(): CTe() + f(200)  ← f(200) 是 nls i18n 字符串（zh="的电脑" / en="'s computer"）
    本机真值（客户端成功请求 body 原文）：DeviceName = "Pengcheng_Li的电脑"
    """
    base = _trae_account_full_name()
    if not base:
        try:
            import getpass
            base = getpass.getuser() or ""
        except Exception:
            base = ""
    if not base:
        base = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    base = (base or "").strip()
    if not base:
        return ""
    return base + _trae_device_suffix()


def _trae_system_facts():
    """对齐客户端 iCubeSystemInformationService（main.js:1606330）的取值口径：

       deviceModel        = BIOS SystemProductName          ("83DG")
       deviceManufacturer = BIOS SystemManufacturer         ("LENOVO")
       osName             = process.platform                ("windows"，小写)
       osVersion          = os.version()                    ("Windows 11 Home")
       cpuBrand           = os.cpus()[0].model              ("Intel(R) Core(TM) i7-14650HX")
       DeviceName         = ETe() = 账户名 + i18n 后缀       ("Pengcheng_Li的电脑")
    """
    import platform as _pf
    model = _trae_reg_str(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName")
    vendor = _trae_reg_str(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer")
    cpu = _trae_reg_str(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                        "ProcessorNameString") or (_pf.processor() or "")
    # osName：客户端硬映射 win32→"windows"
    os_name = {"Windows": "windows", "Darwin": "mac", "Linux": "Linux"}.get(
        _pf.system(), (_pf.system() or "windows").lower())
    os_ver = ""
    try:
        if _pf.system() == "Windows":
            # Electron os.version() 返回形如 "Windows 11 Home"。
            # 注意注册表 ProductName 在 Win11 上仍是 "Windows 10 Home"（已知坑）
            # → 用 CurrentBuild ≥ 22000 校正为大版本号。
            name_os = _trae_reg_str(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName")
            build = _trae_reg_str(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild")
            try:
                major = 11 if int(build) >= 22000 else 10
            except Exception:
                major = 0
            if major and name_os.startswith("Windows 10"):
                name_os = "Windows %d%s" % (major, name_os[len("Windows 10"):])
            os_ver = name_os or _pf.version()
        else:
            os_ver = _pf.version()
    except Exception:
        os_ver = _pf.release() or ""
    name = _trae_device_name() or _pf.node() or "PC"
    return {"device_name": name, "device_model": model or "",
            "device_brand": vendor or "",
            "cpu_brand": cpu[:120],
            "os_name": os_name, "os_version": os_ver or ""}


def _trae_build_authorize_url(line, dev, port, verifier):
    cfg = _TRAE_LINES[line]
    sysf = _trae_system_facts()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    app_ver = dev.get("app_version") or _TRAE_APP_VERSION
    plugin_ver = dev.get("build_version") or _TRAE_PLUGIN_VERSION
    params = [
        ("login_version", "1"), ("auth_from", cfg["auth_from"]),
        ("login_channel", "native_ide"), ("plugin_version", plugin_ver),
        ("auth_type", "local"), ("client_id", cfg["client_id"]), ("redirect", "0"),
        ("login_trace_id", str(uuid.uuid4())),      # 客户端用带连字符的 UUID
        ("auth_callback_url", "http://127.0.0.1:%d/authorize" % port),
        ("machine_id", dev["machine_id"]), ("device_id", dev["device_id"]),
        ("x_device_id", dev["device_id"]), ("x_machine_id", dev["machine_id"]),
        ("x_device_brand", sysf["device_model"]), ("x_device_type", sysf["os_name"]),
        ("x_os_version", sysf["os_version"]), ("x_env", ""),
        ("x_app_version", app_ver), ("x_app_type", "stable"),
        ("code_challenge", challenge), ("code_challenge_method", "S256"),
        ("channel_name", "common"),
    ]
    if cfg["hide_saas"]:
        params.append(("hide_saas_login", "true"))
    return _TRAE_CONSOLE + "/authorization?" + urllib.parse.urlencode(params)


class _TraeCBHandler(http.server.BaseHTTPRequestHandler):
    """接住官网跳回的回调；纯端口探测（无 code 参数）直接回 ok。

    客户端解析方式（main.js:1477302 OAuthLocalServer.z/C）：
      · 只要 url 含 "/authorize" 就取 `url.split("?")[1]` 的原始 query；
      · 再 `qs.parse(decodeURIComponent(query))`（qs 默认会再解一层 %xx）。
    我们等价实现：先整体 decodeURIComponent 一次，再 parse_qsl 默认解一层。
    """
    result = {}

    def do_GET(self):
        try:
            _TraeCBHandler._handle(self)
        except Exception:
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            except Exception:
                pass

    @staticmethod
    def _handle(h):
        path = h.path or ""
        q = urllib.parse.urlsplit(path).query
        # 对齐客户端 decodeURIComponent：整体先解一次（qs 自带一次 unescape）
        try:
            dec = urllib.parse.unquote(q)
        except Exception:
            dec = q
        params = {}
        for pair in dec.split("&"):
            if not pair:
                continue
            k, _, v = pair.partition("=")
            params[k] = v
        try:
            # ⚠ HTTP 请求的 self.path 不含 host:port —— 这里补上真实监听端口，
            #   否则诊断里会显示 "http://127.0.0.1/authorize?"（看起来像端口丢了）
            host = h.headers.get("Host") or ""
            if host:
                _TraeCBHandler.result.setdefault("raw_url", "http://%s%s" % (host, path))
            else:
                _TraeCBHandler.result.setdefault("raw_url", "http://127.0.0.1%s" % path)
        except Exception:
            pass
        if not any(k in params for k in _TRAE_CRED_MARKERS):
            h.send_response(200)
            h.end_headers()
            h.wfile.write(b"ok")
            return
        _TraeCBHandler.result["params"] = params
        body = ("<meta charset='utf-8'><body style='font-family:sans-serif'>"
                "<h2>✅ 登录成功</h2><p>凭证已收到，可关闭此页回到看板。</p></body>").encode("utf-8")
        h.send_response(200)
        h.send_header("Content-Type", "text/html; charset=utf-8")
        h.send_header("Content-Length", str(len(body)))
        h.end_headers()
        h.wfile.write(body)

    def log_message(self, *a):
        pass

def _trae_exchange(line, auth_code, verifier, dev, dbg=None):
    """AuthCode → Token，与客户端 exchangeTokenByAuthCode 逐字段对齐。

    客户端源码（main.js:1284379 `exchangeTokenByAuthCode`，2026-10-08 实地取证）：
      body    = {ClientID, AuthCode, CodeVerifier, DeviceInfo, IDEVersion}
      DeviceInfo = await this.j(publicKeyPEM)
                   → {DeviceID,MachineID,PlatformCode("IDE_PC"),DeviceType("PC"),DeviceName,
                      DeviceModel,ClientVersion,DevicePublicKey,DeviceBrand,DeviceCPU,
                      OSInfo("windows"),OSVersion}
      headers = this.m("")  →  {"Content-Type":"application/json","x-cloudide-token":""}
    端点：`${host}/trae/api/v3/oauth/ExchangeToken`（客户端 host=api.trae.cn）

    本机客户端成功请求原文见
      %APPDATA%\\Trae CN\\logs\\20261008T114448\\main.log:150
    —— 我们的 payload 已逐字段比对为**零差异**（含 DeviceName="Pengcheng_Li的电脑"）。
    """
    cfg = _TRAE_LINES[line]
    sysf = _trae_system_facts()
    app_ver = dev.get("app_version") or _TRAE_APP_VERSION
    main_payload = {
        "ClientID": cfg["client_id"], "AuthCode": auth_code, "CodeVerifier": verifier,
        "DeviceInfo": {
            "DeviceID": dev["device_id"], "MachineID": dev["machine_id"],
            "PlatformCode": cfg["platform"], "DeviceType": "PC",
            "DeviceName": sysf["device_name"], "DeviceModel": sysf["device_model"],
            "ClientVersion": app_ver, "DevicePublicKey": dev["public_key"],
            "DeviceBrand": sysf["device_brand"], "DeviceCPU": sysf["cpu_brand"],
            "OSInfo": sysf["os_name"], "OSVersion": sysf["os_version"],
        },
        "IDEVersion": app_ver,
    }
    # 主端点用客户端同款 2 头；旧端点兜底也一致
    HDR = {"Content-Type": "application/json", "x-cloudide-token": ""}
    variants = [
        ("V1 客户端同款", _TRAE_API + "/trae/api/v3/oauth/ExchangeToken", main_payload),
    ]
    # 诊断留痕：把真实发出的主 payload 摘要写回 job（下次失败可一眼比对）
    if isinstance(dbg, dict):
        try:
            di = main_payload["DeviceInfo"]
            dbg["sent_client_id"] = main_payload["ClientID"]
            dbg["sent_device_name"] = di["DeviceName"]
            dbg["sent_model"] = di["DeviceModel"]
            dbg["sent_brand"] = di["DeviceBrand"]
            dbg["sent_cpu"] = di["DeviceCPU"]
            dbg["sent_os"] = "%s / %s" % (di["OSInfo"], di["OSVersion"])
            dbg["sent_ide_version"] = main_payload["IDEVersion"]
        except Exception:
            pass
    for name, url, payload in variants:
        try:
            r = requests.post(url, json=payload, headers=HDR, timeout=30,
                              proxies={"http": None, "https": None})
            j = r.json()
        except Exception as e:
            if isinstance(dbg, dict):
                dbg["v1_error"] = str(e)[:200]
            print("[Trae 兑换] %s 请求异常: %r" % (name, e))
            return None, "Token 兑换请求异常：%s" % str(e)[:180]
        if isinstance(dbg, dict):
            try:
                dbg["v1_resp"] = json.dumps(j, ensure_ascii=False)[:2000]
                dbg["v1_status"] = r.status_code
                dbg["v1_result_keys"] = (sorted(list((j.get("Result") or {}).keys()))
                                         if isinstance(j.get("Result"), dict) else [])
            except Exception:
                pass
        print("[Trae 兑换] %s -> HTTP %s %s" % (name, r.status_code,
                                                json.dumps(j, ensure_ascii=False)[:800]))
        # ① 客户端结构优先：Result.{Token, RefreshToken, UserJwt, BoundDeviceID, …}
        res = j.get("Result") if isinstance(j, dict) else None
        access = refresh = ""
        if isinstance(res, dict):
            for k, v in res.items():
                kl = str(k).lower()
                if kl == "token" and isinstance(v, str) and v:
                    access = v
                elif kl in ("refresh_token", "refreshtoken"):
                    if isinstance(v, str) and v:
                        refresh = v
        # ② 兜底：大小写不敏感递归找
        if not access:
            access = _trae_find_token(j, ("Token", "AccessToken", "access_token", "Jwt", "JWT"))
        if not refresh:
            refresh = _trae_find_token(j, ("RefreshToken", "refresh_token"))
        if access and refresh:
            print("[Trae 兑换] ✅ 拿到 Token(len=%d) + RefreshToken(len=%d)"
                  % (len(access), len(refresh)))
            return {"access_token": access, "refresh_token": refresh,
                    "host": _TRAE_API, "region": "CN",
                    "user_jwt": (_trae_find_token(j, ("UserJwt", "UserJWT", "user_jwt")) or ""),
                    "bound_device_id": (str(res.get("BoundDeviceID") or "")
                                        if isinstance(res, dict) else "")}, None
        print("[Trae 兑换] ❌ 解析失败 access=%r refresh=%r Result.keys=%s"
              % (bool(access), bool(refresh),
                 sorted(list(res.keys())) if isinstance(res, dict) else None))
        if access and not refresh:
            return None, "响应缺少 RefreshToken（无法续期，已拒绝）：%s" % json.dumps(j, ensure_ascii=False)[:400]
        err = (j.get("ResponseMetadata") or {}).get("Error") or {}
        code = str(err.get("Code") or "")
        if code == "10101":
            # 10101 = AuthCode 无效/已过期/已被消费（实测：过期 code、错 verifier、
            # 甚至空 body 都返回同一 10101 —— 服务端字段校验是泛化的，无区分度）
            return None, ("10101 无效参数：AuthCode 无效/已过期/已被消费"
                          "（最常见：Trae 客户端在运行，它的 OAuthLocalServer 抢先把 code 兑走了）")
        return None, "Token 兑换失败：%s" % json.dumps(j, ensure_ascii=False)[:600]


def _trae_sms_page_ok(page):
    """授权页是否渲染出了登录表单（手机号/验证码输入框其一）。"""
    sels = ["input[placeholder='输入手机号']", "input[type='tel']",
            "input[placeholder*='手机号']", "input[placeholder*='验证码']",
            "input[name='phone']", "input[name='username']",
            "input[id*='phone']", "input[id*='account']"]
    for sel in sels:
        try:
            loc = page.locator(sel)
            if loc.count() and loc.first.is_visible(timeout=500):
                return True
        except Exception:
            continue
    return False


def _trae_agree_checked(page):
    """读取协议勾选态（实测：已勾选时 .icon-group 内是 <svg class="icon-checked">，
    未勾选时是 <div class="icon-uncheck">）。返回 True/False/None(查不到)。"""
    try:
        v = page.evaluate("""() => {
            const g = document.querySelector('.icon-group');
            if (!g) return null;
            const h = g.innerHTML || '';
            if (html_has(h, 'icon-checked')) return true;
            if (html_has(h, 'icon-uncheck')) return false;
            return null;
            function html_has(s, k){ return s.indexOf(k) >= 0; }
        }""")
        return v
    except Exception:
        return None


def _trae_ensure_agree(page):
    """勾选「我已阅读并同意」协议 —— 仅在能确认未勾选时才点，避免把已勾选的取消掉。

    实测（trae.cn/login，2026-10-08，Playwright 实地取证）：
      · 页面上**没有** <input type="checkbox">（count=0）——旧实现只找原生 checkbox，恒 False；
      · 协议控件是 <div class="icon-group"><div class="icon-uncheck"></div></div>，
        点 .icon-uncheck 后其 innerHTML 换成 <svg class="icon-checked">，
        同时提交按钮 <div class="...btn-submit...disabled"> 的 disabled 类被移除。
    → 对策：原生 input 兜底 + .icon-uncheck 主路径 + 点后校验、失败再试 .icon-group / 文本行坐标。
    """
    # ① 若已是勾选态，不重复点（避免把勾好的取消）
    if _trae_agree_checked(page):
        return False
    # ② 原生 checkbox（页面改版后可能出现）
    try:
        cbs = page.locator("input[type='checkbox']")
        for i in range(min(cbs.count(), 5)):
            cb = cbs.nth(i)
            try:
                if cb.is_visible(timeout=300) and not cb.is_checked():
                    cb.click(timeout=1500)
                    return True
            except Exception:
                continue
    except Exception:
        pass
    # ③ 主路径：点自绘方块 .icon-uncheck（实测有效）
    for sel in (".icon-uncheck", ".icon-group"):
        try:
            loc = page.locator(sel)
            for i in range(min(loc.count(), 3)):
                el = loc.nth(i)
                if not el.is_visible(timeout=300):
                    continue
                try:
                    el.click(timeout=1200)
                except Exception:
                    try:
                        el.evaluate("e => e.click()")
                    except Exception:
                        continue
                page.wait_for_timeout(180)
                if _trae_agree_checked(page):
                    return True
        except Exception:
            continue
    # ④ 兜底：点「我已阅读并同意」文本左侧的方块区域
    if _trae_click_agree_row(page):
        page.wait_for_timeout(180)
        if _trae_agree_checked(page):
            return True
    return False


def _trae_click_agree_row(page):
    """styled 复选框兜底：点「我已阅读并同意」文本左侧的方块区域。"""
    try:
        loc = page.get_by_text("我已阅读并同意", exact=False).first
        box = loc.bounding_box(timeout=1500)
        if box:
            page.mouse.click(max(box["x"] - 16, 2), box["y"] + box["height"] / 2)
            return True
    except Exception:
        pass
    return False


def _trae_click_submit(page):
    """点「登录」提交按钮。实测按钮：<div class="...btn-submit btn-large trae__btn ...">
    登录</div>（未勾协议时带 `disabled` 类）。优先用稳定的类名子串，再退老版本 hash 类与文本。"""
    for sel in ("[class*='btn-submit']", "div.sc-ghWlax"):
        try:
            loc = page.locator(sel)
            for i in range(min(loc.count(), 3)):
                el = loc.nth(i)
                if not el.is_visible(timeout=400):
                    continue
                try:
                    el.click(timeout=2000)
                    return True
                except Exception:
                    try:
                        el.evaluate("e => e.click()")
                        return True
                    except Exception:
                        continue
        except Exception:
            continue
    return _click_text(page, ["登录", "登 录", "登录/注册"], timeout=2500)


# Trae 授权确认页（登录成功后弹出）：标题「登录以使用 TRAE」，
# 三个按钮「登录并打开 TRAE」/「使用其他账号登录」/「取消」。
# 点【登录并打开 TRAE】才会 302 回本地随机回调端口把 AuthCode 交给我们。
_TRAE_OPEN_TEXTS = ["登录并打开TRAE", "登录并打开", "登录以使用TRAE",
                    "继续", "授权", "允许", "确认", "同意并继续"]
_TRAE_OPEN_EXCLUDE = ["使用其他账号登录", "取消", "不同意", "退出", "取消注销", "账户", "帐号"]


def _trae_jwt_uid(token):
    """从 Trae 的 access token（JWT）里解出真实用户 id。

    实测 token payload：{"data":{"id":"3999366707165914","source":…,"tenant_id":…},"exp":…}
    → 返回 data.id（取不到返回 ""）。仅用于回调缺 UserID 时兜底，不做签名校验。
    """
    try:
        parts = str(token or "").split(".")
        if len(parts) < 2:
            return ""
        p = parts[1].replace("-", "+").replace("_", "/")
        p += "=" * (-len(p) % 4)
        import base64 as _b64
        j = json.loads(_b64.b64decode(p).decode("utf-8", "ignore"))
        d = j.get("data") if isinstance(j, dict) else None
        if isinstance(d, dict):
            return str(d.get("id") or d.get("userId") or "").strip()
        if isinstance(j, dict):
            return str(j.get("id") or j.get("userId") or "").strip()
    except Exception:
        pass
    return ""


def _trae_click_open(ctx, debug=None):
    """Trae 授权确认页：勾了协议/登录后弹出「登录并打开 TRAE」→ 代点它完成 OAuth 回调。

    铁律（2026-10-08 实地取证，Playwright 真机 dump DOM）：
      · Trae 用 styled-components，按钮一律
        `<div class="sc-xxx trae__btn btn-submit …"><div class="content">登录并打开 TRAE</div></div>`，
        **不是 button/<a>**，且框架会在中英文之间插空白 →
        必须**归一化文本（去所有空白含 \\u3000）匹配**，查询范围含 `div`。
      · ⚠ 事件绑在**外层 `.trae__btn`** 上，点最内层 `.content` 有时不触发 →
        命中后**向上找到最近的 `[class*='trae__btn']` 祖先再点**（没有则点自身）。
      · ⚠ 登录页 URL **也含 `/authorization`**（实测 `www.trae.cn/authorization?…` 渲染的是登录表单），
        所以不能只靠 URL 判断到底该不该点 —— 由调用方每轮尝试，按钮不在就返回 False（成本极低）。
      · 排除「使用其他账号登录 / 取消 / 不同意 / 退出」等否定按钮。
    `debug`（dict）可选：写入命中的 tag/class/text，便于诊断为什么点不到。
    返回 True 表示点到了。"""
    norm = [t.replace(" ", "").replace("\u3000", "") for t in _TRAE_OPEN_TEXTS]
    excl = [t.replace(" ", "").replace("\u3000", "") for t in _TRAE_OPEN_EXCLUDE]
    js = (
        "(args) => {"
        " const targets = args[0], excl = args[1];"
        " const norm = s => (s || '').replace(/\\s+/g, '').replace(/\\u3000/g, '');"
        " const els = Array.from(document.querySelectorAll('div,button,a,[role=button]'));"
        " for (const t of targets) {"
        "   const cands = els.filter(e => {"
        "     const s = norm(e.innerText);"
        "     if (s !== t) return false;"
        "     if (excl.some(x => s.indexOf(x) >= 0)) return false;"
        # 必须可见（登录页有隐藏的协议弹窗「同意」按钮，别误点）
        "     const r = e.getBoundingClientRect();"
        "     if (r.width <= 0 || r.height <= 0) return false;"
        "     return true;"
        "   });"
        "   if (!cands.length) continue;"
        # 优先取最内层（文本最短）；再向上冒泡到 trae__btn 祖先（事件真正绑定处）
        "   cands.sort((a, b) => norm(a.innerText).length - norm(b.innerText).length);"
        "   let pick = cands[0];"
        "   const owner = pick.closest(\"[class*='trae__btn']\");"
        "   if (owner) pick = owner;"
        "   return pick;"
        " }"
        " return null;"
        "}"
    )
    for pg in ctx.pages:
        u = (pg.url or "")
        # 只在 Trae 相关页面找（排除本地回调页与空白页）；不限制是否含 /authorization
        # ——因为授权确认页与登录页 URL 同形，URL 无法区分。
        if u.startswith("http://127.0.0.1"):
            continue
        if u and not any(k in u for k in ("trae.cn", "trae.com")):
            continue
        for target in [pg] + [f for f in pg.frames if f is not pg.main_frame]:
            try:
                el = target.evaluate_handle(js, [norm, excl])
                jsd = el.as_element() if el else None
                if jsd:
                    if isinstance(debug, dict):
                        try:
                            debug["conclick_tag"] = jsd.evaluate("e => e.tagName")
                            debug["conclick_cls"] = jsd.evaluate("e => String(e.className).slice(0,120)")
                            debug["conclick_text"] = jsd.evaluate(
                                "e => (e.innerText||'').replace(/\\s+/g,'')")
                        except Exception:
                            pass
                    try:
                        jsd.click(timeout=1200)
                    except Exception:
                        try:
                            jsd.evaluate("e => e.click()")
                        except Exception:
                            try:
                                jsd.click(timeout=1200, force=True)
                            except Exception:
                                continue
                    return True
            except Exception:
                pass
    return False


def start_trae_sms_job(phone, name, on_success):
    """Trae 手机号+短信直登（OAuth PKCE + 随机回调端口，对齐客户端 listen(0)）。"""
    raw = str(phone or "")
    if "*" in raw:
        # 设备流（客户端授权）登录的账号只有脱敏号（如 180******23），完整号从未落盘
        return False, ("该账号记录的是脱敏手机号（%s），完整号码未保存过——"
                       "请手动输入 11 位手机号后重新续期" % raw), None
    phone = "".join(ch for ch in raw if ch.isdigit())
    if len(phone) != 11:
        return False, "请填写 11 位手机号（当前：%s）" % (phone or "空"), None
    flow = {"user_code": "", "verify_url": "", "expires_in": 600,
            "interval": 2, "platform": "trae", "sub": None}
    job = _new_job("trae", flow)
    job.update(mode="sms", phone=phone, name=name or "",
               hint="授权页登录后凭证自动回到看板（本地随机回调端口）")
    with _job_lock:
        _JOBS[job["job"]] = job
    threading.Thread(target=_run_trae_sms_job,
                     args=(job, phone, name, on_success), daemon=True).start()
    return True, "已发起 Trae 短信登录", _view(job)


def _run_trae_sms_job(job, phone, name, on_success):
    line = "trae"     # IDE 线（SOLO 客户端用户很少；后续要分线再加下拉）
    dev = _trae_oauth_device(line)
    if not dev:
        job.update(status="done", finished=True, ok=False,
                   result="没找到 Trae 客户端设备身份（storage.json 缺 icube-dc）。"
                          "请先安装 Trae 并完成一次客户端登录，再回来用看板登录。")
        return
    job["device_dir"] = os.path.basename(dev.get("app_dir") or "")
    job["plugin_version"] = dev.get("build_version") or _TRAE_PLUGIN_VERSION
    # ⚠ 若 Trae 客户端正在运行，它的 OAuthLocalServer 也在监听并会「抢先兑换」AuthCode，
    #   导致我们拿到已失效 code（实测 10101）。提醒用户先退出客户端。
    if _trae_client_running():
        job["client_running"] = True
    # verifier 对齐客户端 vTe()：base64url(randomBytes(48)) → 64 字符 A-Za-z0-9-_
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode("ascii")
    # ① 随机端口（对齐客户端 r.listen(0, "127.0.0.1")；不固定 17388，避免与客户端/其它进程混淆）
    result = _TraeCBHandler.result = {}
    srv = None
    port = 0
    for _ in range(12):
        try:
            srv = http.server.HTTPServer(("127.0.0.1", 0), _TraeCBHandler)
            port = srv.server_address[1]
            break
        except OSError:
            srv = None
            continue
    if srv is None:
        job.update(status="done", finished=True, ok=False,
                   result="无法在本机开启回调监听端口，请稍后重试。")
        return
    job["callback_port"] = port
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    browser = None
    ok_saved = False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False, args=_OFFSCREEN_ARGS)
            ctx = browser.new_context(locale="zh-CN",
                                      viewport={"width": 560, "height": 840})
            page = ctx.new_page()
            job["status"] = "opening"
            job["result"] = "已打开 Trae 授权窗口，正在加载登录页…"
            page.goto(_trae_build_authorize_url(line, dev, port, verifier),
                      wait_until="domcontentloaded", timeout=60000)
            deadline = time.time() + 620
            form_ok = False
            # ② 等表单渲染 → 填手机号代点
            for _ in range(20):
                if _trae_sms_page_ok(page):
                    form_ok = True
                    break
                page.wait_for_timeout(800)
            if form_ok:
                page.wait_for_timeout(800)
                # 原生 checkbox 未勾选时先勾上（styled 方块状态不可查，留到提交后兜底）
                if _trae_ensure_agree(page):
                    job["result"] = "已自动勾选服务协议。"
                sent = False
                for sel in ("input[placeholder='输入手机号']", "input[type='tel']",
                            "input[placeholder*='手机号']",
                            "input[name='phone']", "input[id*='phone']"):
                    try:
                        loc = page.locator(sel)
                        if loc.count() and loc.first.is_visible(timeout=800):
                            loc.first.fill(phone, timeout=4000)
                            sent = True
                            break
                    except Exception:
                        continue
                if sent:
                    send_ok = False
                    # 实测「获取验证码」按钮：<div class="right-part send-code ">获取验证码</div>
                    # （外层 div.verification-code 是包裹容器，点它有时代理不到真正的按钮）
                    for sel in (".right-part.send-code", "div.verification-code .send-code",
                                "div.verification-code"):
                        try:
                            loc = page.locator(sel)
                            if loc.count() and loc.first.is_visible(timeout=800):
                                loc.first.click(timeout=2000)
                                send_ok = True
                                break
                        except Exception:
                            continue
                    if not send_ok:
                        send_ok = _click_text(page, ["获取验证码", "发送验证码"], timeout=3000)
                    if not send_ok:
                        _pull_window_front(ctx)
                        job["result"] = "手机号已填入，请手动点一下「获取验证码」。"
                    # 滑块实测在点「获取验证码」后 ~0.5s 弹出 → 轮询等待（最多 5s），
                    # 一出现立刻把（移到屏外的）窗口拉回屏幕中央让用户拖动。
                    cap = False
                    for _ in range(10):
                        page.wait_for_timeout(500)
                        if _qoder_has_captcha(ctx):
                            cap = True
                            _pull_window_front(ctx)
                            break
                    job.update(status="waiting_code", sms_sent=True, need_code=True,
                               captcha=cap,
                               result=("窗口弹出了滑块/图片验证码，请先拖动完成（窗口已拉到屏幕中央）。"
                                       if cap else
                                       "验证码已发送 📩 请在下方填入短信验证码"))
                else:
                    _pull_window_front(ctx)
                    job["result"] = ("没找到手机号输入框（页面可能改版），已把窗口拉回屏幕；"
                                     "请在窗口里完成登录，看板会自动接住回调。")
            else:
                _pull_window_front(ctx)
                job["result"] = ("授权页未渲染出登录表单，已把窗口拉回屏幕；"
                                 "请在窗口里完成登录，看板会自动接住回调并换token。")
                job.update(sms_sent=True, need_code=False)

            # ③ 主循环：等验证码提交 / 等回调
            while time.time() < deadline:
                # 有新验证码（或上次没填成功）就填并点登录；submit_code 可重复调用 → 支持填错重试
                if form_ok and job.get("code") and job.get("code") != job.get("_code_filled"):
                    filled = False
                    for sel in ("input[placeholder='输入验证码']",
                                "input[placeholder*='验证码']", "input[name='code']"):
                        try:
                            loc = page.locator(sel)
                            if loc.count() and loc.first.is_visible(timeout=800):
                                loc.first.fill(str(job["code"]), timeout=3000)
                                filled = True
                                break
                        except Exception:
                            continue
                    if filled:
                        job["_code_filled"] = str(job["code"])
                        clicked = _trae_click_submit(page)
                        if clicked:
                            job["code_submitted"] = True
                            job["need_code"] = False
                            job["_submitted_at"] = time.time()
                            job["result"] = "已提交验证码，正在登录…"
                        else:
                            _pull_window_front(ctx)
                            job["result"] = "验证码已填入，但没点到「登录」，请手动点一下。"
                    else:
                        _pull_window_front(ctx)
                        job["result"] = "没找到验证码输入框，请在窗口手动输入并登录。"
                # 提交后 6 秒表单还在 → 八成是协议没勾（新页面上按钮保持 disabled）→ 补勾再重试一次
                if (job.get("code_submitted") and not job.get("agree_retried")
                        and job.get("_submitted_at")
                        and time.time() - job["_submitted_at"] > 6
                        and form_ok and _trae_sms_page_ok(page)):
                    job["agree_retried"] = True
                    if _trae_ensure_agree(page) or _trae_click_agree_row(page):
                        _trae_click_submit(page)
                        job["result"] = "登录没动静，已补勾服务协议并重试…"
                # 短信登录成功后 Trae 会**跳离登录表单**、停在授权确认页（「登录以使用 TRAE」）——
                # 必须代点【登录并打开 TRAE】才会 302 回本地随机端口交出 AuthCode。
                # ⚠ 时序铁律（2026-10-08 实测）：登录提交 → 授权确认页要 2~5 秒才渲染出来，
                #    早期「进来就试 3 次共 1.8 秒」的窗口**会全部落空**，之后就再没机会点 →
                #    用户看到的就是「卡住不动、得自己点」。改为**每轮主循环都试**（约 2.3 秒一轮，
                #    覆盖到 620 秒超时），只用「登录表单是否还在」排除登录阶段，不靠 URL。
                if not result.get("params") and not _trae_sms_page_ok(page):
                    job["_open_tries"] = job.get("_open_tries", 0) + 1
                    if _trae_click_open(ctx, job):
                        if not job.get("_open_clicked"):
                            job["_open_clicked"] = True
                            job["_open_at"] = time.time()
                            job["result"] = "已代点【登录并打开 TRAE】，正在接住回调…"
                    elif job["_open_tries"] in (1, 5, 20, 60):
                        # 留痕：试了几轮还没点到（页面可能停在别处 / 按钮没渲染）
                        job["result"] = ("已进入授权确认页，正在尝试点【登录并打开 TRAE】"
                                         "（第 %d 次）…" % job["_open_tries"])
                params = result.get("params")
                if not params and page.url.startswith("http://127.0.0.1:%d" % port):
                    params = dict(urllib.parse.parse_qsl(
                        urllib.parse.urlsplit(page.url).query, keep_blank_values=True))
                if params:
                    # 诊断：把真实回调原文与解析结果留痕（下次失败可直接定位）
                    try:
                        cb_url = str(result.get("raw_url") or page.url or "")
                        job["callback_url"] = cb_url[:600]
                        job["callback_keys"] = list(params.keys())[:20]
                    except Exception:
                        pass
                    raw = (params.get("authCodeInfo") or "").strip()
                    auth_code = ""
                    if raw:
                        try:
                            auth_code = str(json.loads(raw).get("AuthCode") or "").strip()
                        except Exception:
                            auth_code = ""
                    auth_code = auth_code or (params.get("code") or "").strip()
                    if not auth_code:
                        job.update(status="done", finished=True, ok=False,
                                   result="回调已收到但解析不到 AuthCode：%s"
                                          % str(list(params.keys()))[:120])
                        break
                    job["auth_code_head"] = auth_code[:8] + "…(len=%d)" % len(auth_code)
                    # ⚠ 只能兑一次（AuthCode 一次性）→ 严禁重复调用
                    tok, err = _trae_exchange(line, auth_code, verifier, dev, dbg=job)
                    if not tok:
                        job.update(status="done", finished=True, ok=False,
                                   result=err[:600])
                        break
                    grant = dict(tok)
                    grant["device_id"] = dev["device_id"]
                    # ⚠ 铁律（2026-10-08 实测修 bug）：回调 URL 的**顶层 query 没有 UserID**！
                    #   真实身份埋在 `userInfo` 这个 **JSON 字符串**里（客户端回调原文）：
                    #     userInfo={"AIRegion":"CN",…,"ScreenName":"一只总柴",
                    #               "UserID":"3999366707165914","NonPlainTextMobile":"186******66"}
                    #   旧实现 `params.get("UserID")` 恒为空 → 登录成功却 user_id 落空。
                    ui = {}
                    try:
                        ui = json.loads(params.get("userInfo") or "{}")
                        if not isinstance(ui, dict):
                            ui = {}
                    except Exception:
                        ui = {}
                    uid = str(ui.get("UserID") or ui.get("userId") or "").strip()
                    uname = str(ui.get("ScreenName") or ui.get("userName")
                                or ui.get("nickname") or "").strip()
                    # 兜底：从 JWT payload 的 data.id 取（本次实测 JWT.data.id 就是真实 uid）
                    if not uid:
                        uid = _trae_jwt_uid(tok.get("access_token") or "")
                    grant["user_id"] = uid
                    grant["name"] = uname
                    # 手机号：回调里是脱敏的 NonPlainTextMobile（186******66）；
                    # 任务自己知道完整手机号（job["phone"]），优先用它（看板习惯用手机号命名）
                    grant["mobile"] = str(job.get("phone") or
                                          ui.get("NonPlainTextMobile") or ui.get("Mobile") or "")
                    if isinstance(job, dict):
                        try:
                            job["parsed_user_id"] = uid
                            job["parsed_name"] = uname
                        except Exception:
                            pass
                    try:
                        ok2, nm, msg2 = on_success(grant)
                    except Exception as e:
                        ok2, nm, msg2 = False, "", "保存登录态异常：%s" % str(e)[:150]
                    job.update(status="done", finished=True, ok=bool(ok2),
                               result=msg2 or ("已保存 %s" % nm), name=nm or "")
                    ok_saved = True
                    break
                # 450ms/轮（原 700ms）→ 授权确认页一出现就能在 ~0.5s 内被点到
                page.wait_for_timeout(450)
            if not ok_saved and not job.get("finished"):
                job.update(status="done", finished=True, ok=False,
                           result="登录超时（620 秒内未收到回调），请重试")
    except Exception as e:
        job.update(status="done", finished=True, ok=False,
                   result="Trae 短信登录异常：%s" % str(e)[:200])
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass
        try:
            if browser:
                browser.close()
        except Exception:
            pass
