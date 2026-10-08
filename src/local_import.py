# -*- coding: utf-8 -*-
"""
本地客户端凭据导入（替代不稳定的「浏览器登录抓取」）
═════════════════════════════════════════════════════════════════════════
思路：MiniMax Code 与百度搭子 DuMate 都是桌面客户端，你本机已经登录过。
      它们的登录态本来就以明文/可解密形式落在本机配置里 —— 直接读出来即可，
      不需要再弹一个浏览器去「模拟登录」。这条路 100% 确定性，不受滑块验证、
      网页/桌面 token 不一致、超时等问题影响。

来源（均已在本机实测可用）：

  MiniMax Code
    ① ~/.minimax/local-runtime.auth.json
         auth.accessToken / auth.realUserID / auth.userName
         （桌面端当前登录态，实测可直接调用签到接口）
    ② %APPDATA%/MiniMax/minimax-agent-cn-config.json
         tokens.accessToken / user.realUserID / user.userName（同源备份）

  百度搭子 DuMate
    %APPDATA%/qianfan-desktop-app/auth.json       （Electron 应用数据目录）
      · accountProfiles[].displayName / bceUserId
      · cookies（或 accountProfiles[].encryptedCookies）
    %APPDATA%/qianfan-desktop-app/.cookie-key     （32 字节 AES-256 key）
      加密格式：AES-256-GCM，nonce=前 12 字节，tag=次 16 字节，其余为密文
      明文：Chromium 风格 cookie 列表 JSON → 拼成 HTTP Cookie 头

本模块只「读取并复制」凭据到看板自己的凭据文件，绝不改写客户端原始文件。
"""
import os
import json
import base64

HOME = os.path.expanduser("~")
APPDATA = os.environ.get("APPDATA") or os.path.join(HOME, "AppData", "Roaming")

# ── 候选路径 ──────────────────────────────────────────────
MINIMAX_AUTH_FILES = [
    os.path.join(HOME, ".minimax", "local-runtime.auth.json"),
    os.path.join(APPDATA, "MiniMax", "minimax-agent-cn-config.json"),
]
# 新版 v2 认证存储：切换账号后实时覆写的那份（令牌形如 mmoat_，走 Bearer）
MINIMAX_V2_GLOB = os.path.join(HOME, ".minimax", "auth", "*", "*", "*", "auth.json")
DUMATE_DIR = os.path.join(APPDATA, "qianfan-desktop-app")
DUMATE_AUTH = os.path.join(DUMATE_DIR, "auth.json")
DUMATE_KEY = os.path.join(DUMATE_DIR, ".cookie-key")

# WPS 灵犀（Electron）：wps_sid 存在各 session partition 的 Cookies(sqlite) 里
LINGXI_DIRS = [
    os.path.join(APPDATA, "WPS 灵犀"),
    os.path.join(APPDATA, "com.wps.lingxi.browser"),
]
# Trae（VS Code fork）：登录态加密存在 storage.json
TRAE_DIRS = [
    os.path.join(APPDATA, "TRAE SOLO CN"),
    os.path.join(APPDATA, "Trae CN"),
    os.path.join(APPDATA, "Trae"),
]

# 参与拼接的 cookie 域（含百度通行证与 BCE 会话）
COOKIE_DOMAINS = ("dumate", "baidu")


def _load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


# ────────────────────────── MiniMax ──────────────────────────
def _mm_mod():
    """延迟导入 platforms.minimax（避免与 server 的导入顺序互相牵扯）。"""
    import sys
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    from platforms import minimax as _m
    return _m


def _mm_collect_tokens():
    """收集本机所有可读的 MiniMax 令牌 → [(来源, token, auth_mode)]（按 token 去重）。

    MiniMax 客户端只有 user / sharedUser 两个账号槽位，令牌分散在几处文件里：
      · ~/.minimax/auth/<env>/<region>/<clientId>/auth.json 的 records（当前活跃账号，mmoat_ 走 Bearer）
      · ~/.minimax/local-runtime.auth.json 的 auth.accessToken（user 槽位，JWT）
      · %APPDATA%/MiniMax/minimax-agent-cn-config.json 的 tokens / user.token / sharedUser.token
        （同源备份；新版客户端这两处已不再写 token，留作兼容）

    ⚠ 有意不读 ~/.minimax/integrations/*/credentials.json —— 那是 expiry 仅 1 小时的 MCP 工具凭据，
      subject 指向同一个真实账号，读进来只会凭空多出一张签不了到的卡片。
    """
    import glob as _glob
    out, seen = [], set()

    def add(src, tok, mode=None):
        tok = (tok or "").strip()
        if not tok or tok in seen:
            return
        seen.add(tok)
        if not mode:
            try:
                mode = _mm_mod().detect_auth_mode(tok)
            except Exception:
                mode = "bearer" if tok.startswith("mmoat_") else "token"
        out.append((src, tok, mode))

    def _slot_tok(s):
        if isinstance(s, dict):
            return s.get("accessToken") or s.get("token")
        if isinstance(s, str):
            return s
        return None

    for p in sorted(_glob.glob(MINIMAX_V2_GLOB)):
        d = _load_json(p)
        if not isinstance(d, dict):
            continue
        recs = d.get("records")
        if isinstance(recs, dict):
            for rec in recs.values():
                if isinstance(rec, dict):
                    add("v2store:" + str(rec.get("clientId") or "?"), rec.get("accessToken"), "bearer")
        elif isinstance(recs, list):
            for rec in recs:
                if isinstance(rec, dict):
                    add("v2store", rec.get("accessToken"), "bearer")

    for p in MINIMAX_AUTH_FILES:
        if not os.path.isfile(p):
            continue
        d = _load_json(p)
        if not isinstance(d, dict):
            continue
        base = os.path.basename(p)
        auth = d.get("auth") if isinstance(d.get("auth"), dict) else None
        if auth and auth.get("accessToken"):
            add(base + ":auth", auth.get("accessToken"))
        toks = d.get("tokens") if isinstance(d.get("tokens"), dict) else {}
        for slot in ("user", "sharedUser"):
            tk = _slot_tok(toks.get(slot)) or _slot_tok(d.get(slot))
            if tk:
                add("%s:%s" % (base, slot), tk)
    return out


def _mm_name_of(info, tok, used):
    """给账号取一个稳定且不重名的展示名（subUserName 优先，重名时补手机号/ID 尾号）。"""
    info = info or {}
    base = info.get("sub_name") or info.get("name") or ""
    if not base:
        ph = info.get("phone") or ""
        base = ("MiniMax·" + ph[-4:]) if ph else ("MiniMax·" + tok[-6:])
    name = base
    if name in used:
        tail = (info.get("phone") or "")[-4:] or str(info.get("real_user_id") or "")[-4:] or tok[-4:]
        name, i = "%s·%s" % (base, tail), 2
        while name in used:
            name, i = "%s·%s#%d" % (base, tail, i), i + 1
    used.add(name)
    return name


def read_minimax():
    """从本地 MiniMax 客户端读取【全部】可读登录态。

    为什么不能只读第一个命中的文件：客户端只有 user / sharedUser 两个槽位，
    登录第 3 个号时客户端会把先前的槽位顶掉；令牌又分散在 v2 store / local-runtime 两处。
    只读一个文件 → 每次导入只拿到 1 个账号，于是看板上「后面的号互相覆盖」。
    这里把全部来源读全 → 用 /v1/api/user/info 逐个反查真实身份 → 按 real_user_id 去重，
    看板侧再【累加】写入 minimax_accounts.json，因此客户端后来丢掉的账号也不会从看板消失。

    返回 (ok, msg, accounts)；accounts = {展示名: {access_token,user_id,phone,auth_mode,...}}
    """
    cands = _mm_collect_tokens()
    if not cands:
        paths = [MINIMAX_V2_GLOB.replace(HOME, "~")] + [p.replace(HOME, "~") for p in MINIMAX_AUTH_FILES]
        return False, ("未找到 MiniMax 客户端数据（已查 %s）。"
                       "请确认已安装并登录 MiniMax Code 桌面端。" % "、".join(paths)), {}

    # Bearer(mmoat_) 排前面：那是客户端当前使用的鉴权方式，寿命长于 JWT；
    # 同一账号若两处各存一枚，保留先到的那枚。
    cands.sort(key=lambda c: 0 if c[2] == "bearer" else 1)

    accs, used, by_ident, stale = {}, set(), {}, 0
    for src, tok, mode in cands:
        try:
            info = _mm_mod().fetch_user_info(tok, mode)
        except Exception:
            info = None
        if not info:
            # 解不出身份 = 这枚令牌已经签不了到，导进来只会多一张无效卡片
            stale += 1
            continue
        ident = str(info.get("real_user_id") or info.get("user_id") or info.get("phone") or tok)
        if ident in by_ident:
            by_ident[ident].setdefault("also_from", []).append(src)
            continue
        name = _mm_name_of(info, tok, used)
        rec = {"access_token": tok, "auth_mode": mode, "via_local": True,
               "user_id": str(info.get("real_user_id") or info.get("user_id") or ""),
               "phone": info.get("phone") or "",
               "source": "客户端当前登录（%s）" % src}
        if info.get("name"):
            rec["client_name"] = info["name"]
        by_ident[ident] = rec
        accs[name] = rec

    if not accs:
        return False, ("读到 %d 个 MiniMax 登录态，但都无法通过服务端校验（令牌已失效）。"
                       "请在 MiniMax Code 客户端里重新登录一次，再点「从本地客户端导入」。"
                       % len(cands)), {}
    msg = ("已从本地客户端读取 MiniMax 登录态：%s（共 %d 个）"
           % ("、".join(accs.keys()), len(accs)))
    if stale:
        msg += "；另有 %d 个令牌已失效，已跳过" % stale
    return True, msg, accs


# ────────────────────────── DuMate ──────────────────────────
def _aes_gcm_decrypt(key, blob_b64):
    """AES-256-GCM 解密：nonce(12) + tag(16) + ciphertext"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.b64decode(blob_b64)
    if len(raw) < 28:
        raise ValueError("密文过短")
    nonce, tag, ct = raw[:12], raw[12:28], raw[28:]
    return AESGCM(key).decrypt(nonce, ct + tag, None)


def _cookies_to_header(items):
    """cookie 列表 → HTTP Cookie 头字符串（按域过滤 + 同名去重）"""
    seen, parts = set(), []
    for c in items:
        if not isinstance(c, dict):
            continue
        domain = c.get("domain") or ""
        if not any(d in domain for d in COOKIE_DOMAINS):
            continue
        nm, val = c.get("name"), c.get("value")
        if not nm or val is None:
            continue
        if nm in seen:
            continue
        seen.add(nm)
        parts.append("%s=%s" % (nm, val))
    return "; ".join(parts)


def read_dumate():
    """从本地百度搭子 DuMate 客户端读取并解密 cookie。
    返回 (ok, msg, accounts)；accounts = {名字: {"cookie":...}}
    """
    if not os.path.isfile(DUMATE_AUTH):
        return False, ("未找到 DuMate 客户端数据（%s）。"
                       "请确认已安装并登录百度搭子桌面端。" % DUMATE_AUTH.replace(HOME, "~")), {}
    if not os.path.isfile(DUMATE_KEY):
        return False, "缺少 DuMate 密钥文件 .cookie-key，无法解密本地 cookie。", {}
    auth = _load_json(DUMATE_AUTH)
    if not isinstance(auth, dict):
        return False, "DuMate auth.json 解析失败（可能正在运行占用），请关闭客户端后重试。", {}
    try:
        key = open(DUMATE_KEY, "rb").read()
    except Exception as e:
        return False, "读取 .cookie-key 失败：%s" % str(e)[:80], {}
    if len(key) != 32:
        return False, "DuMate 密钥长度异常（%d 字节，应为 32）。" % len(key), {}

    accs, last_err = {}, ""
    # ① 顶层 cookies（当前激活账号）
    active_id = auth.get("activeProfileId")
    profiles = auth.get("accountProfiles") or []
    name_of = {}
    for p in profiles:
        if isinstance(p, dict) and p.get("profileId"):
            name_of[p["profileId"]] = p.get("displayName") or "DuMate"

    blobs = []
    if auth.get("cookies"):
        blobs.append((active_id, auth["cookies"]))
    for p in profiles:
        if isinstance(p, dict) and p.get("encryptedCookies"):
            pid = p.get("profileId")
            if not any(pid == b[0] for b in blobs):
                blobs.append((pid, p["encryptedCookies"]))

    for pid, blob in blobs:
        try:
            text = _aes_gcm_decrypt(key, blob).decode("utf-8")
            items = json.loads(text)
        except Exception as e:
            last_err = str(e)[:80]
            continue
        header = _cookies_to_header(items)
        if not header:
            last_err = "解密成功但未取到 dumate/baidu 域 cookie"
            continue
        has_bduss = "BDUSS=" in header
        nm = name_of.get(pid) or "DuMate"
        if nm in accs:
            nm += "·2"
        accs[nm] = {"cookie": header}
        last_err = "" if has_bduss else "已取到 cookie 但缺少 BDUSS，可能未登录"

    if accs:
        return True, "已从本地客户端解密 DuMate 登录态：%s" % "、".join(accs.keys()), accs
    return False, "DuMate 本地 cookie 解密失败：%s" % (last_err or "未知原因"), {}


# ────────────────────────── WPS 灵犀 ──────────────────────────
def _dpapi(data):
    """Windows DPAPI 解密（等价于 Electron safeStorage / win32crypt）"""
    import ctypes
    from ctypes import wintypes

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    bi = _BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)),
                                      ctypes.POINTER(ctypes.c_char)))
    bo = _BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(bi), None, None, None, None, 0, ctypes.byref(bo)):
        raise OSError("DPAPI 解密失败 err=%d" % ctypes.GetLastError())
    try:
        buf = ctypes.create_string_buffer(bo.cbData)
        ctypes.memmove(buf, bo.pbData, bo.cbData)
        return buf.raw
    finally:
        ctypes.windll.kernel32.LocalFree(bo.pbData)


def _chromium_key(user_data_dir):
    """从 Chromium/Electron 的 Local State 取出 AES-256 key（DPAPI 包裹）"""
    ls = os.path.join(user_data_dir, "Local State")
    d = _load_json(ls) or {}
    ek = ((d.get("os_crypt") or {}).get("encrypted_key") or "")
    if not ek:
        raise ValueError("Local State 缺少 os_crypt.encrypted_key")
    raw = base64.b64decode(ek)
    if raw[:5] != b"DPAPI":
        raise ValueError("encrypted_key 前缀不是 DPAPI")
    return _dpapi(raw[5:])


def _chromium_cookie_value(key, blob):
    """解密单条 Chromium cookie 值。
    v10/v11 = AES-256-GCM(nonce12 + ct + tag16)；
    解密后的明文前 32 字节是 host 绑定摘要（新版本 Chromium 特性），取值需去掉它。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if blob[:3] in (b"v10", b"v11"):
        pt = AESGCM(key).decrypt(blob[3:15], blob[15:], None)
        if len(pt) > 32:
            pt = pt[32:]
        return pt.decode("utf-8", "replace")
    return _dpapi(blob).decode("utf-8", "replace")


def _candidate_cookie_dbs(user_data_dir):
    """主 Cookies + 各 partition 的 Cookies（后者在客户端运行时往往不被独占）"""
    out = [os.path.join(user_data_dir, "Network", "Cookies")]
    pdir = os.path.join(user_data_dir, "Partitions")
    if os.path.isdir(pdir):
        for nm in sorted(os.listdir(pdir)):
            p = os.path.join(pdir, nm, "Network", "Cookies")
            if os.path.exists(p):
                out.append(p)
    return out


def read_lingxi():
    """从本机 WPS 灵犀客户端读取 wps_sid。
    wps_sid 存放在 Electron 各 session partition 的 Cookies(sqlite) 中，
    用 Local State 的 DPAPI-AES key 解密（v10 格式）。
    返回 (ok, msg, accounts)；accounts = {名字: {"wps_sid": ...}}
    """
    import glob as _glob
    import sqlite3
    import tempfile

    udir = None
    for d in LINGXI_DIRS:
        if os.path.isfile(os.path.join(d, "Local State")) and os.path.isdir(os.path.join(d, "Network")):
            udir = d
            break
    if not udir:
        return False, ("未找到 WPS 灵犀客户端数据（已查 %s）。"
                       "请确认已安装并登录 WPS 灵犀桌面端。"
                       % "、".join(p.replace(HOME, "~") for p in LINGXI_DIRS)), {}
    try:
        key = _chromium_key(udir)
    except Exception as e:
        return False, "读取灵犀加密密钥失败：%s" % str(e)[:100], {}

    found, locked, seen = {}, 0, {}
    for ck in _candidate_cookie_dbs(udir):
        label = ck.replace(udir, "").replace("\\Network\\Cookies", "").strip("\\") or "main"
        try:
            blob = open(ck, "rb").read()          # Python 的共享读模式
        except Exception:
            locked += 1
            continue
        tmp = os.path.join(tempfile.gettempdir(), "_lx_ck_%d.db" % (abs(hash(label)) % 10 ** 8))
        try:
            with open(tmp, "wb") as fh:
                fh.write(blob)
            con = sqlite3.connect(tmp)
            rows = con.execute(
                "SELECT encrypted_value FROM cookies WHERE name='wps_sid' AND host_key='.wps.cn'"
            ).fetchall()
            con.close()
        except Exception:
            continue
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        for (ev,) in rows:
            try:
                sid = _chromium_cookie_value(key, ev)
            except Exception:
                continue
            if not sid or not sid.startswith("V02"):
                continue
            # 归一化：同一账号在多个 partition 会重复出现
            seen.setdefault(sid, []).append(label)

    if not seen:
        extra = ("（有 %d 个 cookie 文件被客户端独占，未能读取 —— "
                 "退出 WPS 灵犀后重试可拿到全部账号）" % locked) if locked else ""
        return False, "未从灵犀客户端解出 wps_sid，请确认已登录灵犀桌面端。" + extra, {}

    # 用分区名里的账号标识尽量给个可辨识的名字；否则按序编号
    for i, (sid, labels) in enumerate(sorted(seen.items(), key=lambda kv: kv[1][0])):
        nm = None
        for lb in labels:
            if "in-app-browser-" in lb:
                nm = "灵犀·" + lb.split("in-app-browser-")[-1][-4:]
                break
        if not nm:
            nm = "灵犀·账号%d" % (i + 1)
        n, base = nm, 1
        while nm in found:
            base += 1
            nm = "%s-%d" % (n, base)
        found[nm] = {"wps_sid": sid}
    msg = "已从本地客户端解密 WPS 灵犀登录态：%s" % "、".join(found.keys())
    if locked:
        msg += "（另有 %d 个 cookie 文件被运行中的客户端独占，未纳入；退出灵犀可全部读出）" % locked
    return True, msg, found


# ────────────────────────── Trae ──────────────────────────
_TRAE_HDR_LEN, _TRAE_KEY_LEN, _TRAE_HMAC_LEN = 6, 32, 64
_TRAE_URE = bytes([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124,
                   227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123,
                   148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102,
                   40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37])
_TRAE_DRE = bytes([31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81,
                   127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59,
                   77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186,
                   119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125])


def _trae_decrypt_auth(b64_text):
    """解密 iCubeAuthInfo://icube.cloudide。
    格式：base64( 6字节头 + 32字节key + AES-128-CBC密文 )
    key 派生：sha512(sh  +  (URE xor DRE))，取前 16 字节为 AES key、次 16 字节为 IV
    明文：前 64 字节 HMAC，其后为 JSON
    （算法与 Trae 客户端一致，已被多个公开脚本交叉验证）"""
    import hashlib
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    t = base64.b64decode(b64_text)
    key = t[_TRAE_HDR_LEN:_TRAE_HDR_LEN + _TRAE_KEY_LEN]
    sha = hashlib.sha512(key).digest()
    xor = bytes(a ^ b for a, b in zip(_TRAE_URE, _TRAE_DRE))
    h = hashlib.sha512(sha + xor).digest()
    dec = Cipher(algorithms.AES(h[:16]), modes.CBC(h[16:32])).decryptor()
    plain = dec.update(t[_TRAE_HDR_LEN + _TRAE_KEY_LEN:]) + dec.finalize()
    plain = plain[:-plain[-1]]                     # PKCS7 去填充
    return json.loads(plain[_TRAE_HMAC_LEN:].decode("utf-8"))


def _trae_device_id(app_dir):
    """设备 ID：优先 ahanet 配置，其次日志中的 [ICDRS] did"""
    import re
    p = os.path.join(app_dir, "ahanet", "tt_net_config.config")
    try:
        m = re.search(r"device_id&#\*(\d+)", open(p, encoding="utf-8", errors="ignore").read())
        if m:
            return m.group(1)
    except OSError:
        pass
    logs = os.path.join(app_dir, "logs")
    if os.path.isdir(logs):
        try:
            dirs = sorted((os.path.join(logs, d) for d in os.listdir(logs)),
                          key=lambda x: os.path.getmtime(x), reverse=True)[:5]
        except OSError:
            dirs = []
        for d in dirs:
            p2 = os.path.join(d, "main.log")
            try:
                m = re.search(r"\[ICDRS\].*?did: (\d+)",
                              open(p2, encoding="utf-8", errors="ignore").read())
                if m:
                    return m.group(1)
            except OSError:
                continue
    return ""


def read_trae():
    """从本机 Trae 客户端读取登录态（解密 iCubeAuthInfo）。
    返回 (ok, msg, accounts)；accounts = {名字: {token, refresh_token, user_id, region, device_id, host, expired_at}}
    """
    tried, last_err = [], ""
    for app_dir in TRAE_DIRS:
        sf = os.path.join(app_dir, "User", "globalStorage", "storage.json")
        if not os.path.isfile(sf):
            continue
        tried.append(os.path.basename(app_dir))
        st = _load_json(sf)
        if not isinstance(st, dict):
            last_err = "storage.json 解析失败（可能被运行中的客户端占用）"
            continue
        enc = st.get("iCubeAuthInfo://icube.cloudide")
        if not enc:
            last_err = "storage.json 中没有 iCubeAuthInfo://icube.cloudide（尚未登录？）"
            continue
        try:
            auth = _trae_decrypt_auth(enc)
        except Exception as e:
            last_err = "登录态解密失败：%s" % str(e)[:90]
            continue
        tok = (auth.get("token") or "").strip()
        if not tok:
            last_err = "解密成功但未取到 token，请重新登录客户端"
            continue
        acct = auth.get("account") or {}
        nm = (acct.get("username") or "").strip() or ("Trae·" + str(auth.get("userId") or "")[-4:])
        ent = {
            "token": tok,
            "refresh_token": (auth.get("refreshToken") or "").strip(),
            "user_id": str(auth.get("userId") or ""),
            "region": ((auth.get("userRegion") or {}).get("region") or "CN"),
            "device_id": _trae_device_id(app_dir),
            "host": (auth.get("host") or "https://api.trae.cn"),
            "expired_at": auth.get("expiredAt") or "",
            "refresh_expired_at": auth.get("refreshExpiredAt") or "",
            "mobile": acct.get("nonPlainTextMobile") or "",
        }
        return True, ("已从本地客户端解密 Trae 登录态：%s（%s）"
                      % (nm, os.path.basename(app_dir))), {nm: ent}
    if not tried:
        return False, ("未找到 Trae 客户端数据（已查 %s）。请确认已安装并登录 Trae / TRAE SOLO CN。"
                       % "、".join(os.path.basename(p) for p in TRAE_DIRS)), {}
    return False, "找到 Trae 配置但未取到有效登录态：%s" % (last_err or "未知原因"), {}


# ────────────────────────── Qoder CN ──────────────────────────
# Qoder 客户端（Chromium 内核）把登录态写成 %APPDATA%/com.qodercn.app.stable/auth.v1.dat：
#   AES-256-GCM，nonce = blob[3:15]，其后为密文 + tag16；key 来自同一目录 Local State 的
#   DPAPI 包裹密钥。与浏览器 cookie 不同，这里明文是**裸 JSON**，没有新版 32 字节 host 前缀
#   （带上前缀反而解不开），故两路都试。
QODER_DIRS = [
    os.path.join(APPDATA, "com.qodercn.app.stable"),
    os.path.join(APPDATA, "QoderCN"),
    os.path.join(APPDATA, "Qoder"),
]


def _qoder_decrypt(dat_path, udir):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    blob = open(dat_path, "rb").read()
    if blob[:3] not in (b"v10", b"v11"):
        raise ValueError("auth.v1.dat 不是 Chromium v10/v11 加密格式")
    key = _chromium_key(udir)
    pt = AESGCM(key).decrypt(blob[3:15], blob[15:], None)
    for cand in ((pt,), (pt[32:],) if len(pt) > 32 else ()):
        try:
            j = json.loads(cand[0].decode("utf-8"))
            if isinstance(j, dict):
                return j
        except Exception:
            continue
    raise ValueError("解密成功但内容不是 JSON")


def read_qoder():
    """从本机 Qoder CN 客户端读取登录态。
    返回 (ok, msg, accounts)；accounts = {名字: {token, refresh_token, expires_at, user_id, phone}}
    """
    import glob as _glob
    tried, last_err = [], ""
    for udir in QODER_DIRS:
        dat = os.path.join(udir, "auth.v1.dat")
        if not os.path.isfile(dat):
            continue
        tried.append(os.path.basename(udir))
        try:
            j = _qoder_decrypt(dat, udir)
        except Exception as e:
            last_err = "auth.v1.dat 解密失败：%s" % str(e)[:90]
            continue
        tok = (j.get("token") or j.get("accessToken") or "").strip()
        if not tok:
            last_err = "解密成功但未取到 token，请在客户端重新登录"
            continue
        usr = j.get("user") if isinstance(j.get("user"), dict) else {}
        nm = (usr.get("name") or "").strip() or ("Qoder·" + str(usr.get("id") or "")[-4:])
        return True, ("已从本地客户端解密 Qoder CN 登录态：%s（%s）"
                      % (nm, os.path.basename(udir))), {
            nm: {"token": tok,
                 "refresh_token": (j.get("refreshToken") or j.get("refresh_token") or "").strip(),
                 "expires_at": j.get("expiresAt") or j.get("expires_at") or "",
                 "user_id": str(usr.get("id") or ""),
                 "phone": usr.get("phone") or ""}}
    for p in _glob.glob(os.path.join(HOME, ".qoder*", "**", "*.json"), recursive=True):
        j = _load_json(p)
        if not isinstance(j, dict):
            continue
        tok = (j.get("token") or j.get("accessToken") or j.get("access_token") or "").strip()
        if not tok:
            continue
        usr = j.get("user") if isinstance(j.get("user"), dict) else {}
        nm = (usr.get("name") or "").strip() or "Qoder"
        return True, ("已从本地文件读取 Qoder CN 登录态：%s（%s）"
                      % (nm, p.replace(HOME, "~"))), {
            nm: {"token": tok, "refresh_token": (j.get("refreshToken") or "").strip(),
                 "expires_at": j.get("expiresAt") or "", "user_id": str(usr.get("id") or ""),
                 "phone": usr.get("phone") or ""}}
    if not tried:
        return False, ("未找到 Qoder CN 客户端数据（已查 %s）。"
                       "请确认已安装并登录 Qoder CN 桌面端。"
                       % "、".join(os.path.basename(p) for p in QODER_DIRS)), {}
    return False, "找到 Qoder 配置但未取到有效登录态：%s" % (last_err or "未知原因"), {}


# ────────────────────────── ZCode（z.ai 客户端） ──────────────────────────
# ~/.zcode/v2/credentials.json 里每个值都是 enc:v1:<iv>.<tag>.<ct>（base64url 无填充），
# AES-256-GCM；key = sha256("zcode-credential-fallback:win32:C:\Users\<用户>:<用户>")。
# 这是客户端在拿不到系统安全存储时的回退密钥，本机实测可解。
ZCODE_CRED = os.path.join(HOME, ".zcode", "v2", "credentials.json")
ZCODE_FALLBACK_SECRET = "zcode-credential-fallback:win32:%s:%s" % (
    os.path.join(HOME.replace("/", "\\")), os.environ.get("USERNAME") or "")


def _enc_v1_decrypt(blob, secret):
    import hashlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def _b64(s):
        s = s.replace("-", "+").replace("_", "/")
        import base64 as _b
        return _b.b64decode(s + "=" * (-len(s) % 4))

    body = blob[len("enc:v1:"):]
    iv, tag, ct = (_b64(x) for x in body.split("."))
    return AESGCM(hashlib.sha256(secret.encode("utf-8")).digest()).decrypt(iv, ct + tag, None)


def read_zcode():
    """从本机 ZCode 客户端读取登录态。
    返回 (ok, msg, accounts)；accounts = {名字: {token, user_id, secret}}
    """
    if not os.path.isfile(ZCODE_CRED):
        return False, ("未找到 ZCode 客户端数据（%s）。请确认已安装并登录 ZCode 桌面端。"
                       % ZCODE_CRED.replace(HOME, "~")), {}
    raw = _load_json(ZCODE_CRED)
    if not isinstance(raw, dict):
        return False, "ZCode credentials.json 解析失败。", {}
    if not raw.get("zcodejwttoken"):
        return False, "ZCode 凭据中没有 zcodejwttoken（尚未登录？请在客户端登录后重试）。", {}
    try:
        tok = _enc_v1_decrypt(raw["zcodejwttoken"], ZCODE_FALLBACK_SECRET).decode("utf-8").strip()
    except Exception as e:
        return False, ("ZCode 凭据解密失败：%s（客户端可能换了加密回退串，"
                       "请把错误反馈给看板维护者）" % str(e)[:90]), {}
    if not tok:
        return False, "ZCode 凭据解密结果为空，请在客户端重新登录。", {}
    uid, nm = "", "ZCode"
    try:
        u = _enc_v1_decrypt(raw.get("oauth:zai:user_info", ""), ZCODE_FALLBACK_SECRET)
        info = json.loads(u.decode("utf-8"))
        uid = str(info.get("user_id") or "")
        nm = (info.get("name") or "").strip() or nm
    except Exception:
        pass
    return True, "已从本地客户端解密 ZCode 登录态：%s" % nm, {
        nm: {"token": tok, "user_id": uid, "secret": ZCODE_FALLBACK_SECRET}}


# ────────────────────────── OfficeACE（华为云 AgentArts） ──────────────────────────
# 凭据在 <安装目录>/packages/api/.config/secure-config-nodejs/ 下：
#   .oauth-profile-encryption-key : 文本 "OC-DPAPI-1\n<base64(DPAPI blob)>"
#       → DPAPI 解出 43 字符 base64url 串 → 再 base64 解码得 32 字节 AES key
#   oauth-<accountId>.json        : {alg:aes-256-gcm, iv, tag, data}（均 base64）
#       → 解出 {credential:{access,secret,sts_token,project_id,expires_at,refresh_token,...}}
# 注意：access/secret/sts_token 是**临时凭据**，sts_token 到期后必须靠客户端登录刷新。
OFFICEACE_CONFIG_DIRS = [
    r"E:\OfficeAce\packages\api\.config\secure-config-nodejs",
    os.path.join(os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                 "OfficeAce", "packages", "api", ".config", "secure-config-nodejs"),
    os.path.join(os.path.expandvars(r"%LOCALAPPDATA%\Programs\OfficeAce"),
                 "packages", "api", ".config", "secure-config-nodejs"),
]

# ── v1.3.3+ 新版存储（2026-10-08 实地取证，勿回退） ──────────────────────
# 1.3.3 起客户端**不再写** oauth-<id>.json（全仓 `oauth-profile-encryption-key` 命中 0 次），
# 改为把登录会话写进 **SQLite**：<安装目录>/data/storage.sqlite
#   表 oc_kv_string，key = `office-claw:oc:session:user:<userId>`
#   value = JSON，身份与凭据在 `providerState` 下：
#     providerState.credential    （旧）{access,secret,sts_token,project_id,expires_at,refresh_token,...}
#     providerState.credentialV3  （新）{access,secret,sts_token,project_id,expires_at}
#   → 两份并存时 **credentialV3 优先**（新版客户端实际使用的那把）。
# 注意：这是**签到/调用用的临时 AK/SK/STS**，过期需客户端重新登录刷新。
OFFICEACE_DATA_DIRS = [
    r"E:\OfficeAce",
    os.path.join(os.environ.get("PROGRAMFILES", r"C:\Program Files"), "OfficeAce"),
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\OfficeAce"),
]


def _officeace_read_sqlite():
    """从 1.3.3+ 的 SQLite 会话表读凭据。返回 accounts dict（读不到则空）。"""
    accs = {}
    for root in OFFICEACE_DATA_DIRS:
        db = os.path.join(root, "data", "storage.sqlite")
        if not os.path.isfile(db):
            continue
        try:
            import sqlite3
            # 只读打开，避免与客户端争用写锁（客户端持有 -wal/-shm）
            uri = "file:%s?mode=ro" % db.replace("\\", "/").replace("?", "%3f").replace("#", "%23")
            con = sqlite3.connect(uri, uri=True, timeout=3)
            con.execute("PRAGMA query_only=ON")
            try:
                rows = list(con.execute(
                    "select value from oc_kv_string "
                    "where key like 'office-claw:oc:session:user:%'"))
            finally:
                con.close()
        except Exception:
            continue
        for (val,) in rows:
            try:
                rec = json.loads(val) if isinstance(val, (str, bytes)) else val
            except Exception:
                continue
            if not isinstance(rec, dict):
                continue
            # 过期会话跳过
            exp = rec.get("expiresAt")
            if exp:
                try:
                    import datetime as _dt
                    t = _dt.datetime.strptime(str(exp)[:19], "%Y-%m-%dT%H:%M:%S")
                    if t < _dt.datetime.utcnow():
                        continue
                except Exception:
                    pass
            ps = rec.get("providerState") or {}
            cred_v3 = ps.get("credentialV3") or {}
            cred_old = ps.get("credential") or {}
            # v3 优先取 access/secret/sts；v3 缺的字段（如 refresh_token）用旧份补齐
            cred = dict(cred_old)
            cred.update({k: v for k, v in cred_v3.items() if v})
            ak, sk, sts = cred.get("access"), cred.get("secret"), cred.get("sts_token")
            if not (ak and sk and sts):
                continue
            nm = rec.get("displayName") or ps.get("userName") or "OfficeACE"
            accs[nm] = {"ak": ak, "sk": sk, "sts_token": sts,
                        "project_id": cred.get("project_id") or "",
                        "expires_at": cred.get("expires_at") or "",
                        "refresh_token": cred.get("refresh_token") or "",
                        "refresh_expires_at": cred.get("refresh_expires_at") or "",
                        "user_id": ps.get("user_id") or rec.get("userId") or "",
                        "host": "https://officeace.cn-southwest-2.huaweicloud-agentarts.com",
                        "region": "cn-southwest-2"}
    return accs


def read_officeace():
    """解密 OfficeACE（华为云 AgentArts）临时凭据。
    返回 (ok, msg, accounts)；accounts = {用户名: {ak, sk, sts_token, project_id, expires_at, region, host}}

    两条路径：① **v1.3.3+ SQLite 会话表**（当前主路径，见 _officeace_read_sqlite）
             ② 旧版 oauth-<id>.json + DPAPI 加密密钥（≤1.2.x，保留兼容）
    """
    import glob as _glob

    # ── 路径①：1.3.3+ SQLite ──
    sqlite_accs = _officeace_read_sqlite()
    if sqlite_accs:
        return (True, "已从本地客户端读取 OfficeACE 凭据：%s" % "、".join(sqlite_accs.keys()),
                sqlite_accs)

    # ── 路径②：旧版文件（回退） ──
    kdir = None
    for d in OFFICEACE_CONFIG_DIRS:
        if os.path.isfile(os.path.join(d, ".oauth-profile-encryption-key")):
            kdir = d
            break
    if not kdir:
        return False, ("未找到 OfficeACE 凭据（已查 SQLite：%s；旧版目录：%s）。"
                       "请确认已登录 OfficeACE 桌面端。"
                       % ("、".join(os.path.join(p, "data", "storage.sqlite")
                                   for p in OFFICEACE_DATA_DIRS),
                          "、".join(OFFICEACE_CONFIG_DIRS))), {}
    try:
        txt = open(os.path.join(kdir, ".oauth-profile-encryption-key"), "rb") \
            .read().decode("utf-8", "replace").strip()
        b64part = txt.split("\n", 1)[1].strip() if "\n" in txt else txt
        import hashlib
        import base64 as _b
        raw = _dpapi(_b.b64decode(b64part))
        # DPAPI 解出的是一段 43 字符 base64url 文本；AES key = sha256(该文本)
        # （不是 sha256(解码后的 32 字节)，实测前者才解得开）
        key = hashlib.sha256(raw).digest()
    except Exception as e:
        return False, "OfficeACE 密钥解析失败：%s" % str(e)[:100], {}

    accs, last = {}, ""
    for f in sorted(_glob.glob(os.path.join(kdir, "oauth-*.json"))):
        try:
            j = _load_json(f) or {}
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            def _b64(s):
                s = s.replace("-", "+").replace("_", "/")
                import base64 as _b
                return _b.b64decode(s + "=" * (-len(s) % 4))
            pt = AESGCM(key).decrypt(_b64(j["iv"]), _b64(j["data"]) + _b64(j["tag"]), None)
            prof = json.loads(pt.decode("utf-8"))
        except Exception as e:
            last = "oauth 配置解密失败：%s" % str(e)[:80]
            continue
        cred = prof.get("credential") or {}
        ak, sk, sts = cred.get("access"), cred.get("secret"), cred.get("sts_token")
        if not (ak and sk and sts):
            last = "凭据字段缺失（access/secret/sts_token）"
            continue
        nm = prof.get("userName") or prof.get("principalUrn") or "OfficeACE"
        accs[nm] = {"ak": ak, "sk": sk, "sts_token": sts,
                    "project_id": cred.get("project_id") or "",
                    "expires_at": cred.get("expires_at") or "",
                    "refresh_token": cred.get("refresh_token") or "",
                    "refresh_expires_at": cred.get("refresh_expires_at") or "",
                    "user_id": prof.get("user_id") or "",
                    "host": "https://officeace.cn-southwest-2.huaweicloud-agentarts.com",
                    "region": "cn-southwest-2"}
        last = ""
    if accs:
        return True, "已从本地客户端解密 OfficeACE 凭据：%s" % "、".join(accs.keys()), accs
    return False, "OfficeACE 凭据读取失败：%s" % (last or "未找到 oauth-*.json"), {}


# ────────────────────────── CodeArts Agent（码道） ──────────────────────────
# 登录态不在 Cookie 里（该表 0 行），而在 VS Code 的 SecretStorage：
#   %APPDATA%/codearts-agent/User/globalStorage/state.vscdb（SQLite）
#     key = secret://{"extensionId":"huaweicloud.authentication","key":"HuaweiCloudSession"}
#     value = {"type":"Buffer","data":[...]}，原始字节前缀 v10（Chromium OSCrypt）
#   AES key 来自同目录 Local State 的 os_crypt.encrypted_key（DPAPI 包裹）
#   明文为 **裸 JSON**（无 32 字节 host 摘要）
# 解出：accessKey / secretKey / securitytoken（华为云 STS 临时凭证，约 1 小时过期）
#       + refresh_token（**一次性、用后轮换**）+ loginContext（DPoP 私钥、PKCE verifier）
#
# ⚠ 本模块对该库**只读**：以 sqlite `mode=ro` 打开，绝不写入。
#   也因此不做自动刷新（刷新会消费掉客户端唯一的那把一次性 refresh_token，
#   与桌面端争用）。凭证过期时由平台适配器给出「请打开客户端」的明确提示。
CODEARTS_USER_DIRS = [
    os.path.join(APPDATA, "codearts-agent"),
]


def read_codearts():
    """只读解密 CodeArts Agent 的华为云临时凭证。
    返回 (ok, msg, accounts)；accounts = {用户名: {ak, sk, sts_token, expires_at, account_id}}
    """
    import sqlite3
    udir = None
    for d in CODEARTS_USER_DIRS:
        if os.path.isfile(os.path.join(d, "Local State")) and \
           os.path.isfile(os.path.join(d, "User", "globalStorage", "state.vscdb")):
            udir = d
            break
    if not udir:
        return False, ("未找到 CodeArts Agent 客户端数据（已查 %s）。"
                       "请确认已安装并登录 CodeArts Agent（码道）。"
                       % "、".join(p.replace(HOME, "~") for p in CODEARTS_USER_DIRS)), {}
    db = os.path.join(udir, "User", "globalStorage", "state.vscdb")
    try:
        key = _chromium_key(udir)
    except Exception as e:
        return False, "读取 CodeArts 加密密钥失败：%s" % str(e)[:100], {}

    # 只读打开（uri=True + mode=ro），确保绝不写入用户凭据库
    try:
        con = sqlite3.connect("file:%s?mode=ro" % db.replace("\\", "/").replace("?", "%3f"),
                              uri=True, timeout=5)
    except Exception:
        try:
            con = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=5)
        except Exception as e:
            return False, "无法只读打开 CodeArts 凭据库：%s" % str(e)[:100], {}
    try:
        row = con.execute(
            "SELECT value FROM ItemTable WHERE key LIKE 'secret://%HuaweiCloudSession%'"
        ).fetchone()
    except Exception as e:
        con.close()
        return False, "读取 CodeArts 会话失败：%s" % str(e)[:100], {}
    con.close()
    if not row:
        return False, "CodeArts 凭据库里没有 HuaweiCloudSession（尚未登录？）", {}

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        val = row[0]
        if isinstance(val, (bytes, bytearray)):
            val = val.decode("utf-8", "replace")
        blob = bytes(json.loads(val)["data"])
        if blob[:3] not in (b"v10", b"v11"):
            return False, "CodeArts 会话不是 v10/v11 加密格式（客户端版本可能已变）", {}
        pt = AESGCM(key).decrypt(blob[3:15], blob[15:], None)
        sess = None
        for cand in ((pt,), (pt[32:],) if len(pt) > 32 else ()):
            try:
                sess = json.loads(cand[0].decode("utf-8"))
                break
            except Exception:
                continue
        if not isinstance(sess, dict):
            return False, "CodeArts 会话解密成功但无法解析为 JSON", {}
    except Exception as e:
        return False, "CodeArts 会话解密失败：%s" % str(e)[:100], {}

    ak = (sess.get("accessKey") or "").strip()
    sk = (sess.get("secretKey") or "").strip()
    sts = (sess.get("securitytoken") or "").strip()
    if not (ak and sk and sts):
        return False, "CodeArts 会话缺少 accessKey/secretKey/securitytoken，请重新登录客户端", {}
    acct = sess.get("account") if isinstance(sess.get("account"), dict) else {}
    nm = (acct.get("label") or "").strip() or ("CodeArts·" + str(acct.get("id") or "")[-4:])
    return True, "已从本地客户端读取 CodeArts Agent 凭证：%s（只读，未改动凭据库）" % nm, {
        nm: {"ak": ak, "sk": sk, "sts_token": sts,
             "expires_at": sess.get("expires_at") or "",
             "account_id": acct.get("id") or "",
             "safely_renew_interval": sess.get("safelyRenewTokenInterval")}}


# ────────────────────────── 统一入口 ──────────────────────────
READERS = {"minimax": read_minimax, "baidu_dumate": read_dumate,
           "lingxi": read_lingxi, "trae": read_trae, "qoder": read_qoder,
           "zcode": read_zcode, "officeace": read_officeace,
           "codearts": read_codearts}


def read_local(platform):
    """统一入口，返回 (ok, msg, accounts)"""
    fn = READERS.get(platform)
    if not fn:
        return False, "该平台不支持从本地客户端读取", {}
    try:
        return fn()
    except ImportError as e:
        if "cryptography" in str(e).lower():
            return False, ("缺少依赖 cryptography，无法解密 DuMate 本地 cookie。请执行："
                           " pip install cryptography（MiniMax 不受影响）"), {}
        return False, "导入异常：%s" % str(e)[:120], {}
    except Exception as e:
        return False, "导入异常：%s" % str(e)[:120], {}


if __name__ == "__main__":
    import sys
    for pid in ("minimax", "baidu_dumate", "lingxi", "trae", "qoder",
                "zcode", "officeace", "codearts"):
        ok, msg, accs = read_local(pid)
        print("[%s] ok=%s | %s | 账号=%s" % (pid, ok, msg, list(accs.keys())))
