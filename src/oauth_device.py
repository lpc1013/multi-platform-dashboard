# -*- coding: utf-8 -*-
"""OAuth 设备码流（Device Authorization Grant）—— 二期拆分自 oauth_login.py。

含 minimax(device) / zcode(cli_poll) / qoder(qoder_device) 三种设备流的
start/poll 与 refresh_grant 静默续期；协议细节见函数内注释。"""
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


# ────────────────────────── 设备码三步 ──────────────────────────
def device_start(platform, region="cn", sub=None):
    """① 申请设备码 / 登录链接。返回 (ok, msg, flow)。

    kind=device      → 标准 RFC 8628 设备码（MiniMax）
    kind=cli_poll    → 各家自研的「init + poll」登录（ZCode）
    kind=qoder_device → Qoder 自研设备流（selectAccounts → sign-in → poll）
    """
    p = _provider(platform)
    kind = p.get("kind")
    if kind == "cli_poll":
        return _cli_poll_start(platform, sub or p.get("default_sub"))
    if kind == "qoder_device":
        return _qoder_start(platform)
    verifier, challenge = _pkce()
    p = _provider(platform)
    url = _origin(platform, region) + "/oauth2/device/code"
    try:
        sc, d = _post_form(url, {
            "client_id": p["client_id"],
            "scope": " ".join(p["scopes"]),
            "audience": p["audience"],
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
    except Exception as e:
        return False, "申请设备码失败：%s" % str(e)[:150], None
    if sc != 200 or not isinstance(d, dict) or not d.get("user_code"):
        return False, "申请设备码被拒绝（HTTP %s）：%s" % (sc, json.dumps(d, ensure_ascii=False)[:200]), None
    verify = d.get("verification_uri_complete") or d.get("verification_uri") or ""
    flow = {
        "platform": platform,
        "kind": "device",
        "region": region,
        "user_code": str(d.get("user_code") or ""),
        "device_code": str(d.get("device_code") or d.get("user_code") or ""),
        "verification_uri": str(d.get("verification_uri") or ""),
        "verify_url": str(verify),
        "expires_in": int(d.get("expires_in") or d.get("expired_in") or 300),
        "interval": float(d.get("interval") or 5),
        "code_verifier": verifier,
        # 账号中心有时用 user_code 轮询（客户端里的 tokenPollingParameter 逻辑）
        "poll_param": "device_code" if d.get("device_code") else "user_code",
    }
    return True, "已生成授权码", flow


def _cli_poll_start(platform, sub):
    """ZCode 的 CLI 登录初始化：拿 flow_id / poll_token / authorize_url。实测通过。"""
    p = _provider(platform)
    bearer = secrets.token_bytes(32).hex()
    try:
        if requests is None:
            raise RuntimeError("缺少依赖 requests")
        r = requests.post(p["init_url"], timeout=25, verify=False,
                          headers={"Authorization": "Bearer " + bearer,
                                   "Content-Type": "application/json",
                                   "Accept": "application/json", "User-Agent": UA},
                          json={"provider": sub})
        try:
            d = r.json()
        except Exception:
            return False, "登录初始化返回非 JSON（HTTP %s）" % r.status_code, None
    except Exception as e:
        return False, "登录初始化失败：%s" % str(e)[:150], None
    if r.status_code != 200 or d.get("code") != 0:
        return False, "登录初始化被拒绝：%s" % json.dumps(d, ensure_ascii=False)[:200], None
    data = d.get("data") or {}
    fid, ptok = str(data.get("flow_id") or ""), str(data.get("poll_token") or "")
    url = str(data.get("authorize_url") or "")
    if not (fid and ptok and url):
        return False, "登录初始化响应缺少 flow_id / poll_token / authorize_url", None
    try:
        left = int(data.get("expires_at")) - int(time.time())
    except Exception:
        left = 300
    flow = {
        "platform": platform,
        "kind": "cli_poll",
        "sub": sub,
        "region": "cn",
        "user_code": "",                       # 该通道不给用户代码，直接开链接
        "device_code": fid,
        "verification_uri": "",
        "verify_url": url,
        "expires_in": max(30, min(left, 900)),
        "interval": float(data.get("poll_interval_sec") or 2),
        "code_verifier": "",
        "poll_param": "device_code",
        # /api/v1/oauth/cli/init → /api/v1/oauth/cli/poll/{flow_id}
        "poll_url": p["init_url"].rsplit("/", 1)[0] + "/poll/" + urllib.parse.quote(fid),
        "poll_token": ptok,
    }
    return True, "已生成登录链接", flow


def _cli_poll_once(flow):
    """ZCode 轮询一次。返回 (state, data)。"""
    try:
        r = requests.get(flow["poll_url"], timeout=25, verify=False,
                         headers={"Authorization": "Bearer " + flow["poll_token"],
                                  "Accept": "application/json", "User-Agent": UA})
        try:
            d = r.json()
        except Exception:
            return "error", {"error": "响应不是 JSON（HTTP %s）" % r.status_code}
    except Exception as e:
        return "error", {"error": str(e)[:150]}
    if r.status_code != 200 or d.get("code") != 0:
        return "error", d
    data = d.get("data") or {}
    if data.get("token"):
        return "ok", {"access_token": str(data.get("token")),
                      "refresh_token": str(data.get("refresh_token") or ""),
                      "token_type": "Bearer",
                      "expires_in": data.get("expires_in"),
                      "scope": "",
                      "zai": data.get("zai") or {}}
    if str(data.get("status") or "") in ("pending", "waiting", ""):
        return "pending", d
    return "error", d


def _qoder_machine_id():
    r"""读取本机 Qoder 已持久化的 machine_id（逆向定位：%APPDATA%\com.qodercn.app.stable\auth.machine-id）。
    读不到则在本看板目录里稳定生成一个，保证设备流机器标识一致。"""
    f = PROVIDERS.get("qoder", {}).get("machine_id_file") or \
        r"%APPDATA%\com.qodercn.app.stable\auth.machine-id"
    f = os.path.expandvars(f)
    try:
        with open(f, "r", encoding="utf-8") as fh:
            v = fh.read().strip()
            if v:
                return v
    except Exception:
        pass
    cache = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".qoder_machine_id")
    try:
        if os.path.exists(cache):
            return open(cache, "r", encoding="utf-8").read().strip()
        mid = secrets.token_hex(16)
        with open(cache, "w", encoding="utf-8") as fh:
            fh.write(mid)
        return mid
    except Exception:
        return secrets.token_hex(16)


def _qoder_pkce():
    """Qoder 客户端同款 PKCE 参数（逆向自 0.4.3 app.asar 的 bft()）：
    · verifier = 64 字符 PKCE 非保留字母表（A-Za-z0-9-._~），不是 base64url(32B)！
    · challenge = base64url(sha256(verifier))
    · nonce 必须是 UUID 格式（客户端用 uuid 生成器，服务端按 UUID 校验；
      2026-10-08 实测：nonce/verifier 不被服务端认可时 poll 恒返 404 NotFound，
      与「未授权」不可区分 —— 授权页显示成功、看板却永远 pending，即此坑）。"""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    verifier = "".join(secrets.choice(alphabet) for _ in range(64))
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    nonce = str(uuid.uuid4())
    return verifier, challenge, nonce


_QODER_DEBUG_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "qoder_oauth_debug.log")


def _qoder_debug(tag, sc, body):
    """把 poll 的关键响应落盘（404=正常 pending 不记，避免刷屏）。
    控制台 stdout 会随窗口丢失，文件不会 —— 这是授权后读不到令牌时的关键证据。"""
    try:
        if sc == 404:
            return
        from datetime import datetime as _dt
        with open(_QODER_DEBUG_LOG, "a", encoding="utf-8") as fh:
            fh.write("%s [%s] HTTP %s %s\n" % (
                _dt.now().strftime("%m-%d %H:%M:%S"), tag, sc,
                str(body)[:400].replace("\n", " ")))
    except Exception:
        pass


def _qoder_start(platform):
    """Qoder 设备流第一步：本地生成 PKCE + nonce + machine_id，拼出登录页 URL。"""
    p = _provider(platform)
    verifier, challenge, nonce = _qoder_pkce()
    machine_id = _qoder_machine_id()
    # QrA：GET {auth_base_url}/device/selectAccounts?challenge&challenge_method=S256&nonce&machine_id&client_id
    sel_url = p["auth_base_url"] + "/device/selectAccounts?" + urllib.parse.urlencode({
        "challenge": challenge,
        "challenge_method": "S256",
        "nonce": nonce,
        "machine_id": machine_id,
        "client_id": p["client_id"],
    })
    # drA：{auth_base_url.origin}/users/sign-in?biz_variant=qoder&oauth_callback=<selectAccounts URL>
    parsed = urllib.parse.urlparse(p["auth_base_url"])
    origin = parsed.scheme + "://" + parsed.netloc
    login_url = origin + "/users/sign-in?" + urllib.parse.urlencode({
        "biz_variant": p["biz_variant"],
        "oauth_callback": sel_url,
    })
    flow = {
        "platform": platform,
        "kind": "qoder_device",
        "region": "cn",
        "user_code": "",
        "device_code": nonce,
        "verification_uri": sel_url,
        "verify_url": login_url,
        "expires_in": 300,
        "interval": 2.0,
        "code_verifier": verifier,
        "poll_param": "device_code",
        "nonce": nonce,
        "verifier": verifier,
        "openapi_base_url": p["openapi_base_url"],
    }
    return True, "已生成登录链接", flow


def _qoder_poll_once(flow):
    """Qoder 轮询一次。返回 (state, data)。

    客户端 0.4.3 的成功判定是 `typeof u.token=="string" && typeof u.refresh_token=="string"`
    —— 即**扁平 {token, refresh_token, ...}**；同时兼容包裹 {code:0, data:{token,...}}
    与 device_token/deviceToken 字段名（老版本差异）。404=未授权（服务端对参数不匹配
    也返 404，参数格式必须与客户端完全一致，见 _qoder_pkce）。"""
    qs = urllib.parse.urlencode({
        "nonce": flow["nonce"],
        "verifier": flow["verifier"],
        "challenge_method": "S256",
    })
    url = flow["openapi_base_url"] + "/api/v1/deviceToken/poll?" + qs
    try:
        r = requests.get(url, timeout=25, verify=False,
                         headers={"Accept": "application/json", "User-Agent": UA})
        try:
            d = r.json()
        except Exception:
            _qoder_debug("poll", r.status_code, (r.text or "")[:400])
            return "error", {"error": "响应不是 JSON（HTTP %s）" % r.status_code}
    except Exception as e:
        return "error", {"error": str(e)[:150]}
    if r.status_code == 404:
        return "pending", d              # 还没授权，继续轮询
    if not r.ok:
        _qoder_debug("poll", r.status_code, d)
        return "error", d
    # 兼容扁平 / 包裹两种返回形态
    data_obj = d.get("data") if isinstance(d.get("data"), dict) else {}
    tok = (d.get("token") or data_obj.get("token")
           or d.get("access_token") or data_obj.get("accessToken")
           or data_obj.get("access_token"))
    dtok = (d.get("refresh_token") or data_obj.get("refresh_token")
            or d.get("refreshToken") or data_obj.get("refreshToken")
            or d.get("device_token") or data_obj.get("deviceToken")
            or data_obj.get("device_token") or "")
    if not tok:
        # 200 但解析不到令牌：原始体落盘 + 打印，便于定位真实字段
        _qoder_debug("poll-200-no-token", r.status_code, d)
        try:
            print("[Qoder] poll 200 但未解析到 token，原始体已写入 %s：%s"
                  % (os.path.basename(_QODER_DEBUG_LOG),
                     json.dumps(d, ensure_ascii=False)[:400]))
        except Exception:
            pass
        return "pending", d
    return "ok", {"access_token": str(tok),
                  "refresh_token": str(dtok),
                  "token_type": "Bearer",
                  "expires_in": (d.get("expires_in") or data_obj.get("expires_in")),
                  "expires_at": (d.get("expires_at") or data_obj.get("expires_at") or "")}


def device_poll(flow):
    """③ 轮询一次。返回 (state, data)：
       state ∈ pending / slow_down / denied / expired / ok / error
    """
    if flow.get("kind") == "cli_poll":
        return _cli_poll_once(flow)
    if flow.get("kind") == "qoder_device":
        return _qoder_poll_once(flow)
    p = _provider(flow["platform"])
    url = _origin(flow["platform"], flow.get("region", "cn")) + "/oauth2/token"
    body = {
        "grant_type": DEVICE_GRANT_TYPE,
        flow.get("poll_param", "device_code"): flow["device_code"],
        "client_id": p["client_id"],
        "code_verifier": flow["code_verifier"],
    }
    try:
        sc, d = _post_form(url, body)
    except Exception as e:
        return "error", {"error": str(e)[:150]}
    if not isinstance(d, dict):
        return "error", {"error": "响应不是 JSON"}
    if sc == 200 and d.get("access_token"):
        return "ok", d
    err = str(d.get("error") or d.get("status") or "")
    if err in ("authorization_pending", "pending"):
        return "pending", d
    if err == "slow_down":
        return "slow_down", d
    if err in ("access_denied", "denied"):
        return "denied", d
    if err in ("expired_token", "expired_in"):
        return "expired", d
    return "error", d


def refresh_grant(platform, refresh_token, region="cn"):
    """用 refresh_token 换新的 access_token（Bearer 令牌约 1 小时过期）。
    返回 (ok, grant, msg)。"""
    p = _provider(platform)
    url = _origin(platform, region) + "/oauth2/token"
    try:
        sc, d = _post_form(url, {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": p["client_id"],
            "scope": " ".join(p["scopes"]),
            "audience": p["audience"],
        })
    except Exception as e:
        return False, None, "刷新异常：%s" % str(e)[:120]
    if sc == 200 and isinstance(d, dict) and d.get("access_token"):
        return True, d, "已续期"
    return False, None, "刷新失败（HTTP %s）：%s" % (sc, json.dumps(d, ensure_ascii=False)[:150])
