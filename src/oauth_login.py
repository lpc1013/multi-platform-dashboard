# -*- coding: utf-8 -*-
"""
OAuth 2.0 设备码授权登录（Device Authorization Grant）
═════════════════════════════════════════════════════════════════════════
MiniMax Code 桌面端「登录」走的就是这套流程（逆向自客户端 app.asar 的
endpoint-config.js / oauth-client.js，并已用真实接口逐字段实测通过）：

  ① POST {account}/oauth2/device/code
       client_id=mcode-public
       scope=agent.default
       audience=agent-backend
       code_challenge=<base64url(sha256(verifier))>
       code_challenge_method=S256
     → {device_code, user_code, expires_in:300, interval:3,
        verification_uri, verification_uri_complete}

  ② 用户在浏览器打开 verification_uri_complete（用「手机号 + 短信验证码」登录）并点「授权」
     —— 这就是「弹出一个网页来」的那一步

  ③ 轮询 POST {account}/oauth2/token
       grant_type=urn:ietf:params:oauth:grant-type:device_code
       device_code=<...>  client_id=mcode-public  code_verifier=<...>
     · 未授权 → HTTP 400 {"error":"authorization_pending"}；轮询过快 → {"error":"slow_down"}
     · 已授权 → 200 {access_token, refresh_token, token_type:"Bearer", expires_in, scope}

为什么比「受控浏览器抓 localStorage」好：
  · 拿到的是 mcode-public / agent-backend 的**正式令牌**，与桌面端同源 → 签到接口直接可用
  · 不需要安装/打开桌面客户端，也不用猜 localStorage 键名（那条路又脆又容易抓错）
  · 令牌自带 refresh_token → 过期可静默续期，不必再手动「重新导入」

MiniMax 账号中心（cn prod）= https://account.minimax.cn
"""
import json
import time
import os
import uuid
import base64
import hashlib
import secrets
import threading
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) MiniMaxCode/3.0.73 Chrome/138.0.7204.251 Safari/537.36")

DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

# ── 各个平台的 OAuth 参数（照抄客户端里的常量，勿臆造）─────────────────
PROVIDERS = {
    "minimax": {
        "kind": "device",           # 标准 RFC 8628 设备码
        "label": "MiniMax Code",
        "client_id": "mcode-public",
        "scopes": ["agent.default"],
        "audience": "agent-backend",
        "origins": {
            "cn": {"prod": "https://account.minimax.cn"},
            "en": {"prod": "https://account.minimax.io"},
        },
        "hint": "在弹出的网页里用「手机号 + 短信验证码」登录，然后点「授权」",
    },
    # ZCode（z.ai）：客户端自带的「CLI 登录」通道，不是标准 RFC 8628，
    # 但同样是「申请登录链接 → 网页登录 → 后端轮询拿令牌」三段式：
    #   POST https://zcode.z.ai/api/v1/oauth/cli/init   {provider:"zai"|"bigmodel"}
    #        header Authorization: Bearer <32 字节随机 hex>
    #        → {code:0, data:{flow_id, poll_token, authorize_url, expires_at, poll_interval_sec}}
    #   GET  https://zcode.z.ai/api/v1/oauth/cli/poll/{flow_id}
    #        header Authorization: Bearer <poll_token>
    #        → {code:0, data:{status:"pending"}} 或 {code:0, data:{token, ...}}
    # 已用真实接口逐字段实测（2026-10-08）。
    "zcode": {
        "kind": "cli_poll",
        "label": "ZCode",
        "base": "https://zcode.z.ai",
        "init_url": "https://zcode.z.ai/api/v1/oauth/cli/init",
        "subs": [
            {"id": "zai", "label": "Z.ai 账号（chat.z.ai）"},
            {"id": "bigmodel", "label": "智谱 BigModel（bigmodel.cn）"},
        ],
        "default_sub": "zai",
        "hint": "在弹出的网页里登录并授权，看板会自动接管令牌",
    },
    # Qoder CN：自研「设备流」三段式（逆向自客户端 app.asar，2026-10-08 实测核验）：
    #   ① 本地生成 verifier → challenge=base64url(sha256(verifier)) → nonce → machine_id
    #   ② GET {auth_base_url}/device/selectAccounts
    #        ?challenge&challenge_method=S256&nonce&machine_id&client_id
    #      → 用该 URL 拼出登录页：
    #        {auth_base_url.origin}/users/sign-in?biz_variant=qoder&oauth_callback=<selectAccounts URL>
    #      用户在登录页用「手机号 + 短信验证码」/ 微信 / 飞书 完成登录并授权
    #   ③ 轮询 GET {openapi_base_url}/api/v1/deviceToken/poll
    #        ?nonce&verifier&challenge_method=S256
    #       · 未授权 → HTTP 404（继续轮询）
    #       · 已授权 → 200 {token, refresh_token, ...}（0.4.3 客户端判定就是这两个扁平字段）
    #         token 即正式令牌，refresh_token 用于续期
    #   ⚠ nonce 必须 UUID、verifier 必须 64 字符 PKCE 字母表（见 _qoder_pkce），
    #     服务端对格式不匹配的 poll 恒返 404，与未授权不可区分。
    # 配置（照抄客户端 environments.prod）：auth_base_url=https://qoder.cn、
    #   openapi_base_url=https://openapi.qoder.com.cn、client_id=732aef47-...、biz_variant=qoder
    "qoder": {
        "kind": "qoder_device",
        "label": "Qoder",
        "auth_base_url": "https://qoder.cn",
        "openapi_base_url": "https://openapi.qoder.com.cn",
        "client_id": "732aef47-9cf2-46a2-95fe-4cebb5d0d1fa",
        "biz_variant": "qoder",
        "machine_id_file": r"%APPDATA%\com.qodercn.app.stable\auth.machine-id",
        "hint": "看板会弹出登录窗口并自动填手机号、代点「获取验证码」，"
                "你只需在看板填短信验证码（窗口里若出现滑块/图片验证码请顺手完成）",
    },
}

_JOBS = {}
_job_lock = threading.Lock()


def _provider(platform):
    p = PROVIDERS.get(platform)
    if not p:
        raise KeyError("该平台未配置 OAuth 设备码登录：%s" % platform)
    return p


def _origin(platform, region="cn", build_env="prod"):
    p = _provider(platform)
    return (p["origins"].get(region) or p["origins"]["cn"]).get(build_env, "") \
        or p["origins"]["cn"]["prod"]


def _post_form(url, data, timeout=20):
    if requests is None:
        raise RuntimeError("缺少依赖 requests，请先 pip install requests")
    r = requests.post(url, data=data, timeout=timeout, verify=False,
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               "Accept": "application/json", "User-Agent": UA})
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"raw": (r.text or "")[:300]}


def _pkce():
    """PKCE：verifier 走 base64url(32 随机字节)，challenge = base64url(sha256(verifier))。
    服务端强制要求 S256（不给就 400 invalid_request: valid S256 PKCE is required）。"""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


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


def _new_job(platform, flow):
    """统一的 job 骨架（设备码登录 / 短信直登共用）。
    注意：短信直登平台（trae/codearts/officeace/lingxi 等）不在 PROVIDERS 设备码表里，
    这里不能调 _provider()（会 KeyError「该平台未配置 OAuth 设备码登录」），
    hint 由各 start_*_sms_job 的 job.update() 自己覆盖。"""
    p = PROVIDERS.get(platform) or {}
    return {
        "job": uuid.uuid4().hex[:12], "platform": platform,
        "mode": "device", "status": "waiting", "finished": False,
        "ok": None, "result": "", "name": "", "started": time.time(),
        "user_code": flow["user_code"], "verify_url": flow["verify_url"],
        "expires_in": flow["expires_in"],
        "hint": p.get("hint", ""),
        # 短信直登专用
        "phone": "", "need_code": False, "code": None, "code_submitted": False,
        "sms_sent": False,
    }


def _view(job):
    left = max(0, int(job["expires_in"] - (time.time() - job["started"])))
    return {"job": job["job"], "platform": job["platform"], "status": job["status"],
            "finished": job["finished"], "ok": job["ok"], "text": job["result"],
            "name": job["name"], "user_code": job["user_code"],
            "verify_url": job["verify_url"], "seconds_left": left,
            "expires_in": job["expires_in"], "hint": job["hint"],
            # 短信直登
            "mode": job.get("mode", "device"), "phone": job.get("phone", ""),
            "need_code": bool(job.get("need_code")),
            "sms_sent": bool(job.get("sms_sent")),
            "captcha": bool(job.get("captcha")),
            "code_submitted": bool(job.get("code_submitted")),
            # Trae 专用诊断（排障用；失败时可直接看到回调原文/端口/身份来源）
            "callback_port": job.get("callback_port"),
            "device_dir": job.get("device_dir", ""),
            "plugin_version": job.get("plugin_version", ""),
            "client_running": bool(job.get("client_running")),
            "callback_url": job.get("callback_url", ""),
            "callback_keys": job.get("callback_keys", []),
            "auth_code_head": job.get("auth_code_head", ""),
            # 兑换请求/响应留痕（与客户端成功样本逐字段比对用）
            "sent_device_name": job.get("sent_device_name", ""),
            "sent_model": job.get("sent_model", ""),
            "sent_os": job.get("sent_os", ""),
            "sent_ide_version": job.get("sent_ide_version", ""),
            "v1_status": job.get("v1_status"),
            "v1_resp": job.get("v1_resp", ""),
            # 代点【登录并打开 TRAE】留痕（判断「按钮点不到 / 点太慢」用）
            "open_clicked": bool(job.get("_open_clicked")),
            "open_tries": job.get("_open_tries", 0),
            "clicked_btn": job.get("conclick_tag", ""),
            "clicked_cls": job.get("conclick_cls", ""),
            # 回调身份解析留痕（userInfo JSON 里的 UserID/ScreenName）
            "parsed_user_id": job.get("parsed_user_id", ""),
            "parsed_name": job.get("parsed_name", "")}


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


# ───────────────── 短信直登：手机号 + 验证码（看板内完成，无需手填网页）─────────────────
# MiniMax 网页登录页（account.minimax.cn/unified-login）的「获取验证码」按钮受
# 腾讯 captcha 保护：无头/自动化点击会弹滑块。所以这里用**可见的受控浏览器**
# 由真人完成风控动作，而「填手机号 / 填验证码 / 点登录」全部由看板代劳 ——
# 用户要做的只是：在看板输手机号 → 收短信 → 在看板输验证码。
_PHONE_SEL = ["input[type='tel']", "input[placeholder*='手机号']"]
_CODE_SEL = ["input[placeholder*='验证码']", "input[type='text']"]


def _first_sel(page, sels, timeout=4000):
    """返回第一个能定位到的 locator，都定位不到返回 None。"""
    for s in sels:
        try:
            loc = page.locator(s).first
            loc.wait_for(state="visible", timeout=timeout)
            return loc
        except Exception:
            continue
    return None


def _click_text(page, names, timeout=1500):
    """按可见文本点按钮；失败退化为按文本点任意元素。"""
    for n in names:
        try:
            page.get_by_role("button", name=n, exact=True).first.click(timeout=timeout)
            return True
        except Exception:
            pass
    for n in names:
        try:
            page.get_by_text(n, exact=True).first.click(timeout=timeout)
            return True
        except Exception:
            pass
    return False


def _has_captcha(page):
    """检测腾讯滑块验证码是否弹出（turing.captcha / tcaptcha 的 iframe 或浮层）。"""
    try:
        return bool(page.evaluate("""() => {
            const fs = Array.from(document.querySelectorAll('iframe'));
            if (fs.some(f => /turing\\.captcha|tcaptcha|captcha/.test((f.src||'')+(f.id||'')))) return true;
            if (document.querySelector('#tcaptcha_iframe,[class*="tcaptcha"],[id*="tcaptcha"]')) return true;
            return false;
        }"""))
    except Exception:
        return False


def _login_submitted(page, names, ctx):
    """点「立即登录」，并校验点击是否**真的被前端接受**。

    为什么需要校验：MiniMax 登录页在未勾协议时，点「立即登录」前端会**静默 return**
    （既不发 network、也不弹提示）—— 单看「有没有点到按钮」完全看不出问题。

    判据（不依赖 network 监听，改用页面状态变化，更稳）：
      · 点击后若页面离开 unified-login（跳转 / 出现验证码错误提示 / 按钮进入 loading）
        → 视为「点击已被接受」；
      · 否则判定被协议前置校验拦截 → 补勾协议后重试一次。

    返回 True 表示点击已被前端接受，False 表示两次尝试后页面仍无反应。
    """
    def _click():
        _click_text(page, names, timeout=2500)

    def _accepted():
        """页面是否出现『登录已在进行』的迹象。"""
        try:
            return bool(page.evaluate("""() => {
                if (!/unified-login/.test(location.href)) return true;   // 已跳转
                const t = document.body.innerText || '';
                // 验证码错误 / 登录中 / 已发送 等文案出现 → 说明请求已发出
                if (/验证码(错误|不正确|失效|已过期)|登录中|正在登录|操作频繁|请稍后/.test(t)) return true;
                for (const e of document.querySelectorAll('button')) {
                    if ((e.innerText||'').trim() === '立即登录' &&
                        (e.disabled || /loading|opacity-60/.test(e.className||''))) return true;
                }
                return false;
            }"""))
        except Exception:
            return False

    _click()
    for _ in range(12):                       # 最多约 3s
        page.wait_for_timeout(250)
        if _accepted():
            return True
    # 被协议前置校验拦截 → 补勾后重试一次
    _click_consent(page)
    page.wait_for_timeout(300)
    _click()
    for _ in range(16):
        page.wait_for_timeout(250)
        if _accepted():
            return True
    return False


def _consent_checked(page):
    """判断「我已阅读并同意…」是否已勾选。返回 True / False / None(未找到协议行)。

    新版 MiniMax 登录页（account.minimax.cn/unified-login）的勾选框是**自绘控件**：
        <div class="flex items-start gap-[6px]">
          <button type="button" class="mt-[2px] flex size-4 ...">
            <div class="size-[14px] rounded-full border-[1.5px] border-gray_200"></div>
          </button>
          <p>我已阅读并同意 服务条款 和 隐私政策，…</p>
        </div>
    未勾选 = `button > div` 是空心圆（class 含 `rounded-full` / `border-gray`）；
    勾选后该圆环消失（换成对勾图标或整块变成实心），`button > div` 置空或不再含 border。

    ⚠ 必须以 `<p>`（含协议文本的那个，且它没有嵌套子行）作锚点：
       用 `querySelectorAll('p,span,div')` 会先命中外层大容器（文本被 length 过滤后
       又落到别的含「同意」字样的行），导致判定漂移 —— 实测初始状态被误判为「已勾」。
    """
    try:
        return page.evaluate("""() => {
            const ps = document.querySelectorAll('p');
            for (const e of ps) {
                const t = (e.innerText || '').trim();
                if (!/我已阅读并同意|已阅读并同意/.test(t)) continue;
                const root = e.closest('.flex.items-start') || e.parentElement;
                if (!root) continue;
                const btn = root.querySelector('button');
                if (!btn) continue;
                const inner = btn.querySelector(':scope > div');
                // 空心圆环还在 → 未勾选
                if (inner && /rounded-full|border-/.test(inner.className || '')) return false;
                return true;    // 没有圆环 → 已勾选
            }
            return null;        // 页面没有协议行（部分批次不渲染）
        }""")
    except Exception:
        return None


def _click_consent(page):
    """勾选「我已阅读并同意…」。返回 True 表示调用后处于「已勾选」状态。

    ⚠ 这个勾选**是必须的**：MiniMax 登录页在未勾协议时点「立即登录」**不弹任何提示**、
    也不发起登录请求（前端前置校验静默 return）—— 表现为「按钮点了没反应」。
    旧实现只按 [role=checkbox]/[class*=agree|check|protocol]/label + 文本匹配，
    而真实控件是一个**无文本的自绘 button>div 圆环**，故永远匹配不到（恒返回 False）。

    新实现：以含『我已阅读并同意』的 <p> 为锚点 → 点它所在行的勾选 button；
    已勾选则幂等不重复点（避免点两次反而取消勾选）。
    """
    # 0) 已勾选 → 幂等返回（避免点两次取消勾选）
    if _consent_checked(page) is True:
        return True

    # 1) 主路径：点协议行内部的勾选 button（三次机会，覆盖渲染慢的批次）
    for _ in range(3):
        try:
            hit = page.evaluate("""() => {
                for (const e of document.querySelectorAll('p')) {
                    const t = (e.innerText || '').trim();
                    if (!/我已阅读并同意|已阅读并同意/.test(t)) continue;
                    const root = e.closest('.flex.items-start') || e.parentElement;
                    if (!root) continue;
                    const btn = root.querySelector('button')
                             || root.querySelector('[class*="size-"][class*="rounded"], [class*="rounded-full"]');
                    if (btn) { btn.click(); return true; }
                }
                return false;
            }""")
        except Exception:
            hit = False
        if hit:
            page.wait_for_timeout(350)
            if _consent_checked(page) is True:
                return True
        else:
            break

    # 2) 原生兜底：万一页面改回标准 checkbox
    try:
        for sel in ["input[type='checkbox']", "[role='checkbox']"]:
            for e in page.locator(sel).all():
                try:
                    if not e.is_checked():
                        e.check(timeout=1200)
                        page.wait_for_timeout(200)
                        if _consent_checked(page) is True:
                            return True
                except Exception:
                    try:
                        e.click(timeout=800)
                        page.wait_for_timeout(200)
                        if _consent_checked(page) is True:
                            return True
                    except Exception:
                        pass
    except Exception:
        pass

    return _consent_checked(page) is True


def start_sms_job(platform, phone, on_success, region="cn"):
    """手机号 + 短信验证码登录。返回 (ok, msg, job_view)。

    流程：申请设备码 → 拉起可见 Chromium 打开登录页 → 自动切「手机号登录」并填手机号
    → 自动点「获取验证码」→ 前端弹验证码输入框 → submit_code() 注入验证码并点登录
    → 自动点「授权」→ 轮询拿到正式令牌 → on_success 落盘 → 关浏览器。
    """
    phone = "".join(ch for ch in str(phone or "") if ch.isdigit())
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


def submit_code(jid, code):
    """前端把短信验证码交回后端，由浏览器线程注入并提交。"""
    code = "".join(ch for ch in str(code or "") if ch.isdigit()).strip()
    if not code:
        return False, "请填写短信验证码"
    with _job_lock:
        job = _JOBS.get(jid)
    if not job or job.get("mode") != "sms":
        return False, "登录任务不存在或已结束，请重新发起"
    if job.get("finished"):
        return False, "该登录任务已结束，请重新发起"
    job["code"] = code
    return True, "已收到验证码，正在提交…"


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
                # 滑块风控状态回传前端，好提示用户去窗口里拖一下
                if not job.get("code_submitted"):
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


def get_job(jid):
    with _job_lock:
        job = _JOBS.get(jid)
        # 顺手清理 10 分钟前的旧任务
        if len(_JOBS) > 50:
            for k, v in list(_JOBS.items()):
                if v.get("finished") and time.time() - v.get("started", 0) > 600:
                    _JOBS.pop(k, None)
    return _view(job) if job else None


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


# 窗口移出屏幕（用户无感），但环境指纹与有头一致——阿里云/腾讯/百度风控盯无头特征，
# 真 headless 会概率性被拦且弹滑块时无法人工兜底。滑块出现时用 _pull_window_front 拉回。
# CalculateNativeWinOcclusion 必须禁用：否则 Windows 把屏幕外窗口判为 occluded
# （visibilityState=hidden），部分登录 SDK 会暂停初始化。
_OFFSCREEN_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--window-position=-32000,-32000",
    "--disable-features=CalculateNativeWinOcclusion",
]


def _pull_window_front(ctx):
    """把（移到屏幕外的）浏览器窗口拉回屏幕中央——CDP Browser.setWindowBounds。

    触发时机：检测到滑块/图片验证码。平时全程不可见，出事时自动显形让人工拖一下。
    """
    try:
        pg = ctx.pages[0] if ctx.pages else None
        if not pg:
            return
        cdp = ctx.new_cdp_session(pg)
        win = cdp.send("Browser.getWindowForTarget")
        wid = win.get("windowId")
        if wid is None:
            return
        try:
            cdp.send("Browser.setWindowBounds",
                     {"windowId": wid, "bounds": {"windowState": "normal"}})
        except Exception:
            pass
        cdp.send("Browser.setWindowBounds",
                 {"windowId": wid, "bounds": {"left": 160, "top": 90}})
    except Exception:
        pass


def _qoder_has_captcha(ctx):
    """阿里云滑块 / 图片验证码是否出现（尽力而为，用于提示用户去窗口操作）。"""
    try:
        for pg in ctx.pages:
            try:
                if pg.evaluate(
                        "() => !!(document.querySelector('[id*=\\'captcha\\'],[class*=\\'captcha\\'],"
                        ".nc-container') || document.querySelector('iframe[src*=\\'captcha\\']'))"):
                    return True
            except Exception:
                pass
            for f in pg.frames:
                u = (f.url or "")
                if "captcha" in u or "punish" in u:
                    return True
    except Exception:
        pass
    return False


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


# ──────────── ZCode（z.ai）短信直登：cli/init 流 + 弹窗代点（2026-10-08 侦察实测 DOM）────────────
# zai（chat.z.ai/auth）：input[type=tel] 手机号 / input[placeholder*=验证码] /
#   「发送验证码」DIV /「登录」DIV，无协议复选框（文案即同意）。
# bigmodel（bigmodel.cn/login）：#tab-sms 默认激活 / input[placeholder*=手机号] /
#   「获取验证码」/「登录 / 注册」；发送时可能弹腾讯滑块（tcaptcha 容器常驻 DOM，
#   必须按尺寸判可见，否则每次都误判成弹了验证码）。
# 令牌走既有 cli_poll 轮询（device_poll → _cli_poll_once），与「打开授权网页」同源。

_ZCODE_PAGE_SEL = {
    "zai": {"phone": "input[type='tel']",
            "code": "input[placeholder*='验证码']",
            "send": ["发送验证码"], "login": ["登录"]},
    "bigmodel": {"phone": "input[placeholder*='手机号']",
                 "code": "input[placeholder*='验证码']",
                 "send": ["获取验证码"], "login": ["登录 / 注册", "登录"]},
}


def start_zcode_sms_job(phone, sub, on_success, name=""):
    """ZCode 手机号+短信直登入口（server.py sms_start 的 zcode 分支调用）。"""
    phone = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if len(phone) != 11:
        return False, "请填写 11 位手机号（当前：%s）" % (phone or "空"), None
    sub = sub if sub in _ZCODE_PAGE_SEL else "zai"
    ok, msg, flow = _cli_poll_start("zcode", sub)
    if not ok:
        return False, msg, None
    job = _new_job("zcode", flow)
    job.update(mode="sms", phone=phone, name=name or "")
    with _job_lock:
        _JOBS[job["job"]] = job
    threading.Thread(target=_run_zcode_sms_job,
                     args=(job, flow, phone, on_success), daemon=True).start()
    return True, "已发起 ZCode 短信登录", _view(job)


def _zcode_captcha_visible(ctx):
    """登录页滑块/图片验证码是否真的弹出。tcaptcha 容器常驻 DOM，须按尺寸/透明度判可见。"""
    js_vis = ("() => { const e = document.getElementById('tcaptcha_transform_dy')"
              " || document.querySelector('[id*=tcaptcha],[class*=tcaptcha]');"
              " if (!e) return false;"
              " const r = e.getBoundingClientRect();"
              " const st = getComputedStyle(e);"
              " return r.width > 120 && r.height > 60 && st.display !== 'none'"
              " && st.visibility !== 'hidden' && parseFloat(st.opacity || '1') > 0.1; }")
    try:
        for pg in ctx.pages:
            try:
                if pg.evaluate(js_vis):
                    return True
            except Exception:
                pass
            try:
                if pg.evaluate("() => !!document.querySelector("
                               "'[class*=geetest_panel], [class*=geetest_widget]')"):
                    return True
            except Exception:
                pass
            for f in pg.frames:
                u = (f.url or "")
                if ("captcha" in u or "geetest" in u or "punish" in u) \
                        and "bigmodel" not in u:
                    return True
    except Exception:
        pass
    return False


def _zcode_click_authorize(ctx):
    """Z.ai 授权页（chat.z.ai/auth/oauth/authorize）的最后一步：勾协议 + 点「继续」。

    2026-10-08 用户实测：验证码登录成功后跳到该页，必须先勾选「用户协议和隐私政策」
    复选框，再点【继续】，令牌才会下发。两个动作缺一不可，否则轮询永远 pending。

    注意：
      · 只在 URL 含 authorize/oauth/consent 的页面动作，避免误点登录表单页；
        但「oauth」过于宽泛（CLI 登录链路本身也走 /oauth/... 路径），因此改为要求
        同时命中「授权页特征」：路径含 authorize/consent，或主机属 chat.z.ai 且路径含 oauth；
      · 复选框可能是自定义元素（非原生 input），先试原生 check()，再 JS 兜底置 checked
        并派发 change/click 事件（很多前端框架靠事件监听刷新按钮可用态）；
      · 按钮点「继续」优先，其次「同意 / 授权 / 确认」。
    返回 True 表示本轮至少完成了一次「勾选 + 点击」。
    """
    def _is_authorize_page(u):
        ul = u.lower()
        if "authorize" in ul or "consent" in ul:
            return True
        # chat.z.ai 的授权页形如 /auth/oauth/authorize?...；单凭 "oauth" 不算，避免误伤
        return ("chat.z.ai" in ul and "/oauth/" in ul and "authorize" in ul)

    did = False
    for pg in ctx.pages:
        u = (pg.url or "")
        if not _is_authorize_page(u):
            continue
        for target in [pg] + [f for f in pg.frames if f is not pg.main_frame]:
            # ① 勾选协议复选框：先用原生 input[type=checkbox]
            try:
                cbs = target.locator("input[type='checkbox']")
                for i in range(min(cbs.count(), 4)):
                    cb = cbs.nth(i)
                    try:
                        if not cb.is_checked():
                            cb.check(timeout=1200)
                            did = True
                    except Exception:
                        try:
                            cb.click(timeout=1000)
                            did = True
                        except Exception:
                            pass
            except Exception:
                pass
            # ①b JS 兜底：自定义 checkbox / 被样式隐藏的原生框，强制勾选并派发事件
            try:
                target.evaluate(
                    "() => {"
                    " const boxes = Array.from(document.querySelectorAll("
                    "   'input[type=checkbox],[role=checkbox],[class*=checkbox],"
                    "   [class*=agree],[class*=consent],[class*=protocol]'));"
                    " for (const b of boxes) {"
                    "   const isInput = b.tagName === 'INPUT';"
                    "   const on = isInput ? b.checked : (b.getAttribute('aria-checked') === 'true');"
                    "   if (!on) {"
                    "     if (isInput) { b.checked = true; }"
                    "     else { b.setAttribute('aria-checked','true'); }"
                    "     b.dispatchEvent(new Event('input',  {bubbles:true}));"
                    "     b.dispatchEvent(new Event('change', {bubbles:true}));"
                    "     b.click && b.click();"
                    "   }"
                    " } }")
            except Exception:
                pass
            # ② 点「继续 / 同意 / 授权 / 确认」
            #    归一化匹配优先（去空白）：antd 等框架会把「继续」渲染成「继 续」，
            #    用 :has-text('继续') 会失配（2026-10-08 Qoder 同款坑）。
            try:
                el = target.evaluate_handle(
                    "(targets) => {"
                    " const norm = s => (s || '').replace(/\\s+/g, '').replace(/\\u3000/g, '');"
                    " const els = Array.from(document.querySelectorAll('button,a,[role=button]'));"
                    " for (const t of targets) {"
                    "   const hit = els.find(e => norm(e.innerText) === t || norm(e.textContent) === t);"
                    "   if (hit) return hit;"
                    " }"
                    " return null;"
                    "}",
                    ["继续", "同意并继续", "同意授权", "同意", "授权", "确认", "Authorize", "Continue"])
                jsd = el.as_element() if el else None
                if jsd:
                    try:
                        jsd.click(timeout=900)
                        did = True
                    except Exception:
                        try:
                            jsd.evaluate("e => e.click()")
                            did = True
                        except Exception:
                            pass
            except Exception:
                pass
            if did:
                return True
            for txt in ("继续", "同意并继续", "同意授权", "同意", "授权", "确认", "Authorize", "Continue"):
                for sel in ("button", "a", "[role=button]"):
                    try:
                        loc = target.locator("%s:has-text('%s')" % (sel, txt))
                        if loc.count():
                            loc.first.click(timeout=900)
                            did = True
                            break
                    except Exception:
                        continue
                if did:
                    break
            if did:
                return True
    return False


def _run_zcode_sms_job(job, flow, phone, on_success):
    try:
        from playwright.sync_api import sync_playwright  # 延迟导入
    except Exception:
        job.update(status="done", finished=True, ok=False,
                   result="缺少 playwright，无法拉起登录窗口。请 pip install playwright")
        return

    sub = flow.get("sub") if flow.get("sub") in _ZCODE_PAGE_SEL else "zai"
    sel = _ZCODE_PAGE_SEL[sub]
    deadline = time.time() + flow["expires_in"] + 150
    interval = 2.0
    browser = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False, args=_OFFSCREEN_ARGS)
            ctx = browser.new_context(locale="zh-CN",
                                      viewport={"width": 560, "height": 840})
            page = ctx.new_page()
            job["status"] = "opening"
            job["result"] = "已打开登录窗口，正在进入 %s 登录页…" % (
                "Z.ai" if sub == "zai" else "智谱 BigModel")
            page.goto(flow["verify_url"], wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(1500)

            # ① 填手机号（bigmodel 短信 tab 默认激活；保险起见未激活就点一下）
            form_ok = True
            try:
                t = page.locator("#tab-sms")
                if t.count() and "is-active" not in (t.get_attribute("class") or ""):
                    t.click(timeout=2000)
                    page.wait_for_timeout(600)
            except Exception:
                pass
            try:
                page.wait_for_selector(sel["phone"], state="visible", timeout=10000)
                page.fill(sel["phone"], phone, timeout=5000)
            except Exception:
                form_ok = False
                job["result"] = ("没找到手机号输入框（页面可能改版），已把窗口拉回屏幕；"
                                 "请在窗口里手动完成登录，看板会继续自动接管令牌")
                _pull_window_front(ctx)
                job.update(sms_sent=True, need_code=False)

            if form_ok:
                job["result"] = "手机号已填入，正在点「%s」…" % sel["send"][0]
                # ② 点发送验证码（弹滑块时把窗口拉回让人工完成）
                if not _click_text(page, sel["send"], timeout=3500):
                    job["result"] = ("没点动「%s」，请在窗口里手动点一下发送。"
                                     % sel["send"][0])
                    _pull_window_front(ctx)
                page.wait_for_timeout(1200)
                cap = (_zcode_captcha_visible(ctx) or _qoder_has_captcha(ctx))
                if cap:
                    _pull_window_front(ctx)
                job.update(status="waiting_code", sms_sent=True, need_code=True,
                           captcha=cap,
                           result=("窗口弹出了滑块/图片验证码，请先在窗口里完成，短信才会发出。"
                                   if cap else
                                   "验证码已发送 📩 请在下方填入短信验证码"
                                   "（若没收到，看看窗口是否弹了验证码）"))

            # ③ 主循环：等验证码 → 提交 → 轮询令牌（cli_poll 与「打开授权网页」共用）
            last_poll = 0.0
            while time.time() < deadline:
                now = time.time()
                if form_ok and job.get("code") and not job.get("code_submitted"):
                    try:
                        page.fill(sel["code"], str(job["code"]), timeout=4000)
                        page.wait_for_timeout(300)
                        if _click_text(page, sel["login"], timeout=2500):
                            job["code_submitted"] = True
                            job["need_code"] = False
                            job["result"] = "已提交验证码，正在登录…"
                    except Exception:
                        pass  # 表单可能已随登录跳转销毁，交给轮询
                if form_ok and job.get("code_submitted"):
                    cap2 = _zcode_captcha_visible(ctx)
                    if cap2 and not job.get("captcha"):
                        _pull_window_front(ctx)
                        job["result"] = "登录时弹出滑块/图片验证码，请先在窗口里完成…"
                    job["captcha"] = cap2
                    # ④ 登录成功后 Z.ai 会跳到授权页（chat.z.ai/auth/oauth/authorize）：
                    #    必须【勾选「用户协议和隐私政策」复选框】再点【继续】才会下发令牌，
                    #    否则页面一直停着、轮询永远 pending —— 2026-10-08 用户实测。
                    #    该页在 chat.z.ai 域；登录表单所在的 zcode.z.ai 页不含此步，因此
                    #    仅在「当前 URL 含 authorize/oauth/consent」时才动作，避免误点登录页。
                    if _zcode_click_authorize(ctx) and not job.get("auth_clicked"):
                        job["auth_clicked"] = True
                        job["result"] = "已勾选协议并点「继续」，等待令牌下发…"
                    elif job.get("auth_clicked"):
                        job["result"] = "已点「继续」，等待令牌下发…"
                if now - last_poll >= interval:
                    last_poll = now
                    state, d = device_poll(flow)
                    if state == "ok":
                        grant = {
                            "access_token": str(d.get("access_token") or ""),
                            "refresh_token": str(d.get("refresh_token") or ""),
                            "token_type": str(d.get("token_type") or "Bearer"),
                            "expires_in": d.get("expires_in"),
                            "scope": "",
                            "zai": d.get("zai") or {},
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
                    # error（偶发网络/未完成）不中断，继续轮询
                page.wait_for_timeout(700)

            if not job.get("finished"):
                job.update(status="done", finished=True, ok=False,
                           result="登录超时，请重新发起（登录链接已过期）")
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


# ═════════ Trae / CodeArts / OfficeACE 手机号短信直登（2026-10-08 协议逆向落地）═══════════
# 来源（先看再写，全部实测/实扫）：
# · Trae     ：客户端 main.js 逆向（loginUrlBuilder/vTe/exchangeTokenByAuthCode/OAuthLocalServer）
#              + 本机 storage.json + Trae CN 真实运行日志（成功兑换样本）。
#              授权页 www.trae.cn/authorization、回调端口 **随机 listen(0)**、
#              设备身份 icube-dc 密钥（按线路取：IDE→Trae CN / SOLO→TRAE SOLO CN）、
#              plugin_version=buildVersion(2.3.87416)、x_app_version=appVersion(3.3.104)。
# · CodeArts ：逆向 huaweicloud.authentication/dist/plugin.js v5.4.2：
#              portal/authorize?...&port=&code_challenge(S256)&ticket_id → authui 登录 →
#              302 回 http://127.0.0.1:<port>/oauth/callback?code=..&secret=.. →
#              POST sts /v1/oauth2/tokens（form + DPoP: ES256 dpop+jwt）→ credentials。
#              **自建会话的 refresh_token 归看板独享，刷新不踢客户端 → 修 1h 过期**。
# · OfficeACE：驱动桌面端本地 API（127.0.0.1:3004 自签名 HTTPS）：
#              POST /api/login/authorize → authorizeUrl(华为云 authui) → 登录成功后
#              页面要跳 officeclaw://oauth/callback?code&state（Playwright 捕获不到该
#              scheme 导航，实测）→ 改用 CDP Network 层在 **https 302 的 Location 头 /
#              XHR 响应体**里先拿 code，再 POST /api/login/callback 让 App 自己交换落盘。
# 华为云 authui 登录页（CodeArts/OfficeACE 共用，2026-10-08 实测 DOM，无 iframe）：
#   手机号 tab 默认选中；手机号 input[name="username"]（placeholder 手机号）；
#   验证码 input[placeholder*=验证码]；「获取验证码」.hwid-getAuthCode-input；
#   「登录/注册」.hwid-input-msgcode。
# ⚠⚠ 2026-10-08 实测（决定性）：`input[name="username"]` **命中 2 个**——
#   · [0] 隐藏模板位（rect=[0,0,0,0]、无 placeholder）← 密码登录 tab 的残留/模板
#   · [1] 真实可见位（rect=[138,357,308,38]、placeholder="手机号"）
#   → `loc.first` 拿到的是**隐藏**那个 → `_hw_stage()` 恒 False；
#   → `page.fill(sel, …)` 严格模式直接抛 "locator resolved to 2 elements"。
#   这就是「没找到华为云手机号输入框（页面可能改版）」的真因（不是改版，是多重命中）。
#   **铁律：华为云 authui 一律用「按 placeholder 定位 + 只取可见元素」的 JS 解析**，
#   绝不用裸 CSS 选择器 + .first / page.fill。

import http.server
import re

_HW_PHONE_SEL = 'input[name="username"]'          # 仅作兜底/文档
_HW_CODE_SEL = 'input[placeholder*="验证码"]'
_HW_SEND_TEXTS = ["获取验证码"]
_HW_LOGIN_TEXTS = ["登录/注册", "登录"]

# 按 placeholder 找「唯一可见」的华为云输入框，返回 DOM 元素（JS 侧过滤可见性）
_HW_INPUT_JS = """(phLike) => {
  const norm = s => (s || '').replace(/\\s+/g, '');
  const vis = e => { const r = e.getBoundingClientRect();
    const st = getComputedStyle(e);
    return r.width > 2 && r.height > 2 && st.visibility !== 'hidden'
           && st.display !== 'none' && !e.disabled && !e.readOnly; };
  const all = Array.from(document.querySelectorAll('input'));
  const hit = all.filter(e => vis(e) && norm(e.placeholder).indexOf(phLike) >= 0);
  return hit.length ? hit[hit.length - 1] : null;   // 多个可见时取最后一个（真实表单通常在后）
}"""


def _hw_visible_input(page, ph_like):
    """华为云 authui：返回唯一可见输入框的 ElementHandle（按 placeholder 子串）。"""
    try:
        h = page.evaluate_handle(_HW_INPUT_JS, ph_like)
        el = h.as_element() if h else None
        return el
    except Exception:
        return None


def _hw_fill_phone(page, phone):
    """填手机号（可见位）。返回 True/False。"""
    el = _hw_visible_input(page, "手机号")
    if el is None:
        return False
    try:
        el.click(timeout=1500)
        el.fill("")
        el.type(str(phone), delay=35)
        return True
    except Exception:
        try:
            el.evaluate("(e, v) => { e.focus(); e.value = v;"
                        " e.dispatchEvent(new Event('input', {bubbles:true}));"
                        " e.dispatchEvent(new Event('change', {bubbles:true})); }", str(phone))
            return True
        except Exception:
            return False


def _hw_stage(page):
    """当前页是否已是华为云 authui 登录页（手机号输入框**可见**）。"""
    return _hw_visible_input(page, "手机号") is not None


def _hw_click_visible(page, ph_or_text, cls_hint=""):
    """华为云 authui：点「可见」的 div 按钮。返回 True 表示点击已被页面接受。

    ⚠⚠ 2026-10-08 实测（决定性，勿回退）：
      旧实现按 `norm(innerText) === norm(txt)` 命中 **5 个元素**（祖孙容器 innerText 完全相同），
      再按 innerText 长度排序取 hit[0] —— 但 5 个命中里除了最外层 400×40 大容器外，
      `.hwid-getAuthCode` / `.button-base-box` / `.textBtn` 文本完全一致，排序**不稳定**，
      实测点到的是**不接收点击的容器** → 页面无任何反应，且 `el.click()` 不抛异常
      → **旧实现返回 True = 假成功**（job 谎报「验证码已发送」但 getHwidSMSCode 根本没发出）。
      对照铁证：`page.click('.hwid-getAuthCode')`（69×15 内层）→ 立即发出
      `POST id1.cloud.huawei.com/.../getHwidSMSCode`，页面变「重新获取(57)／短信验证码已经发送至…」。

    策略：① cls_hint 精确 CSS 选择器（取**可见**命中，多个时取**最深/最小**元素）
          ② 文本归一化匹配，同样取**最深**（无可见子元素者）而非任意 hits[0]
          ③ Playwright 原生 click（真实鼠标事件），失败再退回 JS `el.click()`
    """
    import re as _re
    el = None
    # ① 精确 class 选择器（cls_hint 支持空格分隔多候选）
    if cls_hint:
        for sel in [s for s in _re.split(r"[,\s]+", cls_hint) if s]:
            try:
                el = page.evaluate_handle(_HW_PICK_JS, ["." + sel, None]).as_element()
            except Exception:
                el = None
            if el is not None:
                break
    # ② 文本归一化匹配
    if el is None and ph_or_text:
        try:
            el = page.evaluate_handle(_HW_PICK_JS, [None, ph_or_text]).as_element()
        except Exception:
            el = None
    if el is None:
        return False
    for how in ("pw", "js"):
        try:
            if how == "pw":
                el.click(timeout=2000)
            else:
                el.evaluate("e => e.click()")
            return True
        except Exception:
            continue
    return False


# 取「可见且最深（无可见子节点）」的元素：cls 精确 or 文本归一化相等
_HW_PICK_JS = """(args) => {
  const sel = args[0], txt = args[1];
  const norm = s => (s || '').replace(/\\s+/g, '').replace(/\\u3000/g, '');
  const vis = e => { const r = e.getBoundingClientRect();
    const st = getComputedStyle(e);
    return r.width > 2 && r.height > 2 && st.visibility !== 'hidden'
           && st.display !== 'none' && st.pointerEvents !== 'none'; };
  let cands = [];
  if (sel) {
    cands = Array.from(document.querySelectorAll(sel)).filter(vis);
  } else if (txt) {
    const els = Array.from(document.querySelectorAll('div,button,a,[role=button],span'));
    cands = els.filter(e => vis(e) && norm(e.innerText) === norm(txt));
    // 只保留「最内层」：其可见后代中不含同样文本的兄弟节点
    cands = cands.filter(e => !Array.from(e.children).some(c =>
      vis(c) && norm(c.innerText) === norm(txt)));
  }
  if (!cands.length) return null;
  // 取面积最小者（=最内层可点控件，而非外层大容器）
  cands.sort((a, b) => {
    const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
    return (ra.width * ra.height) - (rb.width * rb.height);
  });
  return cands[0];
}"""


def _hw_sms_sent(page):
    """authui 页：判「验证码是否真的发出去了」——按钮文本变「重新获取(NN)」或出现「已经发送」文案。

    ⚠ 不能靠 `_hw_click_visible` 的返回值（click 不抛异常≠前端接受了），必须以页面状态为准。
    """
    try:
        return bool(page.evaluate("""() => {
            const t = (document.body.innerText || '');
            if (/重新获取|重新发送|秒后重新|已经发送|已发送至/.test(t)) return true;
            return false;
        }"""))
    except Exception:
        return False


def _hw_fill_and_send(page, ctx, job, phone):
    """authui 页：填手机号 → 点获取验证码。返回 False=表单没找到（转手动）。"""
    if not _hw_stage(page):
        return False
    if not _hw_fill_phone(page, phone):
        return False
    # 点「获取验证码」：cls 精确 → 文本匹配；点后**校验页面状态**，未发出则重试
    ok = False
    for attempt in range(3):
        _hw_click_visible(page, "获取验证码", "hwid-getAuthCode")
        page.wait_for_timeout(900)
        if _hw_sms_sent(page):
            ok = True
            break
        page.wait_for_timeout(500)
    if not ok:
        ok_click = _click_text(page, _HW_SEND_TEXTS, timeout=3500)
        page.wait_for_timeout(1200)
        ok = _hw_sms_sent(page)
    if not ok:
        job["result"] = "手机号已填入，但没点动「获取验证码」——已把窗口拉回屏幕，请手动点一下。"
        _pull_window_front(ctx)
        job.update(sms_sent=False, need_code=False)
        return True
    cap = _qoder_has_captcha(ctx)
    if cap:
        _pull_window_front(ctx)
    job.update(status="waiting_code", sms_sent=True, need_code=True, captcha=cap,
               result=("登录窗口弹出了滑块/图片验证码，请先在窗口里完成，短信才会发出。"
                       if cap else
                       "验证码已发送 📩 请在下方填入短信验证码"
                       "（若没收到，看看窗口是否弹了滑块）"))
    return True


def _hw_submit_code(page, ctx, job, code):
    """authui 页：填验证码 → 点登录/注册。"""
    el = _hw_visible_input(page, "验证码")
    if el is None:
        try:
            page.fill(_HW_CODE_SEL, str(code), timeout=5000)
        except Exception:
            return False
    else:
        try:
            el.click(timeout=1500)
            el.fill("")
            el.type(str(code), delay=35)
        except Exception:
            try:
                el.evaluate("(e, v) => { e.focus(); e.value = v;"
                            " e.dispatchEvent(new Event('input', {bubbles:true}));"
                            " e.dispatchEvent(new Event('change', {bubbles:true})); }", str(code))
            except Exception:
                return False
    page.wait_for_timeout(300)
    # ⚠⚠ 2026-10-09 无头 recon 实测（authui 线上 DOM，勿回退）：
    #   「登录/注册」= div.hwid-btn.hwid-btn-primary（外层 .hwid-input-msgcode /
    #   .hwid-reg-btn / .button-base-box 同文本不同层），且按钮带 **hwid-disabled**
    #   禁用态 —— Vue 表单校验未通过时点击被**静默忽略**（14:46 实拍：验证码已填、
    #   按钮没点动、15s 后人工点同一按钮立即通过）。所以：①先等按钮脱 disabled
    #   ②点最内层真实按钮 ③点后**校验页面状态变化**，未变则重试（最多 3 轮）。
    _BTN_JS = """() => {
      const norm = s => (s||'').replace(/\\s+/g,'');
      const vis = e => { const r = e.getBoundingClientRect();
        return r.width>2 && r.height>2; };
      let btn = null, ba = 1e9;
      // ⚠ 只查内层真实按钮：hwid-disabled 只挂在 div.hwid-btn 上，
      //   外层 .hwid-reg-btn/.normalBtn/.hwid-input-msgcode 永远没有该类（recon 实证）
      for (const e of document.querySelectorAll('div.hwid-btn,button')) {
        if (!vis(e) || norm(e.innerText||'') !== '登录/注册') continue;
        const r = e.getBoundingClientRect();
        if (r.width*r.height < ba) { ba = r.width*r.height; btn = e; }
      }
      if (!btn) return {found: false};
      return {found: true,
              disabled: /(^|\\s)hwid-disabled(\\s|$)/.test(btn.className||''),
              cls: (btn.className||'').slice(0,90)};
    }"""
    st_info = {}
    for _ in range(10):                      # ① 等按钮脱 disabled（≤5s）
        try:
            st_info = page.evaluate(_BTN_JS) or {}
        except Exception:
            st_info = {}
        if not st_info.get("found") or not st_info.get("disabled"):
            break
        page.wait_for_timeout(500)
    _codearts_debug("submit", "按钮状态: %s" % str(st_info)[:130])
    accepted = False
    for _round in range(3):
        # ② 首选 Playwright 原生 click（可信输入事件，等价真人）点**内层真实按钮**
        #    （cls_hint='hwid-btn' → _HW_PICK_JS 精确命中 div.hwid-btn，非外层容器）
        if not _hw_click_visible(page, "登录/注册", "hwid-btn"):
            _click_text(page, _HW_LOGIN_TEXTS, timeout=2000)
        # ③ 校验：3s 内 URL 跳走 / 按钮消失 = 页面已接受
        for _ in range(6):
            page.wait_for_timeout(500)
            try:
                u2 = page.url or ""
            except Exception:
                u2 = ""
            if u2 and "/authui/login.html" not in u2:
                accepted = True
                break
            try:
                if not (page.evaluate(_BTN_JS) or {}).get("found"):
                    accepted = True
                    break
            except Exception:
                pass
        if accepted:
            break
        # ④ 兜底：验证码框上回车提交（部分表单支持 Enter 直提）
        try:
            el2 = _hw_visible_input(page, "验证码")
            if el2 is not None:
                el2.press("Enter", timeout=1500)
        except Exception:
            pass
        for _ in range(4):
            page.wait_for_timeout(500)
            try:
                u2 = page.url or ""
            except Exception:
                u2 = ""
            if u2 and "/authui/login.html" not in u2:
                accepted = True
                break
        if accepted:
            break
    _codearts_debug("submit", "click accepted=%s url=%s"
                    % (accepted, (page.url or "")[:110]))
    job["code_submitted"] = True
    job["need_code"] = False
    job["result"] = ("已提交验证码，正在登录…"
                     if accepted else
                     "已填验证码并尝试点击「登录/注册」，但页面暂无响应，如 15 秒后仍停留请手动点一下。")
    return True


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


def _trae_find_token(node, keys):
    """在响应里找 token 字符串（**大小写不敏感**）。

    ⚠⚠ 2026-10-08 实地取证（真凶 #2）：客户端成功响应的字段名是 **`Token`**（首字母大写）
      {"Result":{"BoundDeviceID":"616l754j8orle1","ClientID":"ono9krqynydwx5",
                 "DeviceBindStatus":"BOUND","RefreshExpireAt":…,"RefreshToken":"…",
                 "Token":"…","TokenExpireAt":…,"TokenExpireDuration":…,"UserJwt":"…"}}
    旧实现 `node.get(k)` 是**精确 key 匹配（大小写敏感）**，key 表里只有小写 `"token"`
    → **找不到 `Token`** → 误判「无 token」→ 把成功响应当错误抛给用户。
    """
    want = set(str(k).lower() for k in keys)
    if isinstance(node, dict):
        # ① 同层大小写不敏感匹配（先精确后忽略大小写，避免误取嵌套值）
        for k, v in node.items():
            if isinstance(v, str) and v and str(k).lower() in want:
                return v
        # ② 再递归子层
        for v in node.values():
            r = _trae_find_token(v, keys)
            if r:
                return r
    elif isinstance(node, list):
        for it in node:
            r = _trae_find_token(it, keys)
            if r:
                return r
    return None


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
    phone = "".join(ch for ch in str(phone or "") if ch.isdigit())
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


# ────────────────────────────── CodeArts ──────────────────────────────
_CODEARTS_PORTAL = "https://codearts.huaweicloud.com/portal"
_CODEARTS_STS = "https://sts.cn-north-4.myhuaweicloud.com"
_CODEARTS_CLIENT_ID = "codearts-agent"     # = product.json urlProtocol（= env.uriScheme）
_CODEARTS_PLUGIN = "snap_AIIDE"
_CODEARTS_PLUGIN_VER = "5.4.2"             # huaweicloud.authentication/package.json
_CODEARTS_SNAP = "https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager"

# 授权确认页代点文案（归一化匹配，命中最内层；「取消/拒绝/不同意」等否定项靠**全等**匹配天然排除）
_CODEARTS_CONSENT_TEXTS = ["同意并授权", "授权并登录", "授权并继续", "同意授权", "一键授权",
                           "授权", "同意", "允许", "继续", "确认"]

_CODEARTS_DEBUG_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "codearts_oauth_debug.log")


def _codearts_debug(tag, msg):
    """CodeArts OAuth 关键事件落盘。控制台 stdout 随窗口丢失，文件不会——
    授权后拿不到令牌时（如 2026-10-09 卡「已提交验证码」），这是唯一能回放的证据。"""
    try:
        with open(_CODEARTS_DEBUG_LOG, "a", encoding="utf-8") as fh:
            fh.write("%s [%s] %s\n" % (time.strftime("%m-%d %H:%M:%S"), tag,
                                       str(msg)[:400].replace("\n", " ")))
    except Exception:
        pass


def _codearts_stage(url, port):
    """按 URL 分类当前阶段：callback（回调） / login（authui 登录页） / portal（授权确认） / other。"""
    u = url or ""
    if ("127.0.0.1:%d" % port) in u and "/oauth/callback" in u:
        return "callback"
    if "authui" in u or "auth.huaweicloud.com" in u or "login.huaweicloud" in u:
        return "login"
    if "codearts.huaweicloud.com" in u or "/portal" in u:
        return "portal"
    return "other"


def _codearts_click_consent(page):
    """portal 授权确认页：代点「同意/授权/继续」。返回 "clicked" / "none"。

    ⚠ 页面若有未勾选的协议 checkbox（`input[type=checkbox]`），先勾再点——
    未勾协议时点「授权」很可能被前端静默 return（MiniMax/Trae 同款坑）。"""
    try:
        n = page.evaluate("""() => {
            const vis = c => { const r = c.getBoundingClientRect();
                return r.width > 2 && r.height > 2 && !c.disabled; };
            let n = 0;
            for (const c of Array.from(document.querySelectorAll('input[type=checkbox]'))) {
                if (vis(c) && !c.checked) { c.click(); n++; }
            }
            return n;
        }""")
        if n:
            _codearts_debug("consent", "勾选了 %d 个协议 checkbox" % n)
            page.wait_for_timeout(300)
    except Exception:
        pass
    for t in _CODEARTS_CONSENT_TEXTS:
        if _hw_click_visible(page, t):
            _codearts_debug("consent", "已点「%s」" % t)
            return "clicked"
    # 兜底前先做廉价预检：页面确实存在其中一个文案才走 get_by_text（10 个文案 ×
    # timeout 的逐个尝试最坏 ~24s，会把 700ms 节奏的主循环拖死）
    has_txt = False
    try:
        has_txt = bool(page.evaluate("""(ts) => {
            const norm = s => (s || '').replace(/\\s+/g, '');
            const body = norm(document.body.innerText);
            return ts.some(t => body.includes(norm(t)));
        }""", _CODEARTS_CONSENT_TEXTS))
    except Exception:
        pass
    if has_txt and _click_text(page, _CODEARTS_CONSENT_TEXTS, timeout=600):
        _codearts_debug("consent", "已点（get_by_text 兜底）")
        return "clicked"
    return "none"


def _codearts_extract_code(loc, port):
    """从回调 URL（或 302 Location）提取授权码。非本回调端口的 URL 一律不收。"""
    try:
        sp = urllib.parse.urlsplit(loc or "")
        if sp.port != port or not sp.path.endswith("/oauth/callback"):
            return ""
        return dict(urllib.parse.parse_qsl(sp.query, keep_blank_values=True)).get("code", "") or ""
    except Exception:
        return ""


def _codearts_pkce():
    verifier = secrets.token_hex(32)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _codearts_dpop_keypair():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode("ascii")
    pub = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
    jwk = {"kty": "EC", "crv": "P-256",
           "x": b64u(pub[1:33]), "y": b64u(pub[33:65])}
    return {"priv": priv, "priv_pem": priv_pem, "jwk": jwk}


def _codearts_dpop(dpop, htm, htu):
    """DPoP proof：ES256 P-256，protected {alg,typ:dpop+jwt,jwk}，payload {htm,htu,iat,jti}。"""
    b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
    header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": dpop["jwk"]}
    payload = {"htm": htm, "htu": htu,
               "iat": int(time.time()), "jti": secrets.token_hex(32)}
    si = (b64u(json.dumps(header, separators=(",", ":")).encode("ascii")) + "." +
          b64u(json.dumps(payload, separators=(",", ":")).encode("ascii")))
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    der = dpop["priv"].sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return si + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _codearts_token(form, dpop):
    url = _CODEARTS_STS + "/v1/oauth2/tokens"
    hdr = {"Content-Type": "application/x-www-form-urlencoded",
           "DPoP": _codearts_dpop(dpop, "POST", url)}
    r = requests.post(url, data=urllib.parse.urlencode(form), headers=hdr, timeout=25)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"raw": r.text[:200]}


def _codearts_extract_credentials(j):
    """token/ticket 响应 → (ak, sk, sts_token, expires_at_iso)。
    credentials 包裹优先；⚠ ticket 接口（OldLogin）用**单数 credential**（2026-10-09 实测）。"""
    cred = None
    if isinstance(j, dict):
        for k in ("credentials", "credential"):
            if isinstance(j.get(k), dict):
                cred = j[k]
                break
    if not isinstance(cred, dict):
        cred = j if isinstance(j, dict) else {}

    def g(*keys):
        for src in (cred, j if isinstance(j, dict) else {}):
            for k in keys:
                v = src.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
        return ""
    ak = g("access_key", "accessKey", "access", "ak", "AK")
    sk = g("secret_key", "secretKey", "secret", "sk", "SK")
    sts = g("security_token", "securityToken", "securitytoken", "sts_token")
    exp = g("expires_at", "expiresAt")
    if not exp:
        ein = cred.get("expires_in") or (j or {}).get("expires_in")
        try:
            exp = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                time.gmtime(time.time() + float(ein)))
        except (TypeError, ValueError):
            exp = ""
    return ak, sk, sts, exp


class _CodeArtsCBHandler(http.server.BaseHTTPRequestHandler):
    """照抄客户端回调服务器（plugin.js 实证 2026-10-09）：
    ① ?code=..  → NewIamLogin：记 code → 307 portal/login?login_succeed=true
    ② ?secret=..&redirect=.. → OldLogin：记 secret → 307 到 redirect（portal 登录成功页），
      随后用 GET snap-manager/v1/login/ticket?ticket_id=&secret= 换凭据（含 refresh_token）。"""
    result = {}

    def do_GET(self):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query,
                                        keep_blank_values=True))
        try:
            _codearts_debug("cb", "回调 %s | referer=%s"
                            % (self.path[:230],
                               (self.headers.get("Referer") or "")[:110]))
        except Exception:
            pass        # ① NewIamLogin：授权码直换
        if q.get("code"):
            _CodeArtsCBHandler.result["code"] = q.get("code", "")
            loc = ("%s/login?login_succeed=true&uri_scheme=%s&locale=zh-cn"
                   % (_CODEARTS_PORTAL, _CODEARTS_CLIENT_ID))
        # ② OldLogin：portal 只回 secret+redirect，换凭据走 snap-manager ticket 接口
        elif q.get("secret") and q.get("redirect"):
            _CodeArtsCBHandler.result["secret"] = q.get("secret", "")
            rid = dict(urllib.parse.parse_qsl(
                urllib.parse.urlsplit(q["redirect"]).query,
                keep_blank_values=True)).get("ticket_id", "")
            if rid:
                _CodeArtsCBHandler.result["ticket_id"] = rid
            _codearts_debug("oldlogin", "收到 secret（len=%d）ticket_id=%s"
                            % (len(q.get("secret", "")), rid[:34]))
            loc = q["redirect"]          # 与客户端一致：307 回 portal 成功页
        else:
            loc = ("%s/login?login_succeed=false&uri_scheme=%s&locale=zh-cn"
                   % (_CODEARTS_PORTAL, _CODEARTS_CLIENT_ID))
        self.send_response(307)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def start_codearts_sms_job(phone, name, on_success):
    """CodeArts 手机号+短信直登（自建 OAuth 会话，refresh_token 归看板独享）。"""
    phone = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if len(phone) != 11:
        return False, "请填写 11 位手机号（当前：%s）" % (phone or "空"), None
    flow = {"user_code": "", "verify_url": "", "expires_in": 600,
            "interval": 2, "platform": "codearts", "sub": None}
    job = _new_job("codearts", flow)
    job.update(mode="sms", phone=phone, name=name or "",
               hint="自建会话登录，之后看板可自动续期（不再依赖客户端）")
    with _job_lock:
        _JOBS[job["job"]] = job
    threading.Thread(target=_run_codearts_sms_job,
                     args=(job, phone, name, on_success), daemon=True).start()
    return True, "已发起 CodeArts 短信登录", _view(job)


def _run_codearts_sms_job(job, phone, name, on_success):
    verifier, challenge = _codearts_pkce()
    dpop = _codearts_dpop_keypair()
    ticket_id = secrets.token_hex(16)
    # 端口选择照抄客户端：随机端口，<10000 就重试（10000~65535）
    srv = None
    port = 0
    for _ in range(6):
        try:
            s = http.server.HTTPServer(("127.0.0.1", 0), _CodeArtsCBHandler)
            p_ = s.server_address[1]
            if p_ >= 10000:
                srv, port = s, p_
                break
            s.close()
        except OSError:
            continue
    if srv is None:
        try:
            srv = http.server.HTTPServer(("127.0.0.1", 0), _CodeArtsCBHandler)
            port = srv.server_address[1]
        except OSError as e:
            job.update(status="done", finished=True, ok=False,
                       result="本地回调端口分配失败：%s" % str(e)[:80])
            return
    result = _CodeArtsCBHandler.result = {}
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    auth_url = ("%s/authorize?theme=2&locale=zh-cn&uri_scheme=%s&client_id=%s"
                "&port=%d&code_challenge=%s&code_challenge_method=S256"
                "&ticket_id=%s&plugin-name=%s&plugin-version=%s"
                % (_CODEARTS_PORTAL, _CODEARTS_CLIENT_ID, _CODEARTS_CLIENT_ID,
                   port, challenge, ticket_id, _CODEARTS_PLUGIN, _CODEARTS_PLUGIN_VER))

    browser = None
    ok_saved = False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False, args=_OFFSCREEN_ARGS)
            ctx = browser.new_context(locale="zh-CN",
                                      viewport={"width": 520, "height": 800})
            page = ctx.new_page()
            job["status"] = "opening"
            job["result"] = "已打开华为云登录窗口，正在进入手机号登录…"
            page.goto(auth_url, wait_until="domcontentloaded", timeout=60000)
            _codearts_debug("open", "窗口已打开，当前 url=%s" % (page.url or "")[:150])
            # portal/authorize 会 302 到 authui/login.html?service=…，等表单出现
            # 注意：authui 是 Angular 渲染，先出 tab 再出 input（实测 t≈2s input 才 2 个），
            # 故轮询要够久（25×800ms=20s）。
            form_ok = False
            for _ in range(28):
                if _hw_stage(page):
                    form_ok = True
                    break
                page.wait_for_timeout(800)
            if form_ok:
                page.wait_for_timeout(700)
                # 填表偶发失败（Angular 重渲染）→ 重试 3 次
                filled = False
                for attempt in range(3):
                    if _hw_fill_and_send(page, ctx, job, phone):
                        filled = True
                        break
                    page.wait_for_timeout(900)
                if not filled:
                    _pull_window_front(ctx)
                    job["result"] = ("手机号输入框找到了但自动填报失败，已把窗口拉回屏幕；"
                                     "请手动完成登录，看板自动接回调。")
            else:
                _pull_window_front(ctx)
                job["result"] = "没等到华为云登录页，请在窗口里手动完成登录。"
                job.update(sms_sent=True, need_code=False)
            _codearts_debug("form", "form_ok=%s url=%s" % (form_ok, (page.url or "")[:150]))

            deadline = time.time() + 620
            _codearts_debug("open", "开始轮询回调 port=%d" % port)
            # 网络层兜底：302 Location / 回调响应即使页面导航卡住也能拿到 code
            # （参照 OfficeAce 取证：Playwright 对导航类事件的捕获不可全信，双保险）
            net_locs = []

            def _on_response(resp):
                try:
                    u = resp.url or ""
                    sc = resp.status
                    if 300 <= sc < 400:
                        loc = (resp.headers or {}).get("location", "") or ""
                        if loc and ("code=" in loc or "/oauth/callback" in loc):
                            net_locs.append(loc)
                            _codearts_debug("net3xx", "HTTP %s %s -> %s" % (sc, u[:110], loc[:180]))
                    elif "/oauth/callback" in u and "code=" in u:
                        net_locs.append(u)
                        _codearts_debug("netCb", "HTTP %s %s" % (sc, u[:200]))
                except Exception:
                    pass

            try:
                page.on("response", _on_response)
            except Exception:
                pass

            # 页面发出的每一条回调请求（302 目标 / fetch / 深链）全落盘：
            # portal 若不带 code 重定向过来，这里能看到原始 URL 与 error 参数。
            def _on_request(req):
                try:
                    u = req.url or ""
                    if (":%d" % port) in u and ("127.0.0.1" in u or "localhost" in u):
                        _codearts_debug("reqCb", "%s" % u[:230])
                        net_locs.append(u)
                    elif u.startswith("codearts-agent://"):
                        _codearts_debug("reqScheme", "%s" % u[:230])
                except Exception:
                    pass

            try:
                page.on("request", _on_request)
            except Exception:
                pass

            last_stage = ""
            submit_t = 0.0
            submit_warned = False
            consent_n = 0
            consent_warned = False
            false_warned = False
            while time.time() < deadline:
                try:
                    url = page.url or ""
                except Exception:
                    url = ""
                stg = _codearts_stage(url, port)
                if stg != last_stage:
                    _codearts_debug("stage", "%s -> %s (%s)" % (last_stage or "start", stg, url[:150]))
                    if stg == "portal":
                        job["result"] = "登录成功，已进入授权确认页，正在代点「同意/授权」…"
                    elif stg == "callback":
                        job["result"] = "授权回调已到达，正在换取令牌…"
                    elif stg == "login" and submit_t:
                        job["result"] = "已提交验证码，正在登录…"
                    last_stage = stg

                # ⓪ portal 把浏览器 302 到回调却**不带 code** → 我们 307 到
                #   login_succeed=false 页（即截图的「登录失败：请返回客户端查看」）。
                #   完整请求已由 cb/reqCb 日志留痕，这里把状态说清楚，不再傻点按钮。
                if ("login_succeed=false" in url) and not false_warned:
                    false_warned = True
                    _codearts_debug("warn", "portal 授权未下发 code（login_succeed=false）")
                    _pull_window_front(ctx)
                    job["result"] = ("华为云 portal 授权未下发授权码（页面显示「登录失败："
                                     "请返回客户端查看」）。完整回调请求已记录到 "
                                     "codearts_oauth_debug.log，请关闭本窗口重试一次；"
                                     "若复现请把日志发来分析。")

                # ① 注入验证码（前端 submit_code 只投递，由这里代填代点）
                if form_ok and job.get("code") and not job.get("code_submitted"):
                    _hw_submit_code(page, ctx, job, job["code"])
                    submit_t = time.time()

                # ② 提交后 15s 仍停在登录页 → 可能验证码有误/点「登录/注册」没生效，提醒人工（一次）
                if (submit_t and not submit_warned and stg == "login"
                        and time.time() - submit_t > 15):
                    submit_warned = True
                    _pull_window_front(ctx)
                    job["result"] = ("验证码已提交但 15 秒后页面仍停在登录页（可能验证码有误或"
                                     "「登录/注册」没点动），窗口已拉回屏幕，请查看并手动重试。")
                    _codearts_debug("warn", "提交后 15s 仍在登录页: %s" % url[:150])

                # ③ portal 授权确认页：代点「同意/授权/继续」（点前勾协议，反复试直到跳走）
                if stg == "portal" and consent_n < 12:
                    consent_n += 1
                    if _codearts_click_consent(page) == "none" and consent_n >= 4 \
                            and not consent_warned:
                        consent_warned = True
                        _pull_window_front(ctx)
                        job["result"] = ("已登录，但授权确认页没找到可点的「同意/授权」按钮，"
                                         "窗口已拉回屏幕，请手动点一下授权。")
                        _codearts_debug("warn", "consent 页 4 次未找到按钮: %s" % url[:150])

                # ④ 取授权码：CB handler → 网络层捕获 → 页面 URL，三路兜底
                code = result.get("code") or ""
                if not code:
                    for loc in net_locs:
                        c = _codearts_extract_code(loc, port)
                        if c:
                            code = c
                            _codearts_debug("code", "从网络层捕获 code（%s…）" % code[:8])
                            break
                if not code and url:
                    code = _codearts_extract_code(url, port)
                if code:
                    _codearts_debug("code", "开始换 token")
                    st, j = _codearts_token({
                        "client_id": _CODEARTS_CLIENT_ID, "code": code,
                        "code_verifier": verifier,
                        "grant_type": "authorization_code",
                        "redirect_uri": "http://127.0.0.1:%d/oauth/callback" % port,
                    }, dpop)
                    _codearts_debug("token", "HTTP %s %s" % (st, str(j)[:260]))
                    ak, sk, sts, exp = _codearts_extract_credentials(j)
                    if st == 200 and ak and sk and sts:
                        grant = {"ak": ak, "sk": sk, "sts_token": sts, "expires_at": exp,
                                 "refresh_token": str(_trae_find_token(
                                     j, ("refresh_token", "refreshToken")) or ""),
                                 "code_verifier": verifier,
                                 "dpop_priv_pem": dpop["priv_pem"],
                                 "dpop_pub_jwk": json.dumps(dpop["jwk"]),
                                 "port": port, "phone": phone}
                        try:
                            ok2, nm, msg2 = on_success(grant)
                        except Exception as e:
                            ok2, nm, msg2 = False, "", "保存登录态异常：%s" % str(e)[:150]
                        job.update(status="done", finished=True, ok=bool(ok2),
                                   result=msg2 or ("已保存 %s" % nm), name=nm or "")
                        ok_saved = True
                    else:
                        job.update(status="done", finished=True, ok=False,
                                   result="换token失败（HTTP %s）：%s" % (st, str(j)[:180]))
                    break
                # ④' OldLogin：portal 只回 secret（无 code）→ 照客户端用 ticket 接口换凭据
                #   GET snap-manager/v1/login/ticket?ticket_id=&secret=（含 refresh_token）
                sec = result.get("secret") or ""
                if sec and not job.get("finished"):
                    tid = result.get("ticket_id") or ticket_id
                    u = "%s/v1/login/ticket?ticket_id=%s&secret=%s" % (_CODEARTS_SNAP, tid, sec)
                    _codearts_debug("oldlogin", "ticket 接口请求 tid=%s…" % tid[:12])
                    job["result"] = "已收到授权回执，正在换取临时凭据…"
                    st, j = 0, {}
                    try:
                        rr = requests.get(u, headers={
                            "Content-Type": "application/json;charset=UTF-8",
                            "plugin-name": _CODEARTS_PLUGIN,
                            "plugin-version": _CODEARTS_PLUGIN_VER,
                        }, timeout=30)
                        st = rr.status_code
                        j = rr.json() if rr.content else {}
                    except Exception as e:
                        j = {"__err__": str(e)[:180]}
                    ak, sk, sts, exp = _codearts_extract_credentials(j)
                    _codearts_debug("oldlogin", "HTTP %s user=%s expires=%s keys=%s"
                                    % (st, str((j or {}).get("user_name"))[:24],
                                       (exp or "")[:19],
                                       ",".join(sorted((j or {}).keys()))[:120]))
                    if st == 200 and ak and sk and sts:
                        grant = {"ak": ak, "sk": sk, "sts_token": sts, "expires_at": exp,
                                 "refresh_token": str(_trae_find_token(
                                     j, ("refresh_token", "refreshToken")) or ""),
                                 "code_verifier": verifier,
                                 "dpop_priv_pem": dpop["priv_pem"],
                                 "dpop_pub_jwk": json.dumps(dpop["jwk"]),
                                 "port": port, "phone": phone}
                        try:
                            ok2, nm, msg2 = on_success(grant)
                        except Exception as e:
                            ok2, nm, msg2 = False, "", "保存登录态异常：%s" % str(e)[:150]
                        job.update(status="done", finished=True, ok=bool(ok2),
                                   result=msg2 or ("已保存 %s" % nm), name=nm or "")
                    else:
                        job.update(status="done", finished=True, ok=False,
                                   result="凭据换取失败（HTTP %s）：%s" % (st, str(j)[:180]))
                    break
                page.wait_for_timeout(700)
            if not ok_saved and not job.get("finished"):
                job.update(status="done", finished=True, ok=False,
                           result="登录超时（620 秒内未收到回调），请重试")
    except Exception as e:
        job.update(status="done", finished=True, ok=False,
                   result="CodeArts 短信登录异常：%s" % str(e)[:200])
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
