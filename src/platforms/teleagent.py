# -*- coding: utf-8 -*-
"""
电信 TeleAgent（星辰超级智能体）平台适配器
════════════════════════════════════════════════════════════════════════
凭据链（2026-10-14 实测打通，全部来自本机逆向，非猜测）：

  1) 客户端 2.7.0 数据目录：%USERPROFILE%\\.local\\share\\TeleAgent\\
     - app-auth/device-meta.json   → deviceId / installId（装机即有，明文）
     - users/v1_public_<accountId>/app-auth/token.json
       → {"encryptedToken": base64, "scheme": "safe_storage"}
     - Local State → os_crypt.encrypted_key（Chromium v10 方案）

  2) 解密两层：
     encrypted_key = b64decode；剥 "DPAPI" 前缀 → CryptUnprotectData
     → 32 字节 AES-256-GCM 主密钥
     encryptedToken = b64decode；前 3 字节 "v10" + 12 字节 nonce + GCM 密文
     → AESGCM(key).decrypt(nonce, ct, None)
     → 明文 = "<tenant_key>:<JWT>"（tenant 即 JWT payload.tenant）

  3) JWT（HS256）≈ 29 天有效（实测签发 2026-10-10 → exp 2026-11-08）。

上游接口（签名算法还原自 github.com/ddddx/teleagent2api，已实测 2.7.0 有效）：
  POST /superCowork/sapi/api/v1/chat/completions
  签名：derivedKey = HMAC(jwt第3段, "superagent-auth-v1/{token}/{installId}/{ts}/{nonce}")
        request   = "superagent-auth-v1\\n{METHOD}\\n{path}\\n{ts}\\n{nonce}\\n{appVer}\\n{sha256(body)}"
        X-SuperAgent-Signature = HMAC(derivedKey, request)
  ⚠ X-App-Version 必须用 2.7.0（2.0.0 → 40301 客户端版本过低）。

积分余额 / 每日打卡（2026-10-14 全链路实测打通，纯桌面凭据，无需网页登录）：
  GET  /superCowork/sapi/api/v1/auth/session-code      头：X-Token=<桌面JWT> +
      X-SuperAgent-Device-Id + X-Timestamp + X-Nonce + X-App-Version=2.7.0 +
      X-OS-Type=windows   →   {"data":{"code":"..."}}
  GET  /superCowork/sapi/api/v1/auth/session?code=...  同上头
      → {"data":{"operationToken": <30天JWT，accountId/accountName 内嵌>}}
  GET  /meter/super-agent/user/portal/companyStore/userCenter
      头：Cookie: operationToken=<op> + X-Token: <op> + userId: <uid>
      → 积分余额 / 版本 / 福利活动（expire_days）
  GET  /meter/super-agent/user/portal/points/detail    同上头
      → pointsBalance / groups[]（各积分池 totalQuota/usedQuota/status）
  GET  /meter/super-agent/user/portal/companyStore/checkTask?type=daily_login
      → 每日打卡领取（领取后返回 []，余额 +100）
  GET  /meter/super-agent/user/portal/companyStore/v2/checkDayTask
      → 福利社活动/每日任务状态
  注：operationToken 不必落盘——每次由桌面 JWT 现场兑换（一次 RTT ~0.6s），
  且其 exp 与桌面 JWT 相同，不延长寿命。
"""
import os
import sys
import json
import time
import uuid
import base64
import ctypes
import datetime
from ctypes import wintypes

import requests

try:
    from ._util import dec_cred, enc_cred
except ImportError:
    dec_cred = enc_cred = (lambda o: o)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

try:
    from .. import data_dir as _dd
except ImportError:
    try:
        import data_dir as _dd
    except ImportError:
        _dd = None


def _acc_paths(name):
    if _dd is not None:
        return _dd.candidates(name)
    return [os.path.join(ROOT, name), os.path.join(HERE, name)]

LABEL = "电信 TeleAgent"
TASKS = [{"key": "checkin", "label": "每日打卡"}]

BASE = "https://agent.teleai.com.cn"
SAPI = BASE + "/superCowork/sapi/api/v1"
METER = BASE + "/meter/super-agent/user/portal"
APP_VERSION = "2.7.0"
_os_type = ("windows" if os.name == "nt" else
            "darwin" if sys.platform == "darwin" else "linux")
# 客户端数据根目录（2.7.0 实测：XDG 风格 ~/.local/share/TeleAgent）
CLIENT_DATA_CANDIDATES = [
    os.path.join(os.path.expanduser("~"), ".local", "share", "TeleAgent"),
    os.path.join(os.environ.get("APPDATA", ""), "TeleAgent"),   # 旧版落点兜底
]


# ══════════════════ 客户端凭据解密 ══════════════════
class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi_unprotect(data):
    """CryptUnprotectData（当前用户作用域）。失败抛 OSError。"""
    buf = ctypes.create_string_buffer(bytes(data), len(data))
    bin_ = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    bout = _DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(bin_), None, None, None, None, 0, ctypes.byref(bout)):
        raise OSError("CryptUnprotectData 失败 err=%d" % ctypes.GetLastError())
    out = ctypes.string_at(bout.pbData, bout.cbData)
    ctypes.windll.kernel32.LocalFree(bout.pbData)
    return out


def _client_aes_key(ta_root):
    """Local State os_crypt.encrypted_key → DPAPI → 32 字节 AES-GCM 主密钥。"""
    ls = json.load(open(os.path.join(ta_root, "Local State"), encoding="utf-8"))
    blob = base64.b64decode(ls["os_crypt"]["encrypted_key"])
    if blob[:5] != b"DPAPI":
        raise ValueError("encrypted_key 前缀异常：%r" % blob[:5])
    return _dpapi_unprotect(blob[5:])


def _decrypt_token_json(ta_root, user_dir):
    """users/<dir>/app-auth/token.json → {"token": JWT, "tenant": ..., ...}"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # 延迟导入
    key = _client_aes_key(ta_root)
    p = os.path.join(ta_root, "users", user_dir, "app-auth", "token.json")
    raw = json.load(open(p, encoding="utf-8"))
    if not raw.get("encrypted"):
        return json.loads(raw.get("token") or "{}")     # 理论不出现，兜底
    enc = base64.b64decode(raw["encryptedToken"])
    if enc[:3] != b"v10":
        raise ValueError("encryptedToken 前缀异常：%r" % enc[:3])
    plain = AESGCM(key).decrypt(enc[3:15], enc[15:], None).decode("utf-8")
    # 明文格式 "<tenant_key>:<JWT>"
    if plain.count(":") >= 1 and ":" not in plain[:9]:
        tenant, _, token = plain.partition(":")
        return {"token": token, "tenant": tenant}
    return {"token": plain}


def _jwt_payload(token):
    try:
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


def _client_entries():
    """扫描客户端数据目录，返回 {user_id: ent}（解密失败的用户目录跳过并留痕）。"""
    ents = {}
    for root in CLIENT_DATA_CANDIDATES:
        users_dir = os.path.join(root, "users")
        if not os.path.isdir(users_dir):
            continue
        meta_path = os.path.join(root, "app-auth", "device-meta.json")
        try:
            meta = json.load(open(meta_path, encoding="utf-8"))
        except Exception:
            meta = {}
        try:
            import_fn = json.load(open(
                os.path.join(root, "app-auth", "install-receipt.json"),
                encoding="utf-8"))
        except Exception:
            import_fn = {}
        for ud in sorted(os.listdir(users_dir)):
            if not ud.startswith("v1_public_") or not os.path.isdir(
                    os.path.join(users_dir, ud, "app-auth")):
                continue
            try:
                d = _decrypt_token_json(root, ud)
            except ModuleNotFoundError:
                print("⚠ TeleAgent 本地导入需要 cryptography 包（pip install cryptography）")
                return ents
            except Exception as e:
                print("⚠ TeleAgent 解密 %s 失败：%s" % (ud, str(e)[:80]))
                continue
            payload = _jwt_payload(d.get("token", ""))
            uid = str(payload.get("accountId") or
                      ud.replace("v1_public_", "") or "")
            if not uid:
                continue
            ents[uid] = {
                "token": d.get("token", ""),
                "tenant": d.get("tenant") or payload.get("tenant") or "",
                "user_id": uid,
                "account_name": payload.get("accountName") or "",
                "device_id": meta.get("deviceId", ""),
                "install_id": meta.get("installId", ""),
                "exp": payload.get("exp"),
                "client_user_dir": ud,
                "client_root": root,
                "install_generation": import_fn.get("generation", ""),
            }
    return ents


# ══════════════════ 凭据装配 ══════════════════
def load_accounts():
    """凭据文件条目 + 客户端实时条目（同 user_id 客户端优先——token 会月抛轮换）。"""
    accs = {}
    for path in _acc_paths("teleagent_accounts.json"):
        if not os.path.exists(path):
            continue
        try:
            data = dec_cred(json.load(open(path, encoding="utf-8")))
        except Exception:
            continue
        items = data.items() if isinstance(data, dict) else \
            [(str(it.get("name") or "TeleAgent%d" % (i + 1)), it)
             for i, it in enumerate(data) if isinstance(it, dict)]
        for k, v in items:
            if isinstance(v, dict) and v.get("token"):
                ent = dict(v)
                ent.setdefault("user_id", str(k))
                accs[str(k)] = ent

    client = _client_entries()
    # 键名：备注名(凭据文件) > 客户端 accountName > TeleAgent·uid尾4
    by_uid = {}
    for nm, ent in accs.items():
        by_uid[str(ent.get("user_id") or nm)] = (nm, ent)
    for uid, cent in client.items():
        if uid in by_uid:
            nm, old = by_uid[uid]
            merged = dict(old)
            merged.update({k: v for k, v in cent.items() if v not in (None, "")})
            by_uid[uid] = (nm, merged)
        else:
            disp = cent.get("account_name") or ("TeleAgent·" + uid[-4:])
            by_uid[uid] = (disp, cent)
    return {nm: ent for nm, ent in by_uid.values()}


# ══════════════════ meter 会话（积分/打卡） ══════════════════
def _secret_headers(ent):
    """桌面客户端渲染层的密钥头（asar 实测 e1() 还原，无需签名）。"""
    return {
        "X-Token": ent["token"],
        "X-SuperAgent-Device-Id": ent.get("device_id") or "",
        "X-Timestamp": str(int(time.time())),
        "X-Nonce": uuid.uuid4().hex,
        "X-App-Version": APP_VERSION,
        "X-OS-Type": _os_type,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0",
        "Origin": BASE,
        "Referer": BASE + "/super-agent",
    }


def _meter_session(ent, timeout=20):
    """桌面 JWT → operationToken（30 天 JWT，含 accountId）。失败抛异常。"""
    s = requests.Session()
    s.headers.update(_secret_headers(ent))
    r = s.get(SAPI + "/auth/session-code", timeout=timeout)
    code = (r.json().get("data") or {}).get("code") or ""
    if not code:
        raise RuntimeError("session-code 未返回 code：%s" % r.text[:100])
    r = s.get(SAPI + "/auth/session", params={"code": code}, timeout=timeout)
    d = r.json().get("data") or {}
    op = d.get("operationToken") or ""
    if not op:
        raise RuntimeError("session 未返回 operationToken：%s" % r.text[:100])
    uid = str(_jwt_payload(op).get("accountId") or ent.get("user_id") or "")
    return op, uid


def _meter_get(op, uid, path, params=None, timeout=20):
    """meter 福利社 API。operationToken 走 Cookie（js-cookie 实测），userId 走头。"""
    return requests.get(
        METER + path, params=params,
        headers={"Cookie": "operationToken=" + op, "X-Token": op, "userId": uid,
                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0",
                 "Accept": "application/json", "Referer": BASE + "/super-agent"},
        timeout=timeout)


def _meter_points(ent):
    """拉积分：返回 (ok, info_dict)。任何一步失败返回 (False, {"error": ...})。"""
    op, uid = _meter_session(ent)
    info = {}
    r = _meter_get(op, uid, "/points/detail")
    j = r.json() if "json" in r.headers.get("content-type", "") else {}
    if j.get("code") == 200:
        d = j.get("data") or {}
        info["balance"] = float(d.get("pointsBalance") or 0)
        pools, total, used = [], 0.0, 0.0
        for g in d.get("groups") or []:
            for a in (g.get("active") or []):
                q, u = float(a.get("totalQuota") or 0), float(a.get("usedQuota") or 0)
                total += q
                used += u
                pools.append({
                    "name": (g.get("typeName") or a.get("name") or "积分池"),
                    "total": q, "used": u, "remain": round(q - u, 2),
                    "status": a.get("statusName") or a.get("status") or "",
                })
        info["pools"] = pools
        info["total"] = total
        info["used"] = used
    else:
        info["error_detail"] = "points/detail %s %s" % (r.status_code, r.text[:80])
    r = _meter_get(op, uid, "/companyStore/userCenter")
    j = r.json() if "json" in r.headers.get("content-type", "") else {}
    if j.get("code") == 200:
        d = j.get("data") or {}
        info["plan"] = d.get("plan_display_name") or ""
        acts = []
        for a in (d.get("activities") or []):
            if a.get("expire_days") is not None:
                acts.append({"name": a.get("name") or "", "expire_days": a.get("expire_days")})
        info["activities"] = acts
        if info.get("balance") in (None, 0) and d.get("current_points_balance"):
            info["balance"] = float(d["current_points_balance"])
    # 每日签到状态（/companyStore/checkDayTask 为只读查询，实测返回
    # claimed_today/total_claim_days/total_claimed_points；勿与 checkTask 混淆——
    # checkTask 是领取动作，查状态不能用它）
    try:
        r = _meter_get(op, uid, "/companyStore/checkDayTask")
        j = r.json() if "json" in r.headers.get("content-type", "") else {}
        if j.get("code") == 200:
            d = j.get("data") or {}
            info["signed_today"] = bool(d.get("claimed_today"))
            info["claim_days"] = d.get("total_claim_days")
            info["claim_total_points"] = d.get("total_claimed_points")
    except Exception:
        pass   # 状态查询失败不阻断积分主流程
    return True, info


# ══════════════════ 读取 ══════════════════
def read_account(name, ent):
    token = (ent.get("token") or "").strip()
    out = {
        "name": name, "ok": False, "error": None, "level": "TeleAgent",
        "signed_today": False,
        "credits": {"remain": 0, "total": 0, "used": 0},
        "packages": [], "extra": {},
    }
    if not token:
        out["error"] = "token 为空（请登录 TeleAgent 客户端后刷新）"
        return out
    payload = _jwt_payload(token)
    exp = payload.get("exp") or ent.get("exp")
    now = datetime.datetime.now().timestamp()
    if exp and exp < now:
        out["error"] = "token 已过期（%s），请打开 TeleAgent 客户端重新登录后刷新" % (
            datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M"))
        return out

    remain_days = int((exp - now) / 86400) if exp else None
    out["ok"] = True
    out["extra"] = {
        "account_id": ent.get("user_id") or payload.get("accountId") or "",
        "platform_account": payload.get("accountName") or ent.get("account_name") or "",
        "tenant": ent.get("tenant") or payload.get("tenant") or "",
        "token_expire": datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M")
                        if exp else "",
        "token_remain_days": remain_days,
        "via_client": bool(ent.get("client_user_dir")),
    }
    # 积分余额 / 福利社（meter 链路，失败降级为仅登录态监控）
    try:
        ok, info = _meter_points(ent)
        if ok and info.get("balance") is not None:
            out["credits"] = {
                "remain": info.get("balance", 0),
                "total": info.get("total", 0),
                "used": info.get("used", 0),
            }
            out["packages"] = info.get("pools") or []
            out["extra"]["plan"] = info.get("plan") or ""
            out["extra"]["activities"] = info.get("activities") or []
            # 签到状态（只读 checkDayTask，claimed_today 实测口径）
            if "signed_today" in info:
                out["signed_today"] = info["signed_today"]
            if info.get("claim_days") is not None:
                out["extra"]["claim_days"] = info["claim_days"]
                out["extra"]["claim_total_points"] = info.get("claim_total_points")
            out["extra"]["points_note"] = ""
        elif info.get("error_detail"):
            out["extra"]["points_note"] = "积分读取异常：%s" % info["error_detail"]
    except Exception as e:
        out["extra"]["points_note"] = "积分读取失败：%s" % str(e)[:80]
    return out


# ══════════════════ 任务 ══════════════════
def run_task(name, ent, task_key):
    if task_key != "checkin":
        return {"ok": False, "msg": "未知任务"}
    try:
        op, uid = _meter_session(ent)
    except Exception as e:
        return {"ok": False, "msg": "会话兑换失败：%s" % str(e)[:100]}
    try:
        # 先只读查状态：已签直接返回（不重复打领取接口）
        try:
            r = _meter_get(op, uid, "/companyStore/checkDayTask")
            j = r.json() if "json" in r.headers.get("content-type", "") else {}
            if j.get("code") == 200 and (j.get("data") or {}).get("claimed_today"):
                d = j["data"]
                return {"ok": True, "msg": "今日已签到（累计 %s 天 / 共领 %s 分），无需重复操作"
                        % (d.get("total_claim_days") or "?", d.get("total_claimed_points") or "?")}
        except Exception:
            pass   # 状态查询失败 → 走原领取流程兜底
        # 领前读余额（打卡成功余额 +100）
        before = None
        try:
            _, info = _meter_points(ent)
            before = info.get("balance")
        except Exception:
            pass
        # 领取每日打卡（实测：领取成功后返回 data:[] 且余额 +100）
        r = _meter_get(op, uid, "/companyStore/checkTask",
                       params={"type": "daily_login"})
        j = r.json() if "json" in r.headers.get("content-type", "") else {}
        if j.get("code") != 200:
            return {"ok": False, "msg": "checkTask %s：%s"
                    % (r.status_code, str(j.get("msg") or j.get("message") or r.text[:80]))}
        after = None
        try:
            _, info = _meter_points(ent)
            after = info.get("balance")
        except Exception:
            pass
        rd = j.get("data")
        if before is not None and after is not None:
            delta = round(after - before, 2)
            if delta > 0:
                msg = "打卡成功 +%.0f 积分，余额 %.2f" % (delta, after)
            elif delta == 0:
                msg = "今日打卡已完成（余额无变化 %.2f）" % after
            else:
                msg = "已处理（余额 %.2f，变动 %.2f）" % (after, delta)
        elif isinstance(rd, list) and not rd:
            msg = "今日打卡已完成（无待领任务）"
        else:
            msg = "打卡请求已提交"
        return {"ok": True, "msg": msg}
    except Exception as e:
        return {"ok": False, "msg": "打卡异常：%s" % str(e)[:100]}


# ══════════════════ OpenAI 反代（sapi chat，签名同 teleagent2api） ══════════════════
# 2026-10-14 实测：8 个模型名全 200（上游不严格校验 model），SSE 为标准 OpenAI chunk
# 形状（含 reasoning_content / finish_reason / data:[DONE]），可直接透传。
UPSTREAM_KEY = "sk-qvp4m6h9g20uM6PgYP7E"
SIGN_PREFIX = "superagent-auth-v1"
TA_UA = "opencode/1.2.27 ai-sdk/provider-utils/3.0.20 runtime/bun/1.3.10"
CHAT_PATH = "/superCowork/sapi/api/v1/chat/completions"
CHAT_MODELS = ("chat-flash", "chat-pro", "chat-max", "chat-lite", "chat-standard",
               "deepseek-v3", "doubao-pro-32k", "xingchen")


def chat_headers(ent, body_bytes):
    """sapi chat 网关签名头（实测 200；⚠ X-App-Version 必须 2.7.0，2.0.0 被 40301 拒）。
    签名：derivedKey = HMAC(jwt第3段, "superagent-auth-v1/{token}/{installId}/{ts}/{nonce}")；
         sig = HMAC(derivedKey, "superagent-auth-v1\\nPOST\\n{path}\\n{ts}\\n{nonce}\\n{ver}\\n{sha256(body)}")"""
    import hashlib
    import hmac
    ts = str(int(time.time()))
    nonce = str(uuid.uuid4())
    token = ent["token"]
    jwt3 = token.split(".")[2]
    derived = hmac.new(jwt3.encode(),
                       ("%s/%s/%s/%s/%s" % (SIGN_PREFIX, token,
                                            ent.get("install_id") or "", ts, nonce)
                        ).encode("utf-8"),
                       hashlib.sha256).hexdigest()
    req = "\n".join([SIGN_PREFIX, "POST", CHAT_PATH, ts, nonce, APP_VERSION,
                     hashlib.sha256(body_bytes).hexdigest()])
    return {
        "Authorization": "Bearer " + UPSTREAM_KEY,
        "Content-Type": "application/json",
        "User-Agent": TA_UA,
        "X-App-Version": APP_VERSION,
        "X-SuperAgent-Device-Id": ent.get("device_id") or "",
        "X-SuperAgent-Install-Id": ent.get("install_id") or "",
        "X-SuperAgent-Nonce": nonce,
        "X-SuperAgent-Sign-Version": "v1",
        "X-SuperAgent-Signature": hmac.new(derived.encode(), req.encode(),
                                           hashlib.sha256).hexdigest(),
        "X-SuperAgent-Timestamp": ts,
        "X-Token": token,
        "x-message-id": "msg_" + uuid.uuid4().hex,
        "x-session-id": "ses_" + uuid.uuid4().hex,
        "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close",
    }


def chat_stream(ent, openai_body, timeout=(15, 600)):
    """OpenAI 请求体 → 上游 SSE 行迭代器（恒 stream 上游，非流式由调用方聚合）。
    上游错误抛 errors.UpstreamError(status, msg)；成功返回行迭代器。"""
    from errors import UpstreamError
    b = dict(openai_body)
    # 上游不认识的字段剥掉防参数错误（实测最小体即可）；上游恒 SSE
    for k in ("stream", "stream_options", "user", "logit_bias", "logprobs",
              "top_logprobs", "n", "presence_penalty", "frequency_penalty",
              "seed", "response_format", "stop", "prompt_cache_key",
              "tool_stream", "chat_id"):
        b.pop(k, None)
    b["stream"] = True
    body = json.dumps(b, ensure_ascii=False).encode("utf-8")
    r = requests.post(BASE + CHAT_PATH, data=body,
                      headers=chat_headers(ent, body),
                      timeout=timeout, stream=True,
                      proxies={"http": None, "https": None})
    if r.status_code >= 400:
        raise UpstreamError(r.status_code, "TeleAgent 上游 %s：%s"
                            % (r.status_code, r.text[:200]))
    # ⚠ 上游 SSE 无 charset，必须显式 utf-8（workbuddy.py 同款坑）
    r.encoding = "utf-8"
    return r.iter_lines(decode_unicode=True)


if __name__ == "__main__":
    accs = load_accounts()
    print("账号:", list(accs.keys()))
    for nm, ent in accs.items():
        r = read_account(nm, ent)
        ex = r["extra"] or {}
        print("[%s] ok=%s 到期=%s 余天数=%s 账号=%s err=%s"
              % (nm, r["ok"], ex.get("token_expire"), ex.get("token_remain_days"),
                 ex.get("platform_account"), r["error"]))
