# -*- coding: utf-8 -*-
r"""
WorkBuddy 国际版（workbuddy.ai）· 看板平台适配器
═════════════════════════════════════════════════════════════════════════
协议（2026-10-16 本机实测打通）：

  凭据    %LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop-ai.info
          5.6.2+ 的 accessToken/refreshToken 是 {"$wbEncrypted":1,"envelope":...} 信封
          （AES-256-GCM，keyId=9127dea1b44020a7）。密钥不落盘，由客户端运行时持有：
          ELECTRON_RUN_AS_NODE=1 WorkBuddy.exe -e "<loggerGet JS>" 取 atRestSecretKey，
          key = sha256(secret字符串)，keyId = sha256(key)[:16]（与信封自报 keyId 对账），
          AAD = "WB-AAD\\0" | 01 | u32len("WBEV1") | u32len("sym-v1") | u32(suite)
                | u32len(keyId) | 02 | 00 | 00
          （协议还原自 github AstbReal/dailyAutoCheck codes/workbuddy/at_rest.py，
            与 lyston11/Buddy2api wb_at_rest.py 交叉验证一致）
  chat    POST https://www.workbuddy.ai/v2/chat/completions
          恒流式 SSE（非流式 11101）；messages 首条必须是 system（11128 通道校验）；
          头：Authorization Bearer + X-Domain/X-Product:SaaS/X-Env-ID/X-IDE-*(VSCode)
              + X-Conversation-ID/X-Request-ID 等（github wnddd839/buddy-proxy
              internal/provider/client.go BuildProtocolDirectHeaders 还原）
          响应：标准 OpenAI chat.completion.chunk（含 usage.reasoning_content）
  模型    GET /v3/config → data.models[]（id/credits 倍率/maxInputTokens）
  刷新    POST /v2/plugin/auth/token/refresh，头 X-Refresh-Token（国内版同款路径、
          国际域名）。⚠ RT ≈359 天月抛性质、非一次性轮换，但刷新会返回新 RT——
          必须落盘保存，防「他处刷新顶掉」（MiniMax 教训）
  积分    POST /v2/billing/meter/get-user-resource → data.Response.Data.Accounts[]
          每条一个积分包（CapacityRemain/CapacitySize/CycleEndTime）

国内版与 国际版并存：auth 目录下 workbuddy-desktop.info（国内，明文）与
workbuddy-desktop-ai.info（国际，信封）是两套独立账号，本适配器只管国际版。
"""
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    import cred_store
except ImportError:
    cred_store = None

PLATFORM = "workbuddy_ai"
LABEL = "WorkBuddy 国际版"
# 国际版无国内版那套签到/派猫任务体系；占一个「每日对话」保持看板任务栏可用
TASKS = [{"key": "chat", "label": "每日对话", "daily": True}]

BASE = "https://www.workbuddy.ai"
EP_CHAT = "/v2/chat/completions"
EP_REFRESH = "/v2/plugin/auth/token/refresh"
EP_RESOURCE = "/v2/billing/meter/get-user-resource"
EP_CONFIG = "/v3/config"
# 桌面协议直连版本号（buddy-proxy internal/config 默认值；版本过旧可能被通道校验拦）
IDE_VERSION = "1.119.0"
PRODUCT_VERSION = "4.9.29177644"

AUTH_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""), "CodeBuddyExtension",
                        "Data", "Public", "auth")
AUTH_FILE_AI = os.path.join(AUTH_DIR, "workbuddy-desktop-ai.info")
# 客户端 exe 候选（取 atRestSecretKey 用；WORKBUDDY_EXE 环境变量可覆盖）
EXE_CANDIDATES = [
    os.environ.get("WORKBUDDY_EXE", ""),
    r"E:\WorkBuddy\WorkBuddy.exe",
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "WorkBuddy", "WorkBuddy.exe"),
    os.path.join(os.environ.get("PROGRAMFILES", ""), "WorkBuddy", "WorkBuddy.exe"),
]
LOGGER_GET_JS = (
    "const b=process._linkedBinding('electron_browser_workbuddy_storage');"
    "const p=b.loggerGet();process.stdout.write(typeof p==='string'?p:JSON.stringify(p));"
)

# ── 凭据文件 ──
if cred_store:
    ACCOUNTS_FILE = cred_store.data_dir.path("workbuddy_ai_accounts.json")
else:
    ACCOUNTS_FILE = os.path.join(ROOT, "workbuddy_ai_accounts.json")


def _jwt_payload(tok):
    try:
        seg = (tok or "").split(".")[1]
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception:
        return {}


# ══════════════════ 信封解密（$wbEncrypted） ══════════════════
def _b64d(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _build_field_aad(key_id, suite):
    """字段帧 AAD，逐字段复刻官方 buildAuthenticatedContextAad。"""
    def lp(t):
        raw = t.encode("utf-8")
        return struct.pack(">I", len(raw)) + raw
    return b"".join([b"WB-AAD\0", b"\x01", lp("WBEV1"), lp("sym-v1"),
                     struct.pack(">I", int(suite)), lp(key_id), b"\x02\x00\x00"])


def _client_secret_key(exe=None):
    """从运行中的客户端二进制取 atRestSecretKey（密钥不落盘，只能现取）。"""
    cands = [exe] if exe else [e for e in EXE_CANDIDATES if e]
    last_err = "无可执行文件"
    for exe in cands:
        if not exe or not os.path.exists(exe):
            continue
        env = dict(os.environ)
        env["ELECTRON_RUN_AS_NODE"] = "1"
        try:
            r = subprocess.run([exe, "-e", LOGGER_GET_JS], capture_output=True,
                               text=True, encoding="utf-8", errors="replace",
                               env=env, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            last_err = str(e)[:90]
            continue
        if r.returncode != 0 or not r.stdout.strip():
            last_err = "exit=%s %s" % (r.returncode, (r.stderr or "").strip()[:80])
            continue
        try:
            payload = json.loads(r.stdout)
        except ValueError:
            last_err = "密钥载荷非 JSON（客户端版本可能变化）"
            continue
        secret = str(payload.get("atRestSecretKey") or "").strip()
        if secret:
            return secret, exe
        last_err = "载荷中无 atRestSecretKey"
    raise RuntimeError("取解密密钥失败（须本机装有并登录 WorkBuddy AI 客户端）：%s" % last_err)


def _derive_key(secret):
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    return key, hashlib.sha256(key).hexdigest()[:16]


def decrypt_field(wrapper, secret_key):
    """解开 {"$wbEncrypted":1,"envelope":...} 字段信封，返回明文。keyId 不符即报错。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # 延迟导入
    if not (isinstance(wrapper, dict) and wrapper.get("$wbEncrypted") == 1):
        return str(wrapper or "")
    env = json.loads(_b64d(wrapper["envelope"]))
    key, kid = _derive_key(secret_key)
    declared = env.get("keyId")
    if declared != kid:
        raise ValueError("keyId 不匹配：信封 %s / 本地密钥派生 %s" % (declared, kid))
    plain = AESGCM(key).decrypt(_b64d(env["nonce"]),
                                _b64d(env["ciphertext"]) + _b64d(env["authTag"]),
                                _build_field_aad(declared, env.get("suite") or 1))
    return plain.decode("utf-8")


def import_from_client():
    """扫描 auth 目录里的国际版登录态并解密。
    返回 {显示名: ent}；ent 含 token/refresh_token/user_id/expires_at/domain。"""
    secret, exe = _client_secret_key()
    cands = []
    if os.path.isfile(AUTH_FILE_AI):
        cands.append(AUTH_FILE_AI)
    # 兜底：扫全部 *.info，认 auth.domain=www.workbuddy.ai 的（多账号/异名文件）
    try:
        for fn in sorted(os.listdir(AUTH_DIR)):
            p = os.path.join(AUTH_DIR, fn)
            if fn.endswith(".info") and p not in cands and os.path.isfile(p):
                try:
                    if (json.load(open(p, encoding="utf-8")).get("auth") or {}).get("domain") \
                            == "www.workbuddy.ai":
                        cands.append(p)
                except Exception:
                    continue
    except OSError:
        pass
    if not cands:
        return {}, "未找到国际版登录态文件（%s）" % AUTH_FILE_AI
    out, seen = {}, set()
    for p in cands:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception as e:
            continue
        auth = d.get("auth") or {}
        try:
            tok = decrypt_field(auth.get("accessToken") or {}, secret)
            rt = decrypt_field(auth.get("refreshToken") or {}, secret)
        except Exception as e:
            return {}, "信封解密失败（%s）：%s" % (os.path.basename(p), str(e)[:80])
        if not tok.startswith("ey"):
            continue
        pl = _jwt_payload(tok)
        uid = str(pl.get("sub") or "")
        if uid in seen:
            continue
        seen.add(uid)
        email = str(pl.get("preferred_username") or d.get("account", {}).get("username") or "")
        nm = "WB国际·" + (email.split("@")[0][-8:] or uid[-6:])
        exp = pl.get("exp")
        ent = {"token": tok, "refresh_token": rt, "user_id": uid,
               "domain": "www.workbuddy.ai", "auth_file": os.path.basename(p),
               "imported_from_client": True}
        if exp:
            import datetime
            ent["expires_at"] = datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M")
        out[nm] = ent
    return out, ("已从客户端解密国际版登录态 %d 个账号（密钥取自 %s）"
                 % (len(out), os.path.basename(exe)))


# ══════════════════ 统一接口（OCP） ══════════════════
def load_accounts():
    """凭据文件条目 {键名: ent}。"""
    d = cred_store.read_json(ACCOUNTS_FILE, {}) if cred_store else {}
    return {str(k): v for k, v in d.items() if isinstance(v, dict) and v.get("token")}


def save_accounts(d):
    """原子加密落盘（凭据字段自动 DPAPI 加密）。"""
    if cred_store:
        with cred_store.locked(ACCOUNTS_FILE):
            cred_store.write_json(ACCOUNTS_FILE, d)
    else:
        import tempfile
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as fh:
            json.dump(d, fh, ensure_ascii=False, indent=1)


def update_entry(name, ent):
    """更新单个账号条目并落盘（刷新 token 后调用，防 RT 轮换断链）。"""
    accs = load_accounts()
    key = None
    for k, v in accs.items():
        if k == name or str(v.get("user_id")) == str(ent.get("user_id")):
            key = k
            break
    if key is None:
        return False
    merged = dict(accs[key])
    merged.update(ent)
    accs[key] = merged
    save_accounts(accs)
    return True


def expired(ent):
    """AT JWT exp 判断：True 过期 / False 有效 / None 无 exp（无法判定）。"""
    exp = _jwt_payload((ent or {}).get("token") or "").get("exp")
    if not exp:
        return None
    return exp < time.time() + 60      # 1 分钟提前量


def refresh(ent):
    """RT 换新 AT。成功返回 (新AT, 新RT)；失败返回 (None, err)。"""
    s = requests.Session()
    s.trust_env = False
    try:
        r = s.post(BASE + EP_REFRESH, json={}, timeout=20, verify=False,
                   headers={"X-Refresh-Token": (ent or {}).get("refresh_token") or "",
                            "X-Auth-Refresh-Source": "plugin",
                            "Content-Type": "application/json"})
        d = r.json()
        inner = d.get("data") or {}
        if r.status_code == 200 and d.get("code") == 0 and inner.get("accessToken"):
            return inner["accessToken"], (inner.get("refreshToken") or ent.get("refresh_token"))
        return None, "HTTP%s %s" % (r.status_code, str(d.get("msg") or r.text)[:80])
    except Exception as e:
        return None, str(e)[:80]


def ensure_token(ent, name=""):
    """反代/读状态热路径：AT 有效直接用；过期用 RT 刷新并落盘（防轮换断链）。"""
    tok = (ent or {}).get("token") or ""
    if expired(ent) is False:
        return tok
    if not (ent or {}).get("refresh_token"):
        return tok      # 无 RT 只能硬试
    at, rt2 = refresh(ent)
    if not at:
        return tok      # 刷新失败用旧 AT 硬试（可能仍有效）
    ent["token"] = at
    if rt2 and rt2 != ent.get("refresh_token"):
        ent["refresh_token"] = rt2
    ent["expires_at"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(
        _jwt_payload(at).get("exp") or time.time() + 28 * 86400))
    if name:
        try:
            update_entry(name, dict(ent))
        except Exception:
            pass
    return at


def _uid_of(tok):
    return str(_jwt_payload(tok).get("sub") or "")


def _headers(tok, stream=False):
    """桌面协议直连头（buddy-proxy BuildProtocolDirectHeaders 还原）。"""
    h = {
        "Authorization": "Bearer " + tok,
        "Content-Type": "application/json",
        "Accept": "text/event-stream" if stream else "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
        "X-Agent-Intent": "craft",
        "X-IDE-Type": "VSCode", "X-IDE-Name": "VSCode", "X-IDE-Version": IDE_VERSION,
        "X-Domain": BASE, "X-Product": "SaaS", "X-Product-Version": PRODUCT_VERSION,
        "X-Env-ID": "production", "X-User-Id": _uid_of(tok),
        "User-Agent": "VSCode/%s WorkBuddy/%s" % (IDE_VERSION, PRODUCT_VERSION),
    }
    return h


# ══════════════════ 模型目录 ══════════════════
CATALOG_TTL = 900
_cat_lock = threading.Lock()
_catalog = {"ts": 0.0, "models": []}     # [{id, credit, ctx, free}]


def gw_models(ent, force=False):
    """/v3/config 模型列表（TTL 缓存）。返回 [{id, credit, ctx}, ...]；失败回退缓存。"""
    now = time.time()
    with _cat_lock:
        if not force and _catalog["models"] and now - _catalog["ts"] < CATALOG_TTL:
            return _catalog["models"]
    models = []
    try:
        s = requests.Session(); s.trust_env = False
        r = s.get(BASE + EP_CONFIG, headers=_headers(ent.get("token") or ""),
                  timeout=25, verify=False)
        if r.status_code == 200:
            for m in ((r.json().get("data") or {}).get("models") or []):
                mid = str(m.get("modelId") or m.get("id") or "").strip()
                if not mid:
                    continue
                models.append({"id": mid,
                               "credit": str(m.get("credits") or "").strip(),
                               "ctx": int(m.get("maxInputTokens") or m.get("maxAllowedSize") or 0)})
    except Exception:
        pass
    with _cat_lock:
        if models:
            _catalog.update(ts=now, models=models)
        return _catalog["models"]


def _model_ids(ent):
    return [m["id"] for m in gw_models(ent)]


# ══════════════════ 反代 chat（SSE 透传） ══════════════════
CHAT_TIMEOUT = (15, 600)


def chat_stream(ent, openai_body):
    """调国际版 /v2/chat/completions，返回 SSE 行迭代器。
    上游约束：恒流式（11101）；messages 首条必须 system（11128）。
    OpenAI body 里的非流式参数上游不支持的字段剥掉防 400。"""
    tok = ensure_token(ent)
    b = dict(openai_body)
    for k in ("stream_options", "user", "logit_bias", "logprobs", "top_logprobs",
              "n", "presence_penalty", "frequency_penalty", "seed",
              "response_format", "stop"):
        b.pop(k, None)
    b["stream"] = True
    b["stream_options"] = {"include_usage": True}
    # 11128 通道校验：首条必须 system。客户端没发 system 就补一条极简的。
    msgs = b.get("messages") or []
    if not msgs or str(msgs[0].get("role") or "").lower() != "system":
        b["messages"] = [{"role": "system", "content": "You are a helpful assistant."}] + msgs
    conv_id, msg_id = uuid.uuid4().hex, uuid.uuid4().hex
    hdr = _headers(tok, stream=True)
    hdr.update({"X-Conversation-ID": conv_id, "X-Conversation-Request-ID": msg_id,
                "X-Conversation-Message-ID": msg_id, "X-Request-ID": msg_id})
    url = BASE + EP_CHAT
    r = requests.post(url, headers=hdr, data=json.dumps(b, ensure_ascii=False).encode("utf-8"),
                      timeout=CHAT_TIMEOUT, verify=True, stream=True,
                      proxies={"http": None, "https": None})
    if r.status_code >= 400:
        raise UpstreamErr(r.status_code, r.text[:300])
    r.encoding = "utf-8"     # 上游 SSE 无 charset，防中文乱码（workbuddy.py 同款坑）
    return r.iter_lines(decode_unicode=True)


class UpstreamErr(Exception):
    """(status, message) 形状的上游错误，proxy.relay 里转 OpenAI 错误 JSON。"""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


# ══════════════════ 看板读状态 ══════════════════
def _parse_resource(d):
    """data.Response.Data.Accounts[] → packages。国际版每条 Account 即一个积分包。"""
    accs = (((d or {}).get("Response") or {}).get("Data") or {}).get("Accounts") or []
    pkgs, total, remain = [], 0, 0
    for a in accs:
        try:
            amt = float(a.get("CapacitySize") or 0)
            rem = float(a.get("CapacityRemain") or 0)
        except (TypeError, ValueError):
            continue
        if amt <= 0:
            continue
        total += amt
        remain += rem
        pkgs.append({"name": str(a.get("PackageName") or "积分包")[:24],
                     "amount": amt, "remain": rem,
                     "used": max(0.0, amt - rem),
                     "end": str(a.get("CycleEndTime") or a.get("ExpiredTime") or "")[:19]})
    return pkgs, remain, total


def read_account(name, ent):
    """看板卡片数据：积分包 + 到期日。"""
    try:
        tok = ensure_token(ent, name=name)
    except Exception as e:
        tok = (ent or {}).get("token") or ""
    if not tok:
        return {"name": name, "ok": False, "error": "凭据缺失，请从本地客户端导入",
                "level": "?", "energy": None, "streak_days": None,
                "signed_today": False, "credits": {"remain": 0, "total": 0, "used": 0},
                "packages": [], "buddy": {"state": "unknown"}}
    s = requests.Session(); s.trust_env = False
    s.headers.update(_headers(tok))
    try:
        r = s.post(BASE + EP_RESOURCE, json={}, timeout=25, verify=False)
        d = r.json()
        if r.status_code == 200 and d.get("code") == 0:
            pkgs, remain, total = _parse_resource(d.get("data"))
            # 即将到期提醒：30 天内到期的积分包数量
            expiring = sum(1 for p in pkgs if p["end"] and p["end"] < time.strftime(
                "%Y-%m-%d", time.localtime(time.time() + 30 * 86400)) and p["remain"] > 0)
            return {"name": name, "ok": True,
                    "level": "intl",
                    "energy": None, "streak_days": None, "signed_today": False,
                    "credits": {"remain": remain, "total": total,
                                "used": max(0.0, total - remain)},
                    "packages": pkgs,
                    "extra": {"email": (_jwt_payload(tok).get("preferred_username") or ""),
                              "expiring_in_30d": expiring},
                    "buddy": {"state": "none"}}
        msg = str(d.get("msg") or r.text)[:80]
        return {"name": name, "ok": False, "error": "读积分失败：%s" % msg,
                "level": "?", "energy": None, "streak_days": None,
                "signed_today": False, "credits": {"remain": 0, "total": 0, "used": 0},
                "packages": [], "buddy": {"state": "unknown"}}
    except Exception as e:
        return {"name": name, "ok": False, "error": "网络异常：%s" % str(e)[:60],
                "level": "?", "energy": None, "streak_days": None,
                "signed_today": False, "credits": {"remain": 0, "total": 0, "used": 0},
                "packages": [], "buddy": {"state": "unknown"}}


def run_task(name, ent, task_key):
    if task_key != "chat":
        return {"ok": False, "msg": "未知任务"}
    try:
        lines = chat_stream(ent, {"model": "fast-model",
                                  "messages": [{"role": "user", "content": "你好"}]})
        txt = ""
        for line in lines:
            if not line.startswith("data:") or "[DONE]" in line:
                continue
            try:
                j = json.loads(line[5:])
                for c in j.get("choices", []):
                    txt += (c.get("delta") or {}).get("content") or ""
            except Exception:
                pass
            if len(txt) > 20:
                break
        return {"ok": bool(txt.strip()),
                "msg": ("已对话（回复：%s…）" % txt.strip()[:20]) if txt.strip()
                       else "对话成功但无回复内容"}
    except UpstreamErr as e:
        return {"ok": False, "msg": "对话失败 HTTP%s：%s" % (e.status, e.message[:60])}
    except Exception as e:
        return {"ok": False, "msg": "对话异常：%s" % str(e)[:60]}
