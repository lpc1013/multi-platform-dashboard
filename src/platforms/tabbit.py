# -*- coding: utf-8 -*-
"""
Tabbit（国产 Chromium AI 浏览器）平台适配器
════════════════════════════════════════════════════════════════════════
协议逆向自 github.com/goehou/tabbit-toy（505★，2026-10-19 逐行核对），
看板用途：① 账号卡片（签到/连签/登录态）② 一键签到 ③ OpenAI 反代上游。

  后端   国内版 https://web.tabbit.com / 国际版 https://web.tabbit.ai（协议完全一致）
  鉴权   Cookie（含 HttpOnly JWT，约 7 天有效；等同账号控制权，只落本机 DPAPI 加密）
  签名   GET /chat/sign-key 拿 key；每请求带
          x-timestamp = 毫秒时间戳
          x-signature = UUID v4                （命名反直觉：签名位是 UUID）
          x-nonce     = HMAC-SHA256(key, "<ts>.<uuid>.<sha256(body)>")
  指纹   x-req-ctx   = base64(版本号，如 1.1.39(10101039))
          unique-uuid = 带标记位 UUID（index 5 = '1' 表示「已设默认浏览器」，
                       真实浏览器该位恒为 '1'；上游按账号态校验，免费模型不受影响）
  聊天   POST /api/v1/chat/completion（SSE）
  模型   GET  /proxy/v1/model_config/models?a=0&scene=chat
  会话   GET  /api/v0/chat/md5-key-sessions/user-sessions?page&size → 历史会话
         POST /panel/session → 新建空会话（返回 chat_session_id）
         （旧 /newtab Server Action 已死于 500，2026-10-19 换新端点；
           后端要求 chat_session_id 必须是已登记会话，随机 UUID 会被拒）
  签到   GET  /api/commerce/activity/v1/sign-in/status?scene_codes=daily_sign_in&scene_codes=desktop_pet
         POST /api/commerce/activity/v1/sign-in  body {"request_no": <32hex>, "scene_codes": [...]}
         （签到只靠 Cookie，不需要签名）

账号记录（tabbit_accounts.json，secret_box 自动加密 cookie 字段）：
  {"cookie": "a=1; b=2", "base": "https://web.tabbit.com",
   "version": "1.1.39(10101039)", "user_id": "<JWT sub>", "via_local": true}
"""
import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
import urllib.parse
import uuid

import requests

try:                       # 包内导入（server.py: import platforms.tabbit）
    from ._util import dec_cred, to_float as _num
except ImportError:        # 直接以脚本运行（python platforms/tabbit.py）时的兜底
    dec_cred = (lambda o: o)

    def _num(v, default=0.0):
        try:
            return float(v)
        except (TypeError, ValueError):
            return default

try:
    from .. import data_dir as _dd
except ImportError:
    try:
        import data_dir as _dd
    except ImportError:
        _dd = None

try:
    from errors import UpstreamError
except ImportError:
    class UpstreamError(Exception):      # 独立运行兜底（不改变调用方语义）
        def __init__(self, status, message):
            super().__init__(message)
            self.status = int(status) if status else 502
            self.message = str(message)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

LABEL = "Tabbit"
TASKS = [{"key": "checkin", "label": "每日签到"}]

# ── 协议常量（2026-10-19 核对 goehou/tabbit-toy）──────────────
BASE_DOM = "https://web.tabbit.com"          # 国内版
BASE_INTL = "https://web.tabbit.ai"          # 国际版
DEFAULT_VERSION = "1.1.39(10101039)"         # getDeviceInfo().tabbitVersion 的真实格式
DEFAULT_SIGN_KEY = "f8d0e6a73f8d4b1a9c3d2e1f9a4b7c6d"   # 前端硬编码兜底 key
EP_SIGN_KEY = "/chat/sign-key"
EP_MODELS = "/proxy/v1/model_config/models"
EP_CHAT = "/api/v1/chat/completion"
# 会话（2026-10-19 从现行 web bundle 逆向；旧 /newtab Server Action 已 500 失效）
EP_SESSION_LIST = "/api/v0/chat/md5-key-sessions/user-sessions"
EP_PANEL_SESSION = "/panel/session"
EP_BASE_INFO = "/api/v0/user/base-info"
EP_SIGNIN_STATUS = "/api/commerce/activity/v1/sign-in/status"
EP_SIGNIN = "/api/commerce/activity/v1/sign-in"
SCENE_CODES = ["daily_sign_in", "desktop_pet"]

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36")

CHAT_TIMEOUT = (15, 600)        # 连接 / 读超时（SSE 可能很长）
SIGN_KEY_TTL = 600              # 签名 key 缓存 10 分钟（toy 同款）
SESSION_TTL = 300               # 会话 id 缓存 5 分钟
MODELS_TTL = 600                # 模型目录缓存 10 分钟

# 缓存（进程级；key = base_url）
_cache_lock = threading.Lock()
_sign_keys = {}                 # base -> (key, ts)
_sessions = {}                  # base -> (session_id, ts)
_models_cache = {}              # base -> (ids, ts)
_sess_fetch_lock = threading.Lock()   # 会话列表拉取串行（防并发重复建）


# ════════════════════════════════════════════════════════════════
# 凭据
# ════════════════════════════════════════════════════════════════

def _acc_paths(name):
    """凭据文件读点候选：DATA_DIR → ROOT → HERE。"""
    if _dd is not None:
        return _dd.candidates(name)
    return [os.path.join(ROOT, name), os.path.join(HERE, name)]


def load_accounts():
    """读取 tabbit_accounts.json。
    dict: {"Tabbit·国内版": {"cookie": "...", "base": "...", ...}}
    list: [{"name": "...", "cookie": "...", ...}]
    """
    accs = {}
    for path in _acc_paths("tabbit_accounts.json"):
        if not os.path.exists(path):
            continue
        try:
            data = dec_cred(json.load(open(path, encoding="utf-8")))
        except Exception:
            continue
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, dict) and (v.get("cookie") or "").strip():
                    accs[str(k)] = v
        elif isinstance(data, list):
            for i, it in enumerate(data):
                if isinstance(it, dict) and (it.get("cookie") or "").strip():
                    nm = str(it.get("name") or "Tabbit%d" % (i + 1))
                    accs[nm] = it
    return accs


def base_of(ent):
    return (str((ent or {}).get("base") or BASE_DOM)).rstrip("/")


def version_of(ent):
    return str((ent or {}).get("version") or DEFAULT_VERSION)


def _cookie_of(ent):
    return str((ent or {}).get("cookie") or "").strip()


# ════════════════════════════════════════════════════════════════
# JWT（登录态）
# ════════════════════════════════════════════════════════════════

_JWT_RE = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def _b64json(seg):
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def jwt_payload(cookie_str):
    """从 cookie 串里找 JWT 并解 payload（无 JWT 返回 None）。"""
    for m in _JWT_RE.finditer(str(cookie_str or "")):
        try:
            j = _b64json(m.group(0).split(".")[1])
        except Exception:
            continue
        if isinstance(j, dict) and ("exp" in j or "sub" in j):
            return j
    return None


def stable_uid(cookie_str):
    """稳定身份：JWT 的 sub（账号主键，换 cookie 不变）；取不到返回空串。
    供 cred_store.ensure_identity 回填 user_id（IDENT_FIELDS 首位）。"""
    j = jwt_payload(cookie_str)
    if not j:
        return ""
    return str(j.get("sub") or j.get("userId") or j.get("uid") or "").strip()


def token_exp(ent):
    """JWT exp（unix 秒）；无 JWT 返回 None。"""
    j = jwt_payload(_cookie_of(ent))
    return (j or {}).get("exp")


def expired(ent):
    """登录态是否已过期。无 JWT（判不了）返回 None——不当作过期，
    由上游 401/403 暴露（绝不静默吞掉）。"""
    exp = token_exp(ent)
    if not exp:
        return None
    return exp < time.time()


# ════════════════════════════════════════════════════════════════
# 签名 / 指纹（逆向自前端 60442 / 38363 模块）
# ════════════════════════════════════════════════════════════════

def _sha256_hex(text):
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def sign_headers(body, key):
    """body 字符串 → {x-timestamp, x-nonce, x-signature}。
    ⚠ 命名反直觉（前端原文如此）：x-signature 是 UUID，x-nonce 才是 HMAC。"""
    ts = str(int(time.time() * 1000))
    sig = str(uuid.uuid4())
    msg = "%s.%s.%s" % (ts, sig, _sha256_hex(body))
    nonce = hmac.new(key.encode("utf-8"), msg.encode("utf-8"),
                     hashlib.sha256).hexdigest()
    return {"x-timestamp": ts, "x-nonce": nonce, "x-signature": sig}


def make_unique_uuid(is_default=True):
    """unique-uuid：index 5 = 默认浏览器标记位（'1' = 已设）。
    时间戳位 [2,7,11,14,18,21,25,28] 嵌 Unix 秒 hex（前端原样）。"""
    hexchs = "0123456789abcdef"
    marker_pos, marker = 5, "1"
    ts_pos = [2, 7, 11, 14, 18, 21, 25, 28]
    ts = format(int(time.time()), "08x")[-8:]
    ts_map = {p: ts[i] for i, p in enumerate(ts_pos)}
    pool = hexchs.replace(marker, "")          # 非标记位字符集（去掉 '1'）
    out = []
    for i in range(32):
        if i == marker_pos:
            out.append(marker if is_default else pool[int.from_bytes(os.urandom(2), "big") % len(pool)])
        elif i in ts_map:
            out.append(ts_map[i])
        else:
            out.append(pool[int.from_bytes(os.urandom(2), "big") % len(pool)])
    s = "".join(out)
    return "-".join([s[:8], s[8:12], s[12:16], s[16:20], s[20:]])


def _base_headers(ent, is_default=True):
    return {
        "Cookie": _cookie_of(ent),
        "trace-id": str(uuid.uuid4()),
        "User-Agent": _UA,
        "Origin": base_of(ent),
        "Referer": base_of(ent) + "/",
        "x-req-ctx": base64.b64encode(version_of(ent).encode("utf-8")).decode("ascii"),
        "unique-uuid": make_unique_uuid(is_default),
    }


def _is_default(ent):
    """账号可覆盖标记位（ent.pro_marker='0' 关）；默认 '1'。
    说明：真实浏览器该位恒为 '1'（反映用户已「设为默认浏览器」这一客户端动作），
    上游仍按账号态校验；免费模型不受影响。"""
    return str((ent or {}).get("pro_marker") or "1") != "0"


# ════════════════════════════════════════════════════════════════
# HTTP（统一绕代理：与看板其余平台一致，本地梯子不掺和）
# ════════════════════════════════════════════════════════════════

def _req(ent, path, method="GET", body=None, sign_key=None, timeout=30,
         extra_headers=None):
    """带签名 + 指纹的请求。返回 requests.Response（调用方判 status）。"""
    url = base_of(ent) + path
    data = body if isinstance(body, (bytes, type(None))) else (
        json.dumps(body, ensure_ascii=False).encode("utf-8"))
    hdr = _base_headers(ent, _is_default(ent))
    if extra_headers:
        hdr.update(extra_headers)
    if sign_key is not None:
        hdr.update(sign_headers(data.decode("utf-8") if data else "", sign_key))
    return requests.request(method, url, data=data, headers=hdr,
                            timeout=timeout, verify=True,
                            proxies={"http": None, "https": None})


def fetch_sign_key(ent, force=False):
    """GET /chat/sign-key（无需签名）。进程级缓存 TTL；失败抛 UpstreamError。"""
    base = base_of(ent)
    with _cache_lock:
        k, ts = _sign_keys.get(base) or (None, 0.0)
        if k and not force and time.time() - ts < SIGN_KEY_TTL:
            return k
    try:
        r = _req(ent, EP_SIGN_KEY, timeout=20)
    except Exception as e:
        raise UpstreamError(502, "Tabbit sign-key 请求失败：%s" % str(e)[:120])
    if r.status_code != 200:
        # 401/403 = cookie 失效；给用户可操作的提示
        if r.status_code in (401, 403):
            raise UpstreamError(503, "Tabbit 登录态已失效（HTTP %s），请重新「从本地客户端导入」或粘贴新 Cookie"
                                % r.status_code)
        raise UpstreamError(r.status_code, "Tabbit sign-key HTTP %s：%s"
                            % (r.status_code, r.text[:150]))
    key = (r.text or "").strip() or DEFAULT_SIGN_KEY
    with _cache_lock:
        _sign_keys[base] = (key, time.time())
    return key


def _invalidate_sign_key(ent):
    with _cache_lock:
        _sign_keys.pop(base_of(ent), None)


# ════════════════════════════════════════════════════════════════
# 模型目录
# ════════════════════════════════════════════════════════════════

def _models_uncached(ent):
    key = fetch_sign_key(ent)
    r = _req(ent, EP_MODELS + "?a=0&scene=chat", sign_key=key, timeout=25)
    if r.status_code != 200:
        raise UpstreamError(r.status_code, "Tabbit 模型列表 HTTP %s：%s"
                            % (r.status_code, r.text[:150]))
    try:
        j = r.json()
    except Exception:
        raise UpstreamError(502, "Tabbit 模型列表响应非 JSON：%s" % r.text[:120])
    cand = ((j.get("data") or {}).get("models")
            or (j.get("data") or {}).get("list")
            or j.get("models") or j.get("data") or [])
    ids = []
    for m in (cand if isinstance(cand, list) else []):
        if not isinstance(m, dict):
            continue
        mid = m.get("display_name") or m.get("model") or m.get("id") or m.get("name")
        if mid:
            ids.append(str(mid))
    return list(dict.fromkeys(ids))


def models(ent, force=False):
    """模型 display_name 列表（TTL 缓存；失败抛 UpstreamError）。"""
    base = base_of(ent)
    with _cache_lock:
        ids, ts = _models_cache.get(base) or ([], 0.0)
        if ids and not force and time.time() - ts < MODELS_TTL:
            return ids
    ids = _models_uncached(ent)
    with _cache_lock:
        if ids:
            _models_cache[base] = (ids, time.time())
    return ids


# ════════════════════════════════════════════════════════════════
# 会话（chat_session_id 必须是已登记会话）
# ════════════════════════════════════════════════════════════════

def fetch_session_list(ent):
    """GET /api/v0/chat/md5-key-sessions/user-sessions?page&size → 会话 UUID 列表。

    2026-10-19 实证：旧 /newtab Server Action（action id 607f3555…）已随前端
    发版过期，POST 恒 500 → 列表空 → 聊天不可用。现行前端（chunk 84664/93945）
    改走这个普通 GET（只需 Cookie，无需签名），响应
    {"sessions":[{"chat_session_id": "...", "chat_session_title": "...", ...}]}。
    """
    r = _req(ent, EP_SESSION_LIST + "?page=1&size=20", timeout=25)
    if r.status_code != 200:
        return []
    r.encoding = "utf-8"
    try:
        j = r.json()
    except Exception:
        # JSON 解析失败的兜底：按 UUID 形状扫（老逻辑保留）
        return list(dict.fromkeys(re.findall(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            r.text or "")))
    sess = (j.get("sessions") if isinstance(j, dict) else None) or []
    ids = [str(s.get("chat_session_id") or "").strip()
           for s in sess if isinstance(s, dict)]
    return [i for i in ids if i]


def create_session(ent):
    """POST /panel/session → 新空会话的 chat_session_id。

    前端新标签页发消息的真实第一步（chunk 38791/80399）：无 entity 时
    连 body 都不带，只要 Accept: application/json。响应 {"chat_session_id": "..."}。
    """
    r = _req(ent, EP_PANEL_SESSION, method="POST", body=None,
             extra_headers={"Accept": "application/json"}, timeout=20)
    if r.status_code != 200:
        raise UpstreamError(r.status_code,
                            "Tabbit 创建会话失败 HTTP %s：%s"
                            % (r.status_code, (r.text or "")[:150]))
    try:
        j = r.json()
    except Exception:
        raise UpstreamError(502, "Tabbit 创建会话响应非 JSON：%s" % (r.text or "")[:120])
    sid = str((j or {}).get("chat_session_id") or "").strip()
    if not sid:
        raise UpstreamError(502, "Tabbit 创建会话响应缺少 chat_session_id：%s"
                            % str(j)[:120])
    return sid


def get_session_id(ent, force=False):
    """取一个可用会话 id（缓存 TTL）。ent.session_id 可手动钉住。

    force=True：跳过缓存与历史列表，直接 POST /panel/session 建新空会话
    （反代每次聊天都用，保证无状态、不串上下文；session 失效重试也走这条）。
    普通路径：缓存 → 历史列表第一个 → 都没有则现场建一个。
    """
    pinned = str((ent or {}).get("session_id") or "").strip()
    if pinned:
        return pinned
    base = base_of(ent)
    if force:
        sid = create_session(ent)
        with _cache_lock:
            _sessions[base] = (sid, time.time())
        return sid
    with _cache_lock:
        sid, ts = _sessions.get(base) or (None, 0.0)
        if sid and time.time() - ts < SESSION_TTL:
            return sid
    with _sess_fetch_lock:                      # 并发时只让一个线程真去拉
        with _cache_lock:
            sid, ts = _sessions.get(base) or (None, 0.0)
            if sid and time.time() - ts < SESSION_TTL:
                return sid
        lst = fetch_session_list(ent)
        sid = lst[0] if lst else create_session(ent)
        with _cache_lock:
            _sessions[base] = (sid, time.time())
        return sid


def _invalidate_session(ent):
    with _cache_lock:
        _sessions.pop(base_of(ent), None)


# ════════════════════════════════════════════════════════════════
# 聊天（OpenAI 反代上游）
# ════════════════════════════════════════════════════════════════

def messages_to_content(messages):
    """OpenAI messages → Tabbit content 字符串。
    单条：直接取文本；多条：带角色标注拼接（Tabbit 会话制，无状态代理自带历史）。"""
    valid = [m for m in (messages or []) if isinstance(m, dict) and m.get("content") is not None]
    if not valid:
        raise UpstreamError(400, "messages 为空")

    def _text(c):
        if isinstance(c, str):
            return c
        if isinstance(c, list):                 # 多模态分片：只取文本部分
            return "".join(str(p.get("text") or "") for p in c
                           if isinstance(p, dict) and p.get("type") in (None, "text"))
        return str(c)

    if len(valid) == 1:
        return _text(valid[0].get("content"))
    role_label = {"assistant": "Assistant", "system": "System", "user": "User"}
    return "\n\n".join("[%s]\n%s" % (role_label.get(m.get("role"), "User"),
                                     _text(m.get("content"))) for m in valid)


def _tabbit_body(session_id, model, content):
    return json.dumps({
        "chat_session_id": session_id,
        "message_id": None,
        "content": content,
        "selected_model": model,
        "parallel_group_id": None,
        "task_name": "chat",
        "agent_mode": False,
        "metadatas": {"html_content": "<p>%s</p>" % content},
        "references": [],
        "entity": {"key": "d41d8cd98f00b204e9800998ecf8427e",
                   "extras": {"type": "tab", "url": ""}},
    }, ensure_ascii=False)


def _openai_chunk(cid, created, model, delta, finish=None, usage=None):
    ch = {"id": cid, "object": "chat.completion.chunk", "created": created,
          "model": model, "choices": [{"index": 0, "delta": delta,
                                       "finish_reason": finish}]}
    if usage:
        ch["usage"] = usage
    return "data: " + json.dumps(ch, ensure_ascii=False)


def _err_chunk(cid, created, model, msg, code=""):
    return "data: " + json.dumps({
        "id": cid, "object": "chat.completion.chunk", "created": created,
        "model": model, "choices": [{"index": 0, "delta": {}, "finish_reason": None}],
        "error": {"message": msg, "type": "upstream_error", "code": code},
        # error_code 让 openai_proxy 非流式聚合路径能识别并抛错（流式路径直接透传）
        "error_code": code or "tabbit_error", "error_msg": msg,
    }, ensure_ascii=False)


def _map_upstream_error(status, text):
    """上游错误 → 用户可操作的中文提示。"""
    t = str(text or "")
    if status in (401, 403) or "未登录" in t:
        return 503, ("Tabbit 登录态已失效（HTTP %s）。请打开 Tabbit 浏览器确认已登录，"
                     "然后在看板「从本地客户端导入」或粘贴新 Cookie" % status)
    if status == 492 or "premium" in t.lower():
        return 403, ("该模型需要 Pro 会员：在 Tabbit 浏览器设置里「设为默认浏览器」可免费解锁，"
                     "或改用免费计量模型（Default / DeepSeek / Kimi / GLM 等）")
    if status == 493:
        act = "set_default_browser" if "set_default_browser" in t else (
            "update_version" if "update_version" in t else "")
        if act == "update_version":
            return 400, ("Tabbit 版本号被拒（493 update_version）：账号里的 version 格式/值过旧，"
                         "需更新为浏览器 getDeviceInfo().tabbitVersion 真实值")
        return 403, ("Tabbit 要求先「设为默认浏览器」（493 set_default_browser）："
                     "在 Tabbit 设置里点一下即可，免费解锁 Standard 档")
    if status == 429:
        return 429, "Tabbit 上游限流（429），请稍后重试"
    if status == 499:
        return 502, "Tabbit 签名 key 失效（499），已自动刷新，请重试"
    return status, "Tabbit 上游 HTTP %s：%s" % (status, t[:200])


def _session_stale(j):
    """上游以「会话未登记」秒拒时的特征（2026-10-19 实证）：
    SSE error 事件无 code，message 含「AI服务暂时不可用」。
    随机 UUID / 已失效会话都是这个报错——换新会话重试即可。"""
    if not isinstance(j, dict):
        return False
    if str(j.get("code") or j.get("status") or "").strip():
        return False                    # 带码的是风控/权益类，不走重试
    msg = str(j.get("message") or j.get("details") or "")
    return "AI服务暂时不可用" in msg


def _normalize_usage(u):
    """Tabbit usage 事件 → OpenAI usage（字段名尽量兼容）。"""
    if not isinstance(u, dict):
        return None
    pt = u.get("prompt_tokens", u.get("input_tokens", u.get("prompt")))
    ct = u.get("completion_tokens", u.get("output_tokens", u.get("completion")))
    tt = u.get("total_tokens", u.get("total"))
    if pt is None and ct is None and tt is None:
        return None
    pt = int(_num(pt)); ct = int(_num(ct))
    return {"prompt_tokens": pt, "completion_tokens": ct,
            "total_tokens": int(_num(tt)) or (pt + ct)}


def _thinking_text(j):
    # 实测（2026-10-19）：thinking 事件的文本字段是 reasoning_content
    for k in ("reasoning_content", "content", "text", "thinking",
              "reasoning", "delta"):
        v = j.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def chat_stream(ent, openai_body, timeout=CHAT_TIMEOUT):
    """OpenAI 请求体 → Tabbit SSE → OpenAI chunk 行迭代器（恒流式，非流式由调用方聚合）。

    model 字段：调用方（openai_proxy）已剥掉 "tb:" 前缀；空 → "Default"。
    会话：每次聊天现场 POST /panel/session 建新空会话（无状态不串上下文）；
          若上游秒拒「会话未登记」（无 code + AI服务暂时不可用），换新会话重试一次。
    思考：thinking 事件以 <think>…</think> 包裹并入正文流（多数客户端不渲染
          reasoning_content，会「转圈半天不吐字」——2026-10-20 修复）。
    错误处理：HTTP/SSE error 事件 → 产出 OpenAI error chunk（含 error_code），
    调用方流式透传 / 非流式抛错。cookie 失效类错误在消息里给可操作指引。
    """
    cookie = _cookie_of(ent)
    if not cookie:
        raise UpstreamError(503, "Tabbit 账号未配置 Cookie，请先「从本地客户端导入」或粘贴")
    if expired(ent) is True:
        raise UpstreamError(503, "Tabbit 登录态已过期（JWT exp 已过），请重新导入或粘贴新 Cookie")

    model = str(openai_body.get("model") or "").strip() or "Default"
    content = messages_to_content(openai_body.get("messages"))
    cid = "chatcmpl-" + uuid.uuid4().hex[:24]
    created = int(time.time())

    key = fetch_sign_key(ent)

    def _post(sign_key, body):
        return requests.post(
            base_of(ent) + EP_CHAT, data=body.encode("utf-8"),
            headers={**_base_headers(ent, _is_default(ent)),
                     "Content-Type": "application/json",
                     "Accept": "text/event-stream",
                     "Cache-Control": "no-cache",
                     **sign_headers(body, sign_key)},
            timeout=timeout, verify=True, stream=True,
            proxies={"http": None, "https": None})

    def _open(session_id):
        """开一轮聊天请求 → Response（已判 HTTP / SSE content-type）。"""
        body = _tabbit_body(session_id, model, content)
        try:
            r = _post(key, body)
            if r.status_code == 499:             # 签名 key 失效：刷新重试一次
                _invalidate_sign_key(ent)
                k = fetch_sign_key(ent, force=True)
                r = _post(k, body)
            if r.status_code >= 400:
                st, msg = _map_upstream_error(r.status_code, r.text[:300])
                raise UpstreamError(st, msg)
            ct = r.headers.get("content-type") or ""
            if "event-stream" not in ct:
                st, msg = _map_upstream_error(r.status_code, r.text[:300])
                raise UpstreamError(502, "Tabbit 响应非 SSE（%s）：%s"
                                    % (ct[:60], msg[:150]))
        except UpstreamError:
            raise
        except Exception as e:
            raise UpstreamError(502, "Tabbit 聊天请求失败：%s" % str(e)[:150])
        # ⚠ 上游 SSE Content-Type 不带 charset，requests 按 ISO-8859-1 解码会中文乱码
        r.encoding = "utf-8"
        return r

    def _iter_events(resp):
        """SSE 原始行 → (event_name, j)。event 名只对紧随的一条 data 帧生效。"""
        event = None
        for raw in resp.iter_lines(decode_unicode=True):
            if raw is None:
                continue
            line = raw.rstrip("\r")
            if not line.strip():
                continue                     # 帧分隔空行
            if line.startswith("event:"):
                event = line[6:].strip()
                continue
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if not data:
                continue
            try:
                j = json.loads(data)
            except Exception:
                event = None
                continue
            if not isinstance(j, dict):
                event = None
                continue
            # 事件名取 SSE event: 行；上游也曾只把 type 放在 data 里，两者都认
            ev = event or j.get("type") or "message_chunk"
            event = None
            yield ev, j

    _OUTPUT_EVENTS = {"thinking", "message_chunk", "usage",
                      "message_finish", "finish", "error"}

    def _first_output(evgen):
        """读到第一个产出型事件（ready/message_start 等无产出帧跳过）。
        返回 (event, j) 或 None（流空 / 只有 [DONE]）。"""
        for ev, j in evgen:
            if ev in _OUTPUT_EVENTS:
                return ev, j
        return None

    def _convert(evgen, first):
        """事件流 → OpenAI chunk 行（恒以 data: [DONE] 收尾）。

        thinking 事件并入正文流（<think>…</think> 包裹，逐帧透传）：
        上游思考常达 10-60s 且 reasoning_content 字段多数客户端不渲染，
        观感是「转圈半天不吐字」（2026-10-20 实测：复杂问题前 8.6s 全是
        思考、2435 字）。<think> 标签被主流客户端折叠渲染；不认的客户端
        至少立刻见字，不再白屏等待。
        """
        usage, done = None, False
        think_open = False       # 当前思考块是否已发 <think> 开头
        think_pending = False    # 思考帧已产出、待补 </think> 闭合
        queue = [first] if first else []
        try:
            while True:
                if queue:
                    ev, j = queue.pop(0)
                else:
                    item = next(evgen, None)
                    if item is None:
                        break
                    ev, j = item
                if ev == "message_chunk":
                    c = j.get("content")
                    if c:
                        if think_pending:
                            yield _openai_chunk(cid, created, model,
                                                {"content": "\n</think>\n\n"})
                            think_pending = False
                            think_open = False
                        yield _openai_chunk(cid, created, model, {"content": c})
                elif ev == "thinking":
                    t = _thinking_text(j)
                    if t:
                        if not think_open:
                            yield _openai_chunk(cid, created, model,
                                                {"content": "<think>\n"})
                            think_open = True
                        think_pending = True
                        yield _openai_chunk(cid, created, model, {"content": t})
                elif ev == "usage":
                    usage = _normalize_usage(j.get("usage") or j) or usage
                elif ev in ("message_finish", "finish"):
                    if think_pending:
                        yield _openai_chunk(cid, created, model,
                                            {"content": "\n</think>\n\n"})
                        think_pending = False
                        think_open = False
                    yield _openai_chunk(cid, created, model, {}, "stop", usage)
                    done = True
                elif ev == "error":
                    code = str(j.get("code") or j.get("status") or "")
                    raw = str(j.get("message") or j.get("details") or "")
                    if code in ("401", "403", "492", "493"):
                        _invalidate_session(ent)
                    # 已知风控/权益码 → 用户可操作的中文提示；未知码保留上游原文
                    if code in ("401", "403", "429", "492", "493", "499"):
                        _, msg = _map_upstream_error(int(code), raw)
                    else:
                        msg = raw
                    if think_pending:    # 思考中出错也要闭合，防后续被当思考吞掉
                        yield _openai_chunk(cid, created, model,
                                            {"content": "\n</think>\n\n"})
                        think_pending = False
                    yield _err_chunk(cid, created, model, msg, code)
                    done = True
                elif ev in ("close", "cancel"):
                    break
        except Exception:
            pass                                # 客户端断开等 IO 错误：收尾
        finally:
            if think_pending:                   # 流意外中断同样闭合思考块
                yield _openai_chunk(cid, created, model,
                                    {"content": "\n</think>\n\n"})
                think_pending = False
            if not done:
                yield _openai_chunk(cid, created, model, {}, "stop", usage)
            yield "data: [DONE]"

    # 每次聊天都现场建新空会话（POST /panel/session）：无状态、不串上下文。
    # 上游若以「会话未登记」秒拒（error 无 code + "AI服务暂时不可用"），
    # 换新会话重试一次——2026-10-19 实证随机/失效 UUID 正是这个报错。
    session_id = get_session_id(ent, force=True)
    for attempt in (1, 2):
        r = _open(session_id)
        evgen = _iter_events(r)
        first = _first_output(evgen)
        if first and first[0] == "error" and _session_stale(first[1]) and attempt == 1:
            r.close()
            _invalidate_session(ent)
            session_id = get_session_id(ent, force=True)
            continue
        yield _openai_chunk(cid, created, model, {"role": "assistant"})
        yield from _convert(evgen, first)
        return


# ════════════════════════════════════════════════════════════════
# 签到（纯 HTTP，只靠 Cookie）
# ════════════════════════════════════════════════════════════════

def gen_request_no(is_default=True):
    """request_no = 32 位 hex（还原扩展 en() 算法）：
    位置 [2,7,11,14,18,21,25,28] 填 Unix 秒 hex(8 位)；
    第 5 位是默认浏览器标记 '1'；其余位随机。"""
    hexchs = "0123456789abcdef"
    ts_pos = [2, 7, 11, 14, 18, 21, 25, 28]
    ts = format(int(time.time()), "08x")[-8:]
    ts_map = {p: ts[i] for i, p in enumerate(ts_pos)}
    pool = hexchs.replace("1", "")
    out = []
    for i in range(32):
        if i == 5:
            out.append("1" if is_default else pool[int.from_bytes(os.urandom(2), "big") % len(pool)])
        elif i in ts_map:
            out.append(ts_map[i])
        else:
            out.append(pool[int.from_bytes(os.urandom(2), "big") % len(pool)])
    return "".join(out)


def _signin_status(ent):
    """GET 签到状态 → (daily_dict 或 None, err)。"""
    qs = "&".join("scene_codes=%s" % urllib.parse.quote(s) for s in SCENE_CODES)
    r = _req(ent, EP_SIGNIN_STATUS + "?" + qs, timeout=25)
    if r.status_code != 200:
        return None, "签到状态查询失败（HTTP %s）：%s" % (r.status_code, r.text[:120])
    try:
        j = r.json()
    except Exception:
        return None, "签到状态响应非 JSON：%s" % r.text[:120]
    results = j.get("results") or (j.get("data") or {}).get("results") or []
    for s in results:
        if s.get("scene_code") == "daily_sign_in":
            return s, None
    return None, "签到状态里没有 daily_sign_in 场景：%s" % str(j)[:120]


def _daily_scene(j):
    for s in (j.get("results") or (j.get("data") or {}).get("results") or []):
        if s.get("scene_code") == "daily_sign_in":
            return s
    return None


# ════════════════════════════════════════════════════════════════
# 读取（账号卡片）
# ════════════════════════════════════════════════════════════════

def read_account(name, ent):
    empty = {"name": name, "ok": False, "error": None, "level": "Tabbit",
             "signed_today": False,
             "credits": {"remain": 0, "total": 0, "used": 0},
             "packages": [], "extra": {}}
    if not _cookie_of(ent):
        empty["error"] = "未配置 Cookie（请点「从本地客户端导入」或粘贴）"
        return empty

    exp = token_exp(ent)
    ex = {"base": base_of(ent), "version": version_of(ent)}
    if exp:
        ex["token_expire"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(exp))
        ex["token_remain_days"] = max(0, round((exp - time.time()) / 86400, 1))
    j = jwt_payload(_cookie_of(ent))
    if j:
        ex["platform_account"] = str(j.get("sub") or "")[:24]
        ph = j.get("phone") or j.get("phoneNumber") or j.get("mobile")
        if ph:
            ex["phone"] = str(ph)

    daily, err = _signin_status(ent)
    if daily is None:
        if err and ("401" in err or "403" in err or "未登录" in err):
            empty["error"] = "Tabbit 登录态已失效，请重新「从本地客户端导入」或粘贴新 Cookie"
        else:
            empty["error"] = err
        empty["extra"] = ex
        return empty

    signed = bool(daily.get("signed_today"))
    ex["signed_today"] = signed
    ex["streak_days"] = daily.get("signed_days")
    ex["total_signed_days"] = daily.get("total_signed_days")
    empty.update({"ok": True, "signed_today": signed, "extra": ex})
    return empty


# ════════════════════════════════════════════════════════════════
# 任务（一键签到）
# ════════════════════════════════════════════════════════════════

def run_task(name, ent, task_key):
    if task_key != "checkin":
        return {"ok": False, "msg": "未知任务"}
    if not _cookie_of(ent):
        return {"ok": False, "msg": "未配置 Cookie"}

    daily, err = _signin_status(ent)
    if daily is None:
        return {"ok": False, "msg": err}
    if daily.get("signed_today"):
        return {"ok": True, "flag": "ALREADY_TODAY",
                "msg": "今日已签到（连续 %s 天）" % (daily.get("signed_days") or "?")}

    body = json.dumps({"request_no": gen_request_no(_is_default(ent)),
                       "scene_codes": SCENE_CODES}, ensure_ascii=False)
    try:
        r = _req(ent, EP_SIGNIN, method="POST", body=body,
                 extra_headers={"Content-Type": "application/json"}, timeout=25)
    except Exception as e:
        return {"ok": False, "msg": "签到请求失败：%s" % str(e)[:120]}
    if r.status_code != 200:
        return {"ok": False, "msg": "签到失败（HTTP %s）：%s" % (r.status_code, r.text[:120])}
    try:
        j = r.json()
    except Exception:
        return {"ok": False, "msg": "签到响应非 JSON：%s" % r.text[:120]}
    res = _daily_scene(j) or {}
    result = str(res.get("sign_in_result") or "")
    if result in ("success", "already_signed"):
        days = res.get("signed_days")
        msg = "签到成功（连续 %s 天）" % days if days is not None else "签到成功"
        return {"ok": True, "flag": "SUCCESS", "msg": msg}
    return {"ok": False, "msg": str(res.get("message") or j.get("message") or str(j)[:120])}


if __name__ == "__main__":
    accs = load_accounts()
    print("账号:", list(accs.keys()))
    for nm, ent in accs.items():
        r = read_account(nm, ent)
        ex = r["extra"] or {}
        print("[%s] ok=%s signed=%s 连签=%s 到期=%s err=%s"
              % (nm, r["ok"], r["signed_today"], ex.get("streak_days"),
                 ex.get("token_expire"), r["error"]))
