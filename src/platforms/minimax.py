# -*- coding: utf-8 -*-
"""
MiniMax Code 每日签到 · 看板平台适配器
═════════════════════════════════════════════════════════════════════════
移植自开源方案 welldo/QinglongMy/minimax_checkin.py（MIT，仅供个人学习使用）。

接口口径（逆向自 MiniMax Code 桌面端 app.asar，原脚本已逐字节验证）：
    续期登录  https://agent.minimax.io/v1/api/user/renewal        (POST, body {})
    状态查询  https://agent.minimax.io/minimax-cloud/api/v1/signin/status (GET)
    领取积分  https://agent.minimax.io/minimax-cloud/api/v1/signin/claim   (POST, body {})

签名头（每个请求必带）：
    token        : <JWT accessToken>（仅出现在 HTTP 头，不进签名计算）
    x-timestamp  : 秒级时间戳
    x-signature  : md5("{x_timestamp}I*7Cf%WZ#S&%1RlZJ&C2{body}")
    yy           : md5( encodeURIComponent(path?query) + "_" + "{}" + md5(now_ms) + "ooui" )

本适配器只做「续期 -> 状态 -> 领取」，并暴露看板统一的
load_accounts / read_account / run_task 接口。
"""
import os, sys, json, time, re, glob, hashlib, base64, shutil, urllib.parse
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("缺少依赖 requests，请先：pip install requests")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# ── 域名回退顺序（实测）─────────────────────────────────────────────
# 国内账号走 agent.minimax.cn：本机实测 ~0.2s 即响应，签到接口完全可用；
# agent.minimax.io 的 DNS 优先返回 IPv6（Akamai），而本机 IPv6 不可达，
# 每次请求要等 ~20s 超时再回退 IPv4，两次即 ~40s —— 这是「看板卡住」的真凶。
# 因此默认 cn 优先，io 仅作回退；可用环境变量 MINIMAX_HOST 强制指定。
_HOST_ENV = (os.environ.get("MINIMAX_HOST") or "").strip().rstrip("/")
HOSTS = [h for h in (_HOST_ENV, "https://agent.minimax.cn", "https://agent.minimax.io") if h]
RENEW_PATH = "/v1/api/user/renewal"
USER_INFO_PATH = "/v1/api/user/info"
STATUS_PATH = "/minimax-cloud/api/v1/signin/status"
CLAIM_PATH = "/minimax-cloud/api/v1/signin/claim"
# 积分明细（2026-10-08 逆向 app.asar + 实测打通）：
#   GET /minimax-cloud/api/v1/credit/details?page&page_size
#   → {"details":[{"credit_type","granted_amount","remaining_amount","consumed_amount",
#                  "granted_at_ms","expire_at_ms"}], "total_count"}
# 这是积分看板的数据源（签到 status 只给 7 天日历的 points，不含账户余额）。
CREDIT_PATH = "/minimax-cloud/api/v1/credit/details"

# 新版（v2）认证存储：OAuth 令牌，令牌形如 mmoat_…，必须走 Authorization: Bearer。
# 切换客户端账号时会覆写这里；而 ~/.minimax/local-runtime.auth.json 是旧版遗留文件，
# 账号切换后不会更新 —— 这正是"切换账号后导入仍是旧账号"的根因。
AUTH_STORE_GLOB = os.path.join(os.path.expanduser("~"), ".minimax", "auth", "*", "*", "*", "auth.json")
CN_CONFIG = os.path.join(os.environ.get("APPDATA") or "", "MiniMax", "minimax-agent-cn-config.json")
OLD_AUTH_FILE = os.path.join(os.path.expanduser("~"), ".minimax", "local-runtime.auth.json")

PLATFORM = "minimax"
LABEL = "MiniMax Code"
TASKS = [{"key": "checkin", "label": "每日签到", "daily": True}]

CACHE_FILE = os.path.join(HERE, ".minimax_token.json")
_DEFAULT_UUID = "3548c8fa-9ac2-4a28-8f6b-71ecd88bc048"
_DEFAULT_DEVICE_ID = "1790426211"

DEVICE_PARAM_ORDER = [
    "device_platform", "biz_id", "app_id", "version_code", "unix",
    "timezone_offset", "is_desktop", "desktop_version", "sys_language",
    "lang", "uuid", "device_id", "os_name", "browser_name", "device_memory",
    "cpu_core_num", "browser_language", "browser_platform", "user_id",
    "op_ticket", "screen_width", "screen_height",
]


# ───────────────────────── 工具 ─────────────────────────
def _md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def encode_uri_component(s: str) -> str:
    """忠实复刻 JS encodeURIComponent：仅放行 A-Za-z0-9 - _ . ! ~ * ' ()，其余 %XX 大写。"""
    return re.sub(r'([^A-Za-z0-9\-_.!~*\'()])',
                  lambda m: '%%%02X' % ord(m.group(1)), s)


def build_device_params(user_id, uuid_str, device_id):
    now_ms = int(round(datetime.now(timezone.utc).timestamp() * 1000))
    values = {
        "device_platform": "web", "biz_id": "3", "app_id": "3001", "version_code": "22201",
        "unix": str(now_ms), "timezone_offset": "28800", "is_desktop": "1", "desktop_version": "",
        "sys_language": "en", "lang": "en", "uuid": uuid_str, "device_id": device_id,
        "os_name": "Windows", "browser_name": "Chrome", "device_memory": "16", "cpu_core_num": "4",
        "browser_language": "zh-CN", "browser_platform": "Win32", "user_id": str(user_id),
        "op_ticket": "undefined", "screen_width": "1536", "screen_height": "864",
    }
    return {k: values[k] for k in DEVICE_PARAM_ORDER}


def _sign_request(path, token, params, method, body, auth_mode="token"):
    """计算签名所需 query 串/请求头/body 串。返回 (params, headers, body_str)。"""
    now_ms = int(round(datetime.now(timezone.utc).timestamp() * 1000))
    now_sec = now_ms // 1000
    params = dict(params)
    params["unix"] = str(now_ms)
    params["client"] = "desktop"
    query = urllib.parse.urlencode(params)
    has_search_params_path = f"{path}?{query}"
    body_str = "" if method.lower() == "get" else json.dumps(body or {}, ensure_ascii=False)
    x_signature = _md5_hex(f"{now_sec}I*7Cf%WZ#S&%1RlZJ&C2{body_str}")
    inner = _md5_hex(str(now_ms))
    yy = _md5_hex(encode_uri_component(has_search_params_path) + "_" + "{}" + inner + "ooui")
    headers = {
        "token": token, "yy": yy,
        "x-timestamp": str(now_sec), "x-signature": x_signature,
        "origin": "https://agent.minimax.io", "referer": "https://agent.minimax.io/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) MiniMaxAgent/desktop Chrome/124.0 Safari/537.36",
    }
    if auth_mode == "bearer":
        # 新版 v2 认证（OAuth access_token，形如 mmoat_…）走 Authorization: Bearer。
        # 实测：mmoat 令牌用 Bearer → 200，改用旧 token 头 → 401；JWT 反过来亦然。
        # 两种令牌不可互换，必须按令牌形态选择鉴权头。
        headers.pop("token", None)
        headers["Authorization"] = "Bearer " + token
    if method.lower() != "get":
        headers["content-type"] = "application/json"
    return params, headers, body_str


def detect_auth_mode(token):
    """按令牌形态判断鉴权方式：JWT(eyJ…) → 旧 token 头；其余（mmoat_/mmort_）→ Bearer。"""
    t = (token or "").strip()
    if not t:
        return "token"
    return "token" if t.startswith("eyJ") else "bearer"


def ent_auth_mode(ent, token):
    mode = (ent or {}).get("auth_mode")
    return mode if mode in ("token", "bearer") else detect_auth_mode(token)



def _b64url_decode(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def decode_token(token):
    try:
        parts = str(token or "").split(".")
        if len(parts) != 3:
            return 0, ""
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        return int(payload.get("exp") or 0), str((payload.get("user") or {}).get("id") or "")
    except Exception:
        return 0, ""


def clean_env_value(raw):
    if raw is None:
        return ""
    s = str(raw).strip().strip("\ufeff").strip()
    while len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1].strip()
    return s


def load_persistent_device():
    uid = clean_env_value(os.environ.get("MINIMAX_UUID", ""))
    did = clean_env_value(os.environ.get("MINIMAX_DEVICE_ID", ""))
    if uid and did:
        return uid, did
    return (uid or _DEFAULT_UUID), (did or _DEFAULT_DEVICE_ID)


# ── user_id 语义（实测踩坑，务必注意）──────────────────────────────
# 签到接口签名里的 user_id 必须是客户端配置中的「realUserID」；
# 若误用 JWT payload 里的 user.id，网关会直接返回 HTTP 401（空 body）。
# 本机实测：realUserID → 200；JWT id → 401。两者并不相等。
def _cn_config_users():
    """读取客户端 cn-config 里的账号列表（user / sharedUser），带 realUserID。"""
    try:
        d = json.load(open(CN_CONFIG, encoding="utf-8"))
    except Exception:
        return []
    out = []
    for key in ("user", "sharedUser"):
        u = d.get(key)
        if isinstance(u, dict) and u.get("realUserID"):
            out.append({"slot": key,
                        "userID": str(u.get("userID") or ""),
                        "realUserID": str(u.get("realUserID") or ""),
                        "userName": str(u.get("userName") or ""),
                        "subUserName": str(u.get("subUserName") or "")})
    return out


def _real_uid_from_local():
    """从本机 MiniMax 客户端配置读取 realUserID（读不到返回 ""）。
    注意顺序：cn-config 是实时更新的，local-runtime.auth.json 是旧版遗留（切换账号后
    不会更新），所以必须把实时文件排在前面，否则会拿到过期账号的 realUserID。"""
    cands = [CN_CONFIG, OLD_AUTH_FILE]
    for p in cands:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        auth = d.get("auth") if isinstance(d.get("auth"), dict) else None
        if auth and auth.get("realUserID"):
            return str(auth["realUserID"])
        usr = d.get("user") if isinstance(d.get("user"), dict) else None
        if usr and usr.get("realUserID"):
            return str(usr["realUserID"])
    return ""


def load_auth_store():
    """读取新版（v2）认证存储 `~/.minimax/auth/<env>/<region>/<clientId>/auth.json`。

    返回 [{"access_token","refresh_token","generation","expires_at_ms","client_id","env","region"}]
    这是切换账号后会实时覆写的那份；旧版 local-runtime.auth.json 不会更新。
    """
    out = []
    for p in sorted(glob.glob(AUTH_STORE_GLOB)):
        parts = p.replace("\\", "/").split("/")
        env, region, client_id = parts[-4], parts[-3], parts[-2]
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        for rec in (d.get("records") or {}).values():
            if not isinstance(rec, dict):
                continue
            tok = clean_env_value(rec.get("accessToken") or "")
            if not tok:
                continue
            out.append({
                "access_token": tok,
                "refresh_token": clean_env_value(rec.get("refreshToken") or ""),
                "generation": rec.get("generation"),
                "expires_at_ms": rec.get("expiresAtMs"),
                "client_id": rec.get("clientId") or client_id,
                "env": env, "region": region,
                "auth_mode": "bearer",
            })
    # 同一账号可能被多次写入（generation 递增），只留最新的一份
    out.sort(key=lambda r: (r.get("expires_at_ms") or 0, r.get("generation") or 0), reverse=True)
    seen, uniq = set(), []
    for r in out:
        if r["access_token"] in seen:
            continue
        seen.add(r["access_token"])
        uniq.append(r)
    return uniq


def fetch_user_info(token, auth_mode="bearer", timeout=15):
    """用令牌向 /v1/api/user/info 换取账号身份（name / subUserName / realUserID / phone）。
    这是唯一可靠的「令牌 ↔ 账号」对应方式（单靠 cn-config 无法区分 user/sharedUser）。
    注意：该接口成功时返回 {"data":..., "statusInfo":...}，**没有** base_resp，
    所以不能用 api_succeeded() 判定，否则恒为 False。"""
    params = build_device_params("", *load_persistent_device())
    try:
        _, code, data = _api_any(token, params, USER_INFO_PATH, method="GET",
                                 timeout=timeout, auth_mode=auth_mode)
    except Exception:
        return None
    if code != 200 or not isinstance(data, dict):
        return None
    ui = ((data.get("data") or {}).get("userInfo")) or {}
    if not ui:
        return None
    return {
        "name": str(ui.get("name") or ""),
        "sub_name": str(ui.get("subUserName") or ""),
        "user_id": str(ui.get("userID") or ""),
        "real_user_id": str(ui.get("realUserID") or ""),
        "phone": str(ui.get("phone") or ""),
    }



def _local_jwt_for(uid):
    """取本机客户端的**长寿命 JWT**（local-runtime.auth.json），若其 realUserID 与 uid 一致。

    背景（2026-10-08 实测）：MiniMax 有两种令牌 ——
      · mmoat_ Bearer（v2 auth store / OAuth 设备码授权）：寿命仅 ~1h，refresh_token 是
        **轮换式**且一方用过即作废（实测续期直接 400 invalid_grant），所以频繁 401；
      · JWT（local-runtime.auth.json）：寿命 ~40 天，实测同一 user_id 可直接调通
        /signin/status（code 200）。
    因此当 Bearer 401/403 且续期也失败时，回退到本机 JWT 兜底，避免看板长期挂红字 401。
    uid 为空或 JWT 不属于该账号时返回 ("", "")，不做跨账号误用。
    """
    if not uid:
        return "", ""
    try:
        d = json.load(open(OLD_AUTH_FILE, encoding="utf-8"))
    except Exception:
        return "", ""
    auth = d.get("auth") if isinstance(d.get("auth"), dict) else None
    if not auth:
        return "", ""
    jwt = clean_env_value(auth.get("accessToken") or "")
    jwt_uid = str(auth.get("realUserID") or "")
    if not jwt or (jwt_uid and jwt_uid != str(uid)):
        return "", ""
    if not _token_alive(jwt):
        return "", ""
    return jwt, auth.get("region") or "cn"


def resolve_user_id(ent, token):
    """确定签名用的 user_id：凭据字段 → 本地客户端 realUserID → JWT id（最后兜底）。"""
    uid = clean_env_value(ent.get("user_id", ""))
    if uid:
        return uid
    uid = _real_uid_from_local()
    if uid:
        return uid
    return decode_token(token)[1]


def _token_alive(token):
    if not token:
        return False
    exp, _ = decode_token(token)
    if exp == 0:
        return True
    return exp - time.time() > 60


# ── Bearer(mmoat_) 令牌续期 ────────────────────────────────────────────
# 新版令牌寿命只有 1 小时，到期就 401。桌面端靠 refreshToken 静默换新；
# 看板侧用同一条 OAuth 接口（oauth_login.refresh_grant）自动续期，
# 把新令牌写回凭据文件，用户不必再手动「重新导入」。
def _cred_file_path():
    for p in (os.path.join(ROOT, "minimax_accounts.json"),
              os.path.join(HERE, "minimax_accounts.json")):
        if os.path.exists(p):
            return p
    return os.path.join(HERE, "minimax_accounts.json")


def _persist_grant(name, ent, grant):
    """把续期得到的新令牌原地写回看板凭据文件（键名被改过则按 realUserID 找回）。"""
    path = _cred_file_path()
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return
    if not isinstance(data, dict):
        return
    rec, key = data.get(name), name
    if not isinstance(rec, dict):
        uid = clean_env_value(ent.get("user_id", ""))
        rec = None
        for k, v in data.items():
            if uid and isinstance(v, dict) and str(v.get("user_id") or "") == uid:
                rec, key = v, k
                break
    if not isinstance(rec, dict):
        return
    rec["access_token"] = grant["access_token"]
    if grant.get("refresh_token"):
        rec["refresh_token"] = grant["refresh_token"]
    if grant.get("expires_in"):
        rec["expires_at_ms"] = int((time.time() + float(grant["expires_in"])) * 1000)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
    except Exception:
        pass


def refresh_bearer_token(name, ent):
    """用 refresh_token 静默续期 Bearer 令牌。成功返回新 access_token，失败返回 ""。"""
    rt = clean_env_value(ent.get("refresh_token", ""))
    if not rt:
        return ""
    try:
        import oauth_login
    except Exception:
        return ""
    ok, grant, _ = oauth_login.refresh_grant("minimax", rt, ent.get("region") or "cn")
    if not ok or not (grant or {}).get("access_token"):
        return ""
    g = {"access_token": grant["access_token"],
         "refresh_token": grant.get("refresh_token") or rt,
         "expires_in": grant.get("expires_in") or 3600}
    _persist_grant(name, ent, g)
    ent["access_token"] = g["access_token"]
    ent["refresh_token"] = g["refresh_token"]
    ent["expires_at_ms"] = int((time.time() + float(g["expires_in"])) * 1000)
    save_token_cache(g["access_token"], "oauth_refresh")
    return g["access_token"]


def _maybe_refresh(name, ent, mode):
    """Bearer 令牌临期（<5 分钟）或无 expires_at_ms 时先续期一次，避免看板红字 401。"""
    if mode != "bearer" or not clean_env_value(ent.get("refresh_token", "")):
        return False
    ms = ent.get("expires_at_ms")
    if ms and (float(ms) / 1000.0 - time.time()) > 300:
        return False
    return bool(refresh_bearer_token(name, ent))


def load_token_cache():
    try:
        if not os.path.isfile(CACHE_FILE):
            return ""
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            return clean_env_value(json.load(fh).get("token") or "")
    except Exception:
        return ""


def save_token_cache(token, source="renewal"):
    if not token:
        return False
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump({"token": token, "source": source, "updated_at": int(time.time())}, fh)
        return True
    except Exception:
        return False


# ───────────────────────── 凭据 ─────────────────────────
def _cred_file_items():
    """读看板凭据文件（ROOT 优先，其次 HERE），返回 [(备注名, 条目)]。
    键名就是用户在「修改备注名」里设的名字，必须比客户端自动派生名优先。"""
    out = []
    for path in (os.path.join(ROOT, "minimax_accounts.json"),
                 os.path.join(HERE, "minimax_accounts.json")):
        if not os.path.exists(path):
            continue
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            out += [(str(k), v) for k, v in data.items()]
        elif isinstance(data, list):
            out += [(str(it.get("name") or it.get("user_id") or "MiniMax%d" % (i + 1)), it)
                    for i, it in enumerate(data) if isinstance(it, dict)]
    return out


def _remark_index(items):
    """{uid:<realUserID> | tok:<access_token> → 用户备注名}"""
    idx = {}
    for nm, v in items:
        if not (isinstance(v, dict) and nm):
            continue
        uid = clean_env_value(v.get("user_id", ""))
        tok = clean_env_value(v.get("access_token", ""))
        if uid:
            idx["uid:" + uid] = nm
        if tok:
            idx.setdefault("tok:" + tok, nm)
    return idx


def load_accounts():
    """凭据来源（**令牌新鲜度**优先级从高到低）：
       0) 新版 v2 认证存储 ~/.minimax/auth/<env>/<region>/<clientId>/auth.json
          （切换客户端账号后实时更新，令牌形如 mmoat_，走 Authorization: Bearer）
       1) 环境变量 MINIMAX_TOKEN（单账号；MINIMAX_USER_ID 可选）
       2) 凭据文件 ROOT/minimax_accounts.json 或 HERE/minimax_accounts.json（dict/list）
       3) 续期缓存 .minimax_token.json（同目录）

    **显示名**优先级相反：看板凭据文件的键名（用户改过的备注名）> 客户端派生名。
    否则给「客户端当前活跃账号」改的备注名，每次刷新都会被打回 subUserName
    （v2 存储里的账号总是排在前面，派生名会把备注名盖掉）。

    同一账号在多处各存一份令牌时按 realUserID / access_token 归并成一条，
    免得切换账号后看板上凭空多出重复卡片。
    """
    cred_items = _cred_file_items()
    remark = _remark_index(cred_items)

    accs = {}
    by_tok, by_uid = {}, {}

    def _put(derived, ent):
        uid = clean_env_value(ent.get("user_id", ""))
        tok = ent.get("access_token") or ""
        exist = (by_tok.get(tok) if tok else None) or (by_uid.get(uid) if uid else None)
        if exist:
            # 同一账号已收录：补齐它缺的字段；但**令牌本身要让到期更晚的那个获胜**。
            # 典型场景：v2 存储里还留着旧令牌，而用户刚用「网页授权」换了新令牌 ——
            # 若一味保留先到者，看板会拿旧令牌去签到，眼看就要 401。
            cur = accs[exist]
            new_ms, cur_ms = ent.get("expires_at_ms"), cur.get("expires_at_ms")
            fresher = bool(new_ms and (not cur_ms or float(new_ms) > float(cur_ms)))
            for k, val in ent.items():
                if val in (None, ""):
                    continue
                if fresher and k in ("access_token", "refresh_token", "expires_at_ms",
                                     "auth_mode", "source"):
                    cur[k] = val
                elif cur.get(k) in (None, ""):
                    cur[k] = val
            return
        nm = (remark.get("uid:" + uid) if uid else None) or (remark.get("tok:" + tok) if tok else None) or derived
        base, i = nm, 2
        while nm in accs:                       # 兜底：万一备注名撞车
            nm, i = "%s-%d" % (base, i), i + 1
        accs[nm] = ent
        if tok:
            by_tok[tok] = nm
        if uid:
            by_uid[uid] = nm

    # ── 0) 新版 v2 认证存储 ────────────────────────────────────────
    cn_by_uid = {u["userID"]: u for u in _cn_config_users() if u.get("userID")}
    for rec in load_auth_store():
        tok = rec["access_token"]
        mode = rec.get("auth_mode") or "bearer"
        info = fetch_user_info(tok, mode)
        cn = cn_by_uid.get((info or {}).get("user_id", "")) or {}
        nm = ((info or {}).get("sub_name") or cn.get("subUserName")
              or (info or {}).get("name") or cn.get("userName")
              or ("MiniMax·" + tok[-6:]))
        body = {
            "access_token": tok,
            "auth_mode": mode,
            "user_id": (info or {}).get("real_user_id") or cn.get("realUserID") or "",
            "refresh_token": rec.get("refresh_token") or "",
            "source": "客户端当前登录（v2）",
            "expires_at_ms": rec.get("expires_at_ms"),
        }
        if info and info.get("phone"):
            body["phone"] = info["phone"]
        _put(nm, body)

    # ── 1) 环境变量 ────────────────────────────────────────────────
    tok = clean_env_value(os.environ.get("MINIMAX_TOKEN", ""))
    uid = clean_env_value(os.environ.get("MINIMAX_USER_ID", ""))
    if tok:
        _put("MiniMax", {"access_token": tok, "user_id": uid,
                         "auth_mode": detect_auth_mode(tok)})

    # ── 2) 凭据文件（看板自己存的：带备注名 / phone / 来源）────────
    for nm, v in cred_items:
        if not (isinstance(v, dict) and v.get("access_token")):
            continue
        t2 = clean_env_value(v["access_token"])
        ent = {"access_token": t2,
               "user_id": clean_env_value(v.get("user_id", "")),
               "auth_mode": v.get("auth_mode") or detect_auth_mode(t2)}
        for f in ("phone", "refresh_token", "source", "expires_at", "expires_at_ms",
                  "via_local", "via_browser", "via_oauth", "client_name"):
            if v.get(f) not in (None, ""):
                ent[f] = v[f]
        _put(nm, ent)

    # 续期缓存仅在「读过所有正式凭据后仍为空」时兜底，避免与正式账号重复显示
    ctok = load_token_cache()
    if ctok and not accs:
        _put("MiniMax", {"access_token": ctok, "user_id": uid,
                         "auth_mode": detect_auth_mode(ctok)})

    # 缺 user_id 的账号用本地客户端的 realUserID 补齐：否则 status/claim 会 401，
    # 或返回误导性的 "invalid timezone_id"。
    # ⚠ 只在「确实只有一个账号」时兜底：本地那份 realUserID 只是当前 user 槽位的账号，
    #   多账号下把它硬塞给每个账号，等于拿 A 号的 user_id 去签 B 号的请求 → 必然 401。
    if accs:
        missing = [e for e in accs.values() if not e.get("user_id")]
        if missing and len(accs) == 1:
            local_uid = _real_uid_from_local()
            if local_uid:
                missing[0]["user_id"] = local_uid
    # 标注看板凭据文件（minimax_accounts.json）真正管理的账号：其 _key = 文件里的键名。
    # 看板把「客户端 v2 存储」与「看板凭据文件」按身份归并成同一张卡片，v2 存储优先级更高、
    # 命名不同，会把文件键名盖掉成显示名；而「删除 / 改名」只能按文件键定位，否则就会出现
    # 「显示名删不掉 → 未找到该账号」。这里把真实文件键回写到条目上，前端据此操作。
    # 仅客户端会话、未存盘的账号 _key 为空 → 看板不提供删除（本就删不了客户端会话）。
    _cred_ident = {}
    for _k, _v in cred_items:
        if not (isinstance(_v, dict) and _v.get("access_token")):
            continue
        _uid = clean_env_value(_v.get("user_id", ""))
        _tok = clean_env_value(_v.get("access_token", ""))
        if _uid:
            _cred_ident["uid:" + _uid] = _k
        if _tok:
            _cred_ident.setdefault("tok:" + _tok, _k)
    for _ent in accs.values():
        if _ent.get("_key"):
            continue
        _uid = clean_env_value(_ent.get("user_id", ""))
        _tok = _ent.get("access_token") or ""
        _k = (_cred_ident.get("uid:" + _uid) if _uid else None) \
             or (_cred_ident.get("tok:" + _tok) if _tok else None)
        if _k:
            _ent["_key"] = _k
    return accs


# ───────────────────────── 请求 ─────────────────────────
def remove_local_session(name):
    """删除「仅存在于客户端会话（v2 auth store）」的账号的本地登录记录。

    背景：v2 auth store 里的记录若令牌过期且身份反查失败，卡片只能用派生名
    （MiniMax·xxxxxx），且凭据文件里没有对应条目 → 按「凭据文件键」删除必然
    「未找到该账号」。这类卡片的本体就是 auth.json 里那条记录：删记录 = 删卡。

    返回 (ok, msg)。删除前把 auth.json 备份为 *.bak-删卡前。
    注意：若 MiniMax 客户端随后又用该会话刷新，记录可能被客户端写回（属正常）。
    """
    accs = load_accounts()
    ent = accs.get(name)
    if not ent:
        return False, "看板当前没有这个名字的账号"
    tok = clean_env_value(ent.get("access_token", ""))
    if not tok:
        return False, "该账号没有本地令牌记录可删"
    removed_any, last_err = False, ""
    for p in glob.glob(AUTH_STORE_GLOB):
        try:
            with open(p, "r", encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception as e:
            last_err = str(e)[:80]
            continue
        recs = d.get("records")
        hit_keys = []
        if isinstance(recs, dict):
            hit_keys = [k for k, r in recs.items()
                        if isinstance(r, dict)
                        and clean_env_value(r.get("accessToken") or "") == tok]
        elif isinstance(recs, list):
            hit_keys = [i for i, r in enumerate(recs)
                        if isinstance(r, dict)
                        and clean_env_value(r.get("accessToken") or "") == tok]
        if not hit_keys:
            continue
        try:
            shutil.copy2(p, p + ".bak-删卡前")     # 先备份再动手
            for k in hit_keys:
                if isinstance(recs, dict):
                    recs.pop(k, None)
                else:
                    recs[k] = None
            if isinstance(recs, list):
                d["records"] = [r for r in recs if r is not None]
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(d, fh, ensure_ascii=False, indent=2)
            removed_any = True
        except Exception as e:
            last_err = str(e)[:80]
    if removed_any:
        return True, "已删除客户端会话记录（已备份 auth.json）"
    return False, ("凭据文件里没有该账号，客户端会话记录也未能删除"
                   + ("（%s）" % last_err if last_err else ""))


def _api(host, token, params, path, method="GET", body=None, timeout=30, auth_mode="token"):
    sp, headers, body_str = _sign_request(path, token, params, method, body, auth_mode)
    try:
        r = requests.Request(method.upper(), host + path, params=sp,
                              headers=headers, data=body_str or None).prepare()
        s = requests.Session()
        resp = s.send(r, timeout=timeout, verify=False)
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, {"raw": resp.text[:300]}
    except Exception as e:
        return 0, {"error": str(e)}


def _api_any(token, params, path, method="GET", body=None, timeout=15, auth_mode="token"):
    """按 HOSTS 顺序尝试，返回第一个有响应的结果：(host, code, data)。

    cn 不可达时自动回退 io，避免单域名故障把整个签到卡死。
    """
    last_code, last_data = 0, {"error": "所有域名均不可达"}
    for h in HOSTS:
        code, data = _api(h, token, params, path, method=method, body=body,
                          timeout=timeout, auth_mode=auth_mode)
        if code:
            return h, code, data
        last_code, last_data = code, data
    return HOSTS[0], last_code, last_data


def api_succeeded(data):
    if not isinstance(data, dict):
        return False
    br = data.get("base_resp") or {}
    if isinstance(br, dict) and br.get("status_code") == 0:
        return True
    code = data.get("code")
    if isinstance(code, (int, float)) and code in (0, 200):
        return True
    if isinstance(code, str) and code.strip() in ("0", "200"):
        return True
    if data.get("success") is True:
        return True
    return str(data.get("status", "")).lower() == "success"


def _renew(token, params, auth_mode="token"):
    """旧版 JWT 可续期；新版 Bearer 令牌不适用该端点（实测返回 400），直接跳过。"""
    if auth_mode == "bearer":
        return "", 0, ""
    _, code, data = _api_any(token, params, RENEW_PATH, method="POST", body={},
                             auth_mode=auth_mode)
    if isinstance(data, dict):
        new = ((data.get("data") or {}).get("token") or "").strip()
        if new:
            return new, code, ""
    return "", code, str((data.get("message") or data.get("msg") or (data.get("error") if isinstance(data, dict) else "")) or "")


def _try_checkin(user_id, token, source, auth_mode="token"):
    uid, did = load_persistent_device()
    base = build_device_params(user_id, uid, did)
    renewed = ""
    new_token, rcode, rmsg = _renew(token, base, auth_mode)
    if new_token:
        renewed = new_token
        token = new_token
        auth_mode = "token"          # 续期返回的是 JWT
        save_token_cache(new_token, "renewal")
    elif rcode:
        pass  # 沿用原 token 继续

    sc, sb = _api_any(token, base, STATUS_PATH, method="GET", auth_mode=auth_mode)[1:]
    if not api_succeeded(sb):
        msg = str(sb.get("message") or sb.get("msg") or json.dumps(sb, ensure_ascii=False)[:150] if isinstance(sb, dict) else "")
        br = ((sb or {}).get("base_resp") or {}) if isinstance(sb, dict) else {}
        if isinstance(br, dict) and br.get("status_msg"):
            msg = str(br["status_msg"])
        if "invalid timezone_id" in msg:
            msg += "（通常是签名 user_id 为空导致，请重新「从本地客户端导入」）"
        return "STATUS_ERR", "状态查询异常：HTTP %s %s" % (sc, msg)
    days = (((sb or {}).get("data") or {}).get("days")) or []
    today = next((d for d in days if d.get("is_today")), None)
    if today and today.get("status") == 3:
        extra = "（已自动续期 token）" if renewed else ""
        return "ALREADY_TODAY", "今日已签到（第 %s 天）%s" % (today.get("day_no"), extra)

    cc, cb = _api_any(token, base, CLAIM_PATH, method="POST", body={}, auth_mode=auth_mode)[1:]
    if not api_succeeded(cb):
        msg = str(cb.get("message") or cb.get("msg") or json.dumps(cb, ensure_ascii=False)[:150] if isinstance(cb, dict) else "")
        return "FAIL", "领取未成功：HTTP %s %s" % (cc, msg)
    cdata = (cb or {}).get("data") or {}
    claim_result = cdata.get("claim_result")
    points = cdata.get("points")
    extra = "（已自动续期 token）" if renewed else ""
    if claim_result == 2:
        return "ALREADY_TODAY", "今日已签到（claim_result=2）%s" % extra
    if claim_result == 1 or points is not None:
        gain = ("本次 +%s 积分" % points) if points else "签到成功"
        return "SUCCESS", "%s（第 %s 天）%s" % (gain, cdata.get("day_no"), extra)
    return "SUCCESS", "领取成功%s" % extra


def fetch_credits(token, uid, auth_mode="bearer"):
    """拉取积分明细（积分看板数据源）。返回统一结构：

        {"ok":bool, "total":剩余总额, "granted":累计发放, "used":已消耗,
         "count":笔数, "nearest_expire_ms":最近到期(ms), "items":[{...}]}

    对应接口 GET /minimax-cloud/api/v1/credit/details（见 CREDIT_PATH 注释）。
    失败时返回 ok=False + error，调用方降级展示，不影响签到主流程。
    """
    out = {"ok": False, "total": 0.0, "granted": 0.0, "used": 0.0,
           "count": 0, "nearest_expire_ms": 0, "items": [], "error": None}
    try:
        base = build_device_params(uid, *load_persistent_device())
        _h, sc, sb = _api_any(token, dict(base, page=1, page_size=100),
                              CREDIT_PATH, method="GET", auth_mode=auth_mode)
    except Exception as e:
        out["error"] = "积分请求异常：%s" % str(e)[:80]
        return out
    if sc != 200 or not isinstance(sb, dict) or "details" not in sb:
        out["error"] = "积分查询失败（HTTP %s）：%s" % (
            sc, json.dumps(sb, ensure_ascii=False)[:100] if isinstance(sb, dict) else str(sb)[:60])
        return out
    items, tot_g, tot_r, tot_c, nearest = [], 0.0, 0.0, 0.0, 0
    for d in (sb.get("details") or []):
        if not isinstance(d, dict):
            continue
        g = float(d.get("granted_amount") or 0)
        r = float(d.get("remaining_amount") or 0)
        c = float(d.get("consumed_amount") or 0)
        exp = int(d.get("expire_at_ms") or 0)
        tot_g += g; tot_r += r; tot_c += c
        if r > 0 and exp and (nearest == 0 or exp < nearest):
            nearest = exp
        items.append({
            "type": d.get("credit_type"),
            "granted": g, "remaining": r, "consumed": c,
            "granted_at_ms": int(d.get("granted_at_ms") or 0),
            "expire_at_ms": exp,
        })
    items.sort(key=lambda x: x.get("expire_at_ms") or 0)
    # 转成前端 packages 口径（{name,amount,remain,expire,source,perpetual}）供 pkgGroups 聚合。
    # 每笔 credit 明细就是一个「积分包」，名称带发放日期，方便在明细里分辨来源。
    pkgs = []
    for it in items:
        exp_ms = it.get("expire_at_ms") or 0
        pkgs.append({
            "name": "签到/活动积分",
            "amount": it["granted"],
            "remain": it["remaining"],
            "used": it["consumed"],
            "expire": (time.strftime("%Y-%m-%d", time.localtime(exp_ms / 1000.0))
                       if exp_ms else None),
            "source": "measured",
            "kind": "积分",
            "perpetual": not bool(exp_ms),
        })
    return {"ok": True, "total": tot_r, "granted": tot_g, "used": tot_c,
            "count": len(items), "nearest_expire_ms": nearest,
            "items": items, "packages": pkgs, "error": None}


# ───────────────────────── 统一接口 ─────────────────────────
def read_account(name, ent):
    token = clean_env_value(ent.get("access_token", ""))
    if not token:
        return {"name": name, "ok": False, "error": "未配置 MINIMAX_TOKEN",
                "key": ent.get("_key") or name,
                "level": "?", "signed_today": False,
                "credits": {"remain": 0, "total": 0, "used": 0}, "packages": []}
    mode = ent_auth_mode(ent, token)
    # Bearer 令牌临期先静默续期：否则看板上会出现刺眼的红字 401
    _maybe_refresh(name, ent, mode)
    token = clean_env_value(ent.get("access_token", "")) or token
    exp, _ = decode_token(token)
    uid0 = resolve_user_id(ent, token)
    base = build_device_params(uid0, *load_persistent_device())
    sc, sb = 0, {}
    used_jwt = False
    try:
        sc, sb = _api_any(token, base, STATUS_PATH, method="GET", auth_mode=mode)[1:]
        if not api_succeeded(sb) and mode == "bearer" and sc in (401, 403):
            # 令牌在两次检查之间过期了：续期后重试一次
            if refresh_bearer_token(name, ent):
                token = ent["access_token"]
                uid0 = resolve_user_id(ent, token)
                base = build_device_params(uid0, *load_persistent_device())
                sc, sb = _api_any(token, base, STATUS_PATH, method="GET", auth_mode=mode)[1:]
        # ★ 兜底回退：Bearer 仍 401/403（refresh_token 已轮换作废，续期救不回来）时，
        #   改用本机客户端的**长寿命 JWT**（同账号）再试一次 —— 实测能直接调通。
        if not api_succeeded(sb) and sc in (401, 403):
            jwt, _rg = _local_jwt_for(uid0)
            if jwt:
                jbase = build_device_params(uid0, *load_persistent_device())
                jsc, jsb = _api_any(jwt, jbase, STATUS_PATH, method="GET", auth_mode="token")[1:]
                if api_succeeded(jsb):
                    sc, sb, mode, token, base, used_jwt = jsc, jsb, "token", jwt, jbase, True
    except Exception as e:
        return {"name": name, "ok": False, "error": "请求异常：%s" % str(e)[:80],
                "key": ent.get("_key") or name,
                "level": "?", "signed_today": False,
                "credits": {"remain": 0, "total": 0, "used": 0}, "packages": [],
                "extra": {"exp_days": round((exp - time.time()) / 86400, 1) if exp else None}}
    if not api_succeeded(sb):
        br = (sb or {}).get("base_resp") or {}
        msg = (str((sb or {}).get("message") or (sb or {}).get("msg")
                   or (br.get("status_msg") if isinstance(br, dict) else "")
                   or json.dumps(sb, ensure_ascii=False)[:80]))
        if "invalid timezone_id" in msg:
            msg = "签名 user_id 为空（请重新「从本地客户端导入」）"
        if sc in (401, 403) or "invalid" in msg.lower() and mode == "bearer":
            msg += "；令牌已失效且自动续期未成功（refresh_token 已被客户端轮换作废）"
        return {"name": name, "ok": False,
                "key": ent.get("_key") or name,
                "error": "登录态查询失败（HTTP %s）：%s" % (sc, msg),
                "level": "?", "signed_today": False,
                "credits": {"remain": 0, "total": 0, "used": 0}, "packages": [],
                "extra": {"exp_days": round((exp - time.time()) / 86400, 1) if exp else None}}
    days = (((sb or {}).get("data") or {}).get("days")) or []
    today = next((d for d in days if d.get("is_today")), None)
    signed = bool(today and today.get("status") == 3)
    # 有效期：Bearer 令牌看存储里的 expiresAtMs；JWT 看 exp
    exp_days = None
    if mode == "bearer":
        ms = ent.get("expires_at_ms")
        if ms:
            exp_days = round((float(ms) / 1000.0 - time.time()) / 86400.0, 2)
    if exp_days is None and exp:
        exp_days = round((exp - time.time()) / 86400, 1)
    lvl = "MiniMax" if (ent.get("user_id") or exp) else "?"
    # 积分明细（积分看板数据源）：失败不影响签到卡，只把 credits_ok 置 False
    cred = fetch_credits(token, uid0, mode)
    credits = ({"remain": round(cred["total"]), "granted": round(cred["granted"]),
                "used": round(cred["used"]), "count": cred["count"],
                "nearest_expire_ms": cred["nearest_expire_ms"], "items": cred["items"]}
               if cred.get("ok") else {"remain": 0, "total": 0, "used": 0})
    packages = cred.get("packages") or [] if cred.get("ok") else []
    return {
        "name": name, "ok": True, "error": None,
        "key": ent.get("_key") or name,
        "level": lvl,
        "signed_today": signed,
        "credits": credits,
        "credits_ok": bool(cred.get("ok")),
        "credits_error": cred.get("error"),
        "packages": packages,
        "extra": {"exp_days": exp_days,
                  "day_no": (today or {}).get("day_no"),
                  "auth_mode": mode,
                  "phone": ent.get("phone"),
                  # 带 refresh_token 的 Bearer 令牌能静默续期，倒计时不再有意义（免得常年红字）
                  "refreshable": mode == "bearer" and bool(clean_env_value(ent.get("refresh_token", ""))),
                  "source": ent.get("source")},
    }


def run_task(name, ent, task_key):
    if task_key != "checkin":
        return {"ok": False, "msg": "未知任务"}
    token = clean_env_value(ent.get("access_token", ""))
    if not token:
        return {"ok": False, "msg": "未配置 MINIMAX_TOKEN"}
    mode = ent_auth_mode(ent, token)
    _maybe_refresh(name, ent, mode)
    token = clean_env_value(ent.get("access_token", "")) or token
    user_id = resolve_user_id(ent, token)
    try:
        flag, content = _try_checkin(user_id, token, "env", mode)
    except Exception as e:
        return {"ok": False, "msg": "执行异常：%s" % str(e)[:80]}
    ok = flag in ("SUCCESS", "ALREADY_TODAY")
    # 撞上 Bearer 令牌过期 → 静默续期后重试一次（用户无感）
    if not ok and mode == "bearer" and flag == "STATUS_ERR" and \
            ("401" in content or "403" in content or "invalid" in content.lower()):
        if refresh_bearer_token(name, ent):
            tk = ent["access_token"]
            try:
                flag, content = _try_checkin(resolve_user_id(ent, tk), tk, "env", mode)
                ok = flag in ("SUCCESS", "ALREADY_TODAY")
                content += "（已自动续期登录态）"
            except Exception as e:
                return {"ok": False, "msg": "续期后重试异常：%s" % str(e)[:80]}
    return {"ok": ok, "msg": content, "flag": flag}
