# -*- coding: utf-8 -*-
"""
多平台账号看板 · 本地后端（平台注册表）
═════════════════════════════════════════════════════════════════════════
给 index.html 提供真实数据与操作能力：
  GET  /            → 看板页面（index.html）
  GET  /api/state   → 所有平台 / 所有账号状态
  POST /api/run     → 执行操作：按 platform + 账号 + 任务（可异步）
  POST /api/refresh → 强制刷新，忽略缓存

只监听 127.0.0.1，凭据与 token 不出本机。

平台适配器约定（platforms/<id>.py）：
  PLATFORM / LABEL / TASKS
  load_accounts() -> {name: cred}
  read_account(name, ent) -> 归一化状态 dict
  run_task(name, ent, task_key) -> {ok, msg, ...}

启动：
  python server.py            # 默认 http://127.0.0.1:8799
  python server.py 9000       # 指定端口
"""
import os, sys, json, time, itertools, threading, hashlib
import concurrent.futures as cf
import http.server, socketserver, urllib.parse
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    import requests
except ImportError:
    sys.exit("缺少依赖 requests，请先：pip install requests")

import importlib, importlib.util

try:
    import workbuddy_login as wblogin
except Exception as _e:
    wblogin = None
    print("⚠ 未加载 workbuddy_login，网页端 WorkBuddy 短信登录将不可用：%s" % _e)

try:
    import oauth_login
except Exception as _e:
    oauth_login = None
    print("⚠ 未加载 oauth_login，网页授权（手机号）登录将不可用：%s" % _e)

# ── 网页端「添加账号」凭据落盘 ──
# 落盘位置与各适配器 load_accounts 读取的候选文件一致，写后即被看板识别：
#   WorkBuddy  → HERE/wb_login_result.json          （fetch_state 候选路径之一）
#   MiniMax    → HERE/minimax_accounts.json         （ROUND之一）
#   DuMate     → HERE/dumate_accounts.json         （ROOT之一）
WB_LOGIN_FILE = os.path.join(HERE, "wb_login_result.json")
MINIMAX_ACCOUNTS_FILE = os.path.join(HERE, "minimax_accounts.json")
DUMATE_ACCOUNTS_FILE = os.path.join(HERE, "dumate_accounts.json")
LINGXI_ACCOUNTS_FILE = os.path.join(HERE, "lingxi_accounts.json")
TRAE_ACCOUNTS_FILE = os.path.join(HERE, "trae_accounts.json")
QODER_ACCOUNTS_FILE = os.path.join(HERE, "qoder_accounts.json")
ZCODE_ACCOUNTS_FILE = os.path.join(HERE, "zcode_accounts.json")
OFFICEACE_ACCOUNTS_FILE = os.path.join(HERE, "officeace_accounts.json")
CODEARTS_ACCOUNTS_FILE = os.path.join(HERE, "codearts_accounts.json")

# 各平台的凭据文件（供「添加 / 删除 / 本地导入」统一寻址）
CRED_FILES = {
    "minimax": MINIMAX_ACCOUNTS_FILE,
    "baidu_dumate": DUMATE_ACCOUNTS_FILE,
    "lingxi": LINGXI_ACCOUNTS_FILE,
    "trae": TRAE_ACCOUNTS_FILE,
    "qoder": QODER_ACCOUNTS_FILE,
    "zcode": ZCODE_ACCOUNTS_FILE,
    "officeace": OFFICEACE_ACCOUNTS_FILE,
    "codearts": CODEARTS_ACCOUNTS_FILE,
}
# 支持「从本地客户端导入」的平台
LOCAL_IMPORT_PLATFORMS = ("baidu_dumate", "minimax", "lingxi", "trae",
                          "qoder", "zcode", "officeace", "codearts")


def _read_json(path, default):
    try:
        if os.path.exists(path):
            return json.load(open(path, encoding="utf-8"))
    except Exception:
        pass
    return default


def _write_json(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


def _wb_store_append(phone, at, rt):
    """把一条 WorkBuddy 登录结果追加/更新到 wb_login_result.json（list 格式）。"""
    results = _read_json(WB_LOGIN_FILE, [])
    if not isinstance(results, list):
        results = []
    rec = {"phone": phone, "access_token": at, "refresh_token": rt,
           "env_line": "%s:%s:%s" % (phone, at, rt),
           "login_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    for it in results:
        if isinstance(it, dict) and str(it.get("phone")) == phone:
            it.update(rec)
            break
    else:
        results.append(rec)
    _write_json(WB_LOGIN_FILE, results)
    return rec


def _cred_store_set(path, name, fields):
    data = _read_json(path, {})
    if not isinstance(data, dict):
        data = {}
    data[name] = fields
    _write_json(path, data)
    return data


def _cred_store_remove(path, name):
    data = _read_json(path, {})
    if not isinstance(data, dict) or name not in data:
        return False
    data.pop(name, None)
    _write_json(path, data)
    return True


def _invalidate_state():
    """凭据变更后只把缓存标脏，立刻返回。
    前端在拿到响应后会自己再发一次 /api/state，无需在这里同步重读全部平台——
    否则「添加账号 / 从本地客户端导入」按钮要等十几秒才有反应（看起来像点了没反应）。"""
    _state_cache.update(at=0, data=None)


# 各平台「身份指纹」字段（按优先级）：同一个指纹 = 同一个账号，只是显示名/令牌可能变了
# ⚠ minimax 刻意把 user_id(realUserID) 放在 access_token 之前：客户端会轮换 accessToken
#   （v2 store 的 refreshToken 每刷新一次 generation+1，令牌随之变化），
#   若拿令牌当指纹，同一个人换个令牌就会被当成新账号，多出一张卡片。
IDENT_FIELDS = {
    "minimax": ("user_id", "phone", "access_token"),
    "baidu_dumate": ("cookie",),
    "lingxi": ("wps_sid",),
    "trae": ("user_id", "token"),
    "qoder": ("user_id", "token"),
    "zcode": ("user_id", "token"),
    "officeace": ("ak", "user_id"),
    "codearts": ("user_id", "ak"),   # user_id=华为云 domain_id（续期换 AK 后身份不变）
}

# 「粘贴添加」时若用户没填备注名，用这个前缀 + 手机号/ID 尾号 自动起名，
# 避免多个账号全落进同一个键（"MiniMax"）而互相覆盖。
DEFAULT_LABEL = {
    "minimax": "MiniMax", "baidu_dumate": "DuMate", "lingxi": "灵犀",
    "trae": "Trae", "qoder": "Qoder", "zcode": "ZCode",
    "officeace": "OfficeACE", "codearts": "CodeArts",
}


def _ident_of(pid, rec):
    for f in IDENT_FIELDS.get(pid, ()):
        v = str((rec or {}).get(f) or "").strip()
        if v:
            return f, v
    return None


def _wb_match(it, name):
    """WorkBuddy 的条目以手机号为身份，允许用户另设备注名（alias）。"""
    return isinstance(it, dict) and (str(it.get("phone") or "") == name
                                     or str(it.get("alias") or "") == name)


def _dedupe_store(path, pid, keep_name, rec):
    """写入前清掉「同一身份、换了显示名」的旧条目。
    场景：桌面端把显示名从「示例用户C」改成「用户68388451332」，
    再点一次导入，若不去重就会多出一张同名不同键的卡片，账号数被虚增。"""
    data = _read_json(path, {})
    if not isinstance(data, dict):
        return []
    ident = _ident_of(pid, rec)
    if not ident:
        return []
    f, v = ident
    dropped = []
    for nm, old in list(data.items()):
        if nm == keep_name or not isinstance(old, dict):
            continue
        if str(old.get(f) or "").strip() == v:
            data.pop(nm, None)
            dropped.append(nm)
    if dropped:
        _write_json(path, data)
    return dropped


def _name_tail(rec):
    """取一段能区分账号的短尾号，用于同重名时消歧。
    手机号 / 用户 ID 这类可读标识取末 4 位；cookie、token 这类不透明串取 sha1 前 4 位
    （直接截末 4 位会得到 `EN=2` 这种看不懂的碎片）。"""
    rec = rec or {}
    for f in ("phone", "user_id"):
        v = str(rec.get(f) or "").strip()
        if v:
            return v[-4:]
    for f in ("wps_sid", "cookie", "token", "access_token", "sts_token", "secret",
              "refresh_token", "ak"):
        v = str(rec.get(f) or "").strip()
        if v:
            return hashlib.sha1(v.encode("utf-8")).hexdigest()[:4]
    return ""


def _alloc_account_name(path, pid, ideal, rec):
    """为一条凭据挑一个「不会覆盖其他账号」的键名。

    为什么必须做这件事：MiniMax 客户端只有 user / sharedUser 两个登录槽位，
    登录第 3 个号时客户端会把先前槽位顶掉；而两个不同账号的显示名可能完全相同
    （都叫「示例用户」之类）。此时若直接按名字写入字典，后写的就把前面的**覆盖**掉了
    —— 这正是「登了三个号，后面两个号总是互相覆盖」的根因。

    规则：
      ① 同身份（user_id / phone / token …）已存在 → 沿用旧键名（顺便保住用户改过的备注名）
      ② ideal 未被占用 → 直接用
      ③ ideal 被别的身份占用 → 追加尾号，仍冲突则 #2 #3 …
    """
    data = _read_json(path, {})
    if not isinstance(data, dict):
        data = {}
    ident = _ident_of(pid, rec)

    def _same(nm):
        if not ident:
            return False
        old = data.get(nm)
        return isinstance(old, dict) and str(old.get(ident[0]) or "").strip() == ident[1]

    ideal = (ideal or "").strip()
    if not ideal:
        tail = _name_tail(rec)
        ideal = DEFAULT_LABEL.get(pid, pid) + (("·" + tail) if tail else "")

    if ident:
        for nm in data:
            if nm != ideal and _same(nm):
                return nm          # ① 同一账号已存在 → 沿用旧名，绝不新建
    if ideal not in data or _same(ideal):
        return ideal               # ② 名字空着，或就是同一个账号 → 直接用

    tail = _name_tail(rec)
    base = ("%s·%s" % (ideal, tail)) if tail else ideal
    if base not in data or _same(base):
        return base
    i = 2
    while True:
        nm = "%s#%d" % (base, i)
        if nm not in data or _same(nm):
            return nm
        i += 1


def _dumate_web_save(ideal, grant):
    """DuMate 网页直登成功后的落盘：抓到的百度账号 cookie + 身份。返回 (ok, 键名, 提示)。

    grant["user"] 是 _dumate_fetch_user 归一化后的 {"user_id","name"}；身份反查失败
    （user 为空）不再阻塞落盘——BDUSS 本身就是签到凭证，缺昵称用手机号兜底命名。
    """
    ck = (grant or {}).get("cookie") or ""
    if not ck or "BDUSS=" not in ck:
        return False, "", "未抓到有效登录 Cookie（缺 BDUSS）"
    info = (grant or {}).get("user") or {}
    phone = str((grant or {}).get("phone") or "")
    rec = {"cookie": ck, "via_web": True,
           "source": "网页登录（百度账号）",
           "phone": phone,
           "user_id": str(info.get("user_id") or "")}
    fallback = ("DuMate·" + phone[-4:]) if phone else "DuMate"
    use = _save_cred("baidu_dumate", rec,
                     ideal or str(info.get("name") or "") or fallback)
    _invalidate_state()
    return True, use, "登录成功，已保存 DuMate 账号「%s」" % use


def _lingxi_web_save(ideal, grant):
    """灵犀网页直登成功后的落盘：wps_sid + 身份。返回 (ok, 键名, 提示)。"""
    sid = str((grant or {}).get("wps_sid") or "").strip()
    if not sid:
        return False, "", "未抓到 wps_sid"
    rec = {"wps_sid": sid, "via_web": True,
           "source": "网页登录（WPS 手机号）",
           "phone": str((grant or {}).get("phone") or "")}
    use = _save_cred("lingxi", rec, ideal or "灵犀")
    _invalidate_state()
    return True, use, "登录成功，已保存灵犀账号「%s」" % use


def _oauth_save(platform, name, grant):
    """OAuth 设备码授权成功后的落盘：反查账号身份 → 身份安全分配键名 → 写凭据文件。

    抽成函数（而不是闭包）是为了能拿一枚已知令牌单独回归测试，
    不必每次都真的走一遍「用手机收验证码」。
    返回 (ok, 键名, 提示语)。
    """
    mod = PLATFORMS.get(platform)
    tok = (grant or {}).get("access_token") or ""
    info = None
    try:
        info = mod.fetch_user_info(tok, "bearer") if mod else None
    except Exception:
        info = None
    if not info:
        # ZCode 没有可反查身份的公开接口 —— 令牌本身就是稳定指纹
        # （IDENT_FIELDS["zcode"] 以 token 为准），直接落盘即可。
        if platform == "zcode":
            rec = {"token": tok, "secret": "", "user_id": "",
                   "via_oauth": True, "sub": (grant or {}).get("sub") or "",
                   "source": "网页授权登录（%s）" % ((grant or {}).get("sub") or "zai")}
            use = _save_cred("zcode", rec, name or "ZCode")
            _invalidate_state()
            return True, use, "授权成功，已保存 ZCode 账号「%s」" % use
    if platform == "qoder":
        # Qoder：设备流令牌 + /api/v1/userinfo 反查身份（客户端 fetchUser 同款接口）。
        # 落盘字段结构与本地导入保持一致（token 键），IDENT_FIELDS["qoder"] 以 user_id 优先，
        # 令牌轮换也不会丢身份。refresh_token（drt-）用于静默续期。
        inf = info or {}
        exp = str((grant or {}).get("expires_at") or "")
        if not exp and (grant or {}).get("expires_in"):
            try:
                exp = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                    time.gmtime(time.time() + float(grant["expires_in"])))
            except Exception:
                exp = ""
        rec = {"token": tok,
               "refresh_token": (grant or {}).get("refresh_token") or "",
               "expires_at": exp,
               "user_id": str(inf.get("user_id") or ""),
               "phone": inf.get("phone") or "",
               "via_oauth": True, "source": "网页授权登录（Qoder）"}
        ideal = (name or inf.get("name") or
                 ("Qoder·" + (rec["user_id"] or tok)[-4:]))
        use = _save_cred("qoder", rec, ideal)
        _invalidate_state()
        tail = ("　📱 %s" % rec["phone"]) if rec["phone"] else ""
        return True, use, "授权成功，已保存 Qoder 账号「%s」%s" % (use, tail)
    if not info:
        return (False, "", "授权已完成，但拿到的令牌解不出账号身份"
                           "（可能不是同一账号体系）。请把这条提示反馈给看板维护者。")
    rec = {
        "access_token": tok,
        "auth_mode": "bearer",
        "via_oauth": True,
        "refresh_token": (grant or {}).get("refresh_token") or "",
        "expires_at_ms": int((time.time() + float((grant or {}).get("expires_in") or 3600)) * 1000),
        "user_id": str(info.get("real_user_id") or info.get("user_id") or ""),
        "phone": info.get("phone") or "",
        "client_name": info.get("name") or "",
        "source": "网页授权登录（手机号 + 验证码）",
    }
    ideal = (name or info.get("sub_name") or info.get("name")
             or ("MiniMax·" + (rec["user_id"] or tok)[-4:]))
    use = _save_cred(platform, rec, ideal)
    _invalidate_state()
    tail = ("　📱 %s" % rec["phone"]) if rec["phone"] else ""
    return True, use, "授权成功，已保存账号「%s」%s" % (use, tail)


def _codearts_identity(ak, sk, sts):
    """用换到的临时凭据签 GET /v5/caller-identity，取稳定身份（domain_id）。"""
    try:
        import requests as _rq
        import platforms.codearts as cap
        url = "https://sts.cn-north-4.myhuaweicloud.com/v5/caller-identity"
        hdr = cap.sign_headers(ak, sk, sts, "GET", url)
        j = _rq.get(url, headers=hdr, timeout=15, verify=False).json()
        ident = (j or {}).get("identity") or {}
        return (str(ident.get("domain_id") or ident.get("id") or ""),
                str(ident.get("user_name") or ident.get("name") or ""))
    except Exception:
        return "", ""


def _codearts_oauth_save(name, grant):
    """CodeArts 自建会话落盘：凭据 + 续期材料（refresh_token/code_verifier/DPoP 私钥）。"""
    ak = (grant or {}).get("ak") or ""
    sk = (grant or {}).get("sk") or ""
    sts = (grant or {}).get("sts_token") or ""
    if not (ak and sk and sts):
        return False, "", "换取的凭据不完整，未保存"
    uid, uname = _codearts_identity(ak, sk, sts)
    rec = {"ak": ak, "sk": sk, "sts_token": sts,
           "expires_at": (grant or {}).get("expires_at") or "",
           "refresh_token": (grant or {}).get("refresh_token") or "",
           "code_verifier": (grant or {}).get("code_verifier") or "",
           "dpop_priv_pem": (grant or {}).get("dpop_priv_pem") or "",
           "dpop_pub_jwk": (grant or {}).get("dpop_pub_jwk") or "",
           "port": str((grant or {}).get("port") or ""),
           "user_id": uid, "user_name": uname,
           "via_oauth": True, "source": "看板短信登录（自建会话·可自动续期）"}
    ideal = (name or uname or ("CodeArts·" + (uid or rec["ak"])[:4]))
    use = _save_cred("codearts", rec, ideal)
    _invalidate_state()
    return True, use, "登录成功，已保存 CodeArts 账号「%s」（此会话归看板独享，可自动续期）" % use


def _trae_oauth_save(name, grant):
    """Trae OAuth 兑换成功落盘（token + refresh_token + device_id，签到即用）。"""
    tok = (grant or {}).get("access_token") or ""
    if not tok:
        return False, "", "令牌为空，未保存"
    rec = {"token": tok,
           "refresh_token": (grant or {}).get("refresh_token") or "",
           "user_id": str((grant or {}).get("user_id") or ""),
           "region": (grant or {}).get("region") or "CN",
           "host": (grant or {}).get("host") or "https://api.trae.cn",
           "device_id": (grant or {}).get("device_id") or "",
           "mobile": (grant or {}).get("mobile") or "",
           "screen_name": (grant or {}).get("name") or "",
           "via_oauth": True, "source": "网页授权登录（手机号+验证码）"}
    # 名字优先级：用户手填 > 回调 ScreenName > 手机号 > uid 尾4
    # （回调 ScreenName 可能是「示例用户」这类昵称，与旧账号同名时 _save_cred 会自动加尾号，不会覆盖）
    ideal = (name or rec["screen_name"] or rec["mobile"]
             or ("Trae·" + (rec["user_id"] or rec["token"])[-4:]))
    use = _save_cred("trae", rec, ideal)
    _invalidate_state()
    return True, use, "授权成功，已保存 Trae 账号「%s」" % use


def _officeace_login_save(name, grant):
    """OfficeACE 登录落盘：App 本地 API 已交换并持久化新凭据，这里存身份 + 顺手重导入。"""
    uid = str((grant or {}).get("user_id") or "")
    rec = {"user_id": uid, "user_name": (grant or {}).get("user_name") or "",
           "via_oauth": True, "source": "看板短信登录（App 本地 API 交换，App 已存新凭据）"}
    ideal = (name or (grant or {}).get("user_name")
             or ("OfficeACE·" + (uid or "0000")[-4:]))
    use = _save_cred("officeace", rec, ideal)
    refreshed = 0
    try:
        import local_import
        ok, _m, accs = local_import.read_local("officeace")
        if ok and accs:
            target = CRED_FILES["officeace"]
            for i, (nm, ent) in enumerate(dict(accs).items(), 1):
                r2 = {k: v for k, v in dict(ent).items() if k != "name"}
                r2["via_local"] = True
                u2 = _alloc_account_name(target, "officeace", (name or nm), r2)
                _dedupe_store(target, "officeace", u2, r2)
                _cred_store_set(target, u2, r2)
                refreshed += 1
    except Exception:
        pass
    _invalidate_state()
    extra = ("，并从 App 刷新 %d 条凭据" % refreshed) if refreshed else ""
    return True, use, "登录成功，已保存 OfficeACE 账号「%s」%s" % (use, extra)


def _save_cred(pid, fields, ideal=""):
    """按「不覆盖其他账号」的规则落盘一条凭据，返回最终键名。"""
    path = CRED_FILES[pid]
    use = _alloc_account_name(path, pid, ideal, fields)
    _dedupe_store(path, pid, use, fields)
    _cred_store_set(path, use, fields)
    return use


PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
PLATFORM_IDS = ["workbuddy", "minimax", "baidu_dumate", "lingxi", "trae",
                "qoder", "zcode", "officeace", "codearts"]

PLATFORMS = {}
for _pid in PLATFORM_IDS:
    try:
        _mod = importlib.import_module("platforms." + _pid)
        PLATFORMS[_pid] = _mod
    except Exception as e:
        print("⚠ 平台适配器加载失败 %s：%s" % (_pid, e))

CACHE_TTL = 60
_state_cache = {"at": 0, "data": None}
_lock = threading.Lock()
LOG = []


def log(msg):
    line = "[%s] %s" % (datetime.now().strftime("%H:%M:%S"), msg)
    LOG.append(line)
    if len(LOG) > 300:
        del LOG[0]
    try:
        print(line)
    except Exception:
        pass


# ────────────────────────── 状态读取 ──────────────────────────
def _blank_acct(name, err):
    """读取失败时的占位账号，保证前端卡片结构完整（不会因为一条网络异常整片空白）。"""
    return {"name": name, "ok": False, "error": err,
            "credits": {"remain": 0}, "packages": [], "signed_today": False}


def _safe_read(mod, name, ent):
    try:
        return mod.read_account(name, ent)
    except Exception as e:
        return _blank_acct(name, str(e)[:80])


def collect_state(force=False, scope=None):
    """汇总所有平台状态。

    force=True 忽略缓存重读；scope=<pid> 时只重读该平台并合并进上一份快照
    （用于「添加 / 删除 / 导入账号后只刷新受影响的那一个平台」，秒级返回）。
    账号读取全部并发——原实现是「逐平台逐账号顺序读 + 每条 sleep(0.3)」，
    15 个账号要 10~30 秒，导致点完按钮半分钟没反应，看起来像没生效。
    """
    now = time.time()
    # 普通请求走缓存；带 scope 的请求本来就是为了拿最新值，直接重读
    if not force and not scope and _state_cache["data"] and now - _state_cache["at"] < CACHE_TTL:
        return _state_cache["data"]
    if scope and not _state_cache["data"]:
        scope = None   # 还没有底稿可合并，退回全量首读

    with _lock:
        pids = [scope] if (scope in PLATFORMS) else list(PLATFORMS.keys())

        # 1) 先同步读各平台凭据（本地文件/解密，开销极小）并搭好骨架
        pinfos, loaded = {}, []
        for pid in pids:
            mod = PLATFORMS[pid]
            try:
                accs = mod.load_accounts()
            except Exception as e:
                accs = {}
                log("%s 凭据加载失败：%s" % (pid, e))
            has = bool(accs)
            pinfos[pid] = {"id": pid, "label": getattr(mod, "LABEL", pid),
                           "tasks": getattr(mod, "TASKS", []),
                           "has_credentials": has, "accounts": []}
            for nm, ent in accs.items():
                loaded.append((pid, nm, mod, ent))

        # 2) 所有账号的网络读取并发执行（这是唯一的耗时段）
        got = {}
        if loaded:
            workers = max(4, min(12, len(loaded)))
            with cf.ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(_safe_read, mod, nm, ent): (pid, nm)
                        for pid, nm, mod, ent in loaded}
                for fu in cf.as_completed(futs):
                    got[futs[fu]] = fu.result()
        for pid, nm, mod, ent in loaded:
            # 保持凭据文件中的顺序，卡片不会每次刷新乱跳
            pinfos[pid]["accounts"].append(got.get((pid, nm)) or _blank_acct(nm, "读取失败"))

        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if scope and _state_cache["data"]:
            out = json.loads(json.dumps(_state_cache["data"]))   # 深拷贝，避免污染旧快照
            out["platforms"].update(pinfos)
            out["generated_at"] = stamp
            out["log"] = LOG[-40:]
        else:
            out = {"generated_at": stamp, "platforms": pinfos, "log": LOG[-40:]}

        any_cred = any(p.get("has_credentials") for p in out["platforms"].values())
        out["demo"] = not any_cred
        out["backend"] = True   # 本条响应来自真实后端；与「有无凭据」相互独立
        if any_cred:
            out.pop("hint", None)
        else:
            out["hint"] = ("未检测到任何平台凭据。最省事的办法：点右上角「添加账号」→"
                           "「从本地客户端导入」，会自动读取你已登录的桌面端登录态"
                           "（WorkBuddy / MiniMax / DuMate / WPS 灵犀 / Trae / Qoder / ZCode / OfficeACE / CodeArts）。")
        _state_cache.update(at=now, data=out)
        return out


# ────────────────────────── 任务执行 ──────────────────────────
def run_tasks(platform, names=None, tasks=("checkin",), chat_text=None, job=None):
    mod = PLATFORMS.get(platform)
    if not mod:
        return {"ok": False, "error": "未知平台 %s" % platform, "results": []}

    def tick(label):
        if job is not None:
            job["current_name"] = name
            job["current_task"] = label

    accs = mod.load_accounts()
    if not accs:
        return {"ok": False, "error": "未找到 %s 凭据" % platform, "results": []}

    targets = [n for n in (names or []) if n in accs] if names else list(accs.keys())
    results = []
    for name in targets:
        ent = accs[name]
        item = {"name": name, "ok": True, "steps": []}
        for tk in tasks:
            tick(mod.TASKS and tk)
            try:
                r = mod.run_task(name, ent, tk)
            except Exception as e:
                r = {"ok": False, "msg": str(e)[:80]}
            st = {"task": tk, "ok": bool(r.get("ok")),
                  "msg": r.get("msg") or ("完成" if r.get("ok") else "失败")}
            item["steps"].append(st)
            log("%s[%s] %s → %s" % (platform, name, tk, st["msg"]))
            if job is not None:
                job["steps"].append(dict(st, name=name))
                job["done"] = job.get("done", 0) + 1
            time.sleep(0.4)
        item["ok"] = all(st.get("ok") for st in item["steps"]) if item["steps"] else False
        results.append(item)
        time.sleep(0.5)

    collect_state(force=True)
    return {"ok": True, "results": results, "state": collect_state(force=False)}


JOBS = {}
_job_seq = itertools.count(1)
_job_lock = threading.Lock()


def _new_job(total, platform, targets):
    with _job_lock:
        jid = str(next(_job_seq))
        JOBS[jid] = {"total": total, "done": 0, "platform": platform, "targets": targets,
                     "current_name": targets[0] if targets else "", "current_task": "准备中",
                     "steps": [], "results": [], "finished": False, "error": None, "started": time.time()}
        return jid


def run_job(jid, platform, names, tasks, chat_text):
    job = JOBS.get(jid)
    if not job:
        return
    try:
        res = run_tasks(platform, names, tasks, chat_text, job=job)
        job["results"] = res.get("results", [])
        job["state"] = res.get("state")
        job["error"] = res.get("error")
    except Exception as e:
        job["error"] = str(e)[:200]
        log("任务异常：%s" % str(e)[:120])
    finally:
        job["finished"] = True
        job["current_task"] = "已完成"
        with _job_lock:
            for k in [k for k, v in JOBS.items()
                      if v.get("finished") and time.time() - v.get("started", 0) > 180]:
                JOBS.pop(k, None)


def start_job(platform, names, tasks, chat_text):
    mod = PLATFORMS.get(platform)
    if not mod:
        return None, 0, 0
    accs = mod.load_accounts()
    if not accs:
        return None, 0, 0
    targets = [n for n in (names or []) if n in accs] if names else list(accs.keys())
    if not targets:
        return None, 0, 0
    valid_tasks = [t["key"] for t in mod.TASKS]
    tasks = [t for t in (tasks or []) if t in valid_tasks]
    if not tasks:
        return None, 0, 0
    jid = _new_job(len(targets) * len(tasks), platform, targets)
    threading.Thread(target=run_job, args=(jid, platform, names, tasks, chat_text), daemon=True).start()
    return jid, len(targets), len(targets) * len(tasks)


# ────────────────────────── 浏览器辅助登录（DuMate / MiniMax） ──────────────────────────
BLOGINS = {}
_blogin_seq = itertools.count(1)
_blogin_lock = threading.Lock()


def _new_blogin(platform, name):
    with _blogin_lock:
        jid = "bl" + str(next(_blogin_seq))
        BLOGINS[jid] = {"platform": platform, "name": name, "status": "starting",
                        "text": "准备中…", "ok": None, "result": None,
                        "finished": False, "started": time.time()}
        return jid


def _blogin_progress(jid, status, text):
    job = BLOGINS.get(jid)
    if job:
        job["status"] = status
        job["text"] = text


def _has_playwright():
    """浏览器登录依赖 playwright 是否可用（仅影响该功能，不影响其余看板功能）。"""
    try:
        return importlib.util.find_spec("playwright") is not None
    except Exception:
        return False


def _run_blogin(jid, platform, name):
    import browser_login as blmod
    job = BLOGINS.get(jid)
    if not job:
        return
    cb = lambda s, t: _blogin_progress(jid, s, t)
    try:
        ok, msg, cred = blmod.browser_login(platform, cb)
        if ok and cred:
            # 浏览器登录目前只服务 lingxi（抓 wps_sid）；与「粘贴添加」同一套落盘规则
            if platform == "lingxi":
                rec = {"wps_sid": cred, "via_browser": True}
            else:
                rec = {"access_token": cred, "via_browser": True}
            use = _save_cred(platform, rec, name)
            job["name"] = use
            _invalidate_state()
            job["ok"], job["result"] = True, "%s（已保存 %s）" % (msg, use)
        else:
            job["ok"], job["result"] = False, msg
    except Exception as e:
        job["ok"], job["result"] = False, "异常：" + str(e)[:160]
    finally:
        job["finished"] = True
        with _blogin_lock:
            for k, v in list(BLOGINS.items()):
                if v.get("finished") and time.time() - v.get("started", 0) > 600:
                    BLOGINS.pop(k, None)


# ────────────────────────── HTTP 服务 ──────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *a):
        pass

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if p in ("/", "/index.html", "/dashboard"):
            fp = os.path.join(HERE, "index.html")
            try:
                self._send(200, open(fp, "rb").read(), "text/html; charset=utf-8")
            except Exception as e:
                self._send(500, {"error": str(e)})
        elif p == "/api/state":
            try:
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                force = "force" in q
                scope = (q.get("platform") or [""])[0] or None
                self._send(200, collect_state(force=force, scope=scope))
            except Exception as e:
                self._send(500, {"error": str(e)[:200]})
        elif p == "/api/progress":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            jid = (q.get("job") or [""])[0]
            job = JOBS.get(jid)
            if not job:
                self._send(404, {"error": "job not found"})
            else:
                self._send(200, {"job": jid, "total": job["total"], "done": job["done"],
                                  "current_name": job["current_name"], "current_task": job["current_task"],
                                  "steps": job["steps"][-12:], "finished": job["finished"],
                                  "error": job["error"], "results": job["results"] if job["finished"] else []})
        elif p == "/api/log":
            self._send(200, {"log": LOG[-120:]})
        elif p == "/api/account/browser_login_status":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            jid = (q.get("job") or [""])[0]
            job = BLOGINS.get(jid)
            if not job:
                self._send(404, {"error": "job not found"})
            else:
                self._send(200, {"job": jid, "status": job["status"], "text": job["text"],
                                 "finished": job["finished"], "ok": job["ok"],
                                 "result": job["result"], "name": job["name"],
                                 "platform": job["platform"]})
        elif p == "/api/account/oauth_status":
            # 网页授权（手机号登录）任务状态：前端每 1.5 秒轮询一次
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            jid = (q.get("job") or [""])[0]
            if oauth_login is None:
                self._send(200, {"finished": True, "ok": False, "text": "后端未加载 oauth_login 模块"})
            else:
                v = oauth_login.get_job(jid)
                if not v:
                    self._send(404, {"error": "job not found"})
                else:
                    self._send(200, v)
        elif p == "/api/officeace/status":
            # OfficeACE 桌面端本地 API 探活（端口从 runtime-state.json 实时解析）
            if oauth_login is None:
                self._send(200, {"ok": False, "msg": "后端未加载 oauth_login 模块"})
            else:
                try:
                    ok, base, info = oauth_login._officeace_probe(timeout=5)
                except Exception as e:
                    ok, base, info = False, "", {"error": str(e)[:120]}
                try:
                    exe = oauth_login._officeace_exe_path()
                except Exception:
                    exe = None
                self._send(200, {"ok": bool(ok), "api": base, "exe": exe, "info": info})
        elif p == "/api/ping":
            self._send(200, {"ok": True, "port": PORT})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        ln = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            body = {}
        try:
            if p == "/api/run":
                platform = body.get("platform")
                names = body.get("names")
                tasks = tuple(body.get("tasks") or ["checkin"])
                if body.get("async"):
                    jid, n_acc, n_step = start_job(platform, names, tasks, body.get("chat_text"))
                    if not jid:
                        self._send(200, {"ok": False,
                                         "error": "未找到该平台凭据或无可执行账号/任务"})
                    else:
                        self._send(200, {"ok": True, "job": jid, "accounts": n_acc, "total": n_step})
                else:
                    self._send(200, run_tasks(platform, names, tasks, body.get("chat_text")))
            elif p == "/api/refresh":
                self._send(200, collect_state(force=True, scope=body.get("platform") or None))

            # ── 网页端「添加账号」：WorkBuddy 短信两步登录 ──
            elif p == "/api/account/wb_send":
                if not wblogin:
                    self._send(200, {"ok": False, "msg": "后端未加载 workbuddy_login"})
                else:
                    phone = (body.get("phone") or "").strip()
                    if not phone:
                        self._send(200, {"ok": False, "msg": "手机号不能为空"})
                    else:
                        try:
                            ok, msg = wblogin.send_sms(phone)
                            self._send(200, {"ok": ok, "msg": msg})
                        except Exception as e:
                            self._send(200, {"ok": False, "msg": str(e)[:120]})
            elif p == "/api/account/wb_login":
                if not wblogin:
                    self._send(200, {"ok": False, "msg": "后端未加载 workbuddy_login"})
                else:
                    phone = (body.get("phone") or "").strip()
                    code = (body.get("code") or "").strip()
                    if not phone or not code:
                        self._send(200, {"ok": False, "msg": "手机号与验证码都不能为空"})
                    else:
                        try:
                            res = wblogin.login(phone, code)
                        except Exception as e:
                            res = None
                        if not res:
                            self._send(200, {"ok": False, "msg": "登录失败，请检查验证码或重新发送"})
                        else:
                            _wb_store_append(phone, res["accessToken"], res["refreshToken"])
                            _invalidate_state()
                            self._send(200, {"ok": True, "msg": "已保存账号 %s" % phone})

            # ── 批量：多个 WorkBuddy 账号一起发码 / 登录 ──
            elif p == "/api/account/wb_batch_send":
                if not wblogin:
                    self._send(200, {"ok": False, "msg": "后端未加载 workbuddy_login"})
                else:
                    phones = [str(x).strip() for x in (body.get("phones") or []) if str(x).strip()]
                    if not phones:
                        self._send(200, {"ok": False, "msg": "手机号列表为空"})
                    else:
                        details = []
                        for ph in phones:
                            try:
                                ok, msg = wblogin.send_sms(ph)
                                details.append({"phone": ph, "ok": ok, "msg": msg})
                            except Exception as e:
                                details.append({"phone": ph, "ok": False, "msg": str(e)[:80]})
                        self._send(200, {"ok": True, "details": details})
            elif p == "/api/account/wb_batch_login":
                if not wblogin:
                    self._send(200, {"ok": False, "msg": "后端未加载 workbuddy_login"})
                else:
                    phones = [str(x).strip() for x in (body.get("phones") or []) if str(x).strip()]
                    codes = [str(x).strip() for x in (body.get("codes") or []) if str(x).strip()]
                    res_list = []
                    for ph, code in zip(phones, codes):
                        if not code:
                            res_list.append({"phone": ph, "ok": False, "msg": "验证码为空"})
                            continue
                        try:
                            r = wblogin.login(ph, code)
                        except Exception as e:
                            r = None
                        if r:
                            _wb_store_append(ph, r["accessToken"], r["refreshToken"])
                            res_list.append({"phone": ph, "ok": True, "msg": "已保存"})
                        else:
                            res_list.append({"phone": ph, "ok": False, "msg": "登录失败"})
                    _invalidate_state()
                    self._send(200, {"ok": True, "results": res_list})

            # ── MiniMax / DuMate：粘贴 token / cookie 直接落盘 ──
            elif p == "/api/account/add":
                platform = body.get("platform")
                name = (body.get("name") or "").strip()
                if platform == "minimax":
                    token = (body.get("token") or "").strip()
                    if not token:
                        self._send(200, {"ok": False, "msg": "MINIMAX_TOKEN 不能为空"})
                    else:
                        use = _save_cred("minimax",
                                         {"access_token": token,
                                          "user_id": (body.get("user_id") or "").strip()}, name)
                        _invalidate_state()
                        self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
                elif platform == "baidu_dumate":
                    cookie = (body.get("cookie") or "").strip()
                    if not cookie:
                        self._send(200, {"ok": False, "msg": "DuMate Cookie 不能为空"})
                    else:
                        use = _save_cred("baidu_dumate", {"cookie": cookie}, name)
                        _invalidate_state()
                        self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
                elif platform == "lingxi":
                    sid = (body.get("wps_sid") or "").strip()
                    if not sid:
                        self._send(200, {"ok": False, "msg": "wps_sid 不能为空"})
                    else:
                        use = _save_cred("lingxi", {"wps_sid": sid}, name)
                        _invalidate_state()
                        self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
                elif platform == "trae":
                    tok = (body.get("token") or "").strip()
                    if not tok:
                        self._send(200, {"ok": False, "msg": "Trae token 不能为空"})
                    else:
                        use = _save_cred("trae",
                                         {"token": tok,
                                          "device_id": (body.get("device_id") or "").strip(),
                                          "user_id": (body.get("user_id") or "").strip(),
                                          "region": (body.get("region") or "CN").strip()}, name)
                        _invalidate_state()
                        self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
                elif platform == "qoder":
                    tok = (body.get("token") or "").strip()
                    if not tok:
                        self._send(200, {"ok": False, "msg": "Qoder token 不能为空"})
                    else:
                        use = _save_cred("qoder",
                                         {"token": tok,
                                          "refresh_token": (body.get("refresh_token") or "").strip(),
                                          "expires_at": (body.get("expires_at") or "").strip(),
                                          "user_id": (body.get("user_id") or "").strip(),
                                          "phone": (body.get("phone") or "").strip()}, name)
                        _invalidate_state()
                        self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
                elif platform == "zcode":
                    tok = (body.get("token") or "").strip()
                    if not tok:
                        self._send(200, {"ok": False, "msg": "ZCode token 不能为空"})
                    else:
                        use = _save_cred("zcode",
                                         {"token": tok,
                                          "secret": (body.get("secret") or "").strip(),
                                          "user_id": (body.get("user_id") or "").strip()}, name)
                        _invalidate_state()
                        self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
                elif platform == "officeace":
                    ak = (body.get("ak") or "").strip()
                    sk = (body.get("sk") or "").strip()
                    sts = (body.get("sts_token") or "").strip()
                    if not (ak and sk and sts):
                        self._send(200, {"ok": False, "msg": "OfficeACE 需要 AK / SK / STS 三项都填"})
                    else:
                        use = _save_cred("officeace",
                                         {"ak": ak, "sk": sk, "sts_token": sts,
                                          "project_id": (body.get("project_id") or "").strip(),
                                          "expires_at": (body.get("expires_at") or "").strip()}, name)
                        _invalidate_state()
                        self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
                elif platform == "codearts":
                    cookie = (body.get("cookie") or "").strip()
                    tok = (body.get("token") or "").strip()
                    if not (cookie or tok):
                        self._send(200, {"ok": False, "msg": "CodeArts 需要 Cookie 或 token"})
                    else:
                        use = _save_cred("codearts",
                                         {"cookie": cookie, "token": tok,
                                          "device_id": (body.get("device_id") or "").strip()}, name)
                        _invalidate_state()
                        self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
                else:
                    self._send(200, {"ok": False, "msg": "不支持的平台 %s" % platform})

            # ── 删除账号凭据 ──
            elif p == "/api/account/remove":
                platform = body.get("platform")
                name = (body.get("name") or "").strip()
                _del_msg = ""
                if platform == "workbuddy":
                    results = _read_json(WB_LOGIN_FILE, [])
                    if isinstance(results, list):
                        new = [it for it in results if not _wb_match(it, name)]
                        removed = len(new) != len(results)
                        _write_json(WB_LOGIN_FILE, new)
                    else:
                        removed = False
                elif platform in CRED_FILES:
                    key = (body.get("key") or "").strip()
                    removed = _cred_store_remove(CRED_FILES[platform], key) if key else False
                    if not removed:
                        removed = _cred_store_remove(CRED_FILES[platform], name)
                    if not removed and platform == "minimax":
                        # 客户端会话卡（v2 auth store，凭据文件里没有条目）：
                        # 删除 = 移除该本地登录记录（带备份），否则永远「未找到该账号」
                        import importlib as _il
                        try:
                            _mm = _il.import_module("platforms.minimax")
                            _ok, _msg = _mm.remove_local_session(name)
                            removed = bool(_ok)
                            _del_msg = _msg
                        except Exception as _e:
                            _del_msg = "移除客户端会话失败：%s" % str(_e)[:80]
                else:
                    removed = False
                _invalidate_state()
                _msg = "已删除" if removed else (_del_msg if platform == "minimax" and not removed else "未找到该账号")
                self._send(200, {"ok": removed, "msg": _msg})

            # ── 修改账号备注名（只改本机显示名，不动凭据内容/平台账号） ──
            elif p == "/api/account/rename":
                platform = body.get("platform")
                name = (body.get("name") or "").strip()
                new_name = (body.get("new_name") or "").strip()
                if not new_name:
                    self._send(200, {"ok": False, "msg": "备注名不能为空"})
                elif "\n" in new_name or len(new_name) > 40:
                    self._send(200, {"ok": False, "msg": "备注名过长或含非法字符"})
                elif platform == "workbuddy":
                    results = _read_json(WB_LOGIN_FILE, [])
                    hit, dup = None, False
                    if isinstance(results, list):
                        for it in results:
                            if _wb_match(it, name):
                                hit = it
                            elif _wb_match(it, new_name):
                                dup = True
                    if hit is None:
                        self._send(200, {"ok": False, "msg": "未找到该账号"})
                    elif dup and new_name != name:
                        self._send(200, {"ok": False, "msg": "已有同名账号，请换一个备注名"})
                    else:
                        hit["alias"] = new_name
                        _write_json(WB_LOGIN_FILE, results)
                        _invalidate_state()
                        self._send(200, {"ok": True, "msg": "已改名为「%s」" % new_name})
                elif platform in CRED_FILES:
                    path = CRED_FILES[platform]
                    old_key = (body.get("key") or "").strip() or name
                    data = _read_json(path, {})
                    if not isinstance(data, dict) or old_key not in data:
                        self._send(200, {"ok": False, "msg": "未找到该账号"})
                    elif new_name != old_key and new_name in data:
                        self._send(200, {"ok": False, "msg": "已有同名账号，请换一个备注名"})
                    elif new_name == old_key:
                        self._send(200, {"ok": True, "msg": "名称未变化"})
                    else:
                        # 直接改键名：load_accounts() 以键名作为展示名，各适配器无需改动
                        rec = data.pop(old_key)
                        data[new_name] = rec
                        _write_json(path, data)
                        _invalidate_state()
                        self._send(200, {"ok": True, "msg": "已改名为「%s」" % new_name})
                else:
                    self._send(200, {"ok": False, "msg": "该平台不支持改名"})

            # ── 本地客户端导入：直接读取已登录的桌面端凭据（推荐路径） ──
            elif p == "/api/account/import_local":
                platform = body.get("platform")
                name = (body.get("name") or "").strip()
                if platform not in LOCAL_IMPORT_PLATFORMS:
                    self._send(200, {"ok": False, "msg": "该平台暂不支持本地导入"})
                else:
                    try:
                        import local_import
                        ok, msg, accs = local_import.read_local(platform)
                        if ok and accs:
                            target = CRED_FILES[platform]
                            saved, merged = [], []
                            for i, (nm, ent) in enumerate(accs.items(), 1):
                                rec = {k: v for k, v in dict(ent).items() if k != "name"}
                                # 理想名：用户填了备注名就优先用它，否则用客户端里的展示名
                                if name and len(accs) == 1:
                                    ideal = name
                                elif name:
                                    ideal = "%s·%d" % (name, i)
                                else:
                                    ideal = nm
                                rec["via_local"] = True
                                # _alloc_account_name：同身份沿用旧名；名字被别的账号占了就加尾号，
                                # 绝不覆盖 → 这样客户端顶掉槽位后，看板里的老账号依旧在
                                use = _alloc_account_name(target, platform, ideal, rec)
                                merged += _dedupe_store(target, platform, use, rec)
                                _cred_store_set(target, use, rec)
                                saved.append(use)
                            after = _read_json(target, {})
                            total = len(after) if isinstance(after, dict) else 0
                            _invalidate_state()
                            self._send(200, {"ok": True, "msg": msg, "names": saved,
                                             "merged_from": merged, "total": total,
                                             "client_count": len(accs),
                                             # 看板里保留、但本地客户端本次已不再暴露的账号数
                                             # （MiniMax 只有 2 个登录槽位，登第 3 个号就会顶掉一个）
                                             "kept": max(0, total - len(accs))})
                        else:
                            self._send(200, {"ok": False, "msg": msg})
                    except Exception as e:
                        self._send(200, {"ok": False, "msg": "本地导入异常：" + str(e)[:150]})

            # ── 手机号登录（OAuth 设备码）：弹网页 → 手机号+验证码 → 自动回填 ──
            # 与 WorkBuddy 的「手机号+验证码」等价，只是那家给了本地短信接口，
            # 这家走标准 OAuth 设备码：后端拿授权码 → 浏览器打开授权页 → 轮询取令牌。
            elif p == "/api/account/oauth_start":
                platform = body.get("platform")
                name = (body.get("name") or "").strip()
                sub = (body.get("sub") or "").strip() or None
                if oauth_login is None:
                    self._send(200, {"ok": False, "msg": "后端未加载 oauth_login 模块"})
                elif platform not in oauth_login.PROVIDERS:
                    self._send(200, {"ok": False, "msg": "该平台暂不支持网页授权登录"})
                else:
                    try:
                        ok, msg, view = oauth_login.start_job(
                            platform, lambda grant: _oauth_save(platform, name, grant),
                            sub=sub)
                    except Exception as e:
                        ok, msg, view = False, "发起网页授权登录失败：%s" % str(e)[:150], None
                    out = dict(view or {})
                    out["ok"] = ok            # view 里也有 ok（任务结果），必须最后覆盖为「发起是否成功」
                    out["msg"] = msg
                    self._send(200, out)

            # ── 手机号 + 短信验证码直登：看板输手机号 → 收码 → 看板输验证码 ──
            # 后端拉起可见 Chromium 打开 MiniMax 授权页，代用户填手机号 / 填验证码 /
            # 点「获取验证码」/ 点「立即登录」/ 点「授权」，用户只做两步输入。
            # （网页的「获取验证码」有腾讯滑块风控，所以发码动作放在真人可见的窗口里完成）
            elif p == "/api/account/sms_start":
                platform = body.get("platform")
                name = (body.get("name") or "").strip()
                phone = (body.get("phone") or "").strip()
                if oauth_login is None:
                    self._send(200, {"ok": False, "msg": "后端未加载 oauth_login 模块"})
                elif platform in ("baidu_dumate", "dumate"):
                    # DuMate 网页直登：无设备码流程，成功判定 = 百度 cookie 落地
                    try:
                        ok, msg, view = oauth_login.start_dumate_web_job(
                            phone, name, lambda g: _dumate_web_save(name, g))
                    except Exception as e:
                        ok, msg, view = False, "发起 DuMate 登录失败：%s" % str(e)[:150], None
                    out = dict(view or {})
                    out["ok"] = ok
                    out["msg"] = msg
                    self._send(200, out)
                elif platform == "lingxi":
                    # 灵犀网页短信直登：account.wps.cn 弹窗代点，抓 wps_sid
                    try:
                        ok, msg, view = oauth_login.start_lingxi_sms_job(
                            phone, name, lambda g: _lingxi_web_save(name, g))
                    except Exception as e:
                        ok, msg, view = False, "发起灵犀登录失败：%s" % str(e)[:150], None
                    out = dict(view or {})
                    out["ok"] = ok
                    out["msg"] = msg
                    self._send(200, out)
                elif platform == "zcode":
                    # ZCode 短信直登：cli/init 流 + 弹窗代点（zai / bigmodel 双通道）
                    sub = (body.get("sub") or "zai").strip()
                    try:
                        ok, msg, view = oauth_login.start_zcode_sms_job(
                            phone, sub, lambda g: _oauth_save("zcode", name, g), name)
                    except Exception as e:
                        ok, msg, view = False, "发起 ZCode 登录失败：%s" % str(e)[:150], None
                    out = dict(view or {})
                    out["ok"] = ok
                    out["msg"] = msg
                    self._send(200, out)
                elif platform == "trae":
                    # Trae 短信直登：OAuth PKCE + 本地随机回调端口 + 三段兑换链
                    # （身份/版本按线取真值：IDE→Trae CN，见 oauth_login._trae_line_dirs）
                    try:
                        ok, msg, view = oauth_login.start_trae_sms_job(
                            phone, name, lambda g: _trae_oauth_save(name, g))
                    except Exception as e:
                        ok, msg, view = False, "发起 Trae 登录失败：%s" % str(e)[:150], None
                    out = dict(view or {})
                    out["ok"] = ok
                    out["msg"] = msg
                    self._send(200, out)
                elif platform == "codearts":
                    # CodeArts 短信直登：自建 OAuth 会话（DPoP），refresh 归看板独享
                    try:
                        ok, msg, view = oauth_login.start_codearts_sms_job(
                            phone, name, lambda g: _codearts_oauth_save(name, g))
                    except Exception as e:
                        ok, msg, view = False, "发起 CodeArts 登录失败：%s" % str(e)[:150], None
                    out = dict(view or {})
                    out["ok"] = ok
                    out["msg"] = msg
                    self._send(200, out)
                elif platform == "officeace":
                    # OfficeACE 短信直登：驱动桌面端本地 API（127.0.0.1:3004）完成华为云登录
                    try:
                        ok, msg, view = oauth_login.start_officeace_sms_job(
                            phone, name, lambda g: _officeace_login_save(name, g))
                    except Exception as e:
                        ok, msg, view = False, "发起 OfficeACE 登录失败：%s" % str(e)[:150], None
                    out = dict(view or {})
                    out["ok"] = ok
                    out["msg"] = msg
                    self._send(200, out)
                elif platform not in oauth_login.PROVIDERS:
                    self._send(200, {"ok": False, "msg": "该平台暂不支持短信验证码登录"})
                elif not _has_playwright():
                    self._send(200, {"ok": False, "msg": "缺少依赖 playwright，无法拉起登录窗口。"})
                else:
                    try:
                        ok, msg, view = oauth_login.start_sms_job(
                            platform, phone, lambda grant: _oauth_save(platform, name, grant))
                    except Exception as e:
                        ok, msg, view = False, "发起短信登录失败：%s" % str(e)[:150], None
                    out = dict(view or {})
                    out["ok"] = ok
                    out["msg"] = msg
                    self._send(200, out)

            elif p == "/api/account/sms_code":
                jid = (body.get("job") or "").strip()
                code = (body.get("code") or "").strip()
                if oauth_login is None:
                    self._send(200, {"ok": False, "msg": "后端未加载 oauth_login 模块"})
                else:
                    try:
                        ok, msg = oauth_login.submit_code(jid, code)
                    except Exception as e:
                        ok, msg = False, "提交验证码失败：%s" % str(e)[:150]
                    self._send(200, {"ok": ok, "msg": msg})

            # ── OfficeACE：一键启动桌面端客户端（本地 API 未就绪时的兜底手段）──
            elif p == "/api/officeace/launch":
                if oauth_login is None:
                    self._send(200, {"ok": False, "msg": "后端未加载 oauth_login 模块"})
                else:
                    try:
                        ok, base, note = oauth_login._officeace_autostart(wait=25)
                    except Exception as e:
                        ok, base, note = False, "", "启动失败：%s" % str(e)[:150]
                    self._send(200, {"ok": bool(ok),
                                     "msg": note or ("客户端已就绪（%s）" % base if ok
                                                     else "未能启动客户端"),
                                     "api": base})
            elif p == "/api/officeace/status":
                # 见 do_GET（此处保留兜底，允许 POST 形式调用）
                if oauth_login is None:
                    self._send(200, {"ok": False, "msg": "后端未加载 oauth_login 模块"})
                else:
                    try:
                        ok, base, info = oauth_login._officeace_probe(timeout=5)
                    except Exception as e:
                        ok, base, info = False, "", {"error": str(e)[:120]}
                    self._send(200, {"ok": bool(ok), "api": base,
                                     "exe": oauth_login._officeace_exe_path(),
                                     "info": info})

            # ── 浏览器辅助登录（备用）：未安装桌面客户端时，用受控 Chromium 登录后抓凭据 ──
            elif p == "/api/account/browser_login":
                platform = body.get("platform")
                name = (body.get("name") or "").strip()
                if platform not in ("lingxi",):
                    self._send(200, {"ok": False, "msg": "该平台暂不支持浏览器登录"})
                elif not _has_playwright():
                    self._send(200, {"ok": False, "msg": "缺少依赖 playwright，浏览器登录不可用。"
                                                         "请在本看板所用的 Python 下执行： pip install playwright "
                                                         "然后 playwright install chromium；"
                                                         "也可改用「粘贴 token / Cookie」直接添加账号。"})
                else:
                    jid = _new_blogin(platform, name)
                    threading.Thread(target=_run_blogin, args=(jid, platform, name), daemon=True).start()
                    self._send(200, {"ok": True, "job": jid})
            elif p == "/api/account/browser_login_status":
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                jid = (q.get("job") or [""])[0]
                job = BLOGINS.get(jid)
                if not job:
                    self._send(404, {"error": "job not found"})
                else:
                    self._send(200, {"job": jid, "status": job["status"], "text": job["text"],
                                     "finished": job["finished"], "ok": job["ok"],
                                     "result": job["result"], "name": job["name"],
                                     "platform": job["platform"]})

            else:
                self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(500, {"error": str(e)[:200]})


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    os.chdir(HERE)
    url = "http://127.0.0.1:%d" % PORT
    print("=" * 62)
    print(" 多平台账号看板后端已启动：%s" % url)
    print(" 平台：%s" % "、".join(PLATFORMS.keys()))
    print(" 仅监听本机回环，凭据不出本机。关闭此窗口即停止。")
    print("=" * 62)
    for pid, mod in PLATFORMS.items():
        try:
            n = len(mod.load_accounts())
        except Exception:
            n = 0
        print("  · %s：%s 个凭据" % (getattr(mod, "LABEL", pid), n))
    if not PLATFORMS:
        print("⚠ 没有任何平台适配器加载成功，请检查 platforms/ 目录。")
    print("浏览器打开：%s\n" % url)
    try:
        Server(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")


if __name__ == "__main__":
    main()
