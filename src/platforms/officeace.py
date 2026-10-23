# -*- coding: utf-8 -*-
"""
OfficeACE（华为云 AgentArts 智能体平台）· 看板平台适配器
════════════════════════════════════════════════════════════════════════
接口口径（逆向自客户端 packages/api/dist + 本机实测，2026-10）：

  订阅状态  GET  {host}/v1/subscription            header: x-subscription-type: v2
  每日领取  POST {host}/v1/subscription/bonus/claim
              · body 必须带 JSON（用 {}），否则服务端会以 500 + OfficeAce.11020001
                「内部服务器错误」应答——**这是服务端对空 body 的 bug，不是真故障**
              · 200 + bonus_skus 非空 → 本次领到了奖励
              · 200 + bonus_skus 为空 → 今天已经没有可领的（= 今日已签到）

  今日是否已签到（只读判据，不去调用 claim）：
      GET /v1/subscription 的 bonus_skus[] 里，若存在 cbc_resource_id 形如
        bonus:<activity>:<YYYYMMDDHHMMSS>:daily
      且该时间戳（东八区）落在今天，说明今天的每日签到奖励已经发放过 → 今日已签。
      注意 cbc_resource_id 里的时间戳是 **CST(UTC+8)**，而 effective_time 是 UTC，别混用。

鉴权：华为云 API 网关 **V11-HMAC-SHA256**（HKDF 派生密钥），算法与客户端
      `packages/api/dist/index.js` 里的 signRequest 完全一致：

      Host       = officeace.cn-southwest-2.huaweicloud-agentarts.com
      Region     = cn-southwest-2
      Service    = apic                      ← 常量 e8，写错会报
                                               "service in Authorization invalid"
      Credential = <AK>/<YYYYMMDD>/<region>/apic
      派生密钥    tmp = HMAC(key=AK, msg=SK)
                  der = HMAC(key=tmp, msg= (date/region/apic)字节 || 0x01 )[:32]   （hex 字符串）
      签名        sig = HMAC(key=der_hex字符串的 UTF-8 字节, msg=StringToSign)     （hex）
      StringToSign = "V11-HMAC-SHA256\n" + X-Sdk-Date + "\n" + info + "\n" + sha256hex(canonicalRequest)
      CanonicalRequest = METHOD\ncanonicalURI\ncanonicalQuery\ncanonicalHeaders(<k>:<v>\n 结尾)
                         \n SignedHeaders\n payloadHash
      Authorization = "V11-HMAC-SHA256 Credential=<AK>/<info>, SignedHeaders=..., Signature=..."

凭据来源：<安装目录>/packages/api/.config/secure-config-nodejs/ 下的
      .oauth-profile-encryption-key（"OC-DPAPI-1\n<base64(DPAPI blob)>"）
      + oauth-<accountId>.json（AES-256-GCM）
      → {access(AK), secret(SK), sts_token, project_id, expires_at, refresh_token}
      见 local_import.read_officeace。

**重要限制**：AK/SK/sts_token 都是**临时凭据**，sts_token 约 24 小时过期；
      过期后只能靠打开 OfficeACE 客户端重新登录来刷新（客户端内部走 OAuth，
      其 refresh 端点未在 JS 中暴露）。看板会在过期时给出明确提示，而不是静默失败。
"""
import os
import sys
import json
import hmac
import hashlib
import time
import ctypes
import subprocess
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, quote

try:
    from ._util import dec_cred, enc_cred, exp_epoch
except ImportError:  # 被独立脚本直接加载时的兜底
    dec_cred = enc_cred = (lambda o: o)
    exp_epoch = lambda v: 0.0        # 比不出新旧 → 退化成「采纳客户端会话」的旧行为



try:                       # 包内导入（server.py: import platforms.officeace）
    from ._util import to_float
except ImportError:        # 直接以脚本运行时的兜底
    def to_float(v, default=0.0):
        try:
            return float(v)
        except (TypeError, ValueError):
            return default

try:
    import requests
except ImportError:
    sys.exit("缺少依赖 requests，请先：pip install requests")
try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

try:                       # 凭据数据目录（2026-10-12 外移到 %LOCALAPPDATA%）
    from .. import data_dir as _dd
except ImportError:        # platforms 被当顶层包导入（server.py 方式）→ 平铺导入
    try:
        import data_dir as _dd
    except ImportError:
        _dd = None

try:                       # 身份口径与 cred_store 保持一致（domain:user → user）
    from ..cred_store import officeace_stable_uid
except ImportError:
    try:
        from cred_store import officeace_stable_uid
    except ImportError:
        def officeace_stable_uid(uid):
            s = str(uid or "").strip()
            return s.split(":")[-1] if s else ""


def _acc_paths(name):
    """凭据文件读点候选：DATA_DIR → ROOT → HERE。"""
    if _dd is not None:
        return _dd.candidates(name)
    return [os.path.join(ROOT, name), os.path.join(HERE, name)]

PLATFORM = "officeace"
LABEL = "OfficeACE（华为云）"
TASKS = [{"key": "checkin", "label": "每日登录领取", "daily": True}]

DEFAULT_HOST = "https://officeace.cn-southwest-2.huaweicloud-agentarts.com"
REGION = "cn-southwest-2"
SERVICE = "apic"
ALGO = "V11-HMAC-SHA256"

SUB_PATH = "/v1/subscription"
CLAIM_PATH = "/v1/subscription/bonus/claim"
UNSIGNED = "UNSIGNED-PAYLOAD"


# ───────────────────────── 签名 ─────────────────────────
def _db(s):
    """等价 JS Db()：encodeURIComponent + 额外编码 !'()*"""
    return quote(str(s), safe="-_.~") \
        .replace("!", "%21").replace("'", "%27").replace("(", "%28") \
        .replace(")", "%29").replace("*", "%2A")


def _canonical_uri(path):
    segs = (path or "/").split("/")
    out = "/".join(_db(_unquote(x)) for x in segs)
    if not out.endswith("/"):
        out += "/"
    return out


def _unquote(s):
    from urllib.parse import unquote
    try:
        return unquote(s)
    except Exception:
        return s


def _canonical_query(query):
    """query: list[(k, v)]；按 k 再按 v 排序（与 localeCompare 等价于字典序）"""
    items = sorted([(str(k), str(v)) for k, v in (query or [])], key=lambda x: (x[0], x[1]))
    return "&".join("%s=%s" % (_db(k), _db(v)) for k, v in items)


def _canon_headers(headers):
    """小写键 → 值去首尾空格并把连续空白压成单空格"""
    out = {}
    for k, v in headers.items():
        out[k.lower()] = " ".join(str(v).strip().split())
    return out


def _derive_key(ak, sk, info):
    tmp = hmac.new(ak.encode("utf-8"), sk.encode("utf-8"), hashlib.sha256).digest()
    der = hmac.new(tmp, info.encode("utf-8") + b"\x01", hashlib.sha256).digest()[:32]
    return der.hex()


def sign_request(method, url, ak, sk, sts, project_id="", body_text="",
                 extra_headers=None, pre_signed=False, query=None):
    """返回带签名的完整请求头 dict（含 Authorization）"""
    h = dict(extra_headers or {})
    xdate = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    h["X-Sdk-Date"] = xdate
    h["X-Security-Token"] = sts
    h["Host"] = urlparse(url).netloc
    if project_id:
        h["X-Project-ID"] = project_id
    if pre_signed:
        h["X-Sdk-Content-Sha256"] = UNSIGNED

    if pre_signed:
        payload_hash = UNSIGNED
    else:
        payload_hash = hashlib.sha256(body_text.encode("utf-8")).hexdigest()

    ch = _canon_headers(h)
    signed = sorted(ch.keys())
    canon_hdr = "".join("%s:%s\n" % (k, ch[k]) for k in signed)
    canon_req = "\n".join([
        method.upper(),
        _canonical_uri(urlparse(url).path),
        _canonical_query(query),
        canon_hdr,
        ";".join(signed),
        payload_hash,
    ])
    info = "%s/%s/%s" % (xdate[:8], REGION, SERVICE)
    sts_str = "\n".join([ALGO, xdate, info, hashlib.sha256(canon_req.encode("utf-8")).hexdigest()])
    der = _derive_key(ak, sk, info)
    sig = hmac.new(der.encode("utf-8"), sts_str.encode("utf-8"), hashlib.sha256).hexdigest()
    h["Authorization"] = "%s Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
        ALGO, ak, info, ";".join(signed), sig)
    return h


# ───────────────────────── 凭据 ─────────────────────────
# ───────────── 无人值守凭据刷新（2026-10-09 全链路实证，勿回退）────────────
# 链路：① 直启 ServiceHost（**不带 --stop-on-launcher-exit** → 没有 watchdog 自停；
#          ⚠ ServiceHost 检测到 HTTP_PROXY 环境变量会拒绝启动，必须剥掉代理变量）
#       ② 带 oc_sid（WebView2 cookie，DPAPI+AES-GCM v10 解密）调 https://127.0.0.1:3004/api/islogin
#       ③ api 恢复会话时**自动刷新华为 STS（2h）+ 轮换 refresh_token** 并落盘 SQLite
#       ④ 回读 SQLite 更新看板凭据。全程无需打开 GUI。
# 实测：GUI launcher 从会话拉起 55s 自死（--stop-on-launcher-exit 连锁），但 api 已在
#       49s 存活期内完成刷新；直启 ServiceHost 则可常驻。
_SERVICE_PORT = 3004
_SERVICE_HOST_EXE = r"E:\OfficeAce\OfficeAceServiceHost.exe"
_SERVICE_ROOT = r"E:\OfficeAce"
_WV2_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""),
                        "OfficeAce", "DesktopWebView2", "EBWebView")
_sid_cache = {"v": None, "t": 0.0}


def _gui_running():
    """GUI 壳（OfficeAce.exe）是否在跑：在跑说明服务归它所有，看板绝不能动。
    注意 tasklist 输出是 GBK（中文 Windows），按字节匹配进程名（纯 ASCII）最稳。"""
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq OfficeAce.exe"],
                             capture_output=True, timeout=10)
        return b"OfficeAce.exe" in (out.stdout or b"")
    except Exception:
        return False


def _service_state_paths():
    """runtime-state.json 候选（安装形态 + 用户目录形态，与 App 的
    runtimeStateCandidates 对齐）。"""
    home = os.path.expanduser("~")
    return [os.path.join(_SERVICE_ROOT, ".office-claw", "run", "windows",
                         "runtime-state.json"),
            os.path.join(home, ".office-claw", "run", "windows",
                         "runtime-state.json")]


def _service_api_port():
    """本地 API 真实端口：runtime-state.json 的 ApiUrl/ApiPort 优先。
    ⚠ 2026-10-22：GUI 形态下端口可能随机化（asar 内 UseRandomFrontendApiPorts），
    旧代码写死 3004 → GUI 在跑时 _service_up() 误判「服务没起」→ 抢启裸 host →
    与 GUI 租约互斥把客户端顶退（问题2 的一条暗线）。"""
    for st in _service_state_paths():
        try:
            with open(st, encoding="utf-8") as f:
                d = json.load(f)
            url = str(d.get("ApiUrl") or "").strip()
            if url:
                try:
                    from urllib.parse import urlparse
                    p = urlparse(url).port
                    if p:
                        return p
                except Exception:
                    pass
            port = d.get("ApiPort")
            if isinstance(port, int) and port > 0:
                return port
        except Exception:
            continue
    return _SERVICE_PORT


def _service_up():
    import socket
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", _service_api_port()))
        return True
    except Exception:
        return False
    finally:
        s.close()


def _pid_is_host(pid):
    """校验 pid 现在确实是 OfficeAceServiceHost.exe（防 pid 复用误杀）。"""
    try:
        out = subprocess.run(["tasklist", "/FI", "PID eq %d" % int(pid)],
                             capture_output=True, timeout=10)
        return b"OfficeAceServiceHost.exe" in (out.stdout or b"")
    except Exception:
        return False


# 本进程直启的 ServiceHost pid（回收时只杀它；2026-10-22 所有权硬化）
_service_owned_pid = None


def _service_start():
    """直启 ServiceHeadless（无 GUI）。ServiceHost 检测到 *PROXY* 环境变量会拒绝启动。"""
    global _service_owned_pid
    if not os.path.isfile(_SERVICE_HOST_EXE):
        return False, "未找到 ServiceHost：%s" % _SERVICE_HOST_EXE
    env = dict(os.environ)
    for k in list(env):
        if k.lower() in ("http_proxy", "https_proxy", "all_proxy",
                         "no_proxy", "ftp_proxy"):
            env.pop(k, None)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        subprocess.Popen([_SERVICE_HOST_EXE, "--mode", "serve",
                          "--enable-native-runtime", "--packaged-production",
                          "--project-root", _SERVICE_ROOT],
                         env=env, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, creationflags=flags,
                         cwd=_SERVICE_ROOT)
    except Exception as e:
        return False, "ServiceHost 启动失败：%s" % str(e)[:120]
    for _ in range(35):                    # ≤35s 等 api 就绪（实测 ~6s）
        if _service_up():
            # 记住这个 host 的归属：state 里的 HostPid 就是我们刚拉起的这个
            _service_owned_pid = _runtime_host_pid()
            return True, "ServiceHost 已就绪"
        time.sleep(1.0)
    return False, "ServiceHost 35s 内未就绪（查 .office-claw/run/windows/lifecycle.ndjson）"


def _runtime_host_pid():
    """读 runtime-state.json 的 HostPid（服务没在跑/读不到返回 None）。

    ⚠ 2026-10-22（客户端 1.4.1）：状态文件从 <安装目录>\\.office-claw\\run\\windows\\
    迁到了 %USERPROFILE%\\.office-claw\\run\\windows\\（SchemaVersion 3，
    UserDataRoot 也变了）。旧实现只读安装目录 → 1.4.1 下永远返回 None →
    _service_start 记不住归属 → _service_stop 永不回收（裸 host 残留顶死 GUI）。
    现在遍历全部候选路径，并优先返回「pid 确实是活着的 ServiceHost」的那条。"""
    for st in _service_state_paths():
        try:
            with open(st, encoding="utf-8") as f:
                pid = int(json.load(f).get("HostPid") or 0)
        except Exception:
            continue
        if pid and _pid_is_host(pid):
            return pid
    return None


def _service_stop():
    """结束直启的 ServiceHost 进程树（taskkill /T 连 node/web 子进程一起）。
    ⚠ 2026-10-12 新增，勿回退：无头实例常驻会独占 runtime-state 的 HostPid 归属，
    用户之后打开 GUI 客户端时其服务（新 pid）校验状态归属失败 →
    NATIVE_SERVICE_STATE_INVALID 弹窗拒绝启动（实测 21:31 复现）。
    所以看板自己拉起的服务，用完必须回收；用户/客户端自己启动的绝不动。

    ⚠ 2026-10-19 补充：杀掉进程还不够——runtime-state.json 里仍留着死 pid，
    官方客户端下次启动时新 host 写状态前先读到旧文件 → 直接抛
    「expected pid=A, actual pid=B」拒绝启动（实测 19:58/20:03 复现）。
    因此回收后必须把指向该 pid 的状态文件一并清掉，让客户端重新生成。

    ⚠⚠ 2026-10-22 所有权硬化（勿回退）：只杀 _service_start 直启的那个 pid。
    旧实现「读当前 state 的 HostPid 就杀」有个致命 race：刷新起停 host 期间
    用户发起短信登录 → autostart 清掉我们的 host、GUI 拉起新服务并改写 state →
    刷新的 finally 再来 _service_stop，读到的已是 **GUI host 的 pid**，一刀
    把用户的客户端服务杀掉（表现为 authorize HTTP 0 / 客户端抽搐）。
    现在先校验 owned pid 仍是 ServiceHost 才动手，GUI 接管后自动跳过。"""
    global _service_owned_pid
    pid = _service_owned_pid
    _service_owned_pid = None
    if not pid:
        return False
    if not _pid_is_host(pid):
        # 我们的 host 已经没了（被 GUI 接管/已死）→ 只清可能残留的状态文件
        _clear_stale_state(pid)
        return False
    try:
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                       capture_output=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        return False
    _clear_stale_state(pid)
    return True


def _clear_stale_state(pid):
    """删除仍指向已退出 host 的 runtime-state.json（客户端启动时会重新生成）。

    ⚠ 2026-10-22（1.4.1）：状态文件可能在新位置 %USERPROFILE%\\.office-claw\\...，
    必须遍历全部候选路径，否则新位置留着死 pid，客户端抛 expected/actual 拒启。"""
    for st in _service_state_paths():
        try:
            with open(st, encoding="utf-8") as f:
                if int(json.load(f).get("HostPid") or 0) != int(pid):
                    continue
        except Exception:
            continue
        try:
            os.remove(st)
            return True
        except Exception:
            continue
    return False


def _oc_sid():
    """解密 WebView2 cookie 库里的 oc_sid。明文 = 32 字节实例前缀 + 实际值。"""
    now = time.time()
    if _sid_cache["v"] and now - _sid_cache["t"] < 300:
        return _sid_cache["v"]
    db = os.path.join(_WV2_DIR, "Default", "Network", "Cookies")
    lsp = os.path.join(_WV2_DIR, "Local State")
    if not (os.path.isfile(db) and os.path.isfile(lsp)):
        return None
    import shutil
    import sqlite3
    import tempfile
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from ctypes import wintypes

    class _BLOB(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("pb", ctypes.POINTER(ctypes.c_char))]

    def _dpapi(data):
        buf = ctypes.create_string_buffer(data, len(data))
        i = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        o = _BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(i), None, None, None, None, 0, ctypes.byref(o)):
            raise OSError("CryptUnprotectData 失败")
        out = ctypes.string_at(o.pb, o.cb)
        ctypes.windll.kernel32.LocalFree(o.pb)
        return out

    try:
        ls = json.load(open(lsp, encoding="utf-8"))
        key = _dpapi(base64.b64decode(ls["os_crypt"]["encrypted_key"])[5:])
        tmp = os.path.join(tempfile.gettempdir(), "oc_cookies_ro.db")
        shutil.copyfile(db, tmp)           # 原库可能被客户端锁住 → 复制后读
        try:
            con = sqlite3.connect(tmp)
            try:
                row = con.execute("select encrypted_value from cookies "
                                  "where name='oc_sid'").fetchone()
            finally:
                con.close()
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass
        if not row:
            return None
        enc = row[0]
        pt = AESGCM(key).decrypt(enc[3:15], enc[15:], None)
        sid = pt[32:].decode("utf-8", "replace").strip()
    except Exception:
        return None
    if not sid:
        return None
    _sid_cache.update(v=sid, t=now)
    return sid


def _persist_entry(name, ent):
    """把续期后的凭据写回 officeace_accounts.json（首个存在的文件，否则建在 DATA_DIR）。"""
    keep = ("ak", "sk", "sts_token", "project_id", "expires_at", "refresh_token",
            "refresh_expires_at", "user_id", "host", "region", "name")
    path = None
    for p in _acc_paths("officeace_accounts.json"):
        if os.path.exists(p):
            path = p
            break
    path = path or _acc_paths("officeace_accounts.json")[0]
    try:
        data = dec_cred(json.load(open(path, encoding="utf-8"))) if os.path.exists(path) else {}
        if not isinstance(data, dict):
            data = {}
        old = data.get(name) or {}
        # 身份闸：落盘前后 uid 不同＝把别的号的凭据写进了这个键（串号唯一的发生点），
        # 宁可续期失败，也不让两个号长成同一条凭据。
        ou, nu = officeace_stable_uid(old.get("user_id")), officeace_stable_uid(ent.get("user_id"))
        if ou and nu and ou != nu:
            return
        data[name] = {k: ent.get(k, "") for k in keep if ent.get(k)}
        tmp = path + ".tmp"
        json.dump(enc_cred(data), open(tmp, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except Exception:
        pass


def pick_live_session(name, ent, accs):
    """从客户端 SQLite 读到的会话里挑出**本账号**那一条；挑不到就返回 None。

    只认两种：键名相同，或 stable_uid 相同（domain:user 与裸 user 归一到末段）。
    绝不「取第一条」兜底——客户端只登了一个号时，那等于把那个号的
    ak/sk/project_id/user_id 整份写进本号（2026-10-20 实证：果办第二个号的凭据
    被一号逐字段覆盖，两个号在面板上从此一模一样，且备份前的覆盖不可逆）。
    """
    if not isinstance(accs, dict) or not accs:
        return None
    cand = accs.get(name)
    if cand:
        return cand
    uid = officeace_stable_uid((ent or {}).get("user_id"))
    if not uid:
        return None
    for v in accs.values():
        if officeace_stable_uid((v or {}).get("user_id")) == uid:
            return v
    return None


_refresh_fail = {}            # name -> (until_ts, msg) 刷新失败冷却（防每轮起停 host）
_REFRESH_FAIL_COOLDOWN = 300  # 秒；STS 有效期 2h，刷不成功不必秒级重试


def _current_session_uid():
    """客户端 SQLite 里「当前登录账号」的 stable_uid（只读库，不需要服务在跑）。
    判定：expires_at 最新的会话 —— 客户端只给当前登录号续 STS，它的 expires 一直最新。"""
    try:
        import local_import
        _ok, _m, accs = local_import.read_officeace()
        best, best_exp = None, ""
        for v in (accs or {}).values():
            e = str((v or {}).get("expires_at") or "")
            if e > best_exp:
                best_exp, best = e, v
        return officeace_stable_uid((best or {}).get("user_id"))
    except Exception:
        return None


def try_refresh(name, ent):
    """无人值守刷新。成功返回 (True, 提示) 并就地更新 ent + 持久化。
    本函数直启的 ServiceHost 在结束时回收（见 _service_stop 的 NATIVE_SERVICE_STATE_INVALID 教训）。

    ⚠ 2026-10-22：GUI 在跑时绝不直启裸 host —— 客户端检测到另一个 native service
    host 在跑就拒启（startup-failure.json 实证），用户会打不开客户端。GUI 在跑就
    等它自己的 API（端口从 runtime-state.json 动态解析，随机端口也不会误判）。

    ⚠⚠ 2026-10-22 二次根因修复（勿回退）—— 刷新周期曾是「客户端打不开 /
    登录拿不到授权链接（HTTP 0）」的隐形杀手：
    ① 登录互斥：短信登录独占 GUI（officeclaw:// 只能由 GUI 接收），
       刷新起停裸 host 会把客户端顶退 → 登录进行中直接跳过；
    ② 账号前置闸：客户端只刷新「当前登录账号」的 STS。本号不是当前号时
       pick_live_session 必然落空，起裸 host 纯属白试，却每轮刷新都起停一次
       host、把用户双击的客户端顶退（0623 实证：13:49 GUI 被
       "Another OfficeAce native service host is already running" 挡死）；
    ③ 失败冷却 5 分钟：刷不成功就别高频重试，把 host 起停频率压到有界。"""
    try:
        import officeace_guard
        if officeace_guard.login_running():
            return False, "果办登录流程进行中，已跳过本次自动续期"
    except Exception:
        pass
    now = time.time()
    until, msg = _refresh_fail.get(name, (0.0, ""))
    if until > now:
        left = int(until - now)
        return False, (("%s（%d 秒后重试）" % (msg, left)) if msg
                       else ("自动续期冷却中（%d 秒后重试）" % left))
    cur = _current_session_uid()
    my = officeace_stable_uid(ent.get("user_id"))
    if cur and my and cur != my:
        return False, ("客户端当前登录的是其他账号（客户端只刷新当前登录账号）；"
                       "请打开客户端切换到本账号登录，或用本账号手机号看板短信登录")
    spawned = False
    try:
        if not _service_up():
            if _gui_running():
                # 服务是 GUI 的，等它把 API 拉起来即可（Electron 冷启 ~10-25s）
                for _ in range(25):
                    time.sleep(1.0)
                    if _service_up():
                        break
            if not _service_up():
                ok, msg = _service_start()
                if not ok:
                    _refresh_fail[name] = (now + _REFRESH_FAIL_COOLDOWN, msg)
                    return False, msg
                spawned = True
        ok, msg = _try_refresh_inner(name, ent)
        if not ok:
            _refresh_fail[name] = (time.time() + _REFRESH_FAIL_COOLDOWN, msg)
        return ok, msg
    finally:
        if spawned:
            _service_stop()


def _try_refresh_inner(name, ent):
    if not _service_up():
        return False, "服务未就绪"
    sid = _oc_sid()
    if not sid:
        return False, "取不到 WebView2 oc_sid（客户端从未登录过？）"
    import ssl
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    old_exp = (ent.get("expires_at") or "").strip()
    try:
        req = urllib.request.Request(
            "https://127.0.0.1:%d/api/islogin" % _service_api_port(),
            headers={"Cookie": "oc_sid=%s" % sid})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            j = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        return False, "islogin 调用失败：%s" % str(e)[:120]
    if not j.get("islogin"):
        return False, ("华为账号会话已失效（islogin=false）：请在果办 OfficeAce 客户端"
                       "重新登录，并勾选「记住我 / 30 天内免登录」，看板会自动读取新会话")
    # 轮询 SQLite 等新凭据落盘（实测 1~5s）
    try:
        sys.path.insert(0, ROOT)
        import local_import
    except Exception as e:
        return False, "无法导入 local_import：%s" % str(e)[:80]
    new = None
    seen_same_uid = False
    saw_any, why_empty = False, ""
    for _ in range(24):
        time.sleep(1.0)
        try:
            _ok, _m, accs = local_import.read_officeace()
        except Exception as e:
            accs, why_empty = {}, str(e)[:90]
            continue
        if accs:
            saw_any = True
        elif not why_empty:
            why_empty = str(_m or "客户端会话表里没有可用凭据")[:90]
        cand = pick_live_session(name, ent, accs)
        if cand:
            seen_same_uid = True
            if (cand.get("expires_at") or "").strip() != old_exp:
                new = cand
                break
        elif accs:
            # 客户端有会话、但没有本号的那一条 → 立刻失败关闭。
            # 再等 23 秒也不会凭空多出来，而面板每读一次这个号就要站满 24 秒。
            break
    if not new:
        if not seen_same_uid and not saw_any:
            # 一条会话都没读到（库被客户端写锁占着 / 会话表空）：这跟「客户端里没有
            # 本账号」是两种故障，报错了人就只会去切账号，而真正要做的是重开客户端。
            return False, ("读不到客户端会话（%s），无法自动续期；"
                           "请打开 OfficeACE 客户端登录后再续期" % (why_empty or "24 秒内无返回"))
        if not seen_same_uid:
            return False, ("客户端里没有本账号（uid %s）的登录会话，不能借用别的号的凭据；"
                           "请在 OfficeACE 客户端切到该账号登录，或在看板里用该手机号"
                           "「手机号+验证码登录」重登一次后再续期"
                           % (officeace_stable_uid(ent.get("user_id")) or "?")[:20])
        # 本号会话在客户端里、但 24 秒一点没动：客户端只刷新**当前登录**的那个号，
        # 其余号那条会话会一整天停在同一时刻（2026-10-20 实证：0623 停在 07:14，
        # 同时在用的号刷到了 14:08）。点名那个号，比「刷新未生效」可操作得多。
        fresher = None
        for nm, v in (accs or {}).items():
            if nm == name or not isinstance(v, dict):
                continue
            if exp_epoch(v.get("expires_at")) > exp_epoch(old_exp):
                fresher = (nm, str(v.get("expires_at"))[:19])
                break
        if fresher:
            # 客户端只刷新**当前登录**的那个号（2026-10-20 实证：0623 停在 07:14，
            # 同时在用的号刷到 14:08）。点名那个号 + 给出两条可操作路径。
            ph = str(ent.get("phone") or "")
            return False, ("刷新未生效：客户端当前登录的是「%s」（其凭据到 %s），"
                           "本账号的会话没被刷新（客户端只刷当前登录的号）。"
                           "请在 OfficeACE 客户端切到本账号登录，或在看板里用本机号"
                           "「手机号+验证码登录」重登一次再续期%s"
                           % (fresher[0], fresher[1],
                              ("（手机号 %s）" % ph) if len(ph) == 11 else ""))
        return False, "刷新未生效（SQLite expires_at 未变化）"
    for k in ("ak", "sk", "sts_token", "project_id", "expires_at", "refresh_token",
              "refresh_expires_at", "user_id", "host", "region"):
        if new.get(k):
            ent[k] = new[k]
    _persist_entry(name, ent)
    return True, "已自动续期至 %s" % (ent.get("expires_at") or "")[:19]


def load_accounts():
    """凭据来源（优先级从高到低）：
       1) 环境变量 OFFICEACE_AK / OFFICEACE_SK / OFFICEACE_STS
       2) ROOT/officeace_accounts.json 或 HERE/officeace_accounts.json
          （值 = {ak, sk, sts_token, project_id?}）
    """
    accs = {}
    ak = (os.environ.get("OFFICEACE_AK", "") or "").strip()
    sk = (os.environ.get("OFFICEACE_SK", "") or "").strip()
    sts = (os.environ.get("OFFICEACE_STS", "") or "").strip()
    if ak and sk and sts:
        accs["OfficeACE"] = {"ak": ak, "sk": sk, "sts_token": sts,
                             "project_id": (os.environ.get("OFFICEACE_PROJECT") or "").strip()}
    for path in _acc_paths("officeace_accounts.json"):
        if not os.path.exists(path):
            continue
        try:
            data = dec_cred(json.load(open(path, encoding="utf-8")))
        except Exception:
            continue
        items = [(str(k), v) for k, v in data.items()] if isinstance(data, dict) else \
            [(str(it.get("name") or "OfficeACE%d" % (i + 1)), it) for i, it in enumerate(data or [])]
        for nm, v in items:
            if isinstance(v, dict) and v.get("ak") and v.get("sk") and v.get("sts_token"):
                accs[nm] = v
    # ③ SQLite 会话（客户端启动时自动刷新，通常最新）—— 按 user_id/同名覆盖
    #    但**更旧的会话不许覆盖库里刚续好的凭据**（2026-10-20：客户端只刷新当前
    #    登录的那个号，另一个号留着一整天前的过期会话；无条件逐字段覆盖 ⇒ 把
    #    续期成功的凭据退回过期那条，面板报「凭证已过期」）
    try:
        sys.path.insert(0, ROOT)
        import local_import
        _ok, _m, live = local_import.read_officeace()
        for k, v in (live or {}).items():
            uid = officeace_stable_uid(v.get("user_id"))
            target = k if k in accs else None
            if target is None and uid:
                for ek, ev in accs.items():
                    if officeace_stable_uid(ev.get("user_id")) == uid:
                        target = ek
                        break
            if target is None and len(accs) == 1 and len(live) == 1:
                target = next(iter(accs))          # 单账号两边键名不一致 → 对齐
            if target is not None:
                base = accs[target]
                if base.get("ak") and exp_epoch(v.get("expires_at")) < \
                        exp_epoch(base.get("expires_at")):
                    continue            # 客户端这条更旧 → 保留库里续好的凭据
                base.update({kk: v[kk] for kk in v if v.get(kk)})
                accs[target] = base
            else:
                accs[k] = v
    except Exception:
        pass
    return accs


# ───────────────────────── 读取 ─────────────────────────
def _conn_retryable(e):
    """连接级错误（瞬时网络波动 / 本地代理重置连接 / 超时 / 分块中断）才安全重试；
    HTTP 4xx/5xx 是确定的业务响应，绝不重试。"""
    return isinstance(e, (requests.exceptions.ConnectionError,
                          requests.exceptions.Timeout,
                          requests.exceptions.ChunkedEncodingError))


def _clean_conn_err(e):
    """把原始连接异常 repr 转成给用户的干净中文，绝不甩
    'ConnectionResetError(10054, ...)' / 'Connection aborted.' 这类原始栈。
    根因（2026-10-22 实测）：本机挂着 HTTPS_PROXY=127.0.0.1:7890，某次看板查
    订阅时该代理瞬时抖动重置了连接 → 10054；端点本身直连/走代理均可达（已测）。"""
    s = str(e)
    if "10054" in s or "ConnectionReset" in s or "Connection aborted" in s:
        return "OfficeACE 云端连接被重置（网络波动或本地代理中断），已自动重试仍失败，请稍后重试"
    if "10061" in s or "Connection refused" in s:
        return "OfficeACE 云端连接被拒绝（目标不可达），请检查网络或本地代理后重试"
    if "timed out" in s.lower() or "Timeout" in s:
        return "OfficeACE 云端请求超时，请稍后重试"
    return "OfficeACE 云端连接失败，请稍后重试"


def _req(ent, path, method="GET", body=None, extra=None, timeout=25, _tries=3):
    """发请求到 OfficeACE（本地原生服务 or 华为云）。

    ⚠ 2026-10-22 加固：连接级错误（10054 重置 / 超时 / 分块中断）自动退避重试
    （最多 3 次，0.5s→1.0s），避免一次瞬时网络抖动就把订阅查询硬失败；
    最终失败也只回干净中文，不把原始异常 repr 甩给调用方（呼应「别弹原始报错」）。"""
    host = (ent.get("host") or DEFAULT_HOST).rstrip("/")
    url = host + path
    body_text = json.dumps(body, ensure_ascii=False) if body is not None else ""
    hdr = {"x-subscription-type": "v2"}
    if body is not None:
        hdr["Content-Type"] = "application/json;charset=utf8"
    if extra:
        hdr.update(extra)
    h = sign_request(method, url, ent.get("ak", ""), ent.get("sk", ""), ent.get("sts_token", ""),
                     project_id=ent.get("project_id", ""), body_text=body_text, extra_headers=hdr)
    last = None
    for attempt in range(1, _tries + 1):
        try:
            r = requests.request(method.upper(), url, headers=h,
                                 data=(body_text or None), timeout=timeout, verify=False)
        except Exception as e:
            last = e
            if _conn_retryable(e) and attempt < _tries:
                time.sleep(0.5 * attempt)        # 0.5s, 1.0s 退避
                continue
            return 0, {"error": _clean_conn_err(e), "raw": str(e)[:160]}
        try:
            return r.status_code, r.json()
        except Exception:
            # 200 但响应体非 JSON（极少见）→ 不当连接错误重试，直接返回原文截断
            return r.status_code, {"raw": r.text[:300]}
    return 0, {"error": _clean_conn_err(last), "raw": str(last)[:160]}


def _expired(ent):
    """sts_token 是否已过期"""
    e = (ent.get("expires_at") or "").strip()
    if not e:
        return None
    try:
        t = datetime.strptime(e.replace("Z", ""), "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        try:
            t = datetime.strptime(e.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    return t < datetime.utcnow()


# ⚠ 实测（2026-10-09）：客户端服务端只在凭据【真正到期】后才肯刷新 ——
#    还剩 1.5h 时调 islogin 返回 true 但 SQLite expires_at 不变。
#    所以这里不做「临期预续」（预续必然空转，且会让每次读状态白等轮询 24s），
#    只做过期后自动续（到期实测 1~5s 出新票）。


def _today_cst():
    """东八区的今天，格式 YYYYMMDD（cbc_resource_id 的时间戳用的就是这个时区）"""
    return (datetime.utcnow() + timedelta(hours=8)).strftime("%Y%m%d")


def _bonus_grant(b):
    """从 bonus_sku 解析「发放日期(CST, YYYYMMDD)」与「类型(daily/once)」。

    cbc_resource_id 形如  bonus:daily-checkin-2026:20261007194649:daily
                          ^activity             ^YYYYMMDDHHMMSS(CST)  ^kind
    解析不出来时退回 effective_time（UTC → +8h 换算成 CST 日期）。
    """
    rid = str((b or {}).get("cbc_resource_id") or "")
    parts = rid.split(":")
    if len(parts) >= 3 and len(parts[2]) >= 8 and parts[2][:8].isdigit():
        return parts[2][:8], (parts[3] if len(parts) > 3 else "")
    et = str((b or {}).get("effective_time") or "")
    if len(et) >= 19 and et[4] == "-":
        try:
            dt = datetime.strptime(et[:19], "%Y-%m-%dT%H:%M:%S") + timedelta(hours=8)
            return dt.strftime("%Y%m%d"), "daily"
        except ValueError:
            pass
    return "", ""


def _num(v, default=0.0):
    return to_float(v, default)


def _parse_subscription(d):
    """把 /v1/subscription 响应归一化为「积分 + 积分包 + 今日是否已签」。
    2026-10-20 起拆分：daily_free=当天 daily 活动奖励（每日免费积分），
    long_term=套餐周期额度 + 非今日活动（长期积分），两者分开统计。"""
    today = _today_cst()
    pkgs, total, used, remain = [], 0.0, 0.0, 0.0
    d_free = d_free_total = d_free_used = 0.0
    lt_total, lt_used, lt_remain = 0.0, 0.0, 0.0
    claimed, acts = False, []

    # ① 套餐自带的周期额度（skus[].quotas[] 里 sku_attr_code == officeace_points）→ 长期
    for sku in (d.get("skus") or []):
        if not isinstance(sku, dict):
            continue
        for q in (sku.get("quotas") or []):
            if not isinstance(q, dict) or str(q.get("sku_attr_code") or "") != "officeace_points":
                continue
            qt, qc = _num(q.get("sku_value")), _num(q.get("current_value"))
            if qt <= 0:
                continue
            pkgs.append({"name": "%s · 周期额度" % (sku.get("sku_name") or "套餐"),
                         "amount": qt, "remain": max(0.0, qt - qc), "used": qc,
                         "expire": sku.get("expired_time"), "source": "measured",
                         "perpetual": False, "kind": "积分", "bucket": "long"})
            total += qt; used += qc; remain += max(0.0, qt - qc)
            lt_total += qt; lt_used += qc; lt_remain += max(0.0, qt - qc)

    # ② 活动奖励（bonus_skus）：当天发放的 daily 活动 = 今天已签到 → 每日免费积分
    for b in (d.get("bonus_skus") or []):
        if not isinstance(b, dict):
            continue
        bp, bc = _num(b.get("points")), _num(b.get("current_value"))
        day, kind = _bonus_grant(b)
        bucket = "daily" if (day == today and kind == "daily") else "long"
        pkgs.append({"name": str(b.get("activity_name") or b.get("activity_id") or "活动奖励"),
                     "amount": bp, "remain": max(0.0, bp - bc), "used": bc,
                     "expire": b.get("expired_time"), "source": "measured",
                     "perpetual": False, "kind": "积分", "bucket": bucket})
        total += bp; used += bc; remain += max(0.0, bp - bc)
        if bucket == "daily":
            d_free_total += bp; d_free_used += bc
            d_free += max(0.0, bp - bc)
        else:
            lt_total += bp; lt_used += bc; lt_remain += max(0.0, bp - bc)
        if day == today and kind == "daily":
            claimed = True
            acts.append(str(b.get("activity_name") or b.get("activity_id") or ""))

    return {"total": total, "used": used, "remain": remain, "packages": pkgs,
            "claimed": claimed, "activities": acts,
            "daily_free": {"remain": round(d_free), "total": round(d_free_total),
                           "used": round(d_free_used)},   # 当天 daily 活动奖励（已领未用口径）
            "long_term": {"remain": round(lt_remain), "total": round(lt_total),
                          "used": round(lt_used)}}


def read_account(name, ent):
    # 续期按钮预填用：ent.phone 优先（短信登录时落盘），键名是 11 位手机号时兑底
    _phone = str(ent.get("phone") or (name if name.isdigit() and len(name) == 11 else "") or "")
    empty = {"name": name, "ok": False, "error": None, "level": "OfficeACE",
             "signed_today": False,
             "credits": {"remain": 0, "total": 0, "used": 0},
             "packages": [], "extra": {"phone": _phone}}
    if not (ent.get("ak") and ent.get("sk") and ent.get("sts_token")):
        empty["error"] = "凭据不完整（缺 AK/SK/STS），请点「从本地客户端导入」"
        return empty

    exp = _expired(ent)
    if exp:
        # 已过期 → 无人值守续期（起 ServiceHeadless + oc_sid 调 islogin；实测到期后 1~5s 出新票）
        ok, _m = try_refresh(name, ent)
        exp = _expired(ent)
        if exp is True:
            empty["error"] = ("OfficeACE 凭据已于 %s 过期且自动续期失败：%s"
                              % ((ent.get("expires_at") or "")[:19], _m))
            empty["extra"] = {"phone": _phone, "expires_at": ent.get("expires_at"),
                              "expired": True}
            return empty
    st, j = _req(ent, SUB_PATH)
    if st in (401, 403) or (isinstance(j, dict) and "APIG." in str(j.get("error_code", ""))):
        # 网关拒了 → 续一次再试
        if try_refresh(name, ent)[0]:
            st, j = _req(ent, SUB_PATH)
        exp = _expired(ent)
        if st in (401, 403) or (isinstance(j, dict) and "APIG." in str(j.get("error_code", ""))):
            empty["error"] = ("华为网关鉴权失败且续期无效：%s（若持续失败请打开 OfficeACE "
                              "客户端重新登录）" % str(j)[:110])
            empty["extra"] = {"phone": _phone, "expires_at": ent.get("expires_at"),
                              "expired": exp}
            return empty
    if st != 200:
        msg = (j.get("error") if isinstance(j, dict) else None) or str(j)
        empty["error"] = "订阅查询失败（HTTP %s）：%s" % (st, str(msg)[:120])
        empty["extra"] = {"phone": _phone, "expires_at": ent.get("expires_at"), "expired": exp}
        return empty

    d = (j.get("data") if isinstance(j, dict) else None) or j or {}
    if isinstance(d, dict) and isinstance(d.get("subscription"), dict):
        d = d["subscription"]
    info = _parse_subscription(d if isinstance(d, dict) else {})

    plan = "OfficeACE 会员"
    for sku in (d.get("skus") or []) if isinstance(d, dict) else []:
        if isinstance(sku, dict) and sku.get("sku_name"):
            plan = str(sku["sku_name"])
            break

    def pick(*keys, default=None):
        for k in keys:
            if isinstance(d, dict) and d.get(k) is not None:
                return d[k]
        return default

    claimed = bool(info["claimed"]) or bool(
        pick("today_claimed", "todayClaimed", "claimed_today", "bonus_claimed", default=False))
    days = pick("continuous_days", "continuousDays", "streak_days", default=None)

    return {
        "name": name, "ok": True, "error": None,
        "level": plan,
        "signed_today": claimed,
        "credits": {"remain": round(info["remain"]), "total": round(info["total"]),
                    "used": round(info["used"])},
        "daily_free": {"remain": info["daily_free"]["remain"],
                       "total": info["daily_free"]["total"],
                       "used": info["daily_free"]["used"]},
        "long_term": info["long_term"],
        "packages": info["packages"],
        "extra": {
            "phone": _phone,
            "can_sign_in": not claimed,
            "today_reward": 1000,
            "today_kind": "积分",
            "streak_days": days,
            "today_activities": info["activities"],
            "subscribe_status": pick("subscribe_status", default=None),
            "expires_at": ent.get("expires_at"),
            "expired": exp,
            "user_id": ent.get("user_id"),
        },
    }


# ───────────────────────── 领取 ─────────────────────────
def run_task(name, ent, task_key):
    if task_key != "checkin":
        return {"ok": False, "msg": "未知任务"}
    if not (ent.get("ak") and ent.get("sk") and ent.get("sts_token")):
        return {"ok": False, "msg": "凭据不完整，请先「从本地客户端导入」"}
    if _expired(ent) is True and not try_refresh(name, ent)[0]:
        return {"ok": False, "msg": ("OfficeACE 临时凭据已于 %s 过期且自动续期失败，"
                                     "请打开客户端重新登录" % (ent.get("expires_at") or "")[:19])}

    # 客户端是带 JSON body 调的；不带 body 时服务端会以 500 + OfficeAce.11020001 应答
    # （那是空 body 的 bug，会被误读成「领取失败」）。所以先带 {} 打，失败再退回无 body。
    st, j = _req(ent, CLAIM_PATH, method="POST", body={})
    if st in (400, 405, 415) or (isinstance(j, dict) and str(j.get("error_code", "")).startswith("APIG")):
        st, j = _req(ent, CLAIM_PATH, method="POST")

    code = str(j.get("error_code") or "") if isinstance(j, dict) else ""
    msg = str(j)[:150]

    # ① 服务端明确说「今天已经领过了」——这不是故障，按「今日已签」返回
    if code == "OfficeAce.11020001" or "已经" in msg or "重复" in msg or "already" in msg.lower():
        return {"ok": True, "msg": "今日已领取（服务端提示已领过），明天再来", "state": "already"}

    # ② 正常 200
    if st == 200 and not code.startswith("APIG"):
        skus = (j.get("bonus_skus") if isinstance(j, dict) else None) or []
        if skus:
            amt = sum(_num(b.get("points")) for b in skus if isinstance(b, dict))
            names = "、".join(str(b.get("activity_name") or b.get("activity_id") or "")
                              for b in skus if isinstance(b, dict))
            return {"ok": True,
                    "msg": "已领取%s%s" % (" +%d 积分" % int(amt) if amt else "",
                                          ("（%s）" % names if names else "")),
                    "state": "claimed"}
        # bonus_skus 为空 = 今天没有可领的了 = 今日已签
        return {"ok": True, "msg": "今日已领取过（暂无可领奖励），明天再来", "state": "already"}

    if st in (401, 403) or code.startswith("APIG"):
        return {"ok": False, "msg": "华为网关鉴权失败：%s（客户端登录态可能已过期）" % msg}
    return {"ok": False, "msg": "领取失败（HTTP %s）：%s" % (st, msg), "state": "failed"}


# ══════════════════ OpenAI 反代（模型网关，2026-10-14 实测打通）══════════════════
# 协议还原自 github aimod-cc/agent2api（officeace provider 模块）+ 本机实测：
#   · 网关三件套在 /v1/subscription 响应的 model_infos[0] 里：
#       model_api_url_base（= 本适配器的 DEFAULT_HOST 同主机）
#       model_auth_info.model_app_key / model_app_secret（32hex 一对，Basic 头，
#       **不过期**——控制面 STS 过期只影响额度/签到，不影响转发）
#   · 模型目录 GET https://{host}/v2/models（OpenAI {data:[{id,...}]}，21 个）
#   · chat POST https://{host}/v2/chat/completions：标准 OpenAI 体，上游**恒流式**
#     （stream:true 强制 + stream_options.include_usage）；
#     ⚠ 上游把 max_tokens 当「推理+正文」总预算，给小了 200 但正文空
#       （finish_reason=length）→ 本地追加 1024 下限（<16 原样透传）
#   · 关联头 Chat-Id / Session-Id（32hex，本地生成）+ lang: en
_GW_CACHE = {"ts": 0.0, "host": "", "key": "", "secret": ""}
_GW_TTL = 600.0
_MODELS_CACHE = {"ts": 0.0, "ids": []}


def gw_credentials(ent, force=False):
    """订阅响应里的模型网关三件套，返回 (host, app_key, app_secret)。TTL 缓存；
    刷新失败时回退上次缓存（Basic 对不过期，缓存旧值无害）。失败抛 RuntimeError。"""
    now = time.time()
    if not force and _GW_CACHE["key"] and now - _GW_CACHE["ts"] < _GW_TTL:
        return _GW_CACHE["host"], _GW_CACHE["key"], _GW_CACHE["secret"]
    st, j = _req(ent, SUB_PATH, timeout=20)
    if st != 200:
        raise RuntimeError("subscription HTTP %s" % st)
    d = (j.get("data") if isinstance(j, dict) else None) or j or {}
    if isinstance(d, dict) and isinstance(d.get("subscription"), dict):
        d = d["subscription"]
    mi = (d.get("model_infos") or [{}])[0]
    host = str(mi.get("model_api_url_base") or "").strip().strip("/")
    auth = mi.get("model_auth_info") or {}
    key = str(auth.get("model_app_key") or "").strip()
    secret = str(auth.get("model_app_secret") or "").strip()
    if not (host and key and secret):
        raise RuntimeError("订阅响应缺少模型网关三件套（账号可能未开通）")
    _GW_CACHE.update(ts=now, host=host, key=key, secret=secret)
    return host, key, secret


def _gw_headers(host_key_secret):
    host, key, secret = host_key_secret
    import base64 as _b64
    import uuid as _uuid
    basic = _b64.b64encode(("%s:%s" % (key, secret)).encode()).decode()
    return {"Authorization": "Basic " + basic, "Content-Type": "application/json",
            "Accept": "*/*", "lang": "en",
            "Chat-Id": _uuid.uuid4().hex, "Session-Id": _uuid.uuid4().hex}


def gw_models(ent, force=False):
    """模型目录（{host}/v2/models，OpenAI 形状）。TTL 缓存；失败抛异常。"""
    now = time.time()
    if not force and _MODELS_CACHE["ids"] and now - _MODELS_CACHE["ts"] < _GW_TTL:
        return list(_MODELS_CACHE["ids"])
    host, key, secret = gw_credentials(ent, force=force)
    r = requests.get("https://%s/v2/models" % host, headers=_gw_headers((host, key, secret)),
                     timeout=20, verify=False, proxies={"http": None, "https": None})
    if r.status_code != 200:
        raise RuntimeError("models HTTP %s %s" % (r.status_code, r.text[:100]))
    ids = [m.get("id") for m in (r.json().get("data") or []) if m.get("id")]
    if ids:
        _MODELS_CACHE.update(ts=now, ids=ids)
    return ids


# 推理预算追加量：上游把 max_tokens 当总预算（agent2api 同款处理，勿改小）
REASONING_ALLOWANCE = 1024


def chat_stream(ent, openai_body):
    """调模型网关 chat，返回 SSE 行迭代器（标准 OpenAI chunk，可直接透传）。"""
    host, key, secret = gw_credentials(ent)
    body = dict(openai_body or {})
    mt = body.get("max_tokens")
    if isinstance(mt, int) and mt >= 16:
        body["max_tokens"] = mt + REASONING_ALLOWANCE
    body["stream"] = True
    so = body.get("stream_options")
    body["stream_options"] = dict(so) if isinstance(so, dict) else {}
    body["stream_options"].setdefault("include_usage", True)
    data = json.dumps(body, ensure_ascii=False)
    r = requests.post("https://%s/v2/chat/completions" % host,
                      headers=_gw_headers((host, key, secret)), data=data.encode("utf-8"),
                      timeout=(15, 600), verify=False, stream=True,
                      proxies={"http": None, "https": None})
    if r.status_code >= 400:
        raise RuntimeError("chat HTTP %s %s" % (r.status_code, r.text[:200]))
    r.encoding = "utf-8"      # 上游 SSE 不带 charset，防中文乱码（同 CodeArts 坑）
    return r.iter_lines(decode_unicode=True)
