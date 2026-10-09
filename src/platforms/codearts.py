# -*- coding: utf-8 -*-
"""
CodeArts Agent（码道 / 华为云）· 看板平台适配器
════════════════════════════════════════════════════════════════════════
接口口径（逆向自客户端 + 本机实测，2026-10 验证）：

  福利列表  GET  https://snap-access.cn-north-4.myhuaweicloud.com/v1/ops/delivery?channel=IDE
  每日领取  POST /v1/ops/claim    body {"campaignId":1,"channel":"IDE"}
  确认到账  POST /v1/ops/confirm  body {"campaignId":1}   （仅当 claim 返回 data.id != null）
  用户信息  GET  https://sts.cn-north-4.myhuaweicloud.com/v5/caller-identity

鉴权：华为云 API 网关 **SDK-HMAC-SHA256**（不是 V11）；请求头需带
      Content-Type / X-Security-Token / Agent-Type:PromptCenter / X-Language:zh-cn
      / X-Sdk-Date，并对全部头做签名：
        CanonicalURI  = path 每段 RFC3986 编码 + 末尾补 "/"
        StringToSign  = "SDK-HMAC-SHA256\n" + X-Sdk-Date + "\n" + sha256hex(CanonicalRequest)
        Signature     = HMAC-SHA256(secretKey, StringToSign) 的 hex
        Authorization = "SDK-HMAC-SHA256 Access=<AK>, SignedHeaders=a;b;c, Signature=<hex>"

每日奖励：campaignId=1 / type=USER_LOGIN /「每日签到领 1000 积分」/ 30 天有效 /
          北京时间 00:00（UTC+8）重置。重复领取返回 code=40001
          「尚未到达权益刷新时间，暂时无法领取」。

⚠ 本适配器对客户端凭据库 **100% 只读**（sqlite mode=ro），且**不刷新客户端会话**：
   客户端的 refresh_token 是一次性且用后轮换，客户端与看板共用一个；看板一旦刷新就会
   把桌面端踢成「需重新登录」。

✅ 2026-10-08 新增「看板自建会话」：看板自己发起 OAuth 登录（portal/authorize + DPoP
   ES256 换 token），拿到的 refresh_token **归看板独享** —— 刷新它不影响桌面端。
   该会话落在 codearts_accounts.json（带 refresh_token/code_verifier/DPoP 私钥），
   凭据过期时本适配器会自动续期并回写凭据文件，1 小时过期问题就此解决。
"""
import os
import sys
import json
import time
import hmac
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlsplit, parse_qsl, quote

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

PLATFORM = "codearts"
LABEL = "CodeArts Agent"
TASKS = [{"key": "checkin", "label": "每日领取 1000 积分", "daily": True}]

SNAP = "https://snap-access.cn-north-4.myhuaweicloud.com"
DEFAULT_HOST = SNAP
DELIVERY_PATH = "/v1/ops/delivery"
CLAIM_PATH = "/v1/ops/claim"
CONFIRM_PATH = "/v1/ops/confirm"
# 真实余额接口（2026-10-09 逆向自客户端 vscode-codebot/out/extension.js 的
# getTokensBalance，与客户端同口径；GET，同一套 SDK-HMAC-SHA256 签名，实测 200）：
#   返回 result.{total_balance, total_quota, used_amount, daily_token_limit,
#                daily_tokens_used, monthly_*, expire_time}
# ⚠ 这是【每日免费 token 额度】，不是积分！积分（签到领的那种）在
#   GET /snap-manager/v1/statistics/plugin → metrics 里 name=usageTotalPackageCredit
#   的 {package_credit_amount/used/remain, package_credit_expiring_amount}
#   （2026-10-09 实测 remain=25000，与客户端显示一致）。
OPENGW = "https://opengw.developer.huaweicloud.com"
BALANCE_PATH = "/api/v1/user/tokens/balance"
STATS_PATH = "/snap-manager/v1/statistics/plugin"
CHANNEL = "IDE"
ALGO = "SDK-HMAC-SHA256"
DAILY_CAMPAIGN_ID = 1
COMMON_HDR = {"Agent-Type": "PromptCenter", "X-Language": "zh-cn"}


def _hex_sha256(x):
    return hashlib.sha256(x if isinstance(x, bytes) else x.encode("utf-8")).hexdigest()


def _enc(x):
    return quote(str(x), safe="-_.~")


def sign_headers(ak, sk, sts, method, url, body="", extra=None):
    """与客户端 Signer 类等价的 SDK-HMAC-SHA256 签名；返回完整请求头 dict。"""
    hdr = {"Content-Type": "application/json", "X-Security-Token": sts}
    hdr.update(COMMON_HDR)
    if extra:
        hdr.update(extra)
    hdr["X-Sdk-Date"] = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    u = urlsplit(url)
    uri = "/".join(_enc(t) for t in u.path.split("/"))
    if not uri.endswith("/"):
        uri += "/"
    qs = sorted(parse_qsl(u.query, keep_blank_values=True))
    canon_query = "&".join("%s=%s" % (_enc(k), _enc(v)) for k, v in qs)

    signed = sorted(k.lower() for k in hdr)
    low = {k.lower(): v for k, v in hdr.items()}
    canon_headers = "".join("%s:%s\n" % (k, str(low[k]).strip()) for k in signed)
    canon_req = "\n".join([method.upper(), uri, canon_query, canon_headers,
                           ";".join(signed), _hex_sha256(body or "")])
    to_sign = "%s\n%s\n%s" % (ALGO, hdr["X-Sdk-Date"], _hex_sha256(canon_req))
    sig = hmac.new(sk.encode("utf-8"), to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    hdr["Authorization"] = "%s Access=%s, SignedHeaders=%s, Signature=%s" % (
        ALGO, ak, ";".join(signed), sig)
    return hdr


def _req(ent, path, method="GET", query=None, body=None, timeout=25, base=None):
    host = (base or ent.get("host") or DEFAULT_HOST).rstrip("/")
    url = host + path
    if query:
        url += "?" + "&".join("%s=%s" % (_enc(k), _enc(v)) for k, v in query)
    body_text = json.dumps(body, ensure_ascii=False) if body is not None else ""
    hdr = sign_headers(ent.get("ak", ""), ent.get("sk", ""), ent.get("sts_token", ""),
                       method, url, body_text)
    try:
        r = requests.request(method.upper(), url, headers=hdr,
                             data=(body_text or None), timeout=timeout, verify=False)
    except Exception as e:
        return 0, {"error": str(e)[:160]}
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"raw": r.text[:300]}


def expired(ent):
    """临时凭证是否已过期（返回 True/False/None=未知）"""
    e = (ent.get("expires_at") or "").strip()
    if not e:
        return None
    try:
        t = datetime.fromisoformat(e.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t < datetime.now(timezone.utc)


# ───────────────────────── 凭据 ─────────────────────────
_ACC_FILES = (os.path.join(ROOT, "codearts_accounts.json"),
              os.path.join(HERE, "codearts_accounts.json"))
STS_TOKEN_URL = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens"

# ── 删除墓碑（2026-10-09）：删除只删凭据文件还不够 —— load_accounts 每次都会从
#    客户端 state.vscdb 重新导入同名账号（「删完又冒出来；第二次删报未找到」）。
#    墓碑按账号键名记录；文件里真实存在同键名条目时自动解除（新登录即复活）。
_TOMB_FILES = (os.path.join(ROOT, "codearts_deleted.json"),
               os.path.join(HERE, "codearts_deleted.json"))


def _load_tombs():
    """返回 (墓碑列表, 可写路径)。"""
    for p in _TOMB_FILES:
        if os.path.exists(p):
            try:
                d = json.load(open(p, encoding="utf-8"))
                if isinstance(d, list):
                    return d, p
            except Exception:
                pass
    return [], _TOMB_FILES[0]


def _save_tombs(lst, path):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(lst, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def remove_account(name):
    """删除 CodeArts 账号：移除凭据文件条目 + 记墓碑（抑制客户端导入复活）。
    返回 (ok, msg)。"""
    name = str(name or "").strip()
    if not name:
        return False, "缺少账号标识"
    removed_file = False
    for p in _ACC_FILES:
        if not os.path.exists(p):
            continue
        try:
            data = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and name in data:
            data.pop(name, None)
            try:
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=1)
                removed_file = True
            except Exception:
                pass
    tombs, tp = _load_tombs()
    if name not in tombs:
        tombs.append(name)
        _save_tombs(tombs, tp)
    if removed_file:
        return True, "已删除（客户端导入不会再复活）"
    return True, "已删除并加入屏蔽名单（该账号来自客户端会话）"


def load_accounts():
    """凭据来源（合并，同键名时后加载者优先）：
       1) codearts_accounts.json —— 看板自建会话（带 refresh_token → 可自动续期）
       2) 客户端 state.vscdb 里的最新会话（**只读**，永远最准，同键名覆盖自建会话）
       3) 环境变量 CODEARTS_AK / CODEARTS_SK / CODEARTS_STS
    """
    accs = {}
    tombs, _tp = _load_tombs()
    # ① 看板自建会话（真实保存的条目出现 → 自动解除同名墓碑）
    for path in _ACC_FILES:
        if not os.path.exists(path):
            continue
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        items = [(str(k), v) for k, v in data.items()] if isinstance(data, dict) else \
            [(str(it.get("name") or "CodeArts%d" % (i + 1)), it) for i, it in enumerate(data or [])]
        for nm, v in items:
            if isinstance(v, dict) and v.get("ak") and v.get("sk") and v.get("sts_token"):
                accs[nm] = v
                if nm in tombs:
                    tombs = [t for t in tombs if t != nm]
                    _save_tombs(tombs, _tp)
    # ② 客户端最新会话（同键名覆盖，但**保留自建会话的续期材料**：
    #    refresh_token 与 client_id=codearts-agent、DPoP 私钥绑定，与当前 STS 无关；
    #    客户端导入的新鲜 AK/SK + 自建的 refresh_token 可以组合使用，且刷新成功
    #    后 _persist_entry 会把续期材料固化回 codearts_accounts.json）
    _PRESERVE = ("refresh_token", "dpop_priv_pem", "dpop_pub_jwk", "code_verifier")
    try:
        import local_import
        ok, _msg, live = local_import.read_codearts()
        if ok and live:
            for k, v in live.items():
                if k in tombs:          # 已删除的账号：客户端会话不再导入
                    continue
                base = accs.get(k) or {}
                for f in _PRESERVE:
                    if not (v.get(f) or "").strip() and (base.get(f) or "").strip():
                        v[f] = base[f]
                accs[k] = v
    except Exception:
        pass
    # ③ 环境变量
    ak = (os.environ.get("CODEARTS_AK", "") or "").strip()
    sk = (os.environ.get("CODEARTS_SK", "") or "").strip()
    sts = (os.environ.get("CODEARTS_STS", "") or "").strip()
    if ak and sk and sts:
        accs["CodeArts"] = {"ak": ak, "sk": sk, "sts_token": sts,
                            "expires_at": (os.environ.get("CODEARTS_EXPIRES") or "").strip()}
    return accs


# ───────────────── 自动续期（看板自建会话，DPoP refresh）─────────────────
def _dpop_jwt(priv_pem, pub_jwk_json, htm, htu):
    """DPoP proof：ES256 P-256（与客户端 plugin.js 同款：{alg,typ:dpop+jwt,jwk}/{htm,htu,iat,jti}）。"""
    import base64 as b64mod
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

    b64u = lambda b: b64mod.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
    jwk = json.loads(pub_jwk_json)
    priv = serialization.load_pem_private_key(priv_pem.encode("ascii"), password=None)
    header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk}
    payload = {"htm": htm, "htu": htu, "iat": int(datetime.now(timezone.utc).timestamp()),
               "jti": os.urandom(32).hex()}
    si = (b64u(json.dumps(header, separators=(",", ":")).encode("ascii")) + "." +
          b64u(json.dumps(payload, separators=(",", ":")).encode("ascii")))
    der = priv.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    return si + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _extract_credentials(j):
    """token 响应 → (ak, sk, sts_token, expires_at_iso)。credentials 包裹优先，顶层兜底。"""
    cred = (j or {}).get("credentials") if isinstance(j, dict) else None
    if not isinstance(cred, dict):
        cred = j if isinstance(j, dict) else {}

    def g(*keys):
        for src in (cred, j if isinstance(j, dict) else {}):
            for k in keys:
                v = src.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
        return ""
    ak = g("access_key", "accessKey", "ak", "AK")
    sk = g("secret_key", "secretKey", "sk", "SK")
    sts = g("security_token", "securityToken", "securitytoken", "sts_token")
    exp = g("expires_at", "expiresAt")
    if not exp:
        ein = cred.get("expires_in") or (j or {}).get("expires_in")
        try:
            exp = datetime.fromtimestamp(time.time() + float(ein), timezone.utc) \
                .strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError):
            exp = ""
    return ak, sk, sts, exp


def _persist_entry(name, ent):
    """把续期后的凭据回写进 codearts_accounts.json（只动这一个键名）。"""
    for path in _ACC_FILES:
        if not os.path.exists(path):
            continue
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and name in data:
            data[name] = ent
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=1)
                return True
            except Exception:
                return False
    # 没有现成文件/键 → 写第一份（ROOT 优先）
    try:
        data = {}
        if os.path.exists(_ACC_FILES[0]):
            data = json.load(open(_ACC_FILES[0], encoding="utf-8")) or {}
        data[name] = ent
        with open(_ACC_FILES[0], "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        return True
    except Exception:
        return False


def try_refresh(name, ent):
    """用看板自建会话续期（DPoP refresh_token）。成功返回 (True, 提示) 并回写文件。"""
    rt = (ent.get("refresh_token") or "").strip()
    cv = (ent.get("code_verifier") or "").strip()
    pem = (ent.get("dpop_priv_pem") or "").strip()
    jwk = (ent.get("dpop_pub_jwk") or "").strip()
    if not (rt and cv and pem and jwk):
        return False, "无续期材料（客户端导入的会话不支持看板侧刷新）"
    try:
        hdr = {"Content-Type": "application/x-www-form-urlencoded",
               "DPoP": _dpop_jwt(pem, jwk, "POST", STS_TOKEN_URL)}
    except Exception as e:
        return False, "DPoP 材料损坏：%s" % str(e)[:80]
    body = urllib.parse.urlencode({
        "client_id": "codearts-agent", "code_verifier": cv,
        "grant_type": "refresh_token", "refresh_token": rt})
    try:
        r = requests.post(STS_TOKEN_URL, data=body, headers=hdr, timeout=25, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {"raw": r.text[:200]}
    except Exception as e:
        return False, "续期请求异常：%s" % str(e)[:100]
    ak, sk, sts, exp = _extract_credentials(j)
    if r.status_code == 200 and ak and sk and sts:
        ent["ak"], ent["sk"], ent["sts_token"], ent["expires_at"] = ak, sk, sts, exp
        ent["refresh_token"] = (str((j or {}).get("refresh_token") or "") or rt)
        _persist_entry(name, ent)
        return True, "已自动续期至 %s" % exp[:19]
    return False, "续期失败（HTTP %s）：%s" % (r.status_code, str(j)[:120])


def _expiring_soon(ent, margin_s=900):
    """是否将在 margin_s 秒内到期（True/False；None=未知）。"""
    e = (ent.get("expires_at") or "").strip()
    if not e:
        return None
    try:
        t = datetime.fromisoformat(e.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return (t - datetime.now(timezone.utc)).total_seconds() <= margin_s


def _refresh_if_needed(name, ent):
    """临期（≤15 分钟）即预刷新保活（不等真过期，避免链路断档）。
       返回凭据当前是否可用：刷新成功/票还活着 → True。"""
    if not (ent.get("refresh_token") or "").strip():
        return expired(ent) is not True
    if expired(ent) is True or _expiring_soon(ent) is True:
        ok, _msg = try_refresh(name, ent)
        if ok:
            return True
        # 预刷新失败但旧票仍未过期（如瞬时网络问题）→ 继续用旧票
        return expired(ent) is not True
    return True


# ───────────────────────── 读取 ─────────────────────────
def _items(j):
    d = (j or {}).get("data")
    if isinstance(d, dict):
        return d.get("items") or []
    if isinstance(d, list):
        return d
    return []


def fetch_balance(ent):
    """查【每日免费 token 额度】（客户端 getTokensBalance 同款，⚠ 不是积分）。
    返回 (result_dict|None, err|None)。"""
    st, j = _req(ent, BALANCE_PATH, base=OPENGW)
    if st == 200 and isinstance(j, dict) and j.get("error_code") == "0000":
        res = j.get("result")
        return (res if isinstance(res, dict) else None), None
    return None, "token额度查询失败（HTTP %s）：%s" % (st, str(j)[:120])


def fetch_credits(ent):
    """查真实【积分】（客户端「总积分」同款：statistics/plugin →
    metrics[name=usageTotalPackageCredit].package_credit_*）。
    返回 (dict{remain,used,total,expiring,bonus}|None, err|None)。"""
    st, j = _req(ent, STATS_PATH)
    if st != 200:
        return None, "积分查询失败（HTTP %s）：%s" % (st, str(j)[:120])
    metrics = (j or {}).get("metrics") if isinstance(j, dict) else None
    if not isinstance(metrics, list):
        return None, "积分响应无 metrics 字段：%s" % str(j)[:120]
    tot = next((m for m in metrics if m.get("name") == "usageTotalPackageCredit"), None)
    bonus = next((m for m in metrics if m.get("name") == "usageBonusPackageCredit"), None)
    if tot is None:
        return None, "metrics 中无 usageTotalPackageCredit：%s" % str(j)[:120]

    def g(m, k):
        try:
            return float(m.get(k) or 0)
        except (TypeError, ValueError):
            return 0.0
    return {
        "remain": g(tot, "package_credit_remain"),
        "used": g(tot, "package_credit_used"),
        "total": g(tot, "package_credit_amount"),
        "expiring": g(tot, "package_credit_expiring_amount"),
        "bonus_remain": g(bonus, "package_credit_remain") if bonus else None,
        "metrics": metrics,
    }, None


def read_account(name, ent):
    empty = {"name": name, "ok": False, "error": None, "level": "CodeArts Agent",
             "signed_today": False,
             "credits": {"remain": 0, "total": 0, "used": 0},
             "packages": [], "extra": {}}
    if not (ent.get("ak") and ent.get("sk") and ent.get("sts_token")):
        empty["error"] = "凭据不完整（缺 AK/SK/STS），请点「从本地客户端导入」"
        return empty

    exp = expired(ent)
    if not _refresh_if_needed(name, ent):
        empty["error"] = ("CodeArts 凭证已于 %s 过期且自动续期失败。"
                          "看板自建会话请重新短信登录；客户端会话请打开客户端续期。"
                          % (ent.get("expires_at") or "")[:19])
        empty["extra"] = {"expires_at": ent.get("expires_at"), "expired": True,
                          "can_refresh": bool(ent.get("refresh_token"))}
        return empty
    exp = expired(ent)   # 续期后可能已更新
    st, j = _req(ent, DELIVERY_PATH, query=[("channel", CHANNEL)])
    if st in (401, 403) or (isinstance(j, dict) and "APIG." in str(j.get("error_code", ""))):
        # 网关拒了 → 若有续期材料就续一次再试
        if ent.get("refresh_token") and try_refresh(name, ent)[0]:
            st, j = _req(ent, DELIVERY_PATH, query=[("channel", CHANNEL)])
        if st in (401, 403) or (isinstance(j, dict) and "APIG." in str(j.get("error_code", ""))):
            empty["error"] = ("华为网关鉴权失败且续期无效。看板自建会话请重新短信登录；"
                              "客户端会话请打开 CodeArts Agent 客户端续期。")
            empty["extra"] = {"expires_at": ent.get("expires_at"), "expired": expired(ent)}
            return empty
    if st != 200:
        empty["error"] = "福利列表查询失败（HTTP %s）：%s" % (st, str(j)[:120])
        empty["extra"] = {"expires_at": ent.get("expires_at"), "expired": exp}
        return empty

    items = _items(j)
    daily = next((x for x in items if x.get("campaignId") == DAILY_CAMPAIGN_ID), None)
    if daily is None:
        daily = next((x for x in items if x.get("type") == "USER_LOGIN"), None)

    claimable = [x for x in items if x.get("claimable")]
    daily_claimable = bool(daily and daily.get("claimable"))
    amount = (daily or {}).get("benefitAmount") or 1000
    unit = (daily or {}).get("benefitUnit") or "CREDIT"
    pending = (daily or {}).get("pendingTotalAmount")
    if pending is None:
        pending = amount if daily_claimable else 0

    pkgs = []
    try:
        if float(pending) > 0:
            pkgs.append({"name": "每日签到待领", "amount": float(amount), "remain": float(pending),
                         "used": max(0.0, float(amount) - float(pending)), "expire": None,
                         "source": "measured", "perpetual": False, "kind": "积分"})
    except (TypeError, ValueError):
        pass

    # ── 真实【积分】（客户端「总积分」同口径，2026-10-09 二次修复：
    #    第一版误用 tokens/balance（那是每日免费 token 额度，10,000,000），
    #    积分真身 = statistics/plugin → metrics[usageTotalPackageCredit].package_credit_*，
    #    实测 remain=25000 与客户端显示一致）──
    cred, cred_err = fetch_credits(ent)
    if cred:
        credits = {"remain": int(cred["remain"]), "total": int(cred["total"]),
                   "used": int(cred["used"])}
    else:
        # 积分接口失败 → 置 0 并透出错误（绝不用 token 额度冒充积分）
        credits = {"remain": 0, "total": 0, "used": 0}

    extra = {
        "can_sign_in": daily_claimable,
        "today_reward": amount,
        "today_kind": "积分",
        "pending_amount": pending,
        "daily_status": (daily or {}).get("status"),
        "campaign_count": len(items),
        "claimable_count": len(claimable),
        "expires_at": ent.get("expires_at"),
        "expired": exp,
        "other_campaigns": [{"id": x.get("campaignId"), "type": x.get("type"),
                             "amount": x.get("benefitAmount")} for x in items
                            if x.get("campaignId") != DAILY_CAMPAIGN_ID][:5],
        "account_id": ent.get("account_id"),
    }
    if cred:
        extra.update({
            "credits_ok": True,
            "credits_expiring": int(cred["expiring"]),
            "credits_bonus_remain": (int(cred["bonus_remain"])
                                     if cred.get("bonus_remain") is not None else None),
        })
    else:
        extra["credits_ok"] = False
        extra["credits_error"] = cred_err
    # 每日免费 token 额度（另一套体系，勿与积分混淆）→ 只进 extra
    bal, bal_err = fetch_balance(ent)
    if bal:
        def _num(k):
            try:
                return int(float(bal.get(k) or 0))
            except (TypeError, ValueError):
                return 0
        extra.update({
            "free_token_total": _num("total_quota"),
            "free_token_remain": _num("total_balance"),
            "free_token_used": _num("used_amount"),
            "free_token_daily_limit": _num("daily_token_limit"),
            "free_token_daily_used": _num("daily_tokens_used"),
            "free_token_channel": bal.get("channel"),
        })
    else:
        extra["free_token_error"] = bal_err

    return {
        "name": name, "ok": True, "error": None,
        "level": "CodeArts Agent · 华为云",
        "signed_today": not daily_claimable,
        "credits": credits,
        "packages": pkgs,
        "extra": extra,
    }


# ───────────────────────── 领取 ─────────────────────────
def run_task(name, ent, task_key):
    if task_key != "checkin":
        return {"ok": False, "msg": "未知任务"}
    if not (ent.get("ak") and ent.get("sk") and ent.get("sts_token")):
        return {"ok": False, "msg": "凭据不完整，请先「从本地客户端导入」"}
    if expired(ent) is True and not _refresh_if_needed(name, ent):
        return {"ok": False, "msg": ("CodeArts 凭证已于 %s 过期且自动续期失败；"
                                     "看板自建会话请重新短信登录，客户端会话请打开客户端续期"
                                     % (ent.get("expires_at") or "")[:19])}

    st, j = _req(ent, DELIVERY_PATH, query=[("channel", CHANNEL)])
    if st in (401, 403) and ent.get("refresh_token") and try_refresh(name, ent)[0]:
        st, j = _req(ent, DELIVERY_PATH, query=[("channel", CHANNEL)])
    if st != 200:
        return {"ok": False, "msg": "福利列表查询失败（HTTP %s）：%s" % (st, str(j)[:120])}
    items = _items(j)
    daily = next((x for x in items if x.get("campaignId") == DAILY_CAMPAIGN_ID), None) or \
        next((x for x in items if x.get("type") == "USER_LOGIN"), None)
    if not daily:
        return {"ok": False, "msg": "未找到「每日签到」活动（接口返回中无 campaignId=1）"}
    if not daily.get("claimable"):
        return {"ok": True, "msg": "今日已领取（状态 %s），明天再来" % (daily.get("status") or "已领"),
                "state": "already"}

    cid = daily.get("campaignId") or DAILY_CAMPAIGN_ID
    st2, j2 = _req(ent, CLAIM_PATH, method="POST", body={"campaignId": cid, "channel": CHANNEL})
    code = (j2 or {}).get("code") if isinstance(j2, dict) else None
    if st2 == 200 and code == 0:
        d = (j2.get("data") or {})
        amt = d.get("totalAmount") or daily.get("benefitAmount")
        msgs = ["已领取 +%s 积分" % (int(float(amt)) if amt else "")]
        if d.get("id") is not None:
            st3, j3 = _req(ent, CONFIRM_PATH, method="POST", body={"campaignId": cid})
            if st3 == 200 and (j3 or {}).get("code") == 0:
                msgs.append("已确认到账")
            else:
                msgs.append("确认到账未成功（HTTP %s）" % st3)
        if d.get("expireAt"):
            msgs.append("有效期至 %s" % str(d["expireAt"])[:10])
        return {"ok": True, "msg": "；".join(msgs), "state": "claimed"}
    if st2 == 200 and code == 40001:
        return {"ok": True, "msg": "今日已领取（尚未到达下次刷新时间）", "state": "already"}
    if st2 in (401, 403) or "APIG." in str(j2):
        return {"ok": False, "msg": "凭证已失效，请打开 CodeArts Agent 客户端续期后重试"}
    return {"ok": False, "msg": "领取失败（HTTP %s）：%s" % (st2, str(j2)[:140]), "state": "failed"}
