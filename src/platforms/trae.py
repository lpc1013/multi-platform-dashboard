# -*- coding: utf-8 -*-
"""
Trae（CN / SOLO CN）平台适配器
════════════════════════════════════════════════════════════════════════
凭据：从本机 Trae 客户端 storage.json 的 iCubeAuthInfo://icube.cloudide 解密得到
      （AES-128-CBC + SHA-512 密钥派生，见 local_import.read_trae）
      → token(Cloud-IDE-JWT) / userId / userRegion / device_id

接口（Trae 官方签到接口，社区脚本与客户端行为一致）：
  POST /trae/api/v2/ug/checkin_credits/status      今日签到状态
  POST /trae/api/v2/ug/checkin_credits/claim       每日签到
  POST /trae/api/v2/pay/ide_user_ent_usage         额度/权益明细
请求头：
  Authorization: Cloud-IDE-JWT <token>
  x-device-id:   <device_id>       ← claim 缺少它会被网关拒为 9004
  X-User-Region: CN
"""
import os
import json
import time
import datetime
import urllib.request
import urllib.error

try:                       # 包内导入（server.py: import platforms.trae）
    from ._util import to_float as _num
except ImportError:        # 直接以脚本运行（python platforms/trae.py）时的兜底
    def _num(v, default=0.0):
        try:
            return float(v)
        except (TypeError, ValueError):
            return default

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

LABEL = "Trae"
TASKS = [{"key": "checkin", "label": "每日签到"}]

DEFAULT_HOST = "https://api.trae.cn"
STATUS_PATH = "/trae/api/v2/ug/checkin_credits/status"
CLAIM_PATH = "/trae/api/v2/ug/checkin_credits/claim"
USAGE_PATH = "/trae/api/v2/pay/ide_user_ent_usage"
REQ_SOURCE = 1          # 1 = Trae CN IDE（与 SOLO 积分互通）

_UA = "Trae-CN/2.3.87413"


# ───────────────────────── 凭据 ─────────────────────────
def load_accounts():
    """凭据来源（优先级从高到低）：
       1) 环境变量 TRAE_TOKEN（单账号，需配合 TRAE_DEVICE_ID）
       2) 凭据文件 ROOT/trae_accounts.json 或 HERE/trae_accounts.json
          {"一只总柴": {"token": "...", "device_id": "...", "user_id": "...",
                        "region": "CN", "host": "https://api.trae.cn"}}
    """
    accs = {}
    tok = (os.environ.get("TRAE_TOKEN", "") or "").strip()
    if tok:
        accs["Trae"] = {"token": tok,
                        "device_id": (os.environ.get("TRAE_DEVICE_ID", "") or "").strip(),
                        "user_id": (os.environ.get("TRAE_USER_ID", "") or "").strip(),
                        "region": (os.environ.get("TRAE_REGION", "") or "CN").strip(),
                        "host": DEFAULT_HOST}
    for path in (os.path.join(ROOT, "trae_accounts.json"),
                 os.path.join(HERE, "trae_accounts.json")):
        if not os.path.exists(path):
            continue
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, dict) and v.get("token"):
                    accs[str(k)] = v
        elif isinstance(data, list):
            for i, it in enumerate(data):
                if isinstance(it, dict) and it.get("token"):
                    nm = str(it.get("name") or "Trae%d" % (i + 1))
                    accs[nm] = it
    return accs


# ───────────────────────── HTTP ─────────────────────────
def _call(ent, path, body, timeout=25):
    tok = (ent.get("token") or "").strip()
    if not tok:
        raise RuntimeError("未配置 token")
    host = (ent.get("host") or DEFAULT_HOST).rstrip("/")
    h = {
        "Authorization": "Cloud-IDE-JWT " + tok,
        "Content-Type": "application/json",
        "User-Agent": _UA,
        "Accept": "application/json, text/plain, */*",
    }
    did = (ent.get("device_id") or "").strip()
    if did:
        h["x-device-id"] = did
    uid = (ent.get("user_id") or "").strip()
    if uid:
        h["x-user-id"] = uid
        h["X-User-Id"] = uid
    region = (ent.get("region") or "").strip()
    if region:
        h["X-User-Region"] = region
    req = urllib.request.Request(host + path, data=json.dumps(body).encode("utf-8"),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return -1, str(e)[:160]


def _unwrap(j):
    """兼容扁平响应与 {code,data:{...}}"""
    if isinstance(j, dict) and "checked_in" not in j and isinstance(j.get("data"), dict) \
            and "checked_in" in j["data"]:
        return j["data"]
    return j if isinstance(j, dict) else {}


def _status(ent):
    return _call(ent, STATUS_PATH, {"req_source": REQ_SOURCE})


def _usage(ent):
    return _call(ent, USAGE_PATH, {"require_usage": True, "req_source": REQ_SOURCE})


# ───────────────────────── 读取 ─────────────────────────
def read_account(name, ent):
    # 续期按钮预填用：Trae 落盘字段是 mobile；键名是 11 位手机号时兑底
    _phone = str(ent.get("phone") or ent.get("mobile")
                 or (name if name.isdigit() and len(name) == 11 else "") or "")
    empty = {"name": name, "ok": False, "error": None, "level": "?",
             "signed_today": False,
             "credits": {"remain": 0, "total": 0, "used": 0},
             "packages": [], "extra": {"phone": _phone}}
    if not (ent.get("token") or "").strip():
        empty["error"] = "未配置 token（请点「从本地客户端导入」）"
        return empty

    st, j = _status(ent)
    if st == -1:
        empty["error"] = "签到状态查询异常：%s" % str(j)[:100]
        return empty
    if st in (401, 403):
        empty["error"] = "登录态已失效（HTTP %s），请打开 Trae 客户端重新登录后再次导入" % st
        return empty
    d = _unwrap(j)
    if st != 200 or (d.get("code") not in (0, None) and "checked_in" not in d):
        empty["error"] = "签到状态查询失败（HTTP %s）：%s" % (st, _msg_of(d, j))
        return empty

    signed = bool(d.get("checked_in"))
    day_credits = _num(d.get("credits"))
    extra_credits = _num(d.get("extra_credits"))
    enable = d.get("enable", True)

    # 额度
    total = used = remain = 0
    packages = []
    level = "免费版"
    us, uj = _usage(ent)
    if us == 200 and isinstance(uj, dict):
        summ = uj.get("usage_summary") or {}
        total = _num(summ.get("total_amount"))
        used = _num(summ.get("consumed_amount"))
        remain = max(0.0, total - used)
        if uj.get("is_pay_freshman"):
            level = "免费版（新人）"
        if uj.get("is_credits_billing"):
            level += " · 积分计费"
        for p in (uj.get("user_entitlement_pack_list") or []):
            base = p.get("entitlement_base_info") or {}
            quota = base.get("quota") or {}
            limit = _num(quota.get("credits_limit") or quota.get("credits_amount"))
            usage = p.get("usage") or {}
            pk_used = _num(usage.get("credits_amount"))
            if limit <= 0 and pk_used <= 0:
                continue
            packages.append({
                "name": p.get("group_name") or p.get("display_desc") or "权益包",
                "amount": limit,
                "remain": max(0.0, limit - pk_used),
                "used": pk_used,
                "expire": _fmt_ts(p.get("expire_time") or base.get("end_time")),
                "source": "measured",
                "perpetual": False,
            })
        packages.sort(key=lambda p: (p.get("expire") or "9999"))

    exp_at = (ent.get("expired_at") or "").strip()
    exp_days = None
    if exp_at:
        try:
            t = datetime.datetime.fromisoformat(exp_at.replace("Z", "+00:00"))
            exp_days = round((t - datetime.datetime.now(datetime.timezone.utc)).total_seconds() / 86400.0, 1)
        except Exception:
            exp_days = None

    return {
        "name": name, "ok": True, "error": None,
        "level": level,
        "signed_today": signed,
        # 用 round 而非 int 截断，保证 remain + used == total（否则会出现 429+1720≠2150）
        "credits": {"remain": round(remain), "total": round(total), "used": round(used)},
        "packages": packages,
        "extra": {
            "phone": _phone,
            "can_sign_in": bool(enable and not signed),
            "today_reward": int(day_credits or extra_credits or 0),
            "user_id": ent.get("user_id"),
            "region": ent.get("region"),
            "token_exp_days": exp_days,
            "pkg_count": len(packages),
        },
    }


def _msg_of(d, j):
    if isinstance(d, dict):
        for k in ("message", "msg", "hint"):
            if d.get(k):
                return str(d[k])[:120]
    return str(j)[:120]


def _fmt_ts(ts):
    try:
        ts = float(ts)
        if ts <= 0:
            return None
        if ts > 1e12:
            ts /= 1000.0
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
    except Exception:
        return None


# ───────────────────────── 任务 ─────────────────────────
def run_task(name, ent, task_key):
    if task_key != "checkin":
        return {"ok": False, "msg": "未知任务"}
    if not (ent.get("token") or "").strip():
        return {"ok": False, "msg": "未配置 token"}

    st, j = _status(ent)
    d = _unwrap(j)
    if st in (401, 403):
        return {"ok": False, "msg": "登录态已失效（HTTP %s），请在 Trae 客户端重新登录" % st}
    if st != 200:
        return {"ok": False, "msg": "签到状态查询失败（HTTP %s）：%s" % (st, _msg_of(d, j))}

    if d.get("checked_in"):
        return {"ok": True, "flag": "ALREADY_TODAY",
                "msg": "今日已签到（Trae 积分）"}
    if not d.get("enable", True):
        return {"ok": False, "msg": "当前账号签到不可用：%s" % _msg_of(d, j)}

    cs, cj = _call(ent, CLAIM_PATH, {"req_source": REQ_SOURCE})
    cd = _unwrap(cj) if isinstance(cj, dict) else {}
    if cs != 200:
        return {"ok": False, "msg": "签到请求失败（HTTP %s）：%s" % (cs, _msg_of(cd, cj))}
    code = cd.get("code", cj.get("code") if isinstance(cj, dict) else None)
    if code not in (0, None):
        return {"ok": False,
                "msg": str(cd.get("message") or cj.get("message") or "签到失败（code=%s）" % code)[:140]}
    gain = int(_num(d.get("credits") or d.get("extra_credits")))
    return {"ok": True, "flag": "SUCCESS",
            "msg": "签到成功，+%s 积分" % (gain if gain else "?")}


if __name__ == "__main__":
    accs = load_accounts()
    print("账号:", {k: (v.get("user_id"), v.get("device_id")) for k, v in accs.items()})
    for nm, ent in accs.items():
        r = read_account(nm, ent)
        print("[%s] ok=%s signed=%s %s 剩余=%s/%s 可签=%s err=%s"
              % (nm, r["ok"], r["signed_today"], r["level"],
                 r["credits"]["remain"], r["credits"]["total"],
                 (r["extra"] or {}).get("can_sign_in"), r["error"]))
