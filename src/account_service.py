# -*- coding: utf-8 -*-
"""
account_service.py —— 网页端「添加账号」落盘编排（2026-10-13 从 server.py 抽出）
各登录通道（WorkBuddy 短信 / OAuth 设备码 / 各平台短信直登 / 浏览器登录）成功后，
把凭据按「不覆盖其他账号」规则写入凭据文件的统一入口。
"""
import os
import sys
import time
import json
import base64

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import cred_store
from cred_store import (
    CRED_FILES, WB_LOGIN_FILE,
    read_json as _read_json, write_json as _write_json,
    save_cred as _save_cred,
    alloc_account_name as _alloc_account_name,
    dedupe_store as _dedupe_store,
    cred_store_set as _cred_store_set,
)
from logstore import log  # noqa: F401  （预留：落盘审计）
from registry import PLATFORMS
from tasks import _invalidate_state


def _jwt_claim_first(tok, keys):
    """本地解 JWT payload（不验签），按 keys 顺序返回第一个非空声明。

    用于从令牌本身提取稳定身份（如 ZCode 的 user_id/sub）；
    非 JWT / 无该声明返回空串，调用方自行兜底。
    """
    try:
        seg = str(tok or "").split(".")[1]
        seg += "=" * (4 - len(seg) % 4)
        pl = json.loads(base64.urlsafe_b64decode(seg))
        for k in keys:
            v = str(pl.get(k) or "").strip()
            if v:
                return v
    except Exception:
        pass
    return ""


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
        # ZCode 没有可反查身份的公开接口，但 cli_poll 下发的 token 是 JWT——
        # payload 里的 user_id/sub 是稳定身份（重新登录会换 token，sub 不变）。
        # 必须提取落盘：IDENT_FIELDS["zcode"]=("user_id","token")，若 user_id 留空，
        # 身份判定退化为 token，而 token 每次登录都换 → 每次续期都生成重复卡
        # （2026-10-13 实测：2 个账号续期后变 4 张卡）。
        if platform == "zcode":
            uid = _jwt_claim_first(tok, ("user_id", "sub"))
            rec = {"token": tok, "secret": "", "user_id": uid,
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
    """用换到的临时凭据签 GET /v5/caller-identity，取稳定身份（domain_id）。
    ⚠ 2026-10-12 实测响应为**扁平三键**：{"account_id","principal_urn","principal_id"}，
    没有 "identity" 包裹层（旧解析按 j["identity"]["domain_id"] 取值 → 永远拿空 →
    身份回退 ak → 每次续期换新 AK 就另开新卡，两张 CodeArts 卡片即此根因）。
    domain_id = account_id；user_name 从 principal_urn 尾段取（iam::…:user:<name>）。
    identity 包裹层解析保留做兼容。"""
    try:
        import requests as _rq
        import platforms.codearts as cap
        url = "https://sts.cn-north-4.myhuaweicloud.com/v5/caller-identity"
        hdr = cap.sign_headers(ak, sk, sts, "GET", url)
        j = _rq.get(url, headers=hdr, timeout=15, verify=True).json()
        ident = (j or {}).get("identity") or {}
        uid = str(ident.get("domain_id") or ident.get("id")
                  or (j or {}).get("account_id") or "")
        uname = str(ident.get("user_name") or ident.get("name") or "")
        if not uname:
            urn = str((j or {}).get("principal_urn") or "")
            uname = urn.rsplit(":", 1)[-1] if ":" in urn else ""
        return uid, uname
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
           "phone": (grant or {}).get("phone") or "",
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
    # （回调 ScreenName 可能是「一只总柴」这类昵称，与旧账号同名时 _save_cred 会自动加尾号，不会覆盖）
    ideal = (name or rec["screen_name"] or rec["mobile"]
             or ("Trae·" + (rec["user_id"] or rec["token"])[-4:]))
    use = _save_cred("trae", rec, ideal)
    _invalidate_state()
    return True, use, "授权成功，已保存 Trae 账号「%s」" % use


def _officeace_login_save(name, grant):
    """OfficeACE 登录落盘：App 本地 API 已交换并持久化新凭据，这里存身份 + 顺手重导入。"""
    uid = str((grant or {}).get("user_id") or "")
    rec = {"user_id": uid, "user_name": (grant or {}).get("user_name") or "",
           "phone": (grant or {}).get("phone") or "",
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
