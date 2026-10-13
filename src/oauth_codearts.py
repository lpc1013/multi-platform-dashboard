# -*- coding: utf-8 -*-
"""CodeArts 手机号短信直登 + STS/DPoP 凭据交换 + 静默续期 —— 二期拆分。"""
import json
import time
import os
import uuid
import base64
import hashlib
import secrets
import threading
import subprocess
import urllib.parse
import http.server
import re

try:
    import requests
except ImportError:
    requests = None

try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass
from oauth_common import (
    DEVICE_GRANT_TYPE, PROVIDERS, UA, _CODE_SEL, _JOBS, _OFFSCREEN_ARGS, _PHONE_SEL, _click_consent, _click_text, _consent_checked, _first_sel, _has_captcha, _job_lock, _login_submitted, _new_job, _origin, _pkce, _post_form, _provider, _pull_window_front, _view, get_job, submit_code,
)
from oauth_shared import _CODEARTS_DEBUG_LOCK, _CODEARTS_DEBUG_LOG, _codearts_debug, _qoder_has_captcha, _trae_find_token
from oauth_hw import _hw_click_visible, _hw_fill_and_send, _hw_stage, _hw_submit_code


# ────────────────────────────── CodeArts ──────────────────────────────
_CODEARTS_PORTAL = "https://codearts.huaweicloud.com/portal"
_CODEARTS_STS = "https://sts.cn-north-4.myhuaweicloud.com"
_CODEARTS_CLIENT_ID = "codearts-agent"     # = product.json urlProtocol（= env.uriScheme）
_CODEARTS_PLUGIN = "snap_AIIDE"
_CODEARTS_PLUGIN_VER = "5.4.2"             # huaweicloud.authentication/package.json
_CODEARTS_SNAP = "https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager"
# 持久浏览器 profile：登录态 cookie 落盘 → 之后 run_task 可静默续登（无需人工）
# 2026-10-12 起落数据目录（%LOCALAPPDATA%\dashboard_analysis\），src/ 旧目录若有则自动搬迁
import data_dir as _dd
_CODEARTS_PROFILE_DIR = _dd.path(".codearts_profile")
_dd.migrate_profile_dir(".codearts_profile")

# 授权确认页代点文案（归一化匹配，命中最内层；「取消/拒绝/不同意」等否定项靠**全等**匹配天然排除）
_CODEARTS_CONSENT_TEXTS = ["同意并授权", "授权并登录", "授权并继续", "同意授权", "一键授权",
                           "授权", "同意", "允许", "继续", "确认"]

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


def _codearts_secret_exchange(tid, sec, verifier, dpop, port, phone,
                              job=None, sleep_fn=None):
    """OldLogin：portal 只回 secret → 照客户端轮询 ticket 接口换 STS 凭据。
    ⚠ 轮询语义照抄客户端 plugin.js（2026-10-12「无效ticketId」实证修复）：
    doGetAuthenticationTaskByTicketId 是 setInterval 轮询，10 次、失败间隔 6s——
    票据在 snap 后端是**异步登记**的，portal 放行与后端可查之间存在秒级窗口。
    返回 (grant, msg)。grant=None 表示失败。sms 流程与静默续登共用。"""
    u = "%s/v1/login/ticket?ticket_id=%s&secret=%s" % (_CODEARTS_SNAP, tid, sec)
    _codearts_debug("oldlogin", "ticket 接口请求 tid=%s…" % str(tid)[:12])
    grant, st, j = None, 0, {}
    for attempt in range(1, 11):
        try:
            rr = requests.get(u, headers={
                "Content-Type": "application/json;charset=UTF-8",
                "plugin-name": _CODEARTS_PLUGIN,
                "plugin-version": _CODEARTS_PLUGIN_VER,
            }, timeout=30)
            st = rr.status_code
            j = rr.json() if rr.content else {}
        except Exception as e:
            st, j = 0, {"__err__": str(e)[:180]}
        ak, sk, sts, exp = _codearts_extract_credentials(j)
        _codearts_debug("oldlogin", "#%d/10 HTTP %s user=%s expires=%s keys=%s"
                        % (attempt, st, str((j or {}).get("user_name"))[:24],
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
            break
        if attempt < 10:
            if job is not None and attempt == 1:
                job["result"] = ("票据同步中（portal 已放行、后端登记稍延迟），"
                                 "自动重试中…")
            try:
                (sleep_fn or time.sleep)(6)
            except Exception:
                time.sleep(6)
    return grant, ("凭据换取失败（HTTP %s）：%s（已按客户端语义重试 10 次，票据始终未登记）"
                   % (st, str(j)[:160]))


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
    # 记录本地生成的 ticket_id：回调 redirect 里回传的应与此一致，
    # 不一致 = portal 侧重开了新票（2026-10-12「无效ticketId」排障新增取证点）
    _codearts_debug("open", "authorize ticket_id=%s port=%d" % (ticket_id, port))

    browser = None
    ok_saved = False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            # 持久 profile：登录态 cookie 落盘，之后 run_task 可静默续登
            os.makedirs(_CODEARTS_PROFILE_DIR, exist_ok=True)
            ctx = p.chromium.launch_persistent_context(
                _CODEARTS_PROFILE_DIR, headless=False, args=_OFFSCREEN_ARGS,
                locale="zh-CN", viewport={"width": 520, "height": 800})
            browser = ctx   # persistent ctx 自身可 close，收尾统一走 browser.close()
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
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
                # ④' OldLogin：portal 只回 secret（无 code）→ ticket 接口换凭据
                #   （轮询语义在 _codearts_secret_exchange 内，与静默续登共用）
                sec = result.get("secret") or ""
                if sec and not job.get("finished"):
                    job["result"] = "已收到授权回执，正在换取临时凭据…"
                    grant, msg2 = _codearts_secret_exchange(
                        result.get("ticket_id") or ticket_id, sec,
                        verifier, dpop, port, phone, job=job,
                        sleep_fn=page.wait_for_timeout)
                    if grant:
                        try:
                            ok2, nm, msg2 = on_success(grant)
                        except Exception as e:
                            ok2, nm, msg2 = False, "", "保存登录态异常：%s" % str(e)[:150]
                        job.update(status="done", finished=True, ok=bool(ok2),
                                   result=msg2 or ("已保存 %s" % nm), name=nm or "")
                    else:
                        job.update(status="done", finished=True, ok=False, result=msg2)
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


def codearts_silent_renew(on_success):
    """CodeArts 静默续登（无 refresh_token 材料时的保活替代路径）。

    原理：短信登录用持久 profile（.codearts_profile/），登录态 cookie 落盘。
    续期时重开 authorize URL——会话仍活着则 portal 自动 302 回调（无需人工），
    走 OldLogin secret → ticket 换新 STS 凭据。会话失效（被送回登录页）→
    立即放弃并说明，绝不弹人工流程。返回 (ok, msg)。
    on_success(grant) → (ok, msg)。"""
    if not os.path.isdir(_CODEARTS_PROFILE_DIR) or not os.listdir(_CODEARTS_PROFILE_DIR):
        return False, "无浏览器会话存档，请先短信登录一次"
    verifier, challenge = _codearts_pkce()
    dpop = _codearts_dpop_keypair()
    ticket_id = secrets.token_hex(16)
    srv, port = None, 0
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
        return False, "本地回调端口分配失败"
    _CodeArtsCBHandler.result = {}
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    auth_url = ("%s/authorize?theme=2&locale=zh-cn&uri_scheme=%s&client_id=%s"
                "&port=%d&code_challenge=%s&code_challenge_method=S256"
                "&ticket_id=%s&plugin-name=%s&plugin-version=%s"
                % (_CODEARTS_PORTAL, _CODEARTS_CLIENT_ID, _CODEARTS_CLIENT_ID,
                   port, challenge, ticket_id, _CODEARTS_PLUGIN, _CODEARTS_PLUGIN_VER))
    _codearts_debug("silent", "静默续登开始 ticket_id=%s port=%d" % (ticket_id, port))
    ok, msg = False, "静默续登超时（40 秒内未见回调，会话可能已失效）"
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            ctx = p.chromium.launch_persistent_context(
                _CODEARTS_PROFILE_DIR, headless=False, args=_OFFSCREEN_ARGS,
                locale="zh-CN", viewport={"width": 520, "height": 800})
            try:
                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                page.goto(auth_url, wait_until="domcontentloaded", timeout=60000)
                _codearts_debug("silent", "已打开 authorize url=%s" % (page.url or "")[:150])
                deadline = time.time() + 40
                while time.time() < deadline:
                    url = ""
                    try:
                        url = page.url or ""
                    except Exception:
                        pass
                    stg = _codearts_stage(url, port)
                    if stg == "login":
                        _codearts_debug("silent", "会话已失效（回到登录页）url=%s" % url[:150])
                        msg = "浏览器登录会话已失效，请手动短信登录一次以重建"
                        break
                    if stg == "portal":
                        # 会话活着但要求再授权 → 代点（与短信流程同款）
                        _codearts_click_consent(page)
                    res = _CodeArtsCBHandler.result
                    sec, code = res.get("secret") or "", res.get("code") or ""
                    if sec:
                        grant, msg = _codearts_secret_exchange(
                            res.get("ticket_id") or ticket_id, sec,
                            verifier, dpop, port, "")
                        if grant:
                            try:
                                ok, msg = on_success(grant)
                            except Exception as e:
                                ok, msg = False, "保存登录态异常：%s" % str(e)[:150]
                        _codearts_debug("silent", "结果 ok=%s msg=%s" % (ok, str(msg)[:120]))
                        break
                    if code:
                        _codearts_debug("silent", "回调带 code（NewIamLogin），直接换 token")
                        st, j = _codearts_token({
                            "client_id": _CODEARTS_CLIENT_ID, "code": code,
                            "code_verifier": verifier,
                            "grant_type": "authorization_code",
                            "redirect_uri": "http://127.0.0.1:%d/oauth/callback" % port,
                        }, dpop)
                        ak, sk, sts, exp = _codearts_extract_credentials(j)
                        if st == 200 and ak and sk and sts:
                            grant = {"ak": ak, "sk": sk, "sts_token": sts, "expires_at": exp,
                                     "refresh_token": str(_trae_find_token(
                                         j, ("refresh_token", "refreshToken")) or ""),
                                     "code_verifier": verifier,
                                     "dpop_priv_pem": dpop["priv_pem"],
                                     "dpop_pub_jwk": json.dumps(dpop["jwk"]),
                                     "port": port, "phone": ""}
                            try:
                                ok, msg = on_success(grant)
                            except Exception as e:
                                ok, msg = False, "保存登录态异常：%s" % str(e)[:150]
                        else:
                            msg = "换token失败（HTTP %s）：%s" % (st, str(j)[:160])
                        _codearts_debug("silent", "结果 ok=%s msg=%s" % (ok, str(msg)[:120]))
                        break
                    page.wait_for_timeout(800)
            finally:
                try:
                    ctx.close()
                except Exception:
                    pass
    except Exception as e:
        ok, msg = False, "静默续登异常：%s" % str(e)[:160]
        _codearts_debug("silent", "异常 %s" % str(e)[:200])
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass
    return ok, msg
