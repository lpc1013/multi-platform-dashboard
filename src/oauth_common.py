# -*- coding: utf-8 -*-
"""oauth 共享基建（一期拆分自 oauth_login.py，2026-10-12）。
job 调度 + PKCE/表单 + 浏览器助手。**只放无平台反向依赖的代码**——
device 流入口（device_start/device_poll/start_sms_job/_run_job 等
按 provider 分发平台函数的符号）留在 oauth_login.py。
"""

# -*- coding: utf-8 -*-
"""
OAuth 2.0 设备码授权登录（Device Authorization Grant）
═════════════════════════════════════════════════════════════════════════
MiniMax Code 桌面端「登录」走的就是这套流程（逆向自客户端 app.asar 的
endpoint-config.js / oauth-client.js，并已用真实接口逐字段实测通过）：

  ① POST {account}/oauth2/device/code
       client_id=mcode-public
       scope=agent.default
       audience=agent-backend
       code_challenge=<base64url(sha256(verifier))>
       code_challenge_method=S256
     → {device_code, user_code, expires_in:300, interval:3,
        verification_uri, verification_uri_complete}

  ② 用户在浏览器打开 verification_uri_complete（用「手机号 + 短信验证码」登录）并点「授权」
     —— 这就是「弹出一个网页来」的那一步

  ③ 轮询 POST {account}/oauth2/token
       grant_type=urn:ietf:params:oauth:grant-type:device_code
       device_code=<...>  client_id=mcode-public  code_verifier=<...>
     · 未授权 → HTTP 400 {"error":"authorization_pending"}；轮询过快 → {"error":"slow_down"}
     · 已授权 → 200 {access_token, refresh_token, token_type:"Bearer", expires_in, scope}

为什么比「受控浏览器抓 localStorage」好：
  · 拿到的是 mcode-public / agent-backend 的**正式令牌**，与桌面端同源 → 签到接口直接可用
  · 不需要安装/打开桌面客户端，也不用猜 localStorage 键名（那条路又脆又容易抓错）
  · 令牌自带 refresh_token → 过期可静默续期，不必再手动「重新导入」

MiniMax 账号中心（cn prod）= https://account.minimax.cn
"""
import json
import time
import os
import uuid
import base64
import hashlib
import secrets
import threading
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) MiniMaxCode/3.0.73 Chrome/138.0.7204.251 Safari/537.36")
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
# ── 各个平台的 OAuth 参数（照抄客户端里的常量，勿臆造）─────────────────
PROVIDERS = {
    "minimax": {
        "kind": "device",           # 标准 RFC 8628 设备码
        "label": "MiniMax Code",
        "client_id": "mcode-public",
        "scopes": ["agent.default"],
        "audience": "agent-backend",
        "origins": {
            "cn": {"prod": "https://account.minimax.cn"},
            "en": {"prod": "https://account.minimax.io"},
        },
        "hint": "在弹出的网页里用「手机号 + 短信验证码」登录，然后点「授权」",
    },
    # ZCode（z.ai）：客户端自带的「CLI 登录」通道，不是标准 RFC 8628，
    # 但同样是「申请登录链接 → 网页登录 → 后端轮询拿令牌」三段式：
    #   POST https://zcode.z.ai/api/v1/oauth/cli/init   {provider:"zai"|"bigmodel"}
    #        header Authorization: Bearer <32 字节随机 hex>
    #        → {code:0, data:{flow_id, poll_token, authorize_url, expires_at, poll_interval_sec}}
    #   GET  https://zcode.z.ai/api/v1/oauth/cli/poll/{flow_id}
    #        header Authorization: Bearer <poll_token>
    #        → {code:0, data:{status:"pending"}} 或 {code:0, data:{token, ...}}
    # 已用真实接口逐字段实测（2026-10-08）。
    "zcode": {
        "kind": "cli_poll",
        "label": "ZCode",
        "base": "https://zcode.z.ai",
        "init_url": "https://zcode.z.ai/api/v1/oauth/cli/init",
        "subs": [
            {"id": "zai", "label": "Z.ai 账号（chat.z.ai）"},
            {"id": "bigmodel", "label": "智谱 BigModel（bigmodel.cn）"},
        ],
        "default_sub": "zai",
        "hint": "在弹出的网页里登录并授权，看板会自动接管令牌",
    },
    # Qoder CN：自研「设备流」三段式（逆向自客户端 app.asar，2026-10-08 实测核验）：
    #   ① 本地生成 verifier → challenge=base64url(sha256(verifier)) → nonce → machine_id
    #   ② GET {auth_base_url}/device/selectAccounts
    #        ?challenge&challenge_method=S256&nonce&machine_id&client_id
    #      → 用该 URL 拼出登录页：
    #        {auth_base_url.origin}/users/sign-in?biz_variant=qoder&oauth_callback=<selectAccounts URL>
    #      用户在登录页用「手机号 + 短信验证码」/ 微信 / 飞书 完成登录并授权
    #   ③ 轮询 GET {openapi_base_url}/api/v1/deviceToken/poll
    #        ?nonce&verifier&challenge_method=S256
    #       · 未授权 → HTTP 404（继续轮询）
    #       · 已授权 → 200 {token, refresh_token, ...}（0.4.3 客户端判定就是这两个扁平字段）
    #         token 即正式令牌，refresh_token 用于续期
    #   ⚠ nonce 必须 UUID、verifier 必须 64 字符 PKCE 字母表（见 _qoder_pkce），
    #     服务端对格式不匹配的 poll 恒返 404，与未授权不可区分。
    # 配置（照抄客户端 environments.prod）：auth_base_url=https://qoder.cn、
    #   openapi_base_url=https://openapi.qoder.com.cn、client_id=732aef47-...、biz_variant=qoder
    "qoder": {
        "kind": "qoder_device",
        "label": "Qoder",
        "auth_base_url": "https://qoder.cn",
        "openapi_base_url": "https://openapi.qoder.com.cn",
        "client_id": "732aef47-9cf2-46a2-95fe-4cebb5d0d1fa",
        "biz_variant": "qoder",
        "machine_id_file": r"%APPDATA%\com.qodercn.app.stable\auth.machine-id",
        "hint": "看板会弹出登录窗口并自动填手机号、代点「获取验证码」，"
                "你只需在看板填短信验证码（窗口里若出现滑块/图片验证码请顺手完成）",
    },
}
_JOBS = {}
_job_lock = threading.Lock()
def _provider(platform):
    p = PROVIDERS.get(platform)
    if not p:
        raise KeyError("该平台未配置 OAuth 设备码登录：%s" % platform)
    return p
def _origin(platform, region="cn", build_env="prod"):
    p = _provider(platform)
    return (p["origins"].get(region) or p["origins"]["cn"]).get(build_env, "") \
        or p["origins"]["cn"]["prod"]
def _post_form(url, data, timeout=20):
    if requests is None:
        raise RuntimeError("缺少依赖 requests，请先 pip install requests")
    r = requests.post(url, data=data, timeout=timeout, verify=False,
                      headers={"Content-Type": "application/x-www-form-urlencoded",
                               "Accept": "application/json", "User-Agent": UA})
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"raw": (r.text or "")[:300]}
def _pkce():
    """PKCE：verifier 走 base64url(32 随机字节)，challenge = base64url(sha256(verifier))。
    服务端强制要求 S256（不给就 400 invalid_request: valid S256 PKCE is required）。"""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge
def _new_job(platform, flow):
    """统一的 job 骨架（设备码登录 / 短信直登共用）。
    注意：短信直登平台（trae/codearts/officeace/lingxi 等）不在 PROVIDERS 设备码表里，
    这里不能调 _provider()（会 KeyError「该平台未配置 OAuth 设备码登录」），
    hint 由各 start_*_sms_job 的 job.update() 自己覆盖。"""
    p = PROVIDERS.get(platform) or {}
    return {
        "job": uuid.uuid4().hex[:12], "platform": platform,
        "mode": "device", "status": "waiting", "finished": False,
        "ok": None, "result": "", "name": "", "started": time.time(),
        "user_code": flow["user_code"], "verify_url": flow["verify_url"],
        "expires_in": flow["expires_in"],
        "hint": p.get("hint", ""),
        # 短信直登专用
        "phone": "", "need_code": False, "code": None, "code_submitted": False,
        "sms_sent": False,
    }
def _view(job):
    left = max(0, int(job["expires_in"] - (time.time() - job["started"])))
    return {"job": job["job"], "platform": job["platform"], "status": job["status"],
            "finished": job["finished"], "ok": job["ok"], "text": job["result"],
            "name": job["name"], "user_code": job["user_code"],
            "verify_url": job["verify_url"], "seconds_left": left,
            "expires_in": job["expires_in"], "hint": job["hint"],
            # 短信直登
            "mode": job.get("mode", "device"), "phone": job.get("phone", ""),
            "need_code": bool(job.get("need_code")),
            "sms_sent": bool(job.get("sms_sent")),
            "captcha": bool(job.get("captcha")),
            "code_submitted": bool(job.get("code_submitted")),
            # Trae 专用诊断（排障用；失败时可直接看到回调原文/端口/身份来源）
            "callback_port": job.get("callback_port"),
            "device_dir": job.get("device_dir", ""),
            "plugin_version": job.get("plugin_version", ""),
            "client_running": bool(job.get("client_running")),
            "callback_url": job.get("callback_url", ""),
            "callback_keys": job.get("callback_keys", []),
            "auth_code_head": job.get("auth_code_head", ""),
            # 兑换请求/响应留痕（与客户端成功样本逐字段比对用）
            "sent_device_name": job.get("sent_device_name", ""),
            "sent_model": job.get("sent_model", ""),
            "sent_os": job.get("sent_os", ""),
            "sent_ide_version": job.get("sent_ide_version", ""),
            "v1_status": job.get("v1_status"),
            "v1_resp": job.get("v1_resp", ""),
            # 代点【登录并打开 TRAE】留痕（判断「按钮点不到 / 点太慢」用）
            "open_clicked": bool(job.get("_open_clicked")),
            "open_tries": job.get("_open_tries", 0),
            "clicked_btn": job.get("conclick_tag", ""),
            "clicked_cls": job.get("conclick_cls", ""),
            # 回调身份解析留痕（userInfo JSON 里的 UserID/ScreenName）
            "parsed_user_id": job.get("parsed_user_id", ""),
            "parsed_name": job.get("parsed_name", "")}
# ───────────────── 短信直登：手机号 + 验证码（看板内完成，无需手填网页）─────────────────
# MiniMax 网页登录页（account.minimax.cn/unified-login）的「获取验证码」按钮受
# 腾讯 captcha 保护：无头/自动化点击会弹滑块。所以这里用**可见的受控浏览器**
# 由真人完成风控动作，而「填手机号 / 填验证码 / 点登录」全部由看板代劳 ——
# 用户要做的只是：在看板输手机号 → 收短信 → 在看板输验证码。
_PHONE_SEL = ["input[type='tel']", "input[placeholder*='手机号']"]
_CODE_SEL = ["input[placeholder*='验证码']", "input[type='text']"]
def _first_sel(page, sels, timeout=4000):
    """返回第一个能定位到的 locator，都定位不到返回 None。"""
    for s in sels:
        try:
            loc = page.locator(s).first
            loc.wait_for(state="visible", timeout=timeout)
            return loc
        except Exception:
            continue
    return None
def _click_text(page, names, timeout=1500):
    """按可见文本点按钮；失败退化为按文本点任意元素。"""
    for n in names:
        try:
            page.get_by_role("button", name=n, exact=True).first.click(timeout=timeout)
            return True
        except Exception:
            pass
    for n in names:
        try:
            page.get_by_text(n, exact=True).first.click(timeout=timeout)
            return True
        except Exception:
            pass
    return False
def _has_captcha(page):
    """检测腾讯滑块验证码是否弹出（turing.captcha / tcaptcha 的 iframe 或浮层）。"""
    try:
        return bool(page.evaluate("""() => {
            const fs = Array.from(document.querySelectorAll('iframe'));
            if (fs.some(f => /turing\\.captcha|tcaptcha|captcha/.test((f.src||'')+(f.id||'')))) return true;
            if (document.querySelector('#tcaptcha_iframe,[class*="tcaptcha"],[id*="tcaptcha"]')) return true;
            return false;
        }"""))
    except Exception:
        return False
def _login_submitted(page, names, ctx):
    """点「立即登录」，并校验点击是否**真的被前端接受**。

    为什么需要校验：MiniMax 登录页在未勾协议时，点「立即登录」前端会**静默 return**
    （既不发 network、也不弹提示）—— 单看「有没有点到按钮」完全看不出问题。

    判据（不依赖 network 监听，改用页面状态变化，更稳）：
      · 点击后若页面离开 unified-login（跳转 / 出现验证码错误提示 / 按钮进入 loading）
        → 视为「点击已被接受」；
      · 否则判定被协议前置校验拦截 → 补勾协议后重试一次。

    返回 True 表示点击已被前端接受，False 表示两次尝试后页面仍无反应。
    """
    def _click():
        _click_text(page, names, timeout=2500)

    def _accepted():
        """页面是否出现『登录已在进行』的迹象。"""
        try:
            return bool(page.evaluate("""() => {
                if (!/unified-login/.test(location.href)) return true;   // 已跳转
                const t = document.body.innerText || '';
                // 验证码错误 / 登录中 / 已发送 等文案出现 → 说明请求已发出
                if (/验证码(错误|不正确|失效|已过期)|登录中|正在登录|操作频繁|请稍后/.test(t)) return true;
                for (const e of document.querySelectorAll('button')) {
                    if ((e.innerText||'').trim() === '立即登录' &&
                        (e.disabled || /loading|opacity-60/.test(e.className||''))) return true;
                }
                return false;
            }"""))
        except Exception:
            return False

    _click()
    for _ in range(12):                       # 最多约 3s
        page.wait_for_timeout(250)
        if _accepted():
            return True
    # 被协议前置校验拦截 → 补勾后重试一次
    _click_consent(page)
    page.wait_for_timeout(300)
    _click()
    for _ in range(16):
        page.wait_for_timeout(250)
        if _accepted():
            return True
    return False
def _consent_checked(page):
    """判断「我已阅读并同意…」是否已勾选。返回 True / False / None(未找到协议行)。

    新版 MiniMax 登录页（account.minimax.cn/unified-login）的勾选框是**自绘控件**：
        <div class="flex items-start gap-[6px]">
          <button type="button" class="mt-[2px] flex size-4 ...">
            <div class="size-[14px] rounded-full border-[1.5px] border-gray_200"></div>
          </button>
          <p>我已阅读并同意 服务条款 和 隐私政策，…</p>
        </div>
    未勾选 = `button > div` 是空心圆（class 含 `rounded-full` / `border-gray`）；
    勾选后该圆环消失（换成对勾图标或整块变成实心），`button > div` 置空或不再含 border。

    ⚠ 必须以 `<p>`（含协议文本的那个，且它没有嵌套子行）作锚点：
       用 `querySelectorAll('p,span,div')` 会先命中外层大容器（文本被 length 过滤后
       又落到别的含「同意」字样的行），导致判定漂移 —— 实测初始状态被误判为「已勾」。
    """
    try:
        return page.evaluate("""() => {
            const ps = document.querySelectorAll('p');
            for (const e of ps) {
                const t = (e.innerText || '').trim();
                if (!/我已阅读并同意|已阅读并同意/.test(t)) continue;
                const root = e.closest('.flex.items-start') || e.parentElement;
                if (!root) continue;
                const btn = root.querySelector('button');
                if (!btn) continue;
                const inner = btn.querySelector(':scope > div');
                // 空心圆环还在 → 未勾选
                if (inner && /rounded-full|border-/.test(inner.className || '')) return false;
                return true;    // 没有圆环 → 已勾选
            }
            return null;        // 页面没有协议行（部分批次不渲染）
        }""")
    except Exception:
        return None
def _click_consent(page):
    """勾选「我已阅读并同意…」。返回 True 表示调用后处于「已勾选」状态。

    ⚠ 这个勾选**是必须的**：MiniMax 登录页在未勾协议时点「立即登录」**不弹任何提示**、
    也不发起登录请求（前端前置校验静默 return）—— 表现为「按钮点了没反应」。
    旧实现只按 [role=checkbox]/[class*=agree|check|protocol]/label + 文本匹配，
    而真实控件是一个**无文本的自绘 button>div 圆环**，故永远匹配不到（恒返回 False）。

    新实现：以含『我已阅读并同意』的 <p> 为锚点 → 点它所在行的勾选 button；
    已勾选则幂等不重复点（避免点两次反而取消勾选）。
    """
    # 0) 已勾选 → 幂等返回（避免点两次取消勾选）
    if _consent_checked(page) is True:
        return True

    # 1) 主路径：点协议行内部的勾选 button（三次机会，覆盖渲染慢的批次）
    for _ in range(3):
        try:
            hit = page.evaluate("""() => {
                for (const e of document.querySelectorAll('p')) {
                    const t = (e.innerText || '').trim();
                    if (!/我已阅读并同意|已阅读并同意/.test(t)) continue;
                    const root = e.closest('.flex.items-start') || e.parentElement;
                    if (!root) continue;
                    const btn = root.querySelector('button')
                             || root.querySelector('[class*="size-"][class*="rounded"], [class*="rounded-full"]');
                    if (btn) { btn.click(); return true; }
                }
                return false;
            }""")
        except Exception:
            hit = False
        if hit:
            page.wait_for_timeout(350)
            if _consent_checked(page) is True:
                return True
        else:
            break

    # 2) 原生兜底：万一页面改回标准 checkbox
    try:
        for sel in ["input[type='checkbox']", "[role='checkbox']"]:
            for e in page.locator(sel).all():
                try:
                    if not e.is_checked():
                        e.check(timeout=1200)
                        page.wait_for_timeout(200)
                        if _consent_checked(page) is True:
                            return True
                except Exception:
                    try:
                        e.click(timeout=800)
                        page.wait_for_timeout(200)
                        if _consent_checked(page) is True:
                            return True
                    except Exception:
                        pass
    except Exception:
        pass

    return _consent_checked(page) is True
def submit_code(jid, code):
    """前端把短信验证码交回后端，由浏览器线程注入并提交。"""
    code = "".join(ch for ch in str(code or "") if ch.isdigit()).strip()
    if not code:
        return False, "请填写短信验证码"
    with _job_lock:
        job = _JOBS.get(jid)
    if not job or job.get("mode") != "sms":
        return False, "登录任务不存在或已结束，请重新发起"
    if job.get("finished"):
        return False, "该登录任务已结束，请重新发起"
    job["code"] = code
    return True, "已收到验证码，正在提交…"
def get_job(jid):
    with _job_lock:
        job = _JOBS.get(jid)
        # 顺手清理 10 分钟前的旧任务
        if len(_JOBS) > 50:
            for k, v in list(_JOBS.items()):
                if v.get("finished") and time.time() - v.get("started", 0) > 600:
                    _JOBS.pop(k, None)
    return _view(job) if job else None
# 窗口移出屏幕（用户无感），但环境指纹与有头一致——阿里云/腾讯/百度风控盯无头特征，
# 真 headless 会概率性被拦且弹滑块时无法人工兜底。滑块出现时用 _pull_window_front 拉回。
# CalculateNativeWinOcclusion 必须禁用：否则 Windows 把屏幕外窗口判为 occluded
# （visibilityState=hidden），部分登录 SDK 会暂停初始化。
_OFFSCREEN_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--window-position=-32000,-32000",
    "--disable-features=CalculateNativeWinOcclusion",
]
def _pull_window_front(ctx):
    """把（移到屏幕外的）浏览器窗口拉回屏幕中央——CDP Browser.setWindowBounds。

    触发时机：检测到滑块/图片验证码。平时全程不可见，出事时自动显形让人工拖一下。
    """
    try:
        pg = ctx.pages[0] if ctx.pages else None
        if not pg:
            return
        cdp = ctx.new_cdp_session(pg)
        win = cdp.send("Browser.getWindowForTarget")
        wid = win.get("windowId")
        if wid is None:
            return
        try:
            cdp.send("Browser.setWindowBounds",
                     {"windowId": wid, "bounds": {"windowState": "normal"}})
        except Exception:
            pass
        cdp.send("Browser.setWindowBounds",
                 {"windowId": wid, "bounds": {"left": 160, "top": 90}})
    except Exception:
        pass
