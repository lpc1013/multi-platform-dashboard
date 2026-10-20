# -*- coding: utf-8 -*-
"""
OpenAI 兼容反代：把 CodeArts Agent 的免费模型额度暴露为本机 OpenAI API。
════════════════════════════════════════════════════════════════════════
协议（2026-10-12 实测验证，另参考 github.com/HITZY2002/codearts2api 逆向记录）：

  聊天    POST https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions
          鉴权 = AK/SK SDK-HMAC-SHA256 签名（platforms/codearts.sign_headers 同款）
                 + x-auth-token: <STS security_token>
          请求体原生 OpenAI 形状（model/messages/stream/max_tokens/temperature/…）
          + chat_id（32hex）+ prompt_cache_key + tool_stream:true
          + Chat-Id / Session-Id 头（prompt cache 亲和）
          ⚠ 福利模型（每日免费额度）必须带头 maas_type: benefit，
            否则 InferHub.002002009.404 model is not registered
  模型    GET /v1/model/builtin（内置，计积分）
          GET {opengw}/api/v1/gateway/config（福利/免费额度模型）
  响应    SSE：本身就是 OpenAI chat.completion.chunk 形状（含 reasoning_content、
          usage、finish_reason、data:[DONE]），可直接透传。

限制（如实说明）：
  - 每日额度按账号计（福利模型 daily_token_limit），上游有并发/TPM 限制；
  - tool_choice 对象形态上游会报参数错误（上游限制）；
  - 多模态消息透传，福利模型不支持图片时上游报错原样返回。
"""
import hashlib
import itertools
import json
import os
import threading
import time
import urllib.parse
import uuid

import requests

import platforms.codearts as cap
import platforms.teleagent as tat
import platforms.officeace as oac
import platforms.workbuddy_ai as wai
import platforms.tabbit as tbt

SNAP = "https://snap-access.cn-north-4.myhuaweicloud.com"
OPENGW = "https://opengw.developer.huaweicloud.com"
EP_CHAT = "/api/v2/chat/completions"
EP_MODELS = "/v1/model/builtin"
EP_GWCFG = "/api/v1/gateway/config"

# 冷启动种子：福利网关临时故障时兜底（宁可多带 maas_type，少带必 404）
_SEED_BENEFIT = {"deepseek-v4-flash-0731", "deepseek-v4-pro-0813",
                 "glm-5.3-flash", "deepseek-v4.1-flash"}

CATALOG_TTL = 600          # 模型目录缓存 10 分钟
CHAT_TIMEOUT = (15, 600)   # 连接 / 读超时（SSE 可能很长）

_lock = threading.Lock()
_catalog = {"ts": 0.0, "builtin": [], "benefit": set()}


# ── 访问网关：API Key（可选）+ 令牌桶限流（2026-10-13，对应外部评审「八」）──
# 服务只监听 127.0.0.1，默认对「本机任意进程/浏览器页面」开放（与看板其余 API 同级）。
# 若设置 DASHBOARD_PROXY_API_KEY，则 /v1/* 必须带 Authorization: Bearer <key>——
# 为将来放开局域网监听预留开关。限流防失控客户端把每日免费额度瞬间打光。
PROXY_API_KEY = os.environ.get("DASHBOARD_PROXY_API_KEY", "").strip()
RATE_PER_MIN = max(1.0, float(os.environ.get("DASHBOARD_PROXY_RATELIMIT", "60") or 60))
BURST = max(1.0, float(os.environ.get("DASHBOARD_PROXY_BURST", "30") or 30))
_rl_lock = threading.Lock()
_rl = {"tokens": BURST, "ts": time.time()}


def allow_request():
    """令牌桶：每分钟稳定 RATE_PER_MIN 个，桶容量 BURST 允许突发。"""
    with _rl_lock:
        now = time.time()
        _rl["tokens"] = min(BURST, _rl["tokens"] + (now - _rl["ts"]) * RATE_PER_MIN / 60.0)
        _rl["ts"] = now
        if _rl["tokens"] >= 1.0:
            _rl["tokens"] -= 1.0
            return True
        return False


def gate(handler):
    """/v1/* 统一入口校验：鉴权 + 限流。失败时直接写响应并返回 False。"""
    if PROXY_API_KEY:
        import hmac as _hmac
        auth = str(handler.headers.get("Authorization") or "")
        if not _hmac.compare_digest(auth, "Bearer %s" % PROXY_API_KEY):
            handler._send(401, {"error": {
                "message": "Invalid API key。后端设置了 DASHBOARD_PROXY_API_KEY，"
                           "客户端须以 Authorization: Bearer <key> 访问。",
                "type": "auth_error", "code": "invalid_api_key"}})
            return False
    if not allow_request():
        handler._send(429, {"error": {
            "message": "本地代理限流：请求过于频繁（当前 %s 次/分钟，可用环境变量 "
                       "DASHBOARD_PROXY_RATELIMIT / DASHBOARD_PROXY_BURST 调整）" % int(RATE_PER_MIN),
            "type": "rate_limit_error", "code": "rate_limit_exceeded"}})
        return False
    return True


from errors import UpstreamError   # noqa: E402  统一异常体系（保持 (status, message) 旧签名）


def _pick_freshest(d):
    """多账号时选 expires_at 最晚的一个（凭据最新鲜、可用窗口最长）。
    返回 (name, ent)；无有效过期时间的账号排最后。"""
    def key(item):
        exp = str((item[1] or {}).get("expires_at") or "")
        return exp   # ISO 时间字符串字典序即时间序
    name, ent = max(d.items(), key=key)
    return name, ent


def _load_ent():
    """取凭据可用的 codearts 账号（多账号取 expires_at 最晚者），只判断
    凭据是否可用——⚠ 不触发续期/预刷新：代理是热路径（客户端启动就会打
    /v1/models），在这里拉起浏览器续登会随机弹窗打断人工。续期只留给
    run_task（签到时）与看板「续期凭据」按钮；过期直接 503 引导用户。"""
    import server as srv   # 延迟导入：取账号文件路径
    path = srv.CRED_FILES.get("codearts")
    d = srv._read_json(path, {}) if path else {}
    if not d:
        raise UpstreamError(503, "CodeArts 账号不存在，请先在看板登录 CodeArts")
    name, ent = _pick_freshest(d)
    if not (ent.get("ak") and ent.get("sk") and ent.get("sts_token")):
        raise UpstreamError(503, "CodeArts 凭据不完整，请先在看板完成登录")
    if cap.expired(ent) is True:
        raise UpstreamError(
            503, "CodeArts 凭证已于 %s 过期，请到看板「🔄 续期凭据」"
                 "（或点一次签到触发自动续期）" % (ent.get("expires_at") or "")[:19])
    return name, ent


# ── TeleAgent 上游（星辰，2026-10-14 实测打通）──────────────
# 路由规则：model 命中 tat.CHAT_MODELS → TeleAgent；其余（含空）→ CodeArts。
# 两套模型名无交集，客户端只靠 model 字段即可选上游。
TA_MODELS = set(tat.CHAT_MODELS)

# ── WorkBuddy 国际版上游（workbuddy.ai，2026-10-16 实测打通）──────────────
# 路由规则：`wb:` 前缀 → 国际版（如 wb:glm-5.2 / wb:gpt-5.5 / wb:auto）。
# 国际版模型名与 CodeArts/OfficeACE 大量交集（glm/kimi/deepseek 系），
# 用命名空间前缀隔离（buddy-proxy 同思路），客户端改前缀即切上游。
WBAI_PREFIX = "wb:"

# ── Tabbit 上游（web.tabbit.com / web.tabbit.ai，2026-10-19 逆向打通）──────────────
# 路由规则：`tb:` 前缀 → Tabbit（如 tb:Default / tb:GPT-5.6-Sol）。
# Tabbit 模型名与 CodeArts/OfficeACE/WBAI 均有交集（GLM/Kimi/DeepSeek 系），
# 同样用命名空间前缀隔离；免费周额计量模型签到/每日额度归 Tabbit 账号。
TB_PREFIX = "tb:"


def route_of(model):
    m = str(model or "").strip()
    if m.lower().startswith(WBAI_PREFIX):
        return "wbai"
    if m.lower().startswith(TB_PREFIX):
        return "tabbit"
    return "teleagent" if m.lower() in TA_MODELS else "codearts"


def _wbai_ent():
    """取国际版账号（单号）。只判断不强制刷新失败即 503；AT 过期时 ensure_token
    会用 RT 刷新并落盘（RT 非一次性，但新 RT 必须保存防断链）。"""
    accs = wai.load_accounts()
    if not accs:
        raise UpstreamError(503, "WorkBuddy 国际版账号不存在，请先在看板「从本地客户端导入」"
                                 "（需本机装有 WorkBuddy AI 客户端并已登录）")
    name, ent = _pick_freshest(accs)
    if not (ent.get("token") or ent.get("refresh_token")):
        raise UpstreamError(503, "WorkBuddy 国际版凭据不完整，请重新导入")
    if wai.expired(ent) is True:
        tok = wai.ensure_token(ent, name=name)     # 尝试 RT 刷新（内部落盘）
        if wai.expired(ent) is True:
            raise UpstreamError(503, "WorkBuddy 国际版 token 已过期且刷新失败"
                                     "（expires_at=%s），请打开客户端重新登录或重新导入"
                                % (ent.get("expires_at") or "")[:19])
        return name, ent
    return name, ent


# ── 通用多账号池：所有上游平台共用 ────────────────────────────────
# 规则：同平台账号按「未冷却优先 + 有效期新→旧」排序；每个请求先试第一个号，
# 命中「额度耗尽 / 鉴权失效 / 429」即冷却该号（30 分钟）并自动换下一个。
# 换号判定发生在「首个 chunk 到达之前」，不会重复输出、客户端完全无感。
# 覆盖：codearts / officeace / teleagent / tabbit / wbai。
_POOL_COOL = {}
_POOL_COOL_SEC = 1800
_POOL_LOCK = threading.Lock()

_POOL_SWITCH_HINTS = ("额度", "余额", "配额", "次数已用尽", "已达上限", "不足",
                      "quota", "exhaust", "insufficient", "credit",
                      "limit reached", "rate limit")


def _exp_key(v):
    """有效期统一成 epoch 秒（兼容 ISO 字符串 / 毫秒 / 秒）。"""
    if isinstance(v, (int, float)):
        return float(v) / 1000.0 if v > 1e11 else float(v)
    s = str(v or "")
    try:
        import datetime
        return datetime.datetime.strptime(s[:19], "%Y-%m-%d %H:%M").timestamp()
    except Exception:
        return 0.0


def _pool_spec(provider):
    """返回 (load, ok, exp, label)：读账号 / 是否可用 / 到期时间 / 展示名。"""
    if provider == "codearts":
        import server as srv
        return (lambda: srv._read_json(srv.CRED_FILES.get("codearts"), {})
                if srv.CRED_FILES.get("codearts") else {},
                lambda e: bool(e.get("ak") and e.get("sk") and e.get("sts_token"))
                          and cap.expired(e) is not True,
                lambda e: e.get("expires_at"), "CodeArts")
    if provider == "officeace":
        # 走适配器的 load_accounts：它会过滤掉「只有身份、没有 AK/SK/STS」的残条，
        # 并把本地客户端的 live 凭据按 user_id 归并进来。直接读原始 JSON 会把残条
        # 也列成账号（2026-10-20：同一账号因此显示成「异常」+「100%」两个 tab）。
        return (oac.load_accounts,
                lambda e: oac._expired(e) is not True,
                lambda e: e.get("expires_at"), "OfficeACE")
    if provider == "teleagent":
        return (tat.load_accounts,
                lambda e: (lambda t: (not t) or t > time.time())(
                    tat._jwt_payload((e or {}).get("token") or "").get("exp") or 0),
                lambda e: tat._jwt_payload((e or {}).get("token") or "").get("exp") or 0,
                "TeleAgent")
    if provider == "tabbit":
        return (tbt.load_accounts,
                lambda e: bool(tbt._cookie_of(e))
                          and (tbt.token_exp(e) or 0) > time.time(),
                lambda e: tbt.token_exp(e) or 0, "Tabbit")
    return (wai.load_accounts,
            lambda e: bool(e.get("token") or e.get("refresh_token")),
            lambda e: e.get("expires_at"), "WorkBuddy 国际版")


def _pool_status(provider):
    """池概况（/api/proxy_info 前端展示用）：账号名单 + 冷却剩余秒。只读不打上游。"""
    load, ok, exp, label = _pool_spec(provider)
    try:
        accs = load() or {}
    except Exception:
        accs = {}
    now = time.time()
    with _POOL_LOCK:
        cool = {k: int(v - now) for k, v in
                (_POOL_COOL.get(provider) or {}).items() if v > now}
    names = sorted(accs.keys()) if isinstance(accs, dict) else []
    return {"n": len(names), "names": names, "cool": cool}


def _pool_ents(provider):
    """该平台可用账号，未冷却在前、有效期新→旧。全部不可用时报 503。"""
    load, ok, exp, label = _pool_spec(provider)
    try:
        accs = load() or {}
    except Exception as e:
        raise UpstreamError(503, "%s 账号读取失败：%s" % (label, str(e)[:80]))
    if not isinstance(accs, dict) or not accs:
        raise UpstreamError(503, "%s 账号不存在，请先在看板添加/导入" % label)

    now = time.time()
    with _POOL_LOCK:
        cool = {k for k, v in (_POOL_COOL.get(provider) or {}).items() if v > now}

    valid, bad = [], 0
    for n, e in accs.items():
        if not isinstance(e, dict):
            continue
        try:
            usable = bool(ok(e))
        except Exception:
            usable = False
        if usable:
            valid.append((n, e))
        else:
            bad += 1
    if not valid:
        raise UpstreamError(503, "%s 的 %d 个账号全部不可用（已过期或凭据不完整），"
                                 "请在看板重新登录/导入" % (label, bad or len(accs)))

    key = lambda it: _exp_key(exp(it[1]))
    fresh = sorted([it for it in valid if it[0] not in cool], key=key, reverse=True)
    cold = sorted([it for it in valid if it[0] in cool], key=key, reverse=True)
    return fresh + cold


def _pool_cool(provider, name, why, sec=None):
    """账号冷却（额度耗尽 / 鉴权失效），窗口内优先用别的号。
    sec 可指定短冷却：瞬时态错误（如并发上限）不该拉黑 30 分钟。"""
    sec = int(sec or _POOL_COOL_SEC)
    with _POOL_LOCK:
        _POOL_COOL.setdefault(provider, {})[name] = time.time() + sec
    try:
        import server as srv
        srv.log("[proxy:%s] 账号 %s 冷却 %ds（%s）"
                % (provider, name, sec, str(why)[:60]))
    except Exception:
        pass


def _pool_switchable(provider, status, msg):
    """该错误是否值得换号（账号级硬限），而不是模型/参数问题。
    TM.00001041（并发上限）也换号：每号并发配额独立，换号立即可用；
    配额是瞬时态，配合 60s 短冷却（见 _open_pool），全号都满时外层再退避重试。"""
    m = str(msg or "")
    if status in (401, 403, 429):
        return True
    low = m.lower()
    return any(h in low for h in _POOL_SWITCH_HINTS) or \
        any(h in m for h in ("额度", "余额", "配额", "次数已用尽", "已达上限"))


def _pool_err_of(line):
    """SSE 行里是否带「可换号」错误，返回原因或 None。"""
    s = (line or "").strip()
    if not s.startswith("data:"):
        return None
    try:
        j = json.loads(s[5:].strip())
    except Exception:
        return None
    if not isinstance(j, dict):
        return None
    ec = j.get("error_code")
    msg = str(j.get("error_msg") or j.get("message") or "")
    if not ec:
        err = j.get("error")
        if isinstance(err, dict):
            inner = err.get("data") if isinstance(err.get("data"), dict) else {}
            ec = err.get("code") or inner.get("code")
            msg = msg or str(err.get("msg") or inner.get("msg") or "")
    if not ec or str(ec) == "0":
        return None
    low = msg.lower()
    if ("14018" in str(ec) or "credit" in low or "额度" in msg or "quota" in low
            or "exhaust" in low or "insufficient" in low
            or "上限" in msg or "余额" in msg):
        return "额度耗尽(%s) %s" % (ec, msg[:60])
    return None


# 兼容旧测试/调用点
def _wbai_ents():
    return _pool_ents("wbai")


def _wbai_cool(name, why):
    return _pool_cool("wbai", name, why)


def _pool_open(provider, name, ent, body):
    """按平台构造上游流迭代器（model 前缀在这里剥掉）。"""
    if provider == "codearts":
        return _chat_stream(ent, body)
    if provider == "officeace":
        return oac.chat_stream(ent, body)
    if provider == "teleagent":
        return tat.chat_stream(ent, body)
    if provider == "tabbit":
        b = dict(body)
        mb = str(b.get("model") or "").strip()
        if mb.lower().startswith(TB_PREFIX):
            b["model"] = mb[len(TB_PREFIX):]
        return tbt.chat_stream(ent, b)
    # wbai
    b = dict(body)
    mb = str(b.get("model") or "").strip()
    if mb.lower().startswith(WBAI_PREFIX):
        b["model"] = mb[len(WBAI_PREFIX):]
    if not b.get("model"):
        b["model"] = "auto"
    return wai.chat_stream(ent, b, name=name)


def _open_pool(provider, openai_body):
    """按池顺序开流：额度耗尽/鉴权失效/429 自动换下一个号。
    返回 (name, lines)；所有号都失败时抛 UpstreamError。"""
    if provider == "wbai":
        return _open_wbai_pool(openai_body)
    last_err = None
    for name, ent in _pool_ents(provider):
        try:
            it = _pool_open(provider, name, ent, openai_body)
        except Exception as e:
            st = getattr(e, "status", None)
            msg = getattr(e, "message", None) or str(e)
            if st is not None and _pool_switchable(provider, st, msg):
                # 并发上限是瞬时态：60s 短冷却跳过即可，别拉黑 30 分钟
                short = "TM.00001041" in str(msg) or "并发会话" in str(msg)
                _pool_cool(provider, name, msg, sec=60 if short else None)
                last_err = UpstreamError(int(st), str(msg))
                continue
            if isinstance(e, UpstreamError):
                raise
            last_err = UpstreamError(502, str(msg)[:200])
            continue

        # 预读首个非空 chunk：账号级错误通常在第一帧就返回，此时还没向客户端写任何字节
        first = None
        try:
            for ln in it:
                if ln and ln.strip():
                    first = ln
                    break
        except Exception as e:
            st = getattr(e, "status", None)
            msg = getattr(e, "message", None) or str(e)
            if st is not None and _pool_switchable(provider, st, msg):
                short = "TM.00001041" in str(msg) or "并发会话" in str(msg)
                _pool_cool(provider, name, msg, sec=60 if short else None)
                last_err = UpstreamError(int(st), str(msg))
                continue
            last_err = UpstreamError(502, str(msg)[:200])
            continue

        why = _pool_err_of(first)
        if why:
            _pool_cool(provider, name, why)
            last_err = UpstreamError(502, why)
            try:
                it.close()
            except Exception:
                pass
            continue
        if first is None:
            last_err = UpstreamError(502, "%s 上游返回空流" % provider)
            continue
        return name, itertools.chain([first], it)

    raise last_err or UpstreamError(503, "%s 所有账号均不可用（额度或登录态）" % provider)


def _open_wbai(openai_body):
    """兼容旧调用点/测试：等价于 _open_pool("wbai", body)。"""
    return _open_pool("wbai", openai_body)


# ── 国际版：模型优先级 + 免费额度优先 + 行级限流回退 ─────────────────
# 经验来自 GitHub XDTrees/dsh-xdpool：
#   · 账号池 priority 模式（先用完一个号再换下一个）
#   · 上游按「模型行」限流：免费行被 429 时，同名付费行通常还通
#     （deepseek-v4.1-flash → deepseek-v4.1-flash-sg）
#   · 模型目录带倍率，0 倍率/限免的优先用
# 用户策略（2026-10-19 定，2026-10-20 改）：auto 只走目录里 x0.00 的四个免费行，
# 且这四行各是一个接口（DeepSeek → Hy3 → Hy4-Preview-F → Step-5-Preview）。
# hy4-preview 是 x0.29 付费行，不进链：积分见底的号上它必回 14018
# （2026-10-20 实测：两号各 13 行 14018 全在 hy4-preview / hy4-preview-f 上）。
WBAI_AUTO_CHAIN = ["deepseek-v4.1-flash", "hy3", "step-5-preview", "hy4-preview-f"]
# 免费行被限流时的同名付费退路（上游按行限流，付费行常仍可用）。
# 只有 deepseek 这条是上游 ModelRateLimitCap 明确给的；hy4-preview-f 没有付费变体
# （dsh-xdpool#30 同结论），配了也只会在积分见底的号上多撞一次 14018，故不加。
WBAI_PAID_ALIAS = {"deepseek-v4.1-flash": "deepseek-v4.1-flash-sg"}

_WBAI_WAIT_MAX = 90.0                         # 全链被限时，最多替客户端等这么久
_WBAI_WAIT_SLICE = 3.0                        # 心跳粒度：每 3s 醒一次，顺便发 keep-alive

_Q_CACHE = {}          # 账号 -> (ts, rank)
_Q_TTL = 300


def _wbai_is_free(m):
    """credit 形如 'x0.00' / 'x0.29' / 'x0.34 credits'；只有明确 0 才算免费
    （空/'-' 是未知倍率，不当免费模型用）。"""
    c = str((m or {}).get("credit") or "").strip().lower().lstrip("x")
    if not c or c == "-":
        return False
    try:
        return float(c.split()[0]) == 0.0
    except Exception:
        return False


def _wbai_free_ids(ent):
    try:
        return {m["id"] for m in wai.gw_models(ent) if _wbai_is_free(m)}
    except Exception:
        return set()


def _wbai_chain(ent, want, name=None):
    """本次请求要依次尝试的模型列表。
    显式模型：只试它本身 + 同名付费退路；auto/空：按用户优先级链。
    name 提供时跳过该号限流冷却中的模型行（6004 行级冷却）。"""
    if want:
        out = [want]
        alt = WBAI_PAID_ALIAS.get(want)
        if alt:
            out.append(alt)
        return [m for m in out if not (name and _wbai_ml_hit(name, m))]
    try:
        ids = {m["id"] for m in wai.gw_models(ent)}
    except Exception:
        ids = set()
    out = [m for m in WBAI_AUTO_CHAIN if (not ids) or m in ids]
    for m in sorted(_wbai_free_ids(ent)):
        if m not in out and m != "default-model":
            out.append(m)
    if (not ids) or ("default-model" in ids):
        out.append("default-model")
    if name:
        out = [m for m in out if not _wbai_ml_hit(name, m)]
    return out or ["default-model"]


def _wbai_quota_rank(name, ent):
    """账号额度健康度：0=还有免费包，1=只剩可累计积分，2=都没有/查不到。
    TTL 缓存，热路径不重复打上游。"""
    now = time.time()
    c = _Q_CACHE.get(name)
    if c and now - c[0] < _Q_TTL:
        return c[1]
    tok = str((ent or {}).get("token") or "")
    if not tok.startswith("eyJ"):      # 非 JWT（占位/测试凭据）不打上游
        _Q_CACHE[name] = (now, 1)
        return 1
    rank = 1
    try:
        import requests
        s = requests.Session()
        s.trust_env = False
        r = s.post(wai.BASE + wai.EP_RESOURCE, headers=wai._headers(ent.get("token") or ""),
                   json={}, timeout=8, verify=False)
        d = r.json()
        accs = (((d.get("data") or {}).get("Response") or {}).get("Data") or {}).get("Accounts") or []
        free_left = paid_left = 0.0
        for a in accs:
            try:
                rem = float(a.get("CapacityRemain") or 0)
            except Exception:
                continue
            nm = str(a.get("PackageName") or "").lower()
            if "free" in nm or "subscription" in nm:
                free_left += rem
            else:
                paid_left += rem
        rank = 0 if free_left > 0 else (1 if paid_left > 0 else 2)
    except Exception:
        rank = 1
    _Q_CACHE[name] = (now, rank)
    return rank


def _wbai_err_kind(line):
    """区分账号级（14018 额度耗尽）与模型行级（429 限流）错误。
    返回 'account' / 'model' / None。"""
    s = (line or "").strip()
    if not s.startswith("data:"):
        return None
    try:
        j = json.loads(s[5:].strip())
    except Exception:
        return None
    if not isinstance(j, dict):
        return None
    ec = j.get("error_code")
    msg = str(j.get("error_msg") or j.get("message") or "")
    if not ec:
        err = j.get("error")
        if isinstance(err, dict):
            inner = err.get("data") if isinstance(err.get("data"), dict) else {}
            ec = err.get("code") or inner.get("code")
            msg = msg or str(err.get("msg") or inner.get("msg") or "")
    if not ec:
        # 网关原生格式：{"code":6004,"msg":"usage exceeds frequency limit..."}
        ec = j.get("code")
        msg = msg or str(j.get("msg") or "")
    if not ec or str(ec) == "0":
        return None
    low = msg.lower()
    if "14018" in str(ec) or "credits exhausted" in low or "额度" in msg or "余额" in msg:
        return "account"
    if (str(ec) in ("429", "6004", "14003") or "rate limit" in low
            or "too many" in low or "frequency limit" in low
            or "限流" in msg or "繁忙" in msg):
        return "model"
    if "credit" in low or "quota" in low or "insufficient" in low:
        return "account"
    return None


# ---- 模型行级限流（6004）：重置时间解析 + (账号,模型) 级冷却 ----
# 社区实测参考（magpie#1361，与国内版同款网关）：6004 按「请求的模型」限流而非账号级；
# 触发量级观测 ≈ 每模型 5 小时窗口 44-45 次或 24 小时窗口 74 次（官方未公开，仅参考）。
# 重置时刻就在错误 msg 里（"将在 2026-08-06 15:49:30 UTC+8重置" / "明天早上 9:30 重置"），
# 这里解析出来做精确冷却与前端展示，不再拍脑袋固定 1800s。
_WBAI_ML_COOL = {}                            # (acct_name, model_lower) -> reset_epoch
# 面板可见性用（2026-10-20 用户要求「不要当瞎子」）：
#   _WBAI_EVENTS  最近 N 次上游限流（码 / 账号 / 模型 / 撞线时刻 / 重置时刻）
#   _WBAI_WAITING 此刻正在替客户端等待的请求（key → 到期时刻）
_WBAI_EVENTS = []                             # [{at, code, acct, model, reset, msg}]
_WBAI_EVENTS_MAX = 40
_WBAI_WAITING = {}                            # id -> {acct, model, until, code}
_WBAI_EV_LOCK = threading.Lock()


def _wbai_event(code, acct, model, reset=None, msg=""):
    """记一条限流事件（环形缓冲，只留最近 40 条；不含任何凭据）。"""
    with _WBAI_EV_LOCK:
        _WBAI_EVENTS.append({"at": time.time(), "code": str(code or ""),
                             "acct": str(acct or "?")[:40], "model": str(model or "")[:40],
                             "reset": reset, "msg": str(msg or "")[:120]})
        if len(_WBAI_EVENTS) > _WBAI_EVENTS_MAX:
            del _WBAI_EVENTS[:-_WBAI_EVENTS_MAX]
_WBAI_BUSY_COOL = 60                          # 14003 模型繁忙：瞬时态，短冷却即可
_WBAI_QUOTA_COOL = 600                        # 14018 额度耗尽：只冷当前模型行 10 分钟
_WBAI_NET_RETRY_WAIT = 0.5                    # 连接层瞬时错误（无 HTTP 状态）同号重试一次
_wbai_tls = threading.local()                 # 本轮实际选中的上游模型（relay 记账用）


def _wbai_reset_ts(text):
    """从上游错误消息解析限流重置时刻（本地 epoch），失败返回 None。
    支持：绝对（"2026-08-06 15:49:30 UTC+8重置" / "will reset at 2026-10-20 19:41:31 UTC+8"）
    与相对（"明天早上 9:30 重置"）。msg 里的时刻固定为北京时间（UTC+8）。"""
    s = str(text or "")
    import re as _re
    m = _re.search(r"(20\d{2})[-/年]\s*(\d{1,2})[-/月]\s*(\d{1,2})日?\s*[T\s]+(\d{1,2}):(\d{2})(?::(\d{2}))?", s)
    if m:
        try:
            import calendar, datetime
            dt = datetime.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                                   int(m.group(4)), int(m.group(5)), int(m.group(6) or 0))
            return calendar.timegm(dt.timetuple()) - 8 * 3600   # 北京墙上时间 → UTC epoch
        except Exception:
            pass
    # 相对表述："明天早上 9:30 重置" / "明天 02:44:26 重置"
    m = _re.search(r"明天[^\d]{0,6}(\d{1,2}):(\d{2})(?::(\d{2}))?", s)
    if m:
        try:
            import datetime
            now = datetime.datetime.now()
            t = datetime.datetime.combine(now.date() + datetime.timedelta(days=1),
                                          datetime.time(int(m.group(1)), int(m.group(2)),
                                                        int(m.group(3) or 0)))
            return t.timestamp()
        except Exception:
            pass
    return None


def _wbai_ml_hit(name, model):
    """该 (账号,模型) 行是否处于限流冷却中。过期即清理。"""
    k = (name, str(model or "").lower())
    ts = _WBAI_ML_COOL.get(k)
    if ts is None:
        return False
    if time.time() >= ts:
        _WBAI_ML_COOL.pop(k, None)
        return False
    return True


def _wbai_ml_limit(name, model, line, sec=None):
    """记录模型行限流冷却（从错误行解析重置时刻），返回人类可读的「HH:MM 重置」后缀。
    sec：调用方明确的短冷却（14018 额度耗尽 / 瞬时态）；不给则按 6004 窗口处理。"""
    ts = _wbai_reset_ts(line)
    _wbai_event(_wbai_code_of(line), name, model, ts, line)
    if ts:
        _WBAI_ML_COOL[(name, str(model or "").lower())] = ts
        return "（%s 重置）" % time.strftime("%H:%M", time.localtime(ts))
    if sec:
        ts = time.time() + int(sec)
        _WBAI_ML_COOL[(name, str(model or "").lower())] = ts
        return "（%d 分钟后自动重试）" % (int(sec) // 60 or 1)
    # 14003「too many requests / 模型繁忙」是瞬时态：拉黑 5 小时会把整条免费链拖死
    # （2026-10-20 实证：一次 14003 后 4 个免费行全被冷却 → 客户端连续 503）。
    if "14003" in str(line) or "too many requests" in str(line).lower():
        ts = time.time() + _WBAI_BUSY_COOL
        _WBAI_ML_COOL[(name, str(model or "").lower())] = ts
        return "（%d 秒后重试）" % _WBAI_BUSY_COOL
    # 解析不到精确时刻：免费模型的 6004 是 24 小时 token 窗口（社区 #253 十几个
    # 窗口样本一致），按 24h 冷；5 小时那一档是 magpie#1361 观测到的**次数**窗口，
    # 只发生在付费模型上，别再拿它当免费行的兜底（2026-10-20 纠正）。
    ts = time.time() + 24 * 3600
    _WBAI_ML_COOL[(name, str(model or "").lower())] = ts
    return "（约 %s 重置）" % time.strftime("%H:%M", time.localtime(ts))


def _wbai_code_of(line):
    """从上游错误行里取业务码（6004 / 14003 / 14018…），取不到返回 ""。"""
    import re as _re
    s = str(line or "")
    m = _re.search(r'"code"\s*:?\s*"?\d+', s)
    if m:
        return _re.search(r"\d+", m.group(0)).group(0)
    for c in ("6004", "14018", "14003", "11140", "11128"):
        if c in s:
            return c
    return ""


def wbai_limit_state():
    """面板用：此刻仍在冷却的 (账号,模型) 行 + 正在等待的请求 + 最近限流事件。"""
    now = time.time()
    rows = {}
    for (nm, mdl), t in list(_WBAI_ML_COOL.items()):
        if t <= now:
            _WBAI_ML_COOL.pop((nm, mdl), None)
            continue
        rows.setdefault(nm, {})[mdl] = t
    with _WBAI_EV_LOCK:
        waiting = [dict(v) for v in _WBAI_WAITING.values() if v.get("until", 0) > now]
        events = list(_WBAI_EVENTS)
    return {"rows": rows, "waiting": waiting, "events": events[-15:]}


def _wbai_next_avail():
    """当前被限的所有行里，最早恢复的 epoch；没有可解析的行返回 None。

    含两类：(账号,模型) 行级冷却（6004/14003/14018 都记在这）与整号冷却。
    等待重试只需要「最早那一个」——它一通，链上就有活口。"""
    ts = [v for v in _WBAI_ML_COOL.values() if v > time.time()]
    for nm, until in (_POOL_COOL.get("wbai") or {}).items():
        if until > time.time():
            ts.append(until)
    return min(ts) if ts else None


def _wbai_wait_retry(err, att, beat=None, acct=None, model=None):
    """限流不弹错误，改成替客户端等：最早恢复时刻在 _WBAI_WAIT_MAX 内就睡到点再重试。
    beat(剩余秒) 每 _WBAI_WAIT_SLICE 醒一次调一下——流式请求靠它发 SSE 注释心跳，
    否则 WorkBuddy 官方客户端「转几秒就自动取消」（2026-10-20 用户实证）。
    等待期间把自己登记进 _WBAI_WAITING，面板能看见「正在等谁、等到几点」。
    返回 True=已睡好、可以重试；False=要么太晚（几小时后才有额度）、要么没解析出时刻，
    那种情况直接把「几点恢复」如实回给客户端，让它自己决定要不要等。"""
    nxt = _wbai_next_avail()
    if not nxt:
        return False
    left = nxt - time.time()
    if left > _WBAI_WAIT_MAX or att >= 3:
        return False
    try:
        import server as srv
        srv.log("[proxy:wbai] 限流等待重试：最早 %s 恢复（还有 %ds，第 %d 轮）：%s"
                % (time.strftime("%H:%M:%S", time.localtime(nxt)), int(left), att + 1,
                   str(getattr(err, "message", "") or "")[:70]))
    except Exception:
        pass
    key = "%s/%s#%d" % (acct or "?", model or "auto", id(threading.current_thread()))
    _WBAI_WAITING[key] = {"acct": acct, "model": model, "until": nxt,
                          "code": _wbai_code_of(getattr(err, "message", "") or "")}
    end = time.time() + left + 0.5
    try:
        while True:
            rem = end - time.time()
            if rem <= 0:
                break
            if beat:
                try:
                    beat(int(rem))
                except Exception:
                    return False          # 心跳写不出去＝客户端已断开，别再空等
            time.sleep(min(_WBAI_WAIT_SLICE, rem))
    finally:
        _WBAI_WAITING.pop(key, None)
    return True


def wbai_model_limits():
    """供 pool_quota 展示：{acct: {model: reset_epoch}}，只含未过期的行级限流。"""
    now = time.time()
    out = {}
    for (nm, mdl), ts in list(_WBAI_ML_COOL.items()):
        if ts <= now:
            _WBAI_ML_COOL.pop((nm, mdl), None)
            continue
        out.setdefault(nm, {})[mdl] = ts
    return out


def _wbai_open(ent, body, name):
    """开一条上游流。连接层瞬时错误（没有 HTTP 状态）同号同模型重试一次。"""
    try:
        return wai.chat_stream(ent, body, name=name)
    except Exception as e:
        if getattr(e, "status", None) is not None:
            raise
        time.sleep(_WBAI_NET_RETRY_WAIT)
        return wai.chat_stream(ent, body, name=name)


def _wbai_quota_line(line):
    """14018 积分/额度耗尽（可能藏在 HTTP 429 外壳里）。"""
    s = str(line or "")
    low = s.lower()
    return ("14018" in s or "credits exhausted" in low
            or "额度" in s or "余额" in s)


def _open_wbai_pool(openai_body):
    """国际版专用池：账号按「免费额度优先」排序，账号内按模型优先级链尝试。
    账号级错误 → 换号；模型行级限流 → 同号换下一个模型。"""
    want = str(openai_body.get("model") or "").strip()
    if want.lower().startswith(WBAI_PREFIX):
        want = want[len(WBAI_PREFIX):]
    if want.lower() in ("", "auto"):
        want = None

    ents = _pool_ents("wbai")
    # priority 模式：还有每日免费包的号排前面（同 rank 保持有效期序）
    ents.sort(key=lambda it: _wbai_quota_rank(it[0], it[1]))

    last_err = None
    for name, ent in ents:
        for model in _wbai_chain(ent, want, name=name):
            body = dict(openai_body)
            body["model"] = model
            try:
                it = _wbai_open(ent, body, name)
            except Exception as e:
                st = getattr(e, "status", None)
                msg = getattr(e, "message", None) or str(e)
                if st in (401, 403):
                    _pool_cool("wbai", name, msg)
                    last_err = UpstreamError(int(st), str(msg))
                    break                      # 换号
                if _wbai_quota_line(msg):
                    # 14018 可能以 HTTP 402/429 外壳出现：只冷当前模型行，
                    # 同号继续试其它免费模型（整号 30 分钟拉黑曾导致连续 503）。
                    tag = _wbai_ml_limit(name, model, msg, sec=_WBAI_QUOTA_COOL)
                    last_err = UpstreamError(int(st or 402), str(msg)[:160] + tag)
                    continue                   # 同号换模型
                if st == 429:
                    # HTTP 429：行级限流（6004 也可能走 HTTP 外壳）——解析重置时刻做行级冷却
                    tag = _wbai_ml_limit(name, model, msg)
                    last_err = UpstreamError(429, str(msg)[:160] + tag)
                    continue                   # 同号换模型
                last_err = UpstreamError(int(st or 502), str(msg)[:200])
                continue

            first = None
            try:
                for ln in it:
                    if ln and ln.strip():
                        first = ln
                        break
            except Exception as e:
                st = getattr(e, "status", None)
                msg = getattr(e, "message", None) or str(e)
                last_err = UpstreamError(int(st or 502), str(msg)[:200])
                continue

            kind = _wbai_err_kind(first)
            if kind == "account":
                if _wbai_quota_line(first):
                    # 14018 额度耗尽：按模型行冷却，同号继续试其它模型；不整号拉黑
                    tag = _wbai_ml_limit(name, model, first, sec=_WBAI_QUOTA_COOL)
                    last_err = UpstreamError(402, first[:160] + tag)
                    try:
                        it.close()
                    except Exception:
                        pass
                    continue
                _pool_cool("wbai", name, first)
                last_err = UpstreamError(402, first[:160])
                try:
                    it.close()
                except Exception:
                    pass
                break                          # 账号级 → 换号
            if kind == "model":
                # 6004 行级限流：解析 msg 里的重置时刻 → (账号,模型) 级冷却；账号不拉黑
                tag = _wbai_ml_limit(name, model, first)
                last_err = UpstreamError(429, first[:160] + tag)
                try:
                    it.close()
                except Exception:
                    pass
                continue                       # 行级限流 → 同号换模型
            if first is None:
                last_err = UpstreamError(502, "上游返回空流")
                continue
            if want is None or model != want:
                try:
                    import server as srv
                    srv.log("[proxy:wbai] auto → %s（acct=%s）" % (model, name))
                except Exception:
                    pass
            _wbai_tls.model = model          # auto 时 relay 按实际模型记账/命名
            return name, itertools.chain([first], it)

    raise last_err or UpstreamError(503, "WorkBuddy 国际版所有账号/模型均不可用")


def _tb_ent():
    """取 Tabbit 账号（多账号选 JWT exp 最晚者）。只判断不刷新——
    cookie 登录态无刷新令牌，过期只能重新登录/导入。"""
    import datetime
    accs = tbt.load_accounts()
    if not accs:
        raise UpstreamError(503, "Tabbit 账号不存在，请先在看板「从本地客户端导入」"
                                 "（需本机装有 Tabbit 浏览器并已登录网页版）")
    def exp_of(item):
        return (tbt.token_exp(item[1]) or 0)
    name, ent = max(accs.items(), key=exp_of)
    exp = exp_of((name, ent))
    if exp and exp < time.time():
        raise UpstreamError(503, "Tabbit 登录态已于 %s 过期（JWT ~7 天）。"
                                 "请打开 Tabbit 浏览器重新登录网页版，再看板「从本地客户端导入」"
                            % datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M"))
    if not tbt._cookie_of(ent):
        raise UpstreamError(503, "Tabbit 凭据不完整（缺 cookie），请重新导入")
    return name, ent


# ── CodeArts 上游并发闸门 ──
# 华为福利网关限制并发会话 3 个（TM.00001041「并发会话数已达上限」），这是上游硬限制、撤不掉。
# 反代侧本地排队：超出的请求等槽位而非直接 400，客户端可任意并发、体感无感。
_CA_SEM = threading.BoundedSemaphore(3)
_CA_QUEUE_WAIT = 120        # 排队最长等 120s，再拿不到槽位才回 429


def _ta_ent():
    """取 TeleAgent 账号（多账号选 JWT exp 最晚者）。只读解密，不触发刷新。"""
    import datetime
    accs = tat.load_accounts()
    if not accs:
        raise UpstreamError(503, "TeleAgent 账号不存在，请先在看板导入 TeleAgent")
    def exp_of(item):
        return (tat._jwt_payload((item[1] or {}).get("token") or "").get("exp")) or 0
    name, ent = max(accs.items(), key=exp_of)
    exp = exp_of((name, ent))
    if exp and exp < time.time():
        raise UpstreamError(503, "TeleAgent token 已于 %s 过期，请打开 TeleAgent 客户端"
                                 "重新登录一次（约 29 天月抛）"
                            % datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M"))
    return name, ent


# ── OfficeACE 上游（华为云果办，2026-10-14 实测打通）──────────────
# 协议：agent2api 还原 + 本机实测——网关 Basic 对在订阅响应 model_infos[0]，
# chat 原生 OpenAI 恒流式。模型名与 CodeArts 有交集（如 deepseek-v4.1-flash），
# 交集名保持走 CodeArts（福利免费额度优先），OfficeAce 只接独有模型
# （openpangu / kimi-k3 / glm-5.3 / qwen3 系等 ~15 个）。
_OA_IDS = {"ts": 0.0, "ids": set()}


def _oa_ent():
    """取 OfficeACE 账号（expires_at 最晚者）。只判断不续期（热路径，同 _load_ent）。"""
    import server as srv
    path = srv.CRED_FILES.get("officeace")
    d = srv._read_json(path, {}) if path else {}
    if not d:
        raise UpstreamError(503, "OfficeACE 账号不存在，请先在看板导入 OfficeACE")
    name, ent = _pick_freshest(d)
    if oac._expired(ent) is True:
        raise UpstreamError(503, "OfficeACE 凭据已于 %s 过期，请到看板「从本地客户端导入」"
                                 "或打开客户端重新登录" % (ent.get("expires_at") or "")[:19])
    return name, ent


def oa_model_ids():
    """OfficeACE 网关模型 id 集合（TTL 缓存）。失败返回上次缓存/空集合（回退 CodeArts）。"""
    now = time.time()
    if _OA_IDS["ids"] and now - _OA_IDS["ts"] < CATALOG_TTL:
        return _OA_IDS["ids"]
    try:
        name, ent = _oa_ent()
        ids = set(oac.gw_models(ent))
        if ids:
            _OA_IDS.update(ts=now, ids=ids)
        return _OA_IDS["ids"]
    except Exception:
        return _OA_IDS["ids"]   # 网关不可用时回退：名字全归 CodeArts，行为不变


def _get(ent, url):
    hdr = cap.sign_headers(ent["ak"], ent["sk"], ent["sts_token"], "GET", url)
    r = requests.get(url, headers=hdr, timeout=30, verify=True,
                     proxies={"http": None, "https": None})
    if r.status_code != 200:
        raise UpstreamError(r.status_code, "上游 %s 失败：%s"
                            % (urllib.parse.urlsplit(url).path, r.text[:200]))
    return r.json() if r.content else {}


def catalog(ent, force=False):
    """返回 (builtin_ids, benefit_ids)。缓存 CATALOG_TTL；失败回退种子。
    ⚠ 网络 GET 在锁外做：锁内只读写缓存——否则冷启动时并发请求会
    在这把锁上串行排队，最坏阻塞 60s（2×30s 超时）。"""
    if not force:
        with _lock:
            if _catalog["ts"] and time.time() - _catalog["ts"] < CATALOG_TTL:
                return _catalog["builtin"], _catalog["benefit"]
    builtin, benefit = [], set(_SEED_BENEFIT)
    try:
        j = _get(ent, SNAP + EP_MODELS)
        for m in (j.get("builtinModels") or []):
            if m.get("enable") and m.get("model_id"):
                builtin.append(m["model_id"])
    except Exception:
        pass
    try:
        j = _get(ent, OPENGW + EP_GWCFG)
        for m in ((j.get("result") or {}).get("models") or []):
            if m.get("model_id"):
                benefit.add(m["model_id"])
    except Exception:
        pass
    with _lock:
        if builtin:
            _catalog.update(ts=time.time(), builtin=builtin, benefit=benefit)
        return _catalog["builtin"] or builtin, _catalog["benefit"] or benefit


def _upstream_body(openai_body, chat_id):
    """OpenAI 请求体 → v2 上游体（原生 OpenAI 形状 + 看板附加字段）。"""
    b = dict(openai_body)
    for k in ("stream", "stream_options", "user", "logit_bias", "logprobs",
              "top_logprobs", "n", "presence_penalty", "frequency_penalty",
              "seed", "response_format", "stop"):
        b.pop(k, None)   # 上游不支持/无意义字段，剥掉防参数错误
    b["stream"] = True                      # 上游恒为 SSE，客户端想要非流式由本地聚合
    b["prompt_cache_key"] = chat_id
    b["tool_stream"] = True
    b["chat_id"] = chat_id
    if not str(b.get("model") or "").strip():
        b["model"] = "deepseek-v4.1-flash"  # 默认走免费额度最大的福利模型
    return b


def _session_id(chat_id):
    return hashlib.sha256(("codearts-session:" + chat_id).encode()).hexdigest()[:32]


def _chat_stream(ent, openai_body):
    """调上游 v2 聊天，返回 SSE 行迭代器。"""
    chat_id = uuid.uuid4().hex
    _, benefit = catalog(ent)
    is_benefit = str(openai_body.get("model") or "").lower() in benefit
    body = json.dumps(_upstream_body(openai_body, chat_id), ensure_ascii=False)
    url = SNAP + EP_CHAT
    hdr = cap.sign_headers(ent["ak"], ent["sk"], ent["sts_token"], "POST", url,
                           body=body, extra={
                               "Accept": "text/event-stream",
                               "x-auth-token": ent["sts_token"],
                               "x-snap-traceid": uuid.uuid4().hex[:16],
                               "app-id": "CodeAgent3.0",
                               "is_confidential": "false",
                               "Chat-Id": chat_id,
                               "Session-Id": _session_id(chat_id),
                               **({"maas_type": "benefit"} if is_benefit else {}),
                           })
    r = requests.post(url, headers=hdr, data=body.encode("utf-8"),
                      timeout=CHAT_TIMEOUT, verify=True, stream=True,
                      proxies={"http": None, "https": None})
    if r.status_code >= 400:
        raise UpstreamError(r.status_code, r.text[:300])
    # ⚠ 上游 SSE Content-Type 不带 charset，requests 会按 ISO-8859-1 解码 →
    #   中文乱码（workbuddy.py 踩过的同款坑），必须显式指定 utf-8
    r.encoding = "utf-8"
    return r.iter_lines(decode_unicode=True)


def _sse_error(code, msg):
    return json.dumps({"error": {"message": msg, "type": "upstream_error",
                                 "code": code}}, ensure_ascii=False)


def _usage_str(u):
    """usage → 'tokens=in/out/total'（OpenAI 形状）；无则空串。"""
    if not isinstance(u, dict):
        return ""
    pt = u.get("prompt_tokens") or 0
    ct = u.get("completion_tokens") or 0
    tt = u.get("total_tokens") or (pt + ct)
    return " tokens=%s/%s/%s" % (pt, ct, tt)


# ── 用量聚合（看板「今日 token 消耗」卡片数据源）─────────────
# 2026-10-12 落数据目录（%LOCALAPPDATA%\dashboard_analysis\，与看板 /api/proxy_usage 一致）
try:
    import data_dir as _dd
    USAGE_FILE = _dd.path("proxy_usage.json")
except ImportError:
    USAGE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "proxy_usage.json")
USAGE_KEEP_DAYS = 30
_usage_lock = threading.Lock()


def _record_usage(model, u, provider=None, acct=None):
    """按日/按模型聚合 token 用量，原子写 proxy_usage.json。
    结构：{"2026-10-12": {model: {calls, prompt_tokens, completion_tokens}},
           "__acct": {"wbai/<号名>": {model: {calls, pt, ct}}}}（__acct 键嵌套，
    模型名不会与之冲突；wbai 免费模型用量展示用，其他 provider 也顺手记）。
    只含模型名/账号名与数字，不含任何凭据；写失败静默（不影响对话）。"""
    try:
        pt = (u or {}).get("prompt_tokens") or 0
        ct = (u or {}).get("completion_tokens") or 0
        day = time.strftime("%Y-%m-%d")
        with _usage_lock:
            try:
                d = json.load(open(USAGE_FILE, encoding="utf-8"))
            except Exception:
                d = {}
            m = d.setdefault(day, {}).setdefault(
                model, {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0})
            m["calls"] += 1
            m["prompt_tokens"] += pt
            m["completion_tokens"] += ct
            if provider and acct:
                ak = "%s/%s" % (provider, str(acct)[:40])
                a = d.setdefault("__acct", {}).setdefault(ak, {}).setdefault(
                    day, {}).setdefault(
                    model, {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0})
                a["calls"] += 1
                a["prompt_tokens"] += pt
                a["completion_tokens"] += ct
            for k in [k for k in d if k not in ("__acct",) and k < time.strftime(
                    "%Y-%m-%d", time.localtime(time.time() - USAGE_KEEP_DAYS * 86400))]:
                del d[k]                     # 裁掉 30 天前的旧数据
            ac = d.get("__acct") or {}
            for ak in list(ac):              # __acct 内层同口径裁剪
                inner = ac.get(ak) or {}
                for dd in [dd for dd in inner if dd < time.strftime(
                        "%Y-%m-%d", time.localtime(time.time() - USAGE_KEEP_DAYS * 86400))]:
                    del inner[dd]
                if not inner:
                    del ac[ak]
            tmp = USAGE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(d, fh, ensure_ascii=False)
            os.replace(tmp, USAGE_FILE)      # Windows 原子替换
    except Exception:
        pass


def relay(handler, openai_body):
    """主入口：按客户端 stream 开关转发一次对话。异常都转 OpenAI 错误 JSON。
    每次调用落一条审计（模型/账号/耗时/token）到 server.log（看板可见）——
    这是消耗每日免费额度的口子，不记账额度被吃光都查不到去向。"""
    import server as srv
    t0 = time.time()
    name = "?"   # _load_ent 失败（无账号/凭据不完整/已过期）时 log 仍要有值
    model = str(openai_body.get("model") or "deepseek-v4.1-flash")
    provider = route_of(openai_body.get("model"))
    if provider == "codearts":
        # OfficeACE 判定：模型命中 OA 目录且不在 CodeArts 目录 → 走果办网关。
        # 交集名（deepseek-v4.1-flash 等）保持 CodeArts：福利免费额度优先，行为不变。
        m = str(openai_body.get("model") or "").strip()
        if m and m in oa_model_ids():
            try:
                ne, ec = _load_ent()
                _bi, _be = catalog(ec)
                if m not in (set(_bi) | _be):
                    provider = "officeace"
            except UpstreamError:
                pass      # CodeArts 无账号时不拦：OA 独有模型仍可走果办
    want_stream = bool(openai_body.get("stream"))
    # CodeArts 本地排队闸门：等槽位（上游并发上限 3），拿不到才 429
    ca_slotted = False
    if provider == "codearts":
        deadline = time.time() + _CA_QUEUE_WAIT
        while not _CA_SEM.acquire(timeout=1.0):
            if time.time() > deadline:
                srv.log("[proxy:codearts] %s 排队 %.0fs 未获槽位，回 429" % (model, _CA_QUEUE_WAIT))
                handler._send(429, {"error": {
                    "message": "CodeArts 上游并发会话已达上限（华为网关限制 3 个），排队 %ds 仍未释放，请稍后重试"
                               % _CA_QUEUE_WAIT,
                    "type": "rate_limit"}})
                return
        ca_slotted = True

    def _ca_release():
        if ca_slotted:
            _CA_SEM.release()

    # 上游「并发会话数已达上限」(TM.00001041)：会话关闭后有残留计时，紧跟着开新会话也会撞。
    # 自动重试+退避，客户端无感（日志留痕）。
    disp_att, DISP_MAX, RETRY_WAIT = 0, 18, 5.0
    # 国际版限流等待时要提前开流并发心跳：WorkBuddy 官方客户端在「headers 已发、
    # 一个字节都没有」的情况下转几秒就自己取消这条消息（2026-10-20 用户实证）。
    wb_stream_open = [False]

    def _wb_beat(rem):
        if not want_stream:
            return
        if not wb_stream_open[0]:
            handler._begin_stream()
            wb_stream_open[0] = True
        handler._write_chunk(b": wbai rate-limited, retrying in %ds\n\n" % max(1, rem))

    while True:
        try:
            if provider == "teleagent":
                name, lines = _open_pool("teleagent", openai_body)
            elif provider == "wbai":
                name, lines = _open_wbai(openai_body)
                model = getattr(_wbai_tls, "model", model)   # auto → 实际上游模型
            elif provider == "officeace":
                name, lines = _open_pool("officeace", openai_body)
            elif provider == "tabbit":
                name, lines = _open_pool("tabbit", openai_body)
            else:
                name, lines = _open_pool("codearts", openai_body)
            break
        except UpstreamError as e:
            _ca_release()
            if provider == "wbai" and e.status in (402, 429, 503) \
                    and _wbai_wait_retry(e, disp_att,
                                         _wb_beat if want_stream else None,
                                         name, model):
                disp_att += 1
                continue
            if wb_stream_open[0]:
                # 心跳已经开流，只能按 SSE 收尾（再发 HTTP 状态行是坏协议）
                handler._write_chunk((
                    "data: %s\n\ndata: [DONE]\n\n" % json.dumps(
                        {"error": {"message": e.message[:300], "type": "rate_limit"}},
                        ensure_ascii=False)).encode("utf-8"))
                return
            if (provider == "codearts"
                    and ("TM.00001041" in e.message or "并发会话数" in e.message)):
                disp_att += 1
                if disp_att > DISP_MAX:
                    srv.log("[proxy:codearts] %s 上游并发限制重试 %d 次仍失败" % (model, DISP_MAX))
                    handler._send(429, {"error": {
                        "message": "CodeArts 上游并发会话已达上限（华为网关限制 3 个），重试 %d 次仍占用，请稍后重试"
                                   % DISP_MAX,
                        "type": "rate_limit"}})
                    return
                srv.log("[proxy:codearts] %s 上游并发限制，%.1fs 后第 %d/%d 次重试"
                        % (model, RETRY_WAIT, disp_att, DISP_MAX))
                time.sleep(RETRY_WAIT)
                if provider == "codearts":
                    deadline = time.time() + _CA_QUEUE_WAIT
                    while not _CA_SEM.acquire(timeout=1.0):
                        if time.time() > deadline:
                            handler._send(429, {"error": {
                                "message": "CodeArts 上游并发会话已达上限（华为网关限制 3 个），排队 %ds 仍未释放"
                                           % _CA_QUEUE_WAIT,
                                "type": "rate_limit"}})
                            return
                    continue
            srv.log("[proxy:%s] %s acct=%s HTTP%s %s"
                    % (provider, model, name, e.status, e.message[:80]))
            handler._send(e.status if e.status >= 400 else 502,
                          {"error": {"message": e.message, "type": "upstream_error"}})
            return
        except Exception as e:
            _ca_release()
            srv.log("[proxy:%s] %s acct=%s 异常 %s" % (provider, model, name, str(e)[:80]))
            handler._send(502, {"error": {"message": str(e)[:200],
                                          "type": "upstream_error"}})
            return

    if want_stream:
        if not wb_stream_open[0]:
            handler._begin_stream()
        usage, n_lines = None, 0
        try:
            for line in lines:
                n_lines += 1
                if not line:
                    # TeleAgent SSE 是标准事件帧（事件间空行分隔）——空行要透传保帧；
                    # CodeArts SSE 无空行，此分支不会走到，行为不变
                    handler._write_chunk(b"\n")
                    continue
                if line.startswith("data:") and "[DONE]" not in line:
                    try:              # 透传时顺带抓 usage；上游首个 chunk 会发全 0
                        j = json.loads(line[5:].strip())   # 占位，须跳过取尾部的真实值
                        u = j.get("usage") if isinstance(j, dict) else None
                        if isinstance(u, dict) and (u.get("total_tokens") or 0) > 0:
                            usage = u
                    except Exception:
                        pass
                handler._write_chunk((line + "\n").encode("utf-8"))
        except Exception:
            pass                      # 客户端断开等 IO 错误，直接收尾
        finally:
            _ca_release()
            srv.log("[proxy:%s] %s acct=%s stream %.1fs lines=%d%s"
                    % (provider, model, name, time.time() - t0, n_lines, _usage_str(usage)))
            _record_usage(model, usage, provider=provider, acct=name)
        return

    # 非流式：聚合 SSE → 单个 OpenAI 响应
    content, reasoning = [], []
    tool_map = {}                      # tool_call 增量按 index 合并（流式分片→完整调用）
    finish, usage, resp_id, created = None, None, "", 0
    try:
        for line in lines:
            line = (line or "").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                j = json.loads(data)
            except Exception:
                continue
            ec = j.get("error_code")
            if ec and str(ec) != "0":
                raise UpstreamError(502, "%s %s" % (ec, j.get("error_msg") or ""))
            resp_id = j.get("id") or resp_id
            created = j.get("created") or created
            for ch in (j.get("choices") or []):
                d = ch.get("delta") or {}
                if d.get("content"):
                    content.append(d["content"])
                if d.get("reasoning_content"):
                    reasoning.append(d["reasoning_content"])
                if d.get("tool_calls"):
                    for tc in d["tool_calls"]:
                        idx = tc.get("index") or 0
                        fn = tc.get("function") or {}
                        cur = tool_map.get(idx)
                        if cur is None:
                            cur = {"id": tc.get("id") or "", "type": tc.get("type") or "function",
                                   "function": {"name": fn.get("name") or "",
                                                "arguments": fn.get("arguments") or ""}}
                            tool_map[idx] = cur
                            continue
                        if tc.get("id"):
                            cur["id"] = tc["id"]
                        if tc.get("type"):
                            cur["type"] = tc["type"]
                        if fn.get("name"):
                            cur["function"]["name"] += fn["name"]
                        if fn.get("arguments"):
                            cur["function"]["arguments"] += fn["arguments"]
                if ch.get("finish_reason"):
                    finish = ch["finish_reason"]
            if j.get("usage"):
                usage = j["usage"]
    except UpstreamError as e:
        _ca_release()
        srv.log("[proxy:%s] %s acct=%s HTTP%s %s"
                % (provider, model, name, e.status, e.message[:80]))
        handler._send(e.status, {"error": {"message": e.message,
                                           "type": "upstream_error"}})
        return
    except Exception as e:
        _ca_release()
        srv.log("[proxy:%s] %s acct=%s 异常 %s"
                % (provider, model, name, str(e)[:80]))
        handler._send(502, {"error": {"message": str(e)[:200],
                                      "type": "upstream_error"}})
        return

    tool_calls = [tool_map[i] for i in sorted(tool_map)]
    msg = {"role": "assistant", "content": "".join(content)}
    if reasoning:
        msg["reasoning_content"] = "".join(reasoning)
    if tool_calls:
        msg["tool_calls"] = tool_calls
    out = {"id": resp_id or ("chatcmpl-" + uuid.uuid4().hex[:24]),
           "object": "chat.completion", "created": created or int(time.time()),
           "model": model,
           "choices": [{"index": 0, "message": msg, "finish_reason": finish or "stop"}],
           "usage": usage or {}}
    handler._send(200, out)
    _ca_release()
    srv.log("[proxy:%s] %s acct=%s %.1fs%s" % (provider, model, name, time.time() - t0,
                                               _usage_str(usage)))
    _record_usage(model, usage, provider=provider, acct=name)
