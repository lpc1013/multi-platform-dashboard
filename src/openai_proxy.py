# -*- coding: utf-8 -*-
"""
OpenAI 兼容反代：把 CodeArts Agent 等平台的模型额度暴露为本机 OpenAI API。
════════════════════════════════════════════════════════════════════════
协议（2026-10-12 实测验证，另参考 github.com/HITZY2002/codearts2api 逆向记录）：

  聊天    POST https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions
          鉴权 = AK/SK SDK-HMAC-SHA256 签名（platforms/codearts.sign_headers 同款）
                 + x-auth-token: <STS security_token>
          请求体原生 OpenAI 形状（model/messages/stream/max_tokens/temperature/…）
          + chat_id（32hex）+ prompt_cache_key + tool_stream:true
          + Chat-Id / Session-Id 头（prompt cache 亲和）
          ⚠ 2026-10-22：CodeArts 撤掉「每日 1000 万免费 token」福利，改为积分制。
            旧代码对福利模型带头 maas_type: benefit → 现在恒回
            InferHub.4004.200 benefit not found；**不带头**即走积分计费
            （实测 86 tokens = 0.01 积分，正常流式返回）。
  模型    GET /v1/model/builtin（内置，计积分）
          GET {opengw}/api/v1/gateway/config（网关模型目录）
  响应    SSE：本身就是 OpenAI chat.completion.chunk 形状（含 reasoning_content、
          usage、finish_reason、data:[DONE]），可直接透传。

限制（如实说明）：
  - 每账号上游并发会话上限 3（TM.00001041）；高并发瞬时错误（429/并发上限/
    5xx/空流/连接层）由反代自动退避重连（默认最多 14 次、总预算 90s，
    可用 DASHBOARD_PROXY_RETRY_BUDGET 调整），客户端无感；
  - tool_choice 对象形态上游会报参数错误（上游限制）；
  - 多模态消息透传，模型不支持图片时上游报错原样返回。
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
import platforms.officeace as oac
import platforms.workbuddy_ai as wai

SNAP = "https://snap-access.cn-north-4.myhuaweicloud.com"
OPENGW = "https://opengw.developer.huaweicloud.com"
EP_CHAT = "/api/v2/chat/completions"
EP_MODELS = "/v1/model/builtin"
EP_GWCFG = "/api/v1/gateway/config"

# 冷启动种子：网关目录（原「福利模型」列表）临时故障时兜底。
# 2026-10-22 起这些模型改积分计费，目录仍用于「模型归属判定」
# （relay 里决定交集名归 CodeArts 还是果办），与计费方式解耦。
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


from errors import (UpstreamError,
                     sanitize_client_message as _client_err_msg,
                     _QUOTA_HINTS)   # noqa: E402  统一异常体系（保持 (status, message) 旧签名）


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


# ── WorkBuddy 国际版上游（workbuddy.ai，2026-10-16 实测打通）──────────────
# 路由规则：`wb:` 前缀 → 国际版（如 wb:glm-5.2 / wb:gpt-5.5 / wb:auto）。
# 国际版模型名与 CodeArts/OfficeACE 大量交集（glm/kimi/deepseek 系），
# 用命名空间前缀隔离（buddy-proxy 同思路），客户端改前缀即切上游。
WBAI_PREFIX = "wb:"

# ── DS-Flash 统一池虚拟模型名（多平台 DeepSeek-V4.1-Flash 聚合入口）──────────────
# 详见文件「DS-Flash 统一池」一节：请求 ds-flash 即把 WB国际版 / CodeArts /
# OfficeACE 上所有可用的 DeepSeek-V4.1-Flash 账号（含 WB 付费行）聚合成
# 「一个接口」，负载均衡 + 故障转移。客户端用 model=ds-flash /
# deepseek-v4.1-flash / ds4.1-flash 任一写法均可，其余 OpenAI 参数不变。
# ⚠ 2026-10-22：Tabbit / TeleAgent 两个上游已下架（用户反馈「不太行」），
# 其路由/池/前端接口一并移除；账号管理（导入/登录/签到）不受影响。
DSFLASH_MODEL = "ds-flash"
DSFLASH_ALIASES = {"ds-flash", "ds4.1-flash", "ds4.1flash", "deepseek-v4.1-flash"}


def route_of(model):
    m = str(model or "").strip()
    ml = m.lower()
    if ml in DSFLASH_ALIASES:
        return "dsflash"
    if ml.startswith(WBAI_PREFIX):
        return "wbai"
    return "codearts"


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
# 覆盖：codearts / officeace / wbai（Tabbit / TeleAgent 2026-10-22 下架）。
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
    sec 可指定短冷却：瞬时态错误（如并发上限）不该拉黑 30 分钟。
    落盘在锁外：_cool_save 内部要拿 _POOL_LOCK 做快照，避免自锁。"""
    sec = int(sec or _POOL_COOL_SEC)
    with _POOL_LOCK:
        _POOL_COOL.setdefault(provider, {})[name] = time.time() + sec
    _cool_save()
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
        if not why:
            # 高并发时上游首帧直接回 429/5xx 错误帧：换号 + 短冷却 60s，
            # last_err 记 429（可重试）——全号失败时 relay 会退避重连整池，
            # 而不是把 502 弹给客户端让人工重试。参数类 4xx 不换号（_frame_retryable）。
            ferr = _frame_err(first)
            if ferr and _frame_retryable(*ferr):
                _pool_cool(provider, name, "首帧错误 %s %s" % ferr, sec=60)
                last_err = UpstreamError(429, ("%s %s" % ferr)[:200])
                try:
                    it.close()
                except Exception:
                    pass
                continue
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


# ── 冷却态持久化（2026-10-22 用户要求「模型重置可使用时间要持久化保留」）────
# 两类冷却都是「上游还没恢复、本地先避让」的状态，曾为纯内存：看板一重启，
# 「WB国际某号 6004 限到 20:00 / CodeArts 某号 429 冷到 20:30」这类信息即丢，
# 重启后反代立刻拿这些号去打 → 客户端连续撞限流/502，要等再次撞上限才重新
# 冷却。现落盘 proxy_cool.json（与 proxy_usage.json 同目录、同原子写），
# 导入时恢复未过期项。只存「账号名/模型名 + epoch」，无任何凭据。
try:
    import data_dir as _dd
    COOL_FILE = _dd.path("proxy_cool.json")
except ImportError:
    COOL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "proxy_cool.json")
_COOL_SAVE_LOCK = threading.Lock()


def _cool_key(name, model):
    """(账号, 模型行) → 扁平 key。模型名小写，与 _WBAI_ML_COOL 的键口径一致。"""
    return "%s|%s" % (str(name or "")[:80], str(model or "").lower()[:80])


def _cool_snapshot():
    """两类冷却的未过期快照。_POOL_COOL 持锁快照；_WBAI_ML_COOL 无锁遍历
    （修改点都会再触发 save，尽力而为，单次漏写下次补上）。"""
    now = time.time()
    ml = {}
    for (nm, mdl), ts in list(_WBAI_ML_COOL.items()):
        if ts > now:
            ml[_cool_key(nm, mdl)] = int(ts)
    pool = {}
    with _POOL_LOCK:
        for prov, m in list(_POOL_COOL.items()):
            keep = {n: int(t) for n, t in list((m or {}).items()) if t > now}
            if keep:
                pool[prov] = keep
    return {"v": 1, "ml": ml, "pool": pool}


def _cool_save():
    """全量原子写。只在冷却**设置**时调（限流/换号非热路径，可同步写）。
    测试进程不落盘——避免 pytest 构造的假冷却污染线上文件。"""
    try:
        from logstore import _under_test
        if _under_test():
            return
    except Exception:
        pass
    try:
        with _COOL_SAVE_LOCK:
            d = _cool_snapshot()
            tmp = COOL_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(d, fh, ensure_ascii=False)
            os.replace(tmp, COOL_FILE)      # Windows 原子替换
    except Exception:
        pass                                # 写失败不影响对话，下次设置时再写


def _cool_load():
    """模块导入时恢复未过期的冷却态（看板重启不丢「禁用至 HH:MM:SS 放出」）。
    测试进程不自动加载：避免真实冷却态干扰断言，验证恢复逻辑的用例显式调用。"""
    try:
        from logstore import _under_test
        if _under_test():
            return
    except Exception:
        pass
    try:
        d = json.load(open(COOL_FILE, encoding="utf-8"))
    except Exception:
        return
    if not isinstance(d, dict):
        return
    now = time.time()
    n = 0
    for k, ts in (d.get("ml") or {}).items():
        try:
            ts = float(ts)
        except Exception:
            continue
        if ts <= now:
            continue                        # 已过期：恢复即清理
        nm, _, mdl = str(k).rpartition("|")   # 账号名可能含 "|"，模型段在最后
        _WBAI_ML_COOL[(nm, mdl)] = ts
        n += 1
    for prov, m in (d.get("pool") or {}).items():
        if not isinstance(m, dict):
            continue
        for nm, ts in list(m.items()):
            try:
                ts = float(ts)
            except Exception:
                continue
            if ts <= now:
                continue
            _POOL_COOL.setdefault(prov, {})[nm] = ts
            n += 1
    if n:
        try:
            import server as srv
            srv.log("[proxy] 重启恢复冷却态 %d 条（%s）"
                    % (n, os.path.basename(COOL_FILE)))
        except Exception:
            pass


_cool_load()        # 导入即恢复：进程起来后旧的「重置时刻」依然生效


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
    sec：调用方明确的短冷却（14018 额度耗尽 / 瞬时态）；不给则按 6004 窗口处理。
    finally 落盘：重启后「重置时刻」依然生效（2026-10-22 用户要求持久化保留）。"""
    try:
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
    finally:
        _cool_save()


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


# ── CodeArts 上游并发闸门 ──
# 华为网关限制每账号并发会话 3 个（TM.00001041「并发会话数已达上限」），这是上游
# 硬限制、撤不掉。反代侧本地排队：超出的请求等槽位而非直接 400，客户端可任意
# 并发、体感无感。2026-10-22 起改积分制，会话上限不变。
_CA_SEM = threading.BoundedSemaphore(3)
_CA_QUEUE_WAIT = 120        # 排队最长等 120s，再拿不到槽位才回 429


# ── 高并发自动重连（2026-10-22 用户诉求：「应该自动重连 而不是直接弹重试」）──
# 瞬时错误——纯 429 限流 / 并发会话上限(TM.00001041) / 5xx / 空流 / 连接层
# 异常——由反代自己退避重试 + 换号换通道，客户端无感；等待期间流式请求靠
# SSE 注释心跳保活（WorkBuddy 官方客户端几秒无字节就自取消，2026-10-20 实证）。
# 不重试的：真额度耗尽（402/14018/余额类关键词）、鉴权失效（401/403）、
# 参数错误（400）——重试无意义，如实透传让客户端决策；wbai 限流另有
# _wbai_wait_retry 精确等到重置时刻（优先于本机制）。
AUTO_RETRY_MAX = 14                                  # 单请求自动重连次数上限
AUTO_RETRY_BUDGET = float(os.environ.get(
    "DASHBOARD_PROXY_RETRY_BUDGET", "90") or 90)     # 自动重连总时长预算（秒）
AUTO_RETRY_BACKOFF = (1.0, 2.0, 3.0, 5.0, 8.0)       # 退避序列，之后维持 8s

# 客户端可见错误净化已统一收口到 errors.sanitize_client_message
# （本模块经 `from errors import ... as _client_err_msg` 复用，避免逻辑漂移）。
# 内部 UpstreamError.message 仍保留原始码（看板审计与既有测试依赖），
# 仅「发回客户端的文案」经 _client_err_msg 净化。


def _upstream_err_in_line(line):
    """流中某 data 帧是否为上游错误帧；是则返回净化后的客户端文案，否则 None。
    覆盖 error_code / error.data.code / 网关原生 code 三种形态。"""
    s = (line or "").strip()
    if not s.startswith("data:"):
        return None
    body = s[5:].strip()
    if body == "[DONE]":
        return None
    try:
        j = json.loads(body)
    except Exception:
        return None
    if not isinstance(j, dict):
        return None
    ec = j.get("error_code")
    if ec and str(ec) != "0":
        return _client_err_msg(502, "%s %s" % (ec, j.get("error_msg") or ""))
    err = j.get("error")
    if isinstance(err, dict):
        inner = err.get("data") if isinstance(err.get("data"), dict) else {}
        code = err.get("code") or inner.get("code")
        if code and str(code) != "0":
            return _client_err_msg(502, str(err.get("msg") or inner.get("msg") or ""))
    c = j.get("code")
    if c not in (None, 0, "0"):
        return _client_err_msg(502, str(j.get("msg") or j.get("message") or ""))
    return None


def _retryable_err(st, msg):
    """瞬时错误才自动重连；额度耗尽/鉴权失效/参数错误立即透传（重试无意义）。"""
    m = str(msg or "")
    low = m.lower()
    if any(h in m or h in low for h in _QUOTA_HINTS):
        return False
    if st is None:
        return True                  # 连接层瞬时错误（读超时/重置/分帧失败）
    if st in (400, 401, 402, 403):
        return False
    if st == 429:
        return True                  # 纯限流（并发/频率）→ 退避后能活
    if st in (408, 500, 502, 503, 504):
        return True
    if ("TM.00001041" in m or "并发会话" in m or "上限" in m
            or "空流" in m or "timeout" in low or "timed out" in low
            or "reset by peer" in low):
        return True
    return False


def _backoff(att):
    """第 att 次重连前的等待秒数（1→2→3→5→8，之后维持 8s）。"""
    return AUTO_RETRY_BACKOFF[att - 1] if att <= len(AUTO_RETRY_BACKOFF) \
        else AUTO_RETRY_BACKOFF[-1]


def _frame_err(line):
    """SSE 首帧是否为错误帧；是则返回 (code, msg)，否则 None。
    覆盖三种上游形态：error_code（OpenAI 兼容）、error 对象、网关原生 code。"""
    s = str(line or "").strip()
    if not s.startswith("data:"):
        return None
    try:
        j = json.loads(s[5:].strip())
    except Exception:
        return None
    if not isinstance(j, dict):
        return None
    ec = j.get("error_code")
    if ec and str(ec) != "0":
        return (ec, j.get("error_msg") or "")
    if isinstance(j.get("error"), dict):
        return ("err", (j.get("error") or {}).get("message") or "")
    c = j.get("code")
    if c not in (None, 0, "0"):
        return (c, j.get("msg") or j.get("message") or "")
    return None


def _frame_retryable(ec, msg):
    """错误帧是否值得换号重连：限流(429/14003/6004)与服务端错误(5xx)才值得；
    参数类 4xx 换号也一样错，立即透传（test_non_stream_error_chunk_logged 锁此行为）。"""
    s = str(ec or "")
    m = str(msg or "")
    if any(k in s for k in ("429", "503", "500", "502", "504", "408",
                            "14003", "6004", "TM.00001041")):
        return True
    if any(k in m for k in ("rate limit", "too many", "frequency", "限流", "并发",
                            "timeout", "timed out")):
        return True
    return False


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
    """返回 (builtin_ids, gw_ids)。缓存 CATALOG_TTL；失败回退种子。
    gw_ids = opengw 网关目录（2026-10-22 前叫「福利模型」——免费 token 包已撤，
    现按积分计费；目录本身仍有效，用于 relay 的模型归属判定）。
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
        b["model"] = "deepseek-v4.1-flash"  # 默认模型（积分制，两平台都有）
    return b


def _session_id(chat_id):
    return hashlib.sha256(("codearts-session:" + chat_id).encode()).hexdigest()[:32]


def _chat_stream(ent, openai_body):
    """调上游 v2 聊天，返回 SSE 行迭代器。

    ⚠⚠ 2026-10-22：CodeArts 撤掉「每日 1000 万免费 token」福利、DS4.1-Flash 等
    模型改积分制后，**不再发送 maas_type: benefit 头**——带了就恒回
    InferHub.4004.200 benefit not found（两账号实测）；不带头即按积分计费
    （实测 86 tokens ≈ 0.01 积分，流式正常）。顺带省掉每次请求前的
    catalog() 两次目录 GET。"""
    chat_id = uuid.uuid4().hex
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


# ════════════════════ DS-Flash 统一池（多平台 DeepSeek-V4.1-Flash 聚合）═════════════════════
# 诉求（2026-10-21）：高并发下（一个任务开多个子代理并发打 API），把散落在多个平台、
# 多个账号上的所有 DeepSeek-V4.1-Flash 聚合成「一个接口」，请求进来自动均匀分发，
# 既能扛住并发、流量消耗也均匀。用户备注：免不免费问题不大，只要是 DS 积分就扛得住。
#
# 工程经验来自 GitHub one-api / new-api / TokenPAPA / llm-one-api 等：
#   · 通道注册表：虚拟模型 → N 个通道（provider+账号+模型），热路径只读内存（不碰磁盘）；
#   · 负载均衡：round_robin（默认，均匀分配）/ weighted（按权重）/ least_conn（最少在途，
#     天然适配并发突发）；另加「并发上限」约束——超过上限的通道直接跳过，避免把单通道打爆；
#   · 被动健康 + 短冷却故障转移：429/5xx/空流/首帧错误 → 冷却该通道并换下一个，不永久拉黑
#     （瞬时态只冷 60s；wbai 模型行限流按重置时刻精确冷却）；
#   · 错误分级：账号级硬限（401/403/额度耗尽）长冷却，瞬时态短冷却。
#
# 接入方式：客户端把 model 写成 ds-flash / deepseek-v4.1-flash / ds4.1-flash 任一即可，
# 其余 OpenAI 参数不变。想纳入更多 DS 通道在 _DSFLASH_CHANNELS 加一行。
DSFLASH_STRATEGY = os.environ.get("DSFLASH_STRATEGY", "round_robin").strip() or "round_robin"
# 通道注册表：每个 (平台, 模型行) 是一个独立通道，请求进来按策略挑一个。
#   · wbai 免费行 + 付费行（-sg，消耗积分）都纳入：高并发时付费行补充容量，
#     用户策略「免不免费问题不大，只要 DS 积分扛得住」；
#   · codearts（2026-10-22 起积分制，2 账号）+ officeace（果办）网关并列，
#     流量均匀分摊到多账号。果办目录里同样有 deepseek-v4.1-flash（交集名在
#     /v1/models 展示归 CodeArts，但果办网关额度独立，入池扩容量）。
#   · Tabbit 通道 2026-10-22 移除（上游下架）。
_DSFLASH_CHANNELS = [
    ("wbai", "deepseek-v4.1-flash", 1.0),       # 国际版免费行（每日免费额度）
    ("wbai", "deepseek-v4.1-flash-sg", 1.0),    # 国际版付费行（消耗积分，补并发容量）
    ("codearts", "deepseek-v4.1-flash", 1.0),   # CodeArts 积分制（每号并发 3）
    ("officeace", "deepseek-v4.1-flash", 1.0),  # 果办网关（额度独立，与 CodeArts 互为补充）
]
# 每通道并发上限：取上游硬限制（CodeArts 会话并发 3），其余给宽松上限防本地打爆。
_DSFLASH_MAX_CONN = {"codearts": 3, "officeace": 16, "wbai": 64}
_DSFLASH_RR = itertools.count()
_DSFLASH_CONN = {}                       # (prov,name,model) -> 在途请求数
_DSFLASH_CONN_LOCK = threading.Lock()


def _dsflash_cool_until(prov, name, model_id):
    """通道的冷却「到期时刻」（epoch 秒）；未冷却返回 0。
    这是 DS-Flash 池「账号/通道临时禁用」机制的核心：禁用时记录到期时刻，期间跳过该
    通道，到期（> 现在）即**自动放出**。到期时刻取自两处冷却表的最晚值：整号冷却
    (_POOL_COOL) 与 wbai 模型行冷却 (_WBAI_ML_COOL)，保证两种粒度的禁用都能被看到/释放。"""
    now = time.time()
    until = 0.0
    with _POOL_LOCK:
        c = (_POOL_COOL.get(prov) or {}).get(name)
        if c and c > now:
            until = max(until, c)
    if prov == "wbai":
        m = _WBAI_ML_COOL.get((name, str(model_id or "").lower()))
        if m and m > now:
            until = max(until, m)
    return until


def _dsflash_cooling(prov, name, model_id):
    """该 (平台,账号,模型) 通道是否处于冷却（临时禁用）中。"""
    return _dsflash_cool_until(prov, name, model_id) > 0


def _dsflash_live_channels():
    """构造当前可用通道列表：遍历注册表，每个平台枚举可用账号（跳过冷却中的）。
    稳定排序保证轮询顺序确定性。"""
    out = []
    for prov, model_id, weight in _DSFLASH_CHANNELS:
        try:
            ents = _pool_ents(prov)
        except UpstreamError:
            continue
        for name, ent in ents:
            if _dsflash_cooling(prov, name, model_id):
                continue
            out.append({"prov": prov, "name": name, "ent": ent,
                        "model": model_id, "weight": weight,
                        "key": (prov, name, model_id)})
    out.sort(key=lambda c: c["key"])
    return out


def _dsflash_pick(live):
    """按策略挑一个通道；优先在「在途数 < 并发上限」的通道里选，全满则退化为最少连接。"""
    avail = [c for c in live if not _dsflash_cooling(c["prov"], c["name"], c["model"])]
    if not avail:
        return None
    with _DSFLASH_CONN_LOCK:
        cap = _DSFLASH_MAX_CONN.get
        under = [c for c in avail if _DSFLASH_CONN.get(c["key"], 0) < cap(c["prov"], 64)]
        pool = under or avail
        if DSFLASH_STRATEGY == "least_conn":
            c = min(pool, key=lambda c: (_DSFLASH_CONN.get(c["key"], 0), next(_DSFLASH_RR)))
        elif DSFLASH_STRATEGY == "weighted":
            # 按权重展开后轮询（默认权重均为 1.0，等价于 round_robin）
            expanded = []
            for c in pool:
                expanded.extend([c] * max(1, int(round(c["weight"]))))
            c = expanded[next(_DSFLASH_RR) % len(expanded)]
        else:   # round_robin（默认：均匀分配）
            c = pool[next(_DSFLASH_RR) % len(pool)]
    return c


def _dsflash_err_kind(first, ch):
    """首帧是否带可换通道的错误；返回真值即触发故障转移。
    统一池要对客户端透明：首帧只要出现任何错误标记（error_code / error 对象 /
    网关原生 code / 非 data 帧 / 解析失败）就换下一个通道；实在全失败才把最后一条透传。"""
    s = (first or "").strip()
    if not s.startswith("data:"):
        return True                       # 非 data 帧（纯错误文本/解析不了的残留）→ 当错误
    try:
        j = json.loads(s[5:].strip())
    except Exception:
        return True                       # 首帧 JSON 解析失败 → 当错误，换通道
    if not isinstance(j, dict):
        return True
    if ch["prov"] == "wbai" and _wbai_err_kind(first):
        return True
    if j.get("error_code") and str(j.get("error_code")) != "0":
        return True
    if isinstance(j.get("error"), dict):
        return True
    if j.get("code") not in (None, 0, "0"):   # 网关原生格式 {"code":6004,"msg":...}
        return True
    return bool(_pool_err_of(first))            # 兜底：额度类关键词


def _dsflash_cool(ch, st, msg):
    """通道冷却（故障转移用）：错误分级决定冷却时长。"""
    prov, name, model_id = ch["prov"], ch["name"], ch["model"]
    m = str(msg or "")
    low = m.lower()
    # wbai 14018（Credits exhausted）：国际版网关在并发突发时常把「瞬时/额度事件」误报成
    # 14018，并非真额度耗尽（实测同账号免费行几分钟后仍正常流式返回）。复用 wbai 中继的
    # _wbai_ml_limit：只冷却「模型行」且按重置时刻精确冷却，同号其它模型/付费行（-sg）仍可用。
    # 绝不分账号整号拉黑——否则有额度的账号被踢出统一池 30 分钟，高并发下把流量挤到已饱和的
    # 其它平台（CodeArts 上限 3 / 果办 16），某次请求无可用通道即把最后一条 14018 当 502 抛出。
    if prov == "wbai" and ("14018" in m or "credits exhausted" in low):
        # 与 wbai 中继一致：14018 只冷当前模型行 10 分钟（_WBAI_QUOTA_COOL），按重置时刻精确；
        # 不带 sec 会让 _wbai_ml_limit 落到 24h 默认，对瞬时 14018 过长。
        _wbai_ml_limit(name, model_id, m or "{}", sec=_WBAI_QUOTA_COOL)
        return
    # 账号级硬限（401/403 / 非 wbai 的 14018 额度耗尽 / 余额不足）→ 长冷却（复用 _pool_cool，默认 30 分钟）
    if st in (401, 403) or "14018" in m or "credits exhausted" in low \
            or "额度" in m or "余额" in m or "quota" in low or "insufficient" in low:
        _pool_cool(prov, name, m or "账号级错误")
        return
    # wbai 模型行限流（6004/429）→ 按重置时刻精确冷却（复用既有机制）
    if prov == "wbai" and (_wbai_err_kind(m) == "model" or st == 429):
        _wbai_ml_limit(name, model_id, m or "{}")
        return
    # 其余瞬时态（5xx/空流/超时）→ 短冷却 60s，别永久拉黑
    _pool_cool(prov, name, m or "瞬时态", sec=60)


def _open_dsflash_pool(body):
    """DS-Flash 统一池：多平台 DS4.1-Flash 聚合，负载均衡 + 自动故障转移。
    返回 (acct_label, lines)；全部失败抛 UpstreamError。acct_label=平台/账号，审计可见命中谁。"""
    live = _dsflash_live_channels()
    if not live:
        raise UpstreamError(503, "DS-Flash 池为空：所有平台的 DeepSeek-V4.1-Flash 账号均不可用"
                             "（请确认 WB国际版 / CodeArts / 果办 已导入且未过期）")
    tried, last_err, retry_err = set(), None, None
    guard = 0
    while guard < len(live) + 2:
        guard += 1
        ch = _dsflash_pick(live)
        if ch is None or ch["key"] in tried:
            break
        tried.add(ch["key"])
        b = dict(body)
        b["model"] = ch["model"]
        it = None
        try:
            with _DSFLASH_CONN_LOCK:
                _DSFLASH_CONN[ch["key"]] = _DSFLASH_CONN.get(ch["key"], 0) + 1
            it = _pool_open(ch["prov"], ch["name"], ch["ent"], b)
            # 预读首个 data 帧：账号级/模型行错误通常在首帧返回，此时还没向客户端写字节，
            # 失败可无感换下一个通道（与 _open_pool 同款手法）。SSE 注释行（keep-alive）
            # 跳过，不当成错误帧。
            first = None
            try:
                for ln in it:
                    if not ln or not ln.strip():
                        continue
                    if ln.lstrip().startswith(":"):
                        continue
                    first = ln
                    break
            except Exception as e:
                st = getattr(e, "status", None)
                msg = getattr(e, "message", None) or str(e)
                _dsflash_cool(ch, st, msg)
                last_err = UpstreamError(int(st or 502), str(msg)[:200])
                if retry_err is None and _retryable_err(st, msg):
                    retry_err = last_err      # 留给 relay 自动重连（并发释放后能活）
                it = None
        finally:
            with _DSFLASH_CONN_LOCK:
                _DSFLASH_CONN[ch["key"]] = max(0, _DSFLASH_CONN.get(ch["key"], 0) - 1)
        if it is None:
            continue
        if _dsflash_err_kind(first, ch):
            _dsflash_cool(ch, None, first)
            last_err = UpstreamError(502, first[:160])
            if retry_err is None and _retryable_err(None, first):
                retry_err = last_err
            try:
                it.close()
            except Exception:
                pass
            continue
        if first is None:
            _dsflash_cool(ch, None, "空流")
            last_err = UpstreamError(502, "上游返回空流")
            if retry_err is None:
                retry_err = last_err
            continue
        return "%s/%s" % (ch["prov"], ch["name"]), itertools.chain([first], it)
    # 全失败：有任一通道只是「瞬时忙」就抛那个错（relay 会退避重连整池）；
    # 全是额度/鉴权类才透传最后一条（重试无意义，如实告诉客户端）。
    raise retry_err or last_err or UpstreamError(503, "DS-Flash 池所有通道均失败")


def dsflash_status():
    """面板/接口可见：虚拟模型、策略、各通道在途数/并发上限/冷却状态（不要当瞎子）。"""
    live = _dsflash_live_channels()
    with _DSFLASH_CONN_LOCK:
        conn = dict(_DSFLASH_CONN)
    return {
        "virtual_model": DSFLASH_MODEL,
        "aliases": sorted(DSFLASH_ALIASES),
        "strategy": DSFLASH_STRATEGY,
        "channels": [
            {"prov": c["prov"], "name": c["name"], "model": c["model"],
             "in_flight": conn.get(c["key"], 0),
             "max_conn": _DSFLASH_MAX_CONN.get(c["prov"], 64),
             "cooling": _dsflash_cooling(c["prov"], c["name"], c["model"]),
             "cool_until": int(_dsflash_cool_until(c["prov"], c["name"], c["model"]))}
            for c in live
        ],
        "n": len(live),
    }


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
    # CodeArts 本地排队闸门：等槽位（上游并发上限 3），拿不到才 429。
    # 排队 >2s 的流式请求先开流发心跳——客户端「headers 已发、一个字节都没有」
    # 转几秒就自己取消（2026-10-20 用户实证），排队 120s 干等必被取消。
    ca_slotted = False
    wb_stream_open = [False]      # 已向客户端发过 SSE 头（此后再发 HTTP 状态行是坏协议）

    def _ca_acquire():
        """排队等 CodeArts 槽位；返回 False=等超时。流式带心跳保活。"""
        started = time.time()
        deadline = started + _CA_QUEUE_WAIT
        beat_at = 0.0
        while not _CA_SEM.acquire(timeout=1.0):
            if time.time() > deadline:
                return False
            if not want_stream:
                continue
            if not wb_stream_open[0] and time.time() - started > 2:
                handler._begin_stream()          # 排队超 2s 才开流：秒过不值得改协议
                wb_stream_open[0] = True
            if wb_stream_open[0]:
                now = time.time()
                if now - beat_at >= 3:
                    beat_at = now
                    try:
                        handler._write_chunk(
                            b": queued for CodeArts slot, %ds left\n\n"
                            % max(1, int(deadline - now)))
                    except Exception:
                        return False               # 客户端已断开：别再空等
        return True

    def _ca_release():
        if ca_slotted:
            _CA_SEM.release()

    def _ca_timeout_reply():
        """排队超时的统一收尾：开过流只能 SSE 收尾，否则 429 状态行。"""
        msg = ("CodeArts 上游并发会话已达上限（华为网关限制 3 个），"
               "排队 %ds 仍未释放，请稍后重试" % _CA_QUEUE_WAIT)
        srv.log("[proxy:codearts] %s %s" % (model, msg))
        if wb_stream_open[0]:
            handler._write_chunk((
                "data: %s\n\ndata: [DONE]\n\n" % json.dumps(
                    {"error": {"message": msg, "type": "rate_limit"}},
                    ensure_ascii=False)).encode("utf-8"))
        else:
            handler._send(429, {"error": {"message": msg, "type": "rate_limit"}})

    if provider == "codearts":
        if not _ca_acquire():
            _ca_timeout_reply()
            return
        ca_slotted = True

    # 自动重连状态：att=次数（含 wbai 精确等待轮），t0=总预算起点。
    # 高并发瞬时错误（429/并发上限/5xx/空流/连接层）由反代退避重试，不弹给客户端。
    att, retry_t0 = 0, time.time()
    from logstore import _under_test as _ut
    # 测试环境把退避压到近零：重连轮次瞬间跑完（不断言 call_count 的既有用例不受影响），
    # 线上保持真实退避（1→2→3→5→8s）。
    _wait_scale = 0.001 if _ut() else 1.0

    def _retry_beat(wait):
        """自动重连的等待期：流式先开流（此后再发 HTTP 状态行是坏协议），
        每 3s 一次 SSE 注释心跳，客户端能持续看到「正在自动重连」而非干等/取消。"""
        wait *= _wait_scale
        if not want_stream:
            time.sleep(wait)
            return
        if not wb_stream_open[0]:
            handler._begin_stream()
            wb_stream_open[0] = True
        end = time.time() + wait
        while True:
            rem = end - time.time()
            if rem <= 0:
                return
            try:
                handler._write_chunk(
                    b": upstream busy, auto-reconnecting (%ds)\n\n" % max(1, int(rem)))
            except Exception:
                return                          # 客户端已断开：别再空等
            time.sleep(min(3.0, rem))

    def _wb_beat(rem):
        if not want_stream:
            return
        if not wb_stream_open[0]:
            handler._begin_stream()
            wb_stream_open[0] = True
        handler._write_chunk(b": wbai rate-limited, retrying in %ds\n\n" % max(1, rem))

    while True:
        try:
            if provider == "wbai":
                name, lines = _open_wbai(openai_body)
                model = getattr(_wbai_tls, "model", model)   # auto → 实际上游模型
            elif provider == "officeace":
                name, lines = _open_pool("officeace", openai_body)
            elif provider == "dsflash":
                name, lines = _open_dsflash_pool(openai_body)
            else:
                name, lines = _open_pool("codearts", openai_body)
            break
        except UpstreamError as e:
            _ca_release()
            if provider == "wbai" and e.status in (402, 429, 503) \
                    and _wbai_wait_retry(e, att,
                                         _wb_beat if want_stream else None,
                                         name, model):
                att += 1
                continue
            # 高并发自动重连：瞬时错误自己退避重来（池内换号/换通道由 _open_pool /
            # _open_dsflash_pool 负责，冷却号这轮已被跳过）。额度/鉴权/参数类不重试。
            if _retryable_err(e.status, e.message) and att < AUTO_RETRY_MAX \
                    and time.time() - retry_t0 < AUTO_RETRY_BUDGET:
                att += 1
                wait = _backoff(att)
                srv.log("[proxy:%s] %s 上游瞬时错误（%s %s），%.0fs 后自动重连 %d/%d"
                        % (provider, model, e.status, str(e.message)[:60],
                           wait, att, AUTO_RETRY_MAX))
                _retry_beat(wait)
                if provider == "codearts":
                    if not _ca_acquire():
                        _ca_timeout_reply()
                        return
                    ca_slotted = True
                continue
            if wb_stream_open[0]:
                # 心跳已经开流，只能按 SSE 收尾（再发 HTTP 状态行是坏协议）
                handler._write_chunk((
                    "data: %s\n\ndata: [DONE]\n\n" % json.dumps(
                        {"error": {"message": _client_err_msg(e.status, e.message)[:300],
                                   "type": "rate_limit"}},
                        ensure_ascii=False)).encode("utf-8"))
                return
            srv.log("[proxy:%s] %s acct=%s HTTP%s %s"
                    % (provider, model, name, e.status, e.message[:80]))
            fail_note = "（已自动重连 %d 次仍失败）" % att if att else ""
            handler._send(e.status if e.status >= 400 else 502,
                          {"error": {"message": _client_err_msg(e.status, e.message)
                                     + fail_note,
                                     "type": "upstream_error"}})
            return
        except Exception as e:
            _ca_release()
            # 连接层瞬时错误（读超时/连接重置/分帧中断）同样自动重连；
            # 代码 bug（非 requests 异常）不重试，立即暴露。
            if isinstance(e, requests.exceptions.RequestException) \
                    and att < AUTO_RETRY_MAX \
                    and time.time() - retry_t0 < AUTO_RETRY_BUDGET:
                att += 1
                wait = _backoff(att)
                srv.log("[proxy:%s] %s 连接层异常（%s），%.0fs 后自动重连 %d/%d"
                        % (provider, model, type(e).__name__, wait, att, AUTO_RETRY_MAX))
                _retry_beat(wait)
                if provider == "codearts":
                    if not _ca_acquire():
                        _ca_timeout_reply()
                        return
                    ca_slotted = True
                continue
            srv.log("[proxy:%s] %s acct=%s 异常 %s" % (provider, model, name, str(e)[:80]))
            fail_note = "（已自动重连 %d 次仍失败）" % att if att else ""
            handler._send(502, {"error": {"message": _client_err_msg(502, str(e))[:200]
                                          + fail_note,
                                          "type": "upstream_error"}})
            return

    if want_stream:
        if not wb_stream_open[0]:
            handler._begin_stream()
        usage, n_lines = None, 0
        tail, aborted = [], None          # tail=最近 6 行原文；aborted=写失败的异常名
        try:
            for line in lines:
                n_lines += 1
                if not line:
                    # SSE 标准事件帧间空行透传保帧（上游若发标准事件流）；
                    # CodeArts SSE 无空行，此分支不会走到，行为不变
                    handler._write_chunk(b"\n")
                    continue
                # 流中上游错误帧净化：绝不通透原始 JSON/额度码给客户端，
                # 改成干净 SSE 错误后收尾（首帧错误本已在开流前被池逻辑拦截并重试，
                # 此处兜底：防止流中段突然吐错误帧时把 raw JSON 原样发到对端）。
                if line.startswith("data:") and "[DONE]" not in line:
                    em = _upstream_err_in_line(line)
                    if em is not None:
                        try:
                            handler._write_chunk((
                                "data: %s\n\ndata: [DONE]\n\n" % json.dumps(
                                    {"error": {"message": em,
                                               "type": "upstream_error"}},
                                    ensure_ascii=False)).encode("utf-8"))
                        except Exception:
                            pass
                        srv.log("[proxy:%s] %s 流中上游错误已净化：%s"
                                % (provider, model, em[:40]))
                        break
                if line.startswith("data:") and "[DONE]" not in line:
                    try:              # 透传时顺带抓 usage；上游首个 chunk 会发全 0
                        j = json.loads(line[5:].strip())   # 占位，须跳过取尾部的真实值
                        u = j.get("usage") if isinstance(j, dict) else None
                        if isinstance(u, dict) and (u.get("total_tokens") or 0) > 0:
                            usage = u
                    except Exception:
                        pass
                tail.append(line[:240])
                if len(tail) > 6:
                    tail.pop(0)
                handler._write_chunk((line + "\n").encode("utf-8"))
        except Exception as e:
            # 客户端断开（用户点了停止 / 客户端超时 / 浏览器关页）与上游异常
            # 在客户端侧观感完全不同：前者就是「用户已取消」。必须留痕，
            # 否则只能看到 lines=3 这种既没内容也没原因的结果（2026-10-21）。
            aborted = type(e).__name__
        finally:
            _ca_release()
            if n_lines <= 6:
                # 短响应（含空流收尾）必留原文：客户端看到的「用户已取消」只有
                # 这几行能解释是上游空流、错误帧，还是写到一半被客户端掐断。
                # 放在主审计行之前，保证主行始终是本请求最后一条日志。
                srv.log("[proxy:%s] %s ↑短响应原文(%d 行)：%s"
                        % (provider, model, n_lines, " ｜ ".join(tail) or "（无）"))
            srv.log("[proxy:%s] %s acct=%s stream %.1fs lines=%d%s%s%s"
                    % (provider, model, name, time.time() - t0, n_lines,
                       _usage_str(usage),
                       (" 自动重连%d次" % att) if att else "",
                       (" 客户端断开(%s)" % aborted) if aborted else ""))
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
        handler._send(e.status, {"error": {"message": _client_err_msg(e.status, e.message),
                                           "type": "upstream_error"}})
        return
    except Exception as e:
        _ca_release()
        srv.log("[proxy:%s] %s acct=%s 异常 %s"
                % (provider, model, name, str(e)[:80]))
        handler._send(502, {"error": {"message": _client_err_msg(502, str(e))[:200],
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
