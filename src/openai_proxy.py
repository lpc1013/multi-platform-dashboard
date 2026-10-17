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


def route_of(model):
    m = str(model or "").strip()
    if m.lower().startswith(WBAI_PREFIX):
        return "wbai"
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


def _record_usage(model, u):
    """按日/按模型聚合 token 用量，原子写 proxy_usage.json。
    结构：{"2026-10-12": {model: {calls, prompt_tokens, completion_tokens}}}
    只含模型名与数字，不含任何凭据/账号信息；写失败静默（不影响对话）。"""
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
            for k in [k for k in d if k < time.strftime(
                    "%Y-%m-%d", time.localtime(time.time() - USAGE_KEEP_DAYS * 86400))]:
                del d[k]                     # 裁掉 30 天前的旧数据
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
    while True:
        try:
            if provider == "teleagent":
                name, ent = _ta_ent()
                lines = tat.chat_stream(ent, openai_body)
            elif provider == "wbai":
                name, ent = _wbai_ent()
                wb_body = dict(openai_body)
                mb = str(wb_body.get("model") or "").strip()
                if mb.lower().startswith(WBAI_PREFIX):
                    wb_body["model"] = mb[len(WBAI_PREFIX):]
                if not wb_body.get("model"):
                    wb_body["model"] = "auto"
                lines = wai.chat_stream(ent, wb_body)
            elif provider == "officeace":
                name, ent = _oa_ent()
                lines = oac.chat_stream(ent, openai_body)
            else:
                name, ent = _load_ent()
                lines = _chat_stream(ent, openai_body)
            break
        except UpstreamError as e:
            _ca_release()
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
            _record_usage(model, usage)
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
        handler._send(e.status, {"error": {"message": e.message,
                                           "type": "upstream_error"}})
        return
    except Exception as e:
        _ca_release()
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
    _record_usage(model, usage)
