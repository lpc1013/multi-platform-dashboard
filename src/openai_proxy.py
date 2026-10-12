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


class UpstreamError(Exception):
    """上游错误（带 HTTP 状态码与响应体），转译给 OpenAI 客户端。"""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = int(status) if status else 502
        self.message = message


def _load_ent():
    """取第一个有凭据的 codearts 账号，只判断凭据是否可用——
    ⚠ 不触发续期/预刷新：代理是热路径（客户端启动就会打 /v1/models），
    在这里拉起浏览器续登会随机弹窗打断人工。续期只留给 run_task（签到时）
    与看板「续期凭据」按钮；过期直接 503 引导用户。"""
    import server as srv   # 延迟导入：取账号文件路径
    path = srv.CRED_FILES.get("codearts")
    d = srv._read_json(path, {}) if path else {}
    if not d:
        raise UpstreamError(503, "CodeArts 账号不存在，请先在看板登录 CodeArts")
    name, ent = next(iter(d.items()))
    if not (ent.get("ak") and ent.get("sk") and ent.get("sts_token")):
        raise UpstreamError(503, "CodeArts 凭据不完整，请先在看板完成登录")
    if cap.expired(ent) is True:
        raise UpstreamError(
            503, "CodeArts 凭证已于 %s 过期，请到看板「🔄 续期凭据」"
                 "（或点一次签到触发自动续期）" % (ent.get("expires_at") or "")[:19])
    return name, ent


def _get(ent, url):
    hdr = cap.sign_headers(ent["ak"], ent["sk"], ent["sts_token"], "GET", url)
    r = requests.get(url, headers=hdr, timeout=30, verify=False,
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
                      timeout=CHAT_TIMEOUT, verify=False, stream=True,
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


def relay(handler, openai_body):
    """主入口：按客户端 stream 开关转发一次对话。异常都转 OpenAI 错误 JSON。
    每次调用落一条审计（模型/账号/耗时/token）到 server.log（看板可见）——
    这是消耗每日免费额度的口子，不记账额度被吃光都查不到去向。"""
    import server as srv
    t0 = time.time()
    name = "?"   # _load_ent 失败（无账号/凭据不完整/已过期）时 log 仍要有值
    model = str(openai_body.get("model") or "deepseek-v4.1-flash")
    want_stream = bool(openai_body.get("stream"))
    try:
        name, ent = _load_ent()
        lines = _chat_stream(ent, openai_body)
    except UpstreamError as e:
        srv.log("[proxy] %s acct=%s HTTP%s %s" % (model, name, e.status, e.message[:80]))
        handler._send(e.status if e.status >= 400 else 502,
                      {"error": {"message": e.message, "type": "upstream_error"}})
        return
    except Exception as e:
        srv.log("[proxy] %s acct=%s 异常 %s" % (model, name, str(e)[:80]))
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
                    continue          # v2 SSE 无空行分隔，直接透传非空行
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
            srv.log("[proxy] %s acct=%s stream %.1fs lines=%d%s"
                    % (model, name, time.time() - t0, n_lines, _usage_str(usage)))
        return

    # 非流式：聚合 SSE → 单个 OpenAI 响应
    content, reasoning, tool_calls = [], [], []
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
                    tool_calls.extend(d["tool_calls"])
                if ch.get("finish_reason"):
                    finish = ch["finish_reason"]
            if j.get("usage"):
                usage = j["usage"]
    except UpstreamError as e:
        handler._send(e.status, {"error": {"message": e.message,
                                           "type": "upstream_error"}})
        return
    except Exception as e:
        handler._send(502, {"error": {"message": str(e)[:200],
                                      "type": "upstream_error"}})
        return

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
    srv.log("[proxy] %s acct=%s %.1fs%s" % (model, name, time.time() - t0,
                                            _usage_str(usage)))
