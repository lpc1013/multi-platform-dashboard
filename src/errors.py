# -*- coding: utf-8 -*-
"""
errors.py —— 看板统一异常体系（2026-10-13，对应外部评审 P1-6）
═════════════════════════════════════════════════════════════════════════
此前各模块裸 except + 裸字符串错误，HTTP 层只能 500 + str(e)。
统一后：message 面向用户可展示、code 供前端/日志分类、http_status 供路由层映射。

用法：
    from errors import StorageError, UpstreamError
    raise StorageError("跨进程锁等待超时：%s" % path)
    raise UpstreamError(503, "CodeArts 凭证已过期")

路由层（webapi）约定：
    except DashboardError as e:
        self._send(e.http_status, e.to_dict())
"""
__all__ = ["DashboardError", "StorageError", "AuthError", "PlatformError",
           "UpstreamError", "sanitize_client_message"]

# ── 客户端可见错误净化（2026-10-22 起统一收口）──
# 原始上游响应体（含错误码如 14018 / Credits exhausted / 结构化 JSON）绝不能透传
# 给最终用户：既暴露内部信息又极不友好。所有「发回客户端」的边界都经此函数。
_QUOTA_HINTS = ("14018", "credits exhausted", "credit exhausted",
                "额度", "余额", "quota", "insufficient", "exhaust")
_ERR_CLEAN_QUOTA = ("当前模型额度已用尽（已自动尝试其他账号/模型仍不可用）。"
                    "请在看板为该平台充值额度，或稍后重试。")
_ERR_CLEAN_AUTH = "账号登录态已失效或鉴权失败，请到看板重新导入/登录该平台账号。"
_ERR_CLEAN_GENERIC = "上游服务暂时不可用，已自动重试仍失败，请稍后重试。"


def sanitize_client_message(status, msg):
    """把内部错误文案转成给客户端看的干净中文文案；原始码只进日志不进响应。
    入参 msg 可能仍含 14018 / Credits exhausted / 原始 JSON，出参一律干净。
    纯 Python 异常（不含 JSON/额度/鉴权关键词）原样返回，避免误伤正常提示。"""
    m = str(msg or "")
    low = m.lower()
    # 1) 额度/余额类（14018 / credits exhausted / 额度 / 余额 / quota …）
    if any(h in m or h in low for h in _QUOTA_HINTS):
        return _ERR_CLEAN_QUOTA
    # 2) 鉴权失效（401/403 / token 过期 / 凭据不完整）
    if any(h in m for h in ("鉴权", "登录态", "token 已过期", "凭据", "未登录",
                            "401", "403", "unauthorized", "forbidden")):
        return _ERR_CLEAN_AUTH
    # 3) 原始 JSON / 结构化上游响应：绝不原样透传
    s = m.strip()
    if s[:1] in ("{", "[") or ('"error"' in m and '"msg"' in m) \
            or ('"code"' in m and '"msg"' in m):
        return _ERR_CLEAN_GENERIC
    # 4) 已是干净可读文案（如「CodeArts 上游并发会话已达上限…」）原样保留
    return m



class DashboardError(Exception):
    """看板统一异常基类。"""
    code = "dashboard_error"
    http_status = 500

    def __init__(self, message, *, code=None, http_status=None):
        super().__init__(message)
        self.message = str(message)
        if code is not None:
            self.code = code
        if http_status is not None:
            self.http_status = int(http_status)

    def to_dict(self):
        """前端/HTTP 响应形状（与看板既有 {"ok": false, "error": ...} 兼容）。
        出参 error 经净化，绝不把原始上游 JSON / 额度码透传给客户端。"""
        return {"ok": False,
                "error": sanitize_client_message(self.http_status, self.message),
                "err_code": self.code}


class StorageError(DashboardError):
    """凭据/数据存取层错误（锁超时、文件损坏不可恢复等）。"""
    code = "storage_error"


class AuthError(DashboardError):
    """鉴权失败（API key 不匹配、令牌失效等）。"""
    code = "auth_error"
    http_status = 401


class PlatformError(DashboardError):
    """平台适配器层错误。"""
    code = "platform_error"

    def __init__(self, platform, message, **kw):
        self.platform = platform
        super().__init__("[%s] %s" % (platform, message), **kw)


class UpstreamError(DashboardError):
    """上游（各 AI 平台服务端）错误。保留旧签名 UpstreamError(status, message)，
    openai_proxy / webapi 的 e.status / e.message 用法不变。"""
    code = "upstream_error"

    def __init__(self, status, message):
        super().__init__(message, http_status=int(status) if status else 502)
        self.status = self.http_status
        self.message = self.message
