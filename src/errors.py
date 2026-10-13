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
__all__ = ["DashboardError", "StorageError", "AuthError", "PlatformError", "UpstreamError"]


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
        """前端/HTTP 响应形状（与看板既有 {"ok": false, "error": ...} 兼容）。"""
        return {"ok": False, "error": self.message, "err_code": self.code}


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
