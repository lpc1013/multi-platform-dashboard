# -*- coding: utf-8 -*-
"""oauth 跨平台共享小助手（二期拆分自 oauth_login.py 各平台段，2026-10-13）。

- _qoder_has_captcha：阿里云滑块/图片验证码探测（qoder 首创，zcode/lingxi/hw/trae 复用）
- _trae_find_token：嵌套 JSON 里按键名捞 token（trae 首创，codearts 复用）
- _codearts_debug + 日志常量：带时间戳的调试留痕（HW 共享段借用作通用日志器）"""
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


# ═══════════════ 调试留痕（原 CodeArts 段，HW 共享段复用）═══════════════
_CODEARTS_DEBUG_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "codearts_oauth_debug.log")


_CODEARTS_DEBUG_LOCK = threading.Lock()


def _codearts_debug(tag, msg):
    """CodeArts OAuth 关键事件落盘。控制台 stdout 随窗口丢失，文件不会——
    授权后拿不到令牌时（如 2026-10-09 卡「已提交验证码」），这是唯一能回放的证据。
    ⚠ 回调服务器线程与轮询线程都会写这里，必须持锁（否则行内交叉断行，2026-10-12 实证）。"""
    try:
        with _CODEARTS_DEBUG_LOCK:
            with open(_CODEARTS_DEBUG_LOG, "a", encoding="utf-8") as fh:
                fh.write("%s [%s] %s\n" % (time.strftime("%m-%d %H:%M:%S"), tag,
                                           str(msg)[:400].replace("\n", " ")))
    except Exception:
        pass


def _qoder_has_captcha(ctx):
    """阿里云滑块 / 图片验证码是否出现（尽力而为，用于提示用户去窗口操作）。"""
    try:
        for pg in ctx.pages:
            try:
                if pg.evaluate(
                        "() => !!(document.querySelector('[id*=\\'captcha\\'],[class*=\\'captcha\\'],"
                        ".nc-container') || document.querySelector('iframe[src*=\\'captcha\\']'))"):
                    return True
            except Exception:
                pass
            for f in pg.frames:
                u = (f.url or "")
                if "captcha" in u or "punish" in u:
                    return True
    except Exception:
        pass
    return False


def _trae_find_token(node, keys):
    """在响应里找 token 字符串（**大小写不敏感**）。

    ⚠⚠ 2026-10-08 实地取证（真凶 #2）：客户端成功响应的字段名是 **`Token`**（首字母大写）
      {"Result":{"BoundDeviceID":"616l754j8orle1","ClientID":"ono9krqynydwx5",
                 "DeviceBindStatus":"BOUND","RefreshExpireAt":…,"RefreshToken":"…",
                 "Token":"…","TokenExpireAt":…,"TokenExpireDuration":…,"UserJwt":"…"}}
    旧实现 `node.get(k)` 是**精确 key 匹配（大小写敏感）**，key 表里只有小写 `"token"`
    → **找不到 `Token`** → 误判「无 token」→ 把成功响应当错误抛给用户。
    """
    want = set(str(k).lower() for k in keys)
    if isinstance(node, dict):
        # ① 同层大小写不敏感匹配（先精确后忽略大小写，避免误取嵌套值）
        for k, v in node.items():
            if isinstance(v, str) and v and str(k).lower() in want:
                return v
        # ② 再递归子层
        for v in node.values():
            r = _trae_find_token(v, keys)
            if r:
                return r
    elif isinstance(node, list):
        for it in node:
            r = _trae_find_token(it, keys)
            if r:
                return r
    return None
