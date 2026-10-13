# -*- coding: utf-8 -*-
"""平台适配器共用的小工具。

各平台适配器（platforms/<id>.py）此前各自实现了一份几乎相同的 `_num()`，
用于把接口返回里可能是 str / None / 数字的字段安全地转成 float。
这里集中一份，各模块 `from ._util import to_float` 复用即可。

2026-10-13 新增 dec_cred / enc_cred：适配器自有凭据文件（*_accounts.json、
MiniMax RT 备份/令牌缓存等）的敏感字段静态加密（DPAPI，见 src/secret_box.py）。
约定：**只包我们自己写自己读的文件**——外部应用（MiniMax 客户端 auth.json、
OfficeAce storage.sqlite、Trae/Qoder 本地库）的文件绝不触碰。
"""
import os as _os
import sys as _sys

try:
    import secret_box as _sb
except ImportError:  # 适配器被独立脚本直接运行且 src/ 不在 sys.path 时兜底
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    import secret_box as _sb


def dec_cred(obj):
    """读出的凭据对象解密（dpapi: 前缀字段 → 明文；无前缀/异常原样返回）。"""
    try:
        return _sb.decrypt_obj(obj)
    except Exception:
        return obj


def enc_cred(obj):
    """落盘前的凭据对象加密（SECRET_FIELDS → dpapi: 密文；异常原样返回不阻塞写盘）。"""
    try:
        return _sb.encrypt_obj(obj)
    except Exception:
        return obj


def to_float(v, default=0.0):
    """尽力把 v 转成 float，失败返回 default。

    覆盖 None、空串、"12.3"、12.3 等常见形态；不做千分位/单位解析。
    """
    try:
        return float(v)
    except (TypeError, ValueError):
        return default
