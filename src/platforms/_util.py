# -*- coding: utf-8 -*-
"""平台适配器共用的小工具。

各平台适配器（platforms/<id>.py）此前各自实现了一份几乎相同的 `_num()`，
用于把接口返回里可能是 str / None / 数字的字段安全地转成 float。
这里集中一份，各模块 `from ._util import to_float` 复用即可。
"""


def to_float(v, default=0.0):
    """尽力把 v 转成 float，失败返回 default。

    覆盖 None、空串、"12.3"、12.3 等常见形态；不做千分位/单位解析。
    """
    try:
        return float(v)
    except (TypeError, ValueError):
        return default
