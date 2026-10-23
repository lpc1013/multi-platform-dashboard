# -*- coding: utf-8 -*-
"""
registry.py —— 平台注册表与端口配置（2026-10-13 从 server.py 抽出）
导入即加载 platforms/ 下各适配器（加载失败的平台打印警告并跳过，不拖垮后端）。
"""
import os
import sys
import importlib

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# 服务端口（python server.py 9000 可覆盖）
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8799

PLATFORM_IDS = ["workbuddy", "minimax", "baidu_dumate", "lingxi", "trae",
                "qoder", "zcode", "officeace", "codearts", "teleagent", "workbuddy_ai",
                "tabbit", "doubao"]

# 支持「从本地客户端导入」的平台
LOCAL_IMPORT_PLATFORMS = ("baidu_dumate", "minimax", "lingxi", "trae",
                          "qoder", "zcode", "officeace", "codearts", "teleagent",
                          "workbuddy_ai", "tabbit")

PLATFORMS = {}
for _pid in PLATFORM_IDS:
    try:
        _mod = importlib.import_module("platforms." + _pid)
        PLATFORMS[_pid] = _mod
    except Exception as e:
        print("⚠ 平台适配器加载失败 %s：%s" % (_pid, e))
