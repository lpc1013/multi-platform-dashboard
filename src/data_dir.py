# -*- coding: utf-8 -*-
"""
数据目录外移（2026-10-12）
════════════════════════════════════════════════════════════════════════
凭据与运行产物（各平台 *_accounts.json、删除墓碑、wb_login_result.json、
proxy_usage.json、.minimax_rt_backup.json、.codearts_profile/）原来散落在
src/ 下（与代码混居，仅靠 .gitignore 保护）。本模块把它们统一迁到：

    %LOCALAPPDATA%\\dashboard_analysis\\

要点：
  1) 首次 import 即自动迁移：复制 → 逐字节校验 → 删 src 原件；
     任一步失败则保留 src 原件（读点候选含旧位置，行为不受影响）。
  2) 读点候选顺序：DATA_DIR → src/（兼容迁移失败/老版本残留）。
  3) DASHBOARD_DATA_DIR 环境变量可覆盖目录（单测用临时目录）。
  4) 迁移是幂等的：dst 已存在时跳过，不会覆盖新数据。
"""
import os
import json
import shutil

_HERE = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = (os.environ.get("DASHBOARD_DATA_DIR")
            or os.path.join(os.environ.get("LOCALAPPDATA",
                             os.path.join(os.path.expanduser("~"), "AppData", "Local")),
                            "dashboard_analysis"))

# 需要外移的数据文件（gitignore 内的敏感/运行产物全集）
KNOWN_FILES = (
    # 各平台凭据
    "minimax_accounts.json", "dumate_accounts.json", "lingxi_accounts.json",
    "trae_accounts.json", "qoder_accounts.json", "zcode_accounts.json",
    "officeace_accounts.json", "codearts_accounts.json",
    # 删除墓碑 / 登录结果 / 用量聚合
    "codearts_deleted.json", "wb_login_result.json", "proxy_usage.json",
    # MiniMax 续期备份（含真实 refresh_token）
    ".minimax_rt_backup.json", ".minimax_token.json",
)

MIGRATED = []          # 本次进程实际迁走的文件名（server 启动时打印）
_MIGRATE_DONE = False


def path(name):
    """DATA_DIR 下的规范路径（写点用）。"""
    return os.path.join(DATA_DIR, name)


def candidates(name):
    """读点候选顺序：DATA_DIR → src/（旧位置兜底）。"""
    return [path(name), os.path.join(_HERE, name)]


def _migrate(src_dir=None):
    """一次性把 src/ 下的数据文件搬到 DATA_DIR。幂等、失败不丢数据。
    src_dir 参数仅供单测注入临时目录，生产路径恒为模块所在目录。"""
    global _MIGRATE_DONE
    if _MIGRATE_DONE:
        return
    _MIGRATE_DONE = True
    src_dir = src_dir or _HERE
    if DATA_DIR == src_dir:                    # 防御：环境变量误指到 src 自身
        return
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except OSError as e:
        print("⚠ 数据目录 %s 创建失败，数据仍用 src/ 旧位置：%s" % (DATA_DIR, e))
        return
    for name in KNOWN_FILES:
        src = os.path.join(src_dir, name)
        dst = path(name)
        if not os.path.isfile(src) or os.path.exists(dst):
            continue                           # 没得迁 / 已经迁过（不覆盖新数据）
        try:
            shutil.copy2(src, dst)
            with open(src, "rb") as a, open(dst, "rb") as b:
                if a.read() != b.read():
                    raise ValueError("复制后内容不一致")
            os.remove(src)                     # 校验通过才删原件
            MIGRATED.append(name)
        except Exception as e:
            try:
                os.remove(dst)                 # 回滚半成品，保留 src 原件
            except OSError:
                pass
            print("⚠ 数据外移失败（保留原文件 %s）：%s" % (name, e))


def migrate_profile_dir(name=".codearts_profile"):
    """浏览器持久 profile 目录整体搬迁（目录版迁移，同幂等策略）。"""
    src = os.path.join(_HERE, name)
    dst = path(name)
    if not os.path.isdir(src) or os.path.isdir(dst):
        return False
    try:
        shutil.copytree(src, dst)
        # 抽验：文件数一致才删原件
        n_src = sum(len(f) for _, _, f in os.walk(src))
        n_dst = sum(len(f) for _, _, f in os.walk(dst))
        if n_src != n_dst:
            raise ValueError("文件数不一致（%d vs %d）" % (n_src, n_dst))
        shutil.rmtree(src)
        MIGRATED.append(name + "/")
        return True
    except Exception as e:
        try:
            shutil.rmtree(dst)
        except OSError:
            pass
        print("⚠ 数据外移失败（保留原目录 %s）：%s" % (name, e))
        return False


def read_json(name, default=None):
    """按候选顺序读 JSON（DATA_DIR 优先）。"""
    for p in candidates(name):
        if os.path.isfile(p):
            try:
                with open(p, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
    return default


_migrate()
