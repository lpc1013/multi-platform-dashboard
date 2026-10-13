# -*- coding: utf-8 -*-
"""凭据身份回填 + 重复卡合并 维护脚本（2026-10-13）
═════════════════════════════════════════════════════════════════════════
背景：baidu_dumate 原以整串 cookie、lingxi 原以 wps_sid 当身份指纹（IDENT_FIELDS
首位），两者每次登录必换 → 每次网页登录/导入都生成重复卡（实测 3 账号变 6 卡）。
代码修复：IDENT_FIELDS 改 user_id 优先 + 落盘路径回填稳定指纹（account_service.ensure_identity）。
本脚本：给存量数据补 user_id，并把「同一指纹的多张卡」合并回一张。

用法（在 src/ 下）：
    python backfill_identity.py                    # 报告模式：只看不写
    python backfill_identity.py --apply            # 回填 user_id（幂等，写前备份）
    python backfill_identity.py --apply --merge    # 回填 + 合并重复卡（写前备份）

合并规则：
  · 分组：按回填后的稳定指纹（ident_of 首位非空字段值）；
  · 保留键名：优先 via_local 的键名（用户既有命名）→ 无「·尾号」的键名 → 最先出现者；
  · 保留内容：组内**最后写入**的那条（字典序 = 落盘顺序，最后登录的凭据最新）；
  · 任何写盘前先备份为 <file>.bak-dedupe-<时间戳>。
"""
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# ⚠ registry.py 会把 sys.argv[1] 当服务端口——先摘掉命令行开关再导入链，
#   否则 `--apply` 被解析成端口直接 ValueError（实测坑，2026-10-13）。
_FLAGS = [a for a in sys.argv[1:] if a.startswith("-")]
_ARGS = [a for a in sys.argv[1:] if not a.startswith("-")]
sys.argv = [sys.argv[0]]

import cred_store as cs
from cred_store import ensure_identity, dumate_stable_uid


def _is_phone_key(name):
    return bool(re.fullmatch(r"1\d{10}", str(name or "").strip()))


def _has_tail(name):
    """键名是否带自动消歧尾号（<名>·<尾4> / <名>·<尾4>#2）。"""
    return "·" in str(name or "")


def load(pid):
    path = cs.CRED_FILES[pid]
    data = cs.read_json(path, {})
    if not isinstance(data, dict):
        raise SystemExit("%s 内容不是 dict，拒绝处理" % path)
    return path, data


def backfill(pid, data):
    """回填稳定指纹 + phone（就地修改，返回变更条数）。"""
    changed = 0
    for nm, rec in data.items():
        if not isinstance(rec, dict):
            continue
        before = dict(rec)
        ensure_identity(pid, rec)
        # dumate：user_id 语义统一为 bce-login-accountid（老网页记录存过反查 UUID，
        # 与 acctid 对不上 → 强制重写，保证两条落盘路径指纹同源可比）
        if pid == "baidu_dumate":
            uid = dumate_stable_uid(rec.get("cookie"))
            if uid and rec.get("user_id") != uid:
                rec["user_id"] = uid
        # lingxi：键名是 11 位手机号的本地导入条目补 phone（续期预填要用）
        if pid == "lingxi" and not str(rec.get("phone") or "").strip() \
                and _is_phone_key(nm):
            rec["phone"] = nm.strip()
        if rec != before:
            changed += 1
            print("  [回填] %s: user_id=%s phone=%s"
                  % (nm, rec.get("user_id"), rec.get("phone") or "-"))
    return changed


def groups_by_identity(pid, data):
    """按稳定指纹分组：{uid: [键名,…]}（键名保持落盘顺序）。"""
    out = {}
    for nm, rec in data.items():
        if not isinstance(rec, dict):
            continue
        ident = cs.ident_of(pid, rec)
        if not ident:
            out.setdefault("<无指纹>", []).append(nm)
            continue
        out.setdefault("%s=%s" % ident, []).append(nm)
    return out


def pick_keep_name(names, data):
    """保留键名：via_local 优先 → 无尾号 → 最先出现。"""
    for nm in names:
        if isinstance(data[nm], dict) and data[nm].get("via_local"):
            return nm
    for nm in names:
        if not _has_tail(nm):
            return nm
    return names[0]


def merge(pid, data):
    """合并同指纹多卡：返回 (新字典, 合并动作列表)。"""
    out = {}
    actions = []
    for ident, names in groups_by_identity(pid, data).items():
        if len(names) == 1:
            out[names[0]] = data[names[0]]
            continue
        keep = pick_keep_name(names, data)
        newest = names[-1]          # 最后写入 = 最新凭据
        out[keep] = data[newest]
        dropped = [nm for nm in names if nm != keep]
        actions.append("「%s」← %s（指纹 %s，内容取最后写入的「%s」）"
                       % (keep, ", ".join("删「%s」" % d for d in dropped), ident, newest))
    return out, actions


def main():
    apply_mode = "--apply" in _FLAGS
    do_merge = "--merge" in _FLAGS
    pids = _ARGS or ["baidu_dumate", "lingxi"]
    for pid in pids:
        path, data = load(pid)
        print("=== %s（%s）：%d 条" % (pid, os.path.basename(path), len(data)))
        changed = backfill(pid, data)
        if changed:
            print("  回填 %d 条" % changed)
        for ident, names in sorted(groups_by_identity(pid, data).items()):
            flag = "  ⚠ 重复组" if len(names) > 1 else "  组"
            print("%s %s: %s" % (flag, ident, names))
        if not apply_mode:
            print("  （报告模式，未写盘）")
            continue
        if changed or do_merge:
            bak = "%s.bak-dedupe-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
            cs.write_json(bak, data)
            print("  已备份 → %s" % os.path.basename(bak))
        if changed:
            with cs.locked(path):
                cs.write_json(path, data)
        if do_merge:
            merged, actions = merge(pid, data)
            for a in actions:
                print("  [合并] %s" % a)
            if actions:
                with cs.locked(path):
                    cs.write_json(path, merged)
        after = cs.read_json(path, {})
        print("  完成：现 %d 条" % len(after))


if __name__ == "__main__":
    main()
