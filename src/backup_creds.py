# -*- coding: utf-8 -*-
"""
凭据加密备份 / 恢复工具
═══════════════════════
把看板全部敏感文件（各平台 *_accounts.json、删除墓碑、MiniMax RT 备份等）
打包成**单个加密文件**，防磁盘损坏/误删后需要逐平台重新走短信/OAuth 登录。

加密方案：PBKDF2-HMAC-SHA256（600,000 迭代）派生密钥 → Fernet（AES-128-CBC
+ HMAC-SHA256，cryptography 库）。密码不落盘、不进备份文件。

用法（在 src/ 目录下）：
  备份   python backup_creds.py save [输出目录] [-p 密码]
  恢复   python backup_creds.py load 备份文件.creds [-p 密码] [--force]

  - 密码不给 -p 时交互输入（getpass，不回显）；忘了密码 = 备份作废，无法找回
  - 恢复默认拒绝覆盖已存在的凭据文件，加 --force 才覆盖
  - 输出文件名：creds_backup_YYYYMMDD_HHMMSS.creds
"""
import argparse
import base64
import glob
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

try:
    import data_dir as _dd
    _SCAN_DIRS = [_dd.DATA_DIR, HERE]      # 2026-10-12 数据外移后两个位置都扫
except ImportError:
    _SCAN_DIRS = [HERE]

# 收集范围：与 .gitignore 的敏感条目一一对应，新增平台凭据文件时同步这里
PATTERNS = [
    "*_accounts.json",      # 各平台凭据
    "*_deleted.json",       # 删除墓碑
    ".minimax_token.json",  # MiniMax 续期缓存
    "*rt_backup.json",      # MiniMax refresh_token 轮换备份
    "wb_login_result.json", # WorkBuddy 登录结果
]

MAGIC = "dash-creds-v1"


def _collect_files():
    """枚举待备份的敏感文件（去重、只保留存在的；扫 DATA_DIR + src 两处）。"""
    out = []
    for d in _SCAN_DIRS:
        for pat in PATTERNS:
            for p in sorted(glob.glob(os.path.join(d, pat))):
                if p not in out:
                    out.append(p)
    return out


def _derive_key(password, salt):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=600_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _get_password(args):
    if args.password:
        return args.password
    import getpass
    pw = getpass.getpass("备份密码：")
    pw2 = getpass.getpass("再输一遍：")
    if pw != pw2:
        sys.exit("两次输入不一致，中止。")
    if len(pw) < 8:
        sys.exit("密码至少 8 位（忘了密码备份就作废，别用弱密码）。")
    return pw


def cmd_save(args):
    files = _collect_files()
    if not files:
        sys.exit("没有找到任何凭据文件（%s），无从备份。" % "、".join(PATTERNS))
    from cryptography.fernet import Fernet
    pw = _get_password(args)
    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    payload = {"magic": MAGIC, "created": time.strftime("%Y-%m-%d %H:%M:%S"),
               "files": {}}
    for p in files:
        with open(p, "rb") as fh:
            payload["files"][os.path.basename(p)] = \
                base64.b64encode(fh.read()).decode("ascii")
    salt = os.urandom(16)
    ct = Fernet(_derive_key(pw, salt)).encrypt(
        json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    out_path = os.path.join(
        out_dir, "creds_backup_%s.creds" % time.strftime("%Y%m%d_%H%M%S"))
    with open(out_path, "wb") as fh:
        fh.write(salt + b"|" + ct)
    print("已备份 %d 个文件 → %s（%d KB）" %
          (len(files), out_path, os.path.getsize(out_path) // 1024))
    print("请把这个 .creds 文件复制到本机之外（网盘/U盘）才算真备份。")


def cmd_load(args):
    from cryptography.fernet import Fernet, InvalidToken
    pw = args.password or getpass.getpass("备份密码：")
    with open(args.file, "rb") as fh:
        raw = fh.read()
    salt, _, ct = raw.partition(b"|")
    if not salt or not ct:
        sys.exit("文件格式不对（不是本工具生成的 .creds）。")
    try:
        payload = json.loads(Fernet(_derive_key(pw, salt)).decrypt(ct))
    except InvalidToken:
        sys.exit("密码错误或文件损坏（HMAC 校验失败）。")
    if payload.get("magic") != MAGIC:
        sys.exit("文件版本不识别：%r" % payload.get("magic"))
    names = sorted(payload.get("files") or {})
    print("备份创建于 %s，含 %d 个文件：" % (payload.get("created"), len(names)))
    targets = []
    for n in names:
        # 2026-10-12 起恢复到数据目录（读点首候选）；src/ 旧位置仅兜底读
        dst = (_dd.path(n) if _dd else os.path.join(HERE, n))
        flag = ""
        if os.path.exists(dst) and not args.force:
            flag = "  [已存在，跳过——加 --force 覆盖]"
        targets.append((n, dst, flag))
        print("  · %s%s" % (n, flag))
    if all(f for _, _, f in targets):
        print("全部已存在且未指定 --force，什么都没做。")
        return
    for n, dst, flag in targets:
        if flag:
            continue
        with open(dst, "wb") as fh:
            fh.write(base64.b64decode(payload["files"][n]))
        print("已恢复 %s" % n)
    print("完成。重启后端生效。")


def main():
    ap = argparse.ArgumentParser(description="看板凭据加密备份/恢复")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("save", help="备份（加密打包全部凭据文件）")
    s.add_argument("out_dir", nargs="?", default=os.path.join(HERE, "backups"),
                   help="输出目录（默认 src/backups/，已 gitignore）")
    s.add_argument("-p", "--password", help="密码（不给则交互输入）")
    s.set_defaults(fn=cmd_save)
    l = sub.add_parser("load", help="恢复（解密落盘）")
    l.add_argument("file", help=".creds 备份文件路径")
    l.add_argument("-p", "--password", help="密码（不给则交互输入）")
    l.add_argument("--force", action="store_true", help="覆盖已存在的凭据文件")
    l.set_defaults(fn=cmd_load)
    args = ap.parse_args()
    if not args.password and args.cmd == "load":
        import getpass
        args.password = getpass.getpass("备份密码：")
    args.fn(args)


if __name__ == "__main__":
    main()
