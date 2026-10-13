# -*- coding: utf-8 -*-
"""
secret_box.py —— 凭据静态加密层（Windows DPAPI / 字段级）
═════════════════════════════════════════════════════════════════════════
对应外部评审 P0-3「Token 明文存储」：此前 *_accounts.json 里 access_token /
refresh_token / sk / cookie 等一旦落盘就是明文，磁盘被读取 = 账号被接管。

设计：
- **字段级**加密（非整文件）：文件结构、user_id / phone / ak（身份指纹）保持明文
  ——「多账号互不覆盖」的身份判定、人工排障直接看文件的工作流都不受影响，
  只有 SECRET_FIELDS 里的敏感值变成 `dpapi:<base64>` 密文。
- **Windows DPAPI**（crypt32 CryptProtectData，CRYPTPROTECT_UI_FORBIDDEN）：
  密钥由 Windows 按「当前用户」派生，同机同用户 transparent 解密；
  拷到别的机器/别的用户 → 解密失败。
- **自描述前缀**：明文原样存（无前缀不加密），读到 `dpapi:` 前缀才解密；
  解密失败**返回原值不抛异常**（令牌失效会以 401 形式暴露在看板，绝不静默吞掉），
  并 stderr 留痕一次。
- **非 Windows**：protect_value 原样返回（macOS Keychain / Linux Secret Service 留 TODO）。

透明接入点：
- cred_store.read_json / write_json（server / openai_proxy / tests 全覆盖）
- platforms/_util.py 的 read_creds / write_creds（各适配器账号文件 IO）
- 其余直连 json.load 的历史代码读到旧明文照常工作 → **惰性迁移**：
  明文字段在下一次写盘时自动变密文；或运行 `python secret_box.py migrate` 立即全量加密。

CLI：
  python secret_box.py status            # 统计 DATA_DIR 各文件的明文/密文字段数
  python secret_box.py migrate [目录]    # 全量加密（每个文件先落 .bak 备份）
"""
import os
import sys
import json
import base64
import ctypes

# 平铺导入兜底（同 data_dir 约定：src/ 下无父包）
try:
    import data_dir
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import data_dir

__all__ = [
    "SECRET_FIELDS", "PREFIX", "is_protected",
    "protect_value", "unprotect_value",
    "encrypt_obj", "decrypt_obj", "migrate_dir", "scan_dir",
]

PREFIX = "dpapi:"

# 需要加密的敏感字段（跨平台并集）。
# ⚠ 刻意不含 user_id / phone / ak / client_name / screen_name：
#   前两者是身份指纹与展示信息；ak（华为云 AccessKeyId）是 officeace/codearts
#   的身份兜底字段且本身不含密钥（机密在 sk / sts_token）。
SECRET_FIELDS = frozenset({
    "access_token", "refresh_token", "token", "secret",
    "sk", "sts_token", "cookie", "wps_sid",
    "dpop_priv_pem", "code_verifier",
    "env_line",           # wb_login_result.json 的 phone:at:rt 复合行，整行是敏感凭据
})

# ════════════════════════════════════════════════════════════════════
# Windows DPAPI（crypt32）
# ════════════════════════════════════════════════════════════════════

_CRYPTPROTECT_UI_FORBIDDEN = 0x1
_local_free = None
_protect = None
_unprotect = None

if os.name == "nt":
    try:
        _crypt32 = ctypes.WinDLL("crypt32")
        _kernel32 = ctypes.WinDLL("kernel32")

        class _DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_uint),
                        ("pbData", ctypes.POINTER(ctypes.c_char))]

        _protect = _crypt32.CryptProtectData
        _unprotect = _crypt32.CryptUnprotectData
        _local_free = _kernel32.LocalFree
    except OSError as _e:      # pragma: no cover
        sys.stderr.write("[secret_box] crypt32 加载失败，回退明文存储：%s\n" % _e)
        _protect = _unprotect = None


def _dpapi_encrypt(plain: bytes) -> bytes:
    blob_in = _DATA_BLOB(len(plain),
                         ctypes.cast(ctypes.create_string_buffer(plain, len(plain)),
                                     ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()
    if not _protect(ctypes.byref(blob_in), None, None, None, None,
                    _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        _local_free(blob_out.pbData)


def _dpapi_decrypt(cipher: bytes) -> bytes:
    blob_in = _DATA_BLOB(len(cipher),
                         ctypes.cast(ctypes.create_string_buffer(cipher, len(cipher)),
                                     ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()
    if not _unprotect(ctypes.byref(blob_in), None, None, None, None,
                      _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        _local_free(blob_out.pbData)


# ════════════════════════════════════════════════════════════════════
# 字段级加解密（值变换 + 对象递归）
# ════════════════════════════════════════════════════════════════════

def is_protected(v) -> bool:
    return isinstance(v, str) and v.startswith(PREFIX)


def protect_value(v):
    """明文 → 'dpapi:<b64>'；空值 / 已加密 / 非 Windows 原样返回。"""
    if not (isinstance(v, str) and v) or is_protected(v):
        return v
    if _protect is None:
        return v
    try:
        raw = _dpapi_encrypt(v.encode("utf-8"))
        return PREFIX + base64.b64encode(raw).decode("ascii")
    except OSError as e:
        sys.stderr.write("[secret_box] 加密失败，本字段保持明文：%s\n" % e)
        return v


def unprotect_value(v):
    """'dpapi:<b64>' → 明文；解密失败返回原值（401 暴露问题，不静默吞）+ stderr 留痕。"""
    if not is_protected(v):
        return v
    if _unprotect is None:
        sys.stderr.write("[secret_box] 非 Windows 平台遇到 DPAPI 密文，无法解密\n")
        return v
    try:
        raw = base64.b64decode(v[len(PREFIX):])
        return _dpapi_decrypt(raw).decode("utf-8")
    except Exception as e:
        sys.stderr.write("[secret_box] ⚠ DPAPI 解密失败（跨机/跨用户恢复的备份？），"
                         "字段按原样返回，对应平台将提示重新登录：%s\n" % e)
        return v


def encrypt_obj(obj):
    """深拷贝并加密对象中所有 SECRET_FIELDS 字段（dict/list 递归）。"""
    return _walk(obj, protect_value)


def decrypt_obj(obj):
    """深拷贝并解密对象中所有带 dpapi: 前缀的字段值（dict/list 递归，前缀无关字段跳过）。"""
    return _walk(obj, unprotect_value)


def _walk(obj, fn):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(v, str) and k in SECRET_FIELDS:
                out[k] = fn(v)
            elif isinstance(v, (dict, list)):
                out[k] = _walk(v, fn)
            else:
                out[k] = v
        return out
    if isinstance(obj, list):
        return [_walk(it, fn) if isinstance(it, (dict, list)) else it for it in obj]
    return obj


# ════════════════════════════════════════════════════════════════════
# 迁移与盘点（CLI）
# ════════════════════════════════════════════════════════════════════

def _iter_cred_files(directory):
    import glob
    yield from glob.glob(os.path.join(directory, "*_accounts.json"))
    yield from glob.glob(os.path.join(directory, "wb_login_result.json"))


def _count(obj):
    """返回 (敏感字段总数, 其中仍明文的数)。"""
    total = plain = 0
    def _w(o):
        nonlocal total, plain
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, str) and k in SECRET_FIELDS and v:
                    total += 1
                    if not is_protected(v):
                        plain += 1
                elif isinstance(v, (dict, list)):
                    _w(v)
        elif isinstance(o, list):
            for it in o:
                _w(it)
    _w(obj)
    return total, plain


def scan_dir(directory=None):
    """逐文件打印 (文件名, 敏感字段数, 仍明文数)。返回统计列表。"""
    directory = directory or data_dir.DATA_DIR
    rows = []
    for p in sorted(_iter_cred_files(directory)):
        try:
            with open(p, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception as e:
            rows.append((os.path.basename(p), -1, -1))
            print("  ✗ %s 读取失败：%s" % (os.path.basename(p), e))
            continue
        total, plain = _count(obj)
        rows.append((os.path.basename(p), total, plain))
        mark = "✓" if plain == 0 else "…"
        print("  %s %-28s 敏感字段 %3d，待加密 %3d" % (mark, os.path.basename(p), total, plain))
    return rows


def migrate_dir(directory=None):
    """全量加密：每文件先落 .bak 备份，再原地重写为加密版。返回 (处理数, 加密字段数)。"""
    directory = directory or data_dir.DATA_DIR
    files, fields = 0, 0
    for p in sorted(_iter_cred_files(directory)):
        try:
            with open(p, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception as e:
            print("  ✗ 跳过 %s：%s" % (p, e))
            continue
        enc = encrypt_obj(obj)
        _, plain = _count(enc)
        if plain == 0 and _count(obj)[1] == 0:
            continue                       # 无需变更
        bak = p + ".bak-preenc"
        if not os.path.exists(bak):
            with open(bak, "w", encoding="utf-8") as fh:
                json.dump(obj, fh, ensure_ascii=False, indent=1)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(enc, fh, ensure_ascii=False, indent=1)
        n = _count(obj)[1]
        files += 1
        fields += n
        print("  ✓ %s（加密 %d 个字段，备份 %s）" % (os.path.basename(p), n, os.path.basename(bak)))
    return files, fields


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    target = sys.argv[2] if len(sys.argv) > 2 else None
    if cmd == "status":
        print("凭据文件加密状态（%s）：" % (target or data_dir.DATA_DIR))
        scan_dir(target)
    elif cmd == "migrate":
        print("全量加密（%s）：" % (target or data_dir.DATA_DIR))
        n_files, n_fields = migrate_dir(target)
        print("完成：%d 个文件，%d 个字段已加密。" % (n_files, n_fields))
    else:
        sys.exit("用法：python secret_box.py [status|migrate] [目录]")
