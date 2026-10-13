# -*- coding: utf-8 -*-
"""
cred_store.py —— 凭据存储层（2026-10-13 从 server.py 抽出）
═════════════════════════════════════════════════════════════════════════
职责：凭据 JSON 文件的「读 / 原子写 / 加锁 / 身份指纹 / 键名分配 / 去重落盘」。

为什么单独成模块（对应外部评审 P0-1 / P1-4）：
  server.py 原有 _write_json 是「直接 open 覆盖写」——
  ① 非原子：进程在写一半时崩溃/被杀，凭据文件变成半截 JSON，下次 read_json
     静默吞异常返回空 dict，所有账号"消失"；
  ② 无锁：server 是 ThreadingTCPServer，多线程同时 _cred_store_set 走
     读-改-写循环时，后写的整份覆盖先写的（丢账号）；
     且 allow_reuse_address=True 使 Windows 上多实例可同时 bind 8799，
     跨进程同样存在写竞争。
本模块统一加固：
  - write_json：临时文件 + fsync + os.replace（同卷原子替换，读侧永远看到完整 JSON）
  - locked()：进程内 RLock 互斥 + 跨进程文件锁（Windows msvcrt / POSIX fcntl），
    覆盖整个「读-改-写」周期；同线程可重入（OS 锁只在最外层获取，
    避免 Windows 上同进程第二个句柄锁同一文件自锁死）。
  - read_json：损坏 JSON 不再静默吞——隔离为 *.corrupt-<时间戳> 并写 stderr 留痕。
  - save_cred：键名分配 → 去重 → 写入 整周期持锁，多账号互不覆盖语义不变。

兼容约定（薄壳模式，同 oauth 一期）：
  server.py 以 `from cred_store import ... as _read_json` 保持原符号可达，
  tests/test_core.py 与 openai_proxy.py（srv.CRED_FILES / srv._read_json）零改动。
"""
import os
import sys
import json
import time
import hashlib
import threading
import contextlib

# data_dir 平铺导入（src/ 下无父包，`from .. import` 必然 ImportError；同 platforms 约定）
try:
    import data_dir
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import data_dir

# 敏感字段静态加密（DPAPI）：read/write_json 透明加解密，详见 secret_box.py
try:
    import secret_box
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import secret_box

# 统一异常体系（锁超时等存取层错误 → StorageError）
try:
    from errors import StorageError
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from errors import StorageError

__all__ = [
    "CRED_FILES", "IDENT_FIELDS", "DEFAULT_LABEL",
    "read_json", "write_json", "locked",
    "cred_store_set", "cred_store_remove",
    "ident_of", "wb_match", "dedupe_store", "name_tail",
    "alloc_account_name", "save_cred",
]

# ════════════════════════════════════════════════════════════════════
# 路径与平台元信息
# ════════════════════════════════════════════════════════════════════

WB_LOGIN_FILE           = data_dir.path("wb_login_result.json")
MINIMAX_ACCOUNTS_FILE   = data_dir.path("minimax_accounts.json")
DUMATE_ACCOUNTS_FILE    = data_dir.path("dumate_accounts.json")
LINGXI_ACCOUNTS_FILE    = data_dir.path("lingxi_accounts.json")
TRAE_ACCOUNTS_FILE      = data_dir.path("trae_accounts.json")
QODER_ACCOUNTS_FILE     = data_dir.path("qoder_accounts.json")
ZCODE_ACCOUNTS_FILE     = data_dir.path("zcode_accounts.json")
OFFICEACE_ACCOUNTS_FILE = data_dir.path("officeace_accounts.json")
CODEARTS_ACCOUNTS_FILE  = data_dir.path("codearts_accounts.json")

# 各平台的凭据文件（供「添加 / 删除 / 本地导入」统一寻址）
CRED_FILES = {
    "minimax": MINIMAX_ACCOUNTS_FILE,
    "baidu_dumate": DUMATE_ACCOUNTS_FILE,
    "lingxi": LINGXI_ACCOUNTS_FILE,
    "trae": TRAE_ACCOUNTS_FILE,
    "qoder": QODER_ACCOUNTS_FILE,
    "zcode": ZCODE_ACCOUNTS_FILE,
    "officeace": OFFICEACE_ACCOUNTS_FILE,
    "codearts": CODEARTS_ACCOUNTS_FILE,
}

# 各平台「身份指纹」字段（按优先级）：同一个指纹 = 同一个账号，只是显示名/令牌可能变了
# ⚠ minimax 刻意把 user_id(realUserID) 放在 access_token 之前：客户端会轮换 accessToken
#   （v2 store 的 refreshToken 每刷新一次 generation+1，令牌随之变化），
#   若拿令牌当指纹，同一个人换个令牌就会被当成新账号，多出一张卡片。
IDENT_FIELDS = {
    "minimax": ("user_id", "phone", "access_token"),
    "baidu_dumate": ("cookie",),
    "lingxi": ("wps_sid",),
    "trae": ("user_id", "token"),
    "qoder": ("user_id", "token"),
    "zcode": ("user_id", "token"),
    # ⚠ user_id 优先（2026-10-12 修复）：原来 ak 排最前，而 STS 每次续期/重新导入都换新
    #   AK → 同一账号每次导入都被判成新身份，追加 ·1d5e#2 这类重复卡
    #   （实测：同一 user_id 01a080ec...165be 一次导入一张 ·1d5e、再导入一张 ·1d5e#2）。
    #   user_id 是 IAM 身份主键，稳定不变；phone 是短信登录落盘的稳定字段。
    "officeace": ("user_id", "phone", "ak"),
    "codearts": ("user_id", "phone", "ak"),   # user_id=华为云 domain_id（续期换 AK 后身份不变）
}

# 「粘贴添加」时若用户没填备注名，用这个前缀 + 手机号/ID 尾号 自动起名，
# 避免多个账号全落进同一个键（"MiniMax"）而互相覆盖。
DEFAULT_LABEL = {
    "minimax": "MiniMax", "baidu_dumate": "DuMate", "lingxi": "灵犀",
    "trae": "Trae", "qoder": "Qoder", "zcode": "ZCode",
    "officeace": "OfficeACE", "codearts": "CodeArts",
}


# ════════════════════════════════════════════════════════════════════
# 加锁基建
# ════════════════════════════════════════════════════════════════════

_OP_LOCK = threading.RLock()      # 进程内互斥（可重入），覆盖整个读-改-写周期
_tls = threading.local()          # 每线程锁深度：OS 锁只在最外层拿/放

_LOCK_TIMEOUT = 30.0              # 跨进程锁最长等待（秒）


def _os_lock(lock_path):
    """跨进程独占锁：Windows msvcrt / POSIX fcntl。返回锁文件句柄（不可用时返回 None）。"""
    os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
    deadline = time.time() + _LOCK_TIMEOUT
    while True:
        try:
            f = open(lock_path, "a+b")
            break
        except PermissionError:
            # 实测（2026-10-13）：锁文件刚创建时可被杀软/索引器瞬时占用 → Errno 13。
            # 重试窗口内等它放开；彻底失败则降级为进程内锁（写盘照常，留痕可查）。
            if time.time() > deadline:
                sys.stderr.write("[cred_store] ⚠ 锁文件打开失败（杀软/索引器占用？），"
                                 "本次降级为进程内锁：%s\n" % lock_path)
                return None
            time.sleep(0.05)
    if os.name == "nt":
        import msvcrt
        deadline = time.time() + _LOCK_TIMEOUT
        while True:
            try:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                return f
            except OSError:
                if time.time() > deadline:
                    f.close()
                    raise StorageError("cred_store 跨进程锁等待超时（可能有其它实例长时间占用）：%s"
                                       % lock_path)
                time.sleep(0.05)
    else:
        import fcntl
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        return f


def _os_unlock_close(f):
    try:
        if f is not None and os.name == "nt":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    except OSError:
        pass  # 释放失败只能放弃——文件关闭后锁随句柄消失（Windows）
    finally:
        try:
            if f is not None:
                f.close()
        except OSError:
            pass


@contextlib.contextmanager
def locked(path):
    """凭据文件「读-改-写」周期的统一锁。

    - 进程内：_OP_LOCK 串行化所有线程；
    - 跨进程：path+".lock" 文件锁（只在本线程最外层获取，可重入不冲突）。
    锁序：先 _OP_LOCK 再 OS 锁——同进程第二个线程若先拿 OS 锁，
    Windows 对同文件新句柄的同区域加锁会立刻 LOCK_VIOLATION（即便同进程），
    重试循环会空转到超时；先排队进程内互斥即可避免。
    用法：
        with locked(path):
            data = read_json(path, {})
            data[...] = ...
            write_json(path, data)
    """
    lp = os.path.abspath(path) + ".lock"
    depth = getattr(_tls, "d", 0)
    outer = (depth == 0)
    with _OP_LOCK:
        f = _os_lock(lp) if outer else None
        _tls.d = depth + 1
        try:
            yield
        finally:
            _tls.d = depth
            if outer:
                _os_unlock_close(f)


# ════════════════════════════════════════════════════════════════════
# 原子读写
# ════════════════════════════════════════════════════════════════════

def read_json(path, default):
    """读 JSON 并解密敏感字段；文件不存在/不可读返回 default。

    - 排障铁律：损坏的 JSON 不再静默吞——隔离备份为 *.corrupt-<时间戳> 并写 stderr，
      避免「写一半被杀 → 下次读成空 dict → 所有账号从看板消失」且无任何痕迹。
    - 返回前经 secret_box.decrypt_obj：dpapi: 密文字段透明还原为明文，
      调用方（server / 适配器 / openai_proxy）拿到的永远是可用明文。
    """
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
    except json.JSONDecodeError as e:
        bak = "%s.corrupt-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
        try:
            os.replace(path, bak)
            sys.stderr.write("[cred_store] 凭据文件损坏已隔离: %s -> %s (%s)\n"
                             % (path, bak, e))
        except OSError:
            sys.stderr.write("[cred_store] 凭据文件损坏且隔离失败: %s (%s)\n"
                             % (path, e))
        return default
    except OSError:
        return default
    return secret_box.decrypt_obj(obj)


def write_json(path, data):
    """原子写：临时文件 + fsync + os.replace（同卷原子替换）。

    落盘前经 secret_box.encrypt_obj：SECRET_FIELDS（token/refresh_token/sk/
    sts_token/cookie/wps_sid/dpop 私钥…）自动加密为 dpapi: 密文，
    user_id / phone / ak 等身份与展示字段保持明文（排障/身份判定不受影响）。
    读侧要么看到旧完整内容、要么看到新完整内容，绝无半截 JSON。
    调用方如处于读-改-写周期，应先 `with locked(path):`。
    """
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    data = secret_box.encrypt_obj(data)
    tmp = "%s.%d.tmp" % (path, threading.get_ident())
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


# 兼容别名（历史上 server.py 的下划线私有名，tests / openai_proxy 仍在用）
_read_json = read_json
_write_json = write_json


# ════════════════════════════════════════════════════════════════════
# 键名分配 / 去重 / 落盘（多账号互不覆盖的核心语义）
# ════════════════════════════════════════════════════════════════════

def cred_store_set(path, name, fields):
    """写入/更新一个键。整体持锁，多线程/多进程不互踩。"""
    with locked(path):
        data = read_json(path, {})
        if not isinstance(data, dict):
            data = {}
        data[name] = fields
        write_json(path, data)
    return data


def cred_store_remove(path, name):
    """删除一个键；键不存在返回 False。整体持锁。"""
    with locked(path):
        data = read_json(path, {})
        if not isinstance(data, dict) or name not in data:
            return False
        data.pop(name, None)
        write_json(path, data)
    return True


def ident_of(pid, rec):
    for f in IDENT_FIELDS.get(pid, ()):
        v = str((rec or {}).get(f) or "").strip()
        if v:
            return f, v
    return None


def wb_match(it, name):
    """WorkBuddy 的条目以手机号为身份，允许用户另设备注名（alias）。"""
    return isinstance(it, dict) and (str(it.get("phone") or "") == name
                                     or str(it.get("alias") or "") == name)


def dedupe_store(path, pid, keep_name, rec):
    """写入前清掉「同一身份、换了显示名」的旧条目。
    场景：桌面端把显示名从「一只总柴0623」改成「用户68388451332」，
    再点一次导入，若不去重就会多出一张同名不同键的卡片，账号数被虚增。"""
    with locked(path):
        data = read_json(path, {})
        if not isinstance(data, dict):
            return []
        ident = ident_of(pid, rec)
        if not ident:
            return []
        f, v = ident
        dropped = []
        for nm, old in list(data.items()):
            if nm == keep_name or not isinstance(old, dict):
                continue
            if str(old.get(f) or "").strip() == v:
                data.pop(nm, None)
                dropped.append(nm)
        if dropped:
            write_json(path, data)
    return dropped


def name_tail(rec):
    """取一段能区分账号的短尾号，用于同重名时消歧。
    手机号 / 用户 ID 这类可读标识取末 4 位；cookie、token 这类不透明串取 sha1 前 4 位
    （直接截末 4 位会得到 `EN=2` 这种看不懂的碎片）。"""
    rec = rec or {}
    for f in ("phone", "user_id"):
        v = str(rec.get(f) or "").strip()
        if v:
            return v[-4:]
    for f in ("wps_sid", "cookie", "token", "access_token", "sts_token", "secret",
              "refresh_token", "ak"):
        v = str(rec.get(f) or "").strip()
        if v:
            return hashlib.sha1(v.encode("utf-8")).hexdigest()[:4]
    return ""


def alloc_account_name(path, pid, ideal, rec):
    """为一条凭据挑一个「不会覆盖其他账号」的键名。

    为什么必须做这件事：MiniMax 客户端只有 user / sharedUser 两个登录槽位，
    登录第 3 个号时客户端会把先前槽位顶掉；而两个不同账号的显示名可能完全相同
    （都叫「一只总柴」之类）。此时若直接按名字写入字典，后写的就把前面的**覆盖**掉了
    —— 这正是「登了三个号，后面两个号总是互相覆盖」的根因。

    规则：
      ① 同身份（user_id / phone / token …）已存在 → 沿用旧键名（顺便保住用户改过的备注名）
      ② ideal 未被占用 → 直接用
      ③ ideal 被别的身份占用 → 追加尾号，仍冲突则 #2 #3 …
    """
    with locked(path):
        data = read_json(path, {})
        if not isinstance(data, dict):
            data = {}
        ident = ident_of(pid, rec)

        def _same(nm):
            if not ident:
                return False
            old = data.get(nm)
            return isinstance(old, dict) and str(old.get(ident[0]) or "").strip() == ident[1]

        ideal = (ideal or "").strip()
        if not ideal:
            tail = name_tail(rec)
            ideal = DEFAULT_LABEL.get(pid, pid) + (("·" + tail) if tail else "")

        if ident:
            for nm in data:
                if nm != ideal and _same(nm):
                    return nm          # ① 同一账号已存在 → 沿用旧名，绝不新建
        if ideal not in data or _same(ideal):
            return ideal               # ② 名字空着，或就是同一个账号 → 直接用

        tail = name_tail(rec)
        base = ("%s·%s" % (ideal, tail)) if tail else ideal
        if base not in data or _same(base):
            return base
        i = 2
        while True:
            nm = "%s#%d" % (base, i)
            if nm not in data or _same(nm):
                return nm
            i += 1


def save_cred(pid, fields, ideal="", cred_files=None):
    """按「不覆盖其他账号」的规则落盘一条凭据，返回最终键名。

    键名分配 → 去重 → 写入 整个周期在锁内完成：
    并发导入两个账号时，alloc 与 set 之间不会插入他人的写入。
    """
    cf = cred_files if cred_files is not None else CRED_FILES
    path = cf[pid]
    with locked(path):
        use = alloc_account_name(path, pid, ideal, fields)
        dedupe_store(path, pid, use, fields)
        data = read_json(path, {})
        if not isinstance(data, dict):
            data = {}
        data[use] = fields
        write_json(path, data)
    return use


# 兼容别名（server.py 原私有名）
_cred_store_set = cred_store_set
_cred_store_remove = cred_store_remove
_ident_of = ident_of
_wb_match = wb_match
_dedupe_store = dedupe_store
_name_tail = name_tail
_alloc_account_name = alloc_account_name
_save_cred = save_cred
