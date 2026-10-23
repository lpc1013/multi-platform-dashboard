"""果办「登录流程 ↔ 刷新周期」互斥（2026-10-22 用户四连问题最后一环的根因修复）。

背景（本机实证）：
· 短信登录强依赖 GUI 客户端在跑 —— officeclaw:// 回调只能由 GUI 进程接收
  （OS 按 HKCR\\officeclaw 投递给 OfficeAce.exe，裸 ServiceHost 永远拿不到 code）；
· 而刷新周期（read_account / run_task → platforms.officeace.try_refresh）会
  起停裸 ServiceHost，与 GUI 的 native service host 租约互斥，把客户端顶退
  （startup-failure.json: "Another OfficeAce native service host is already
  running for this installation"，13:49 实证）→ 用户既打不开客户端，登录流程的
  authorize 也会撞上服务起停窗口报 HTTP 0。

因此两者必须互斥：
· 登录流程进行中（含等回调的整段时间），刷新周期不碰本地服务；
· 同一时间只允许一个登录流程（并发点击会互相杀服务）。
"""
import threading

# 同一时间只允许一个果办登录/拉起流程。注意：begin 与 end 可能在不同线程
# （请求线程 begin、job 线程 end）——threading.Lock 不校验 owner，正好适用。
_flow_lock = threading.Lock()
# 登录流程进行中（含轮询等 officeclaw:// 回调的整段时间）
_active = threading.Event()


def login_running():
    """刷新周期用：登录流程是否正在进行。"""
    return _active.is_set()


def begin_login():
    """尝试进入登录流程。返回 False = 已有流程在跑，调用方应拒绝新请求。"""
    if not _flow_lock.acquire(blocking=False):
        return False
    _active.set()
    return True


def end_login():
    """结束登录流程（幂等；job 线程结束时调用）。"""
    _active.clear()
    try:
        _flow_lock.release()
    except RuntimeError:
        pass
