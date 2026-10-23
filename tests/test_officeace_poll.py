# -*- coding: utf-8 -*-
"""OfficeACE 果办 2026-10-22 四连问题修复单测（不发起任何真实网络/进程操作）。

覆盖：
  1. _officeace_poll_code：官方 /api/login/oauth/poll 的返回解析
     （202+11000009=未就绪继续等；200+code=拿到；400=坏 state；0=连接失败）
  2. _officeace_relay_file_params：activation relay 中转文件的新鲜度门槛
  3. _officeace_kill_orphan_host：GUI 在跑时绝不动服务；tasklist 全盘扫 +
     状态文件双通道杀孤儿；pid 校验不过不误杀
  4. _officeace_host_pids / _officeace_port_free：CSV 解析与端口释放判定
  5. _officeace_autostart：**只拉 GUI 不兜底裸 host**（officeclaw:// 回调只能由
     GUI 接收）；重试 3 次；单实例锁秒退≠失败；主实例 API 不就绪的明确失败
  6. officeace_guard：登录互斥闸（begin/end/login_running）
  7. start_officeace_sms_job：并发拒绝；失败路径还闸
  8. _run_officeace_sms_job_inner：授权前 API 掉线快速失败
运行：python -m unittest tests.test_officeace_poll   （用 pythoncore-3.14-64）
"""
import json
import os
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.argv = [sys.argv[0]]
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import oauth_officeace as oa  # noqa: E402
import officeace_guard  # noqa: E402


class _FakeTime:
    """替身 clock：让轮询循环瞬间跑完，测试不真睡。"""
    def __init__(self):
        self.t = 1000.0

    def time(self):
        self.t += 0.05
        return self.t

    def sleep(self, s):
        self.t += s


class _FakeProc:
    def __init__(self, args, exit_after=None):
        self.args = args
        self._exit_after = exit_after
        self.returncode = None

    def poll(self):
        if self._exit_after is not None:
            self._exit_after -= 1
            if self._exit_after < 0:
                self.returncode = 0
        return self.returncode


class TestPollCode(unittest.TestCase):
    """_officeace_poll_code 的返回结构解析（2026-10-22 裸 host 实证口径）。"""

    def test_202_not_ready_is_silent(self):
        with mock.patch.object(oa, "_officeace_api",
                               return_value=(202, {"error_code": "AgentArts.11000009",
                                                   "error_msg": "not ready"})):
            code, note = oa._officeace_poll_code("https://127.0.0.1:3004", "a" * 32)
        self.assertIsNone(code)
        self.assertEqual(note, "")            # 正常未就绪不当异常报

    def test_200_with_code(self):
        with mock.patch.object(oa, "_officeace_api",
                               return_value=(200, {"code": "CLAW123"})):
            code, note = oa._officeace_poll_code("https://b", "a" * 32)
        self.assertEqual(code, "CLAW123")

    def test_400_bad_state(self):
        with mock.patch.object(oa, "_officeace_api",
                               return_value=(400, {"error_code": "AgentArts.11000004"})):
            code, note = oa._officeace_poll_code("https://b", "__bogus__")
        self.assertIsNone(code)
        self.assertIn("400", note)

    def test_conn_failure(self):
        with mock.patch.object(oa, "_officeace_api",
                               return_value=(0, {"error": "refused"})):
            code, note = oa._officeace_poll_code("https://b", "a" * 32)
        self.assertIsNone(code)
        self.assertIn("连接失败", note)

    def test_no_state(self):
        code, note = oa._officeace_poll_code("https://b", "")
        self.assertIsNone(code)
        self.assertIn("无 state", note)


class TestRelayFile(unittest.TestCase):
    """%TEMP%\\officeclaw-toast-activation.txt 中转文件兜底。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _write(self, text, age=0):
        p = os.path.join(self.tmp, "officeclaw-toast-activation.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        if age:
            old = time.time() - age
            os.utime(p, (old, old))
        return p

    def test_fresh_file_parsed(self):
        p = self._write('{"url":"officeclaw://oauth/callback?code=RELAY1&state=RELAYST1"}')
        with mock.patch.dict(os.environ, {"TEMP": self.tmp}):
            code, st = oa._officeace_relay_file_params()
        self.assertEqual((code, st), ("RELAY1", "RELAYST1"))

    def test_stale_file_ignored(self):
        self._write('officeclaw://oauth/callback?code=OLD&state=OLDST', age=3600)
        with mock.patch.dict(os.environ, {"TEMP": self.tmp}):
            code, st = oa._officeace_relay_file_params()
        self.assertEqual((code, st), (None, None))

    def test_missing_file(self):
        with mock.patch.dict(os.environ, {"TEMP": self.tmp}):
            self.assertEqual(oa._officeace_relay_file_params(), (None, None))

    def test_file_without_callback(self):
        self._write("hello world")
        with mock.patch.dict(os.environ, {"TEMP": self.tmp}):
            self.assertEqual(oa._officeace_relay_file_params(), (None, None))


class TestHostPidsAndPort(unittest.TestCase):
    """tasklist CSV 解析与端口释放判定（2026-10-22 二次修复新增）。"""

    def test_csv_parsing(self):
        out = (b'"OfficeAceServiceHost.exe","9140","Console","1","42,368 K"\r\n'
               b'"OfficeAceServiceHost.exe","12345","Console","1","10,000 K"\r\n')

        class _R:
            stdout = out
        with mock.patch.object(oa.subprocess, "run", lambda *a, **k: _R()):
            self.assertEqual(oa._officeace_host_pids(), [9140, 12345])

    def test_no_match_info_line(self):
        class _R:
            stdout = (b"INFO: No tasks are running which match the "
                      b"specified criteria.\r\n")
        with mock.patch.object(oa.subprocess, "run", lambda *a, **k: _R()):
            self.assertEqual(oa._officeace_host_pids(), [])

    def test_tasklist_explodes_returns_empty(self):
        def _boom(*a, **k):
            raise OSError("tasklist 不在")
        with mock.patch.object(oa.subprocess, "run", _boom):
            self.assertEqual(oa._officeace_host_pids(), [])

    def test_port_free_detects_listener(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        try:
            self.assertFalse(oa._officeace_port_free(port))   # 有监听=没释放
        finally:
            s.close()
        self.assertTrue(oa._officeace_port_free(port))        # 关了=已释放


class TestKillOrphanHost(unittest.TestCase):
    """孤儿 host 清理的安全闸（双通道：tasklist 全盘扫 + 状态文件兜底）。"""

    def setUp(self):
        oa._OFFICEACE_SPAWNED = False

    def _fake_run(self, calls):
        def _run(args, **kw):
            calls.append(args)

            class _R:
                stdout = b""
                returncode = 0
            return _R()
        return _run

    def test_gui_running_never_kills(self):
        with mock.patch.object(oa, "_officeace_gui_running", return_value=True), \
                mock.patch.object(oa, "_officeace_host_pids") as pids, \
                mock.patch("subprocess.run") as srun:
            self.assertEqual(oa._officeace_kill_orphan_host(), [])
        pids.assert_not_called()
        srun.assert_not_called()

    def test_pid_mismatch_never_kills(self):
        """state 里的 pid 不是 ServiceHost（pid 复用）→ 绝不误杀无辜进程；
        但该状态文件已陈旧（原 host 已死），删掉反而有助 GUI 启动。"""
        with tempfile.TemporaryDirectory() as td:
            st = os.path.join(td, "runtime-state.json")
            with open(st, "w", encoding="utf-8") as f:
                json.dump({"HostPid": 4242}, f)
            calls = []
            with mock.patch.object(oa, "_officeace_gui_running", return_value=False), \
                    mock.patch.object(oa, "_officeace_host_pids", return_value=[]), \
                    mock.patch.object(oa, "_officeace_runtime_state_paths",
                                      return_value=[st]), \
                    mock.patch.object(oa, "_officeace_pid_is_host",
                                      return_value=False), \
                    mock.patch.object(oa.subprocess, "run", self._fake_run(calls)):
                self.assertEqual(oa._officeace_kill_orphan_host(), [])
            self.assertEqual(calls, [])
            self.assertFalse(os.path.exists(st))  # 陈旧 state 清掉；进程没动

    def test_tasklist_channel_kills_all(self):
        """tasklist 扫到多个孤儿 host → 全杀（不依赖状态文件，1.4.1 状态文件会迁走）。"""
        calls = []
        with mock.patch.object(oa, "_officeace_gui_running", return_value=False), \
                mock.patch.object(oa, "_officeace_host_pids", return_value=[111, 222]), \
                mock.patch.object(oa, "_officeace_runtime_state_paths", return_value=[]), \
                mock.patch.object(oa.subprocess, "run", self._fake_run(calls)):
            killed = oa._officeace_kill_orphan_host()
        self.assertEqual(killed, [111, 222])
        self.assertEqual(len([c for c in calls if "taskkill" in c]), 2)

    def test_state_channel_adds_pid_not_in_tasklist(self):
        """tasklist 漏视角（权限/瞬时）→ 状态文件 HostPid 兜底，校验过才杀。"""
        calls = []
        with tempfile.TemporaryDirectory() as td:
            st = os.path.join(td, "runtime-state.json")
            with open(st, "w", encoding="utf-8") as f:
                json.dump({"HostPid": 777}, f)
            with mock.patch.object(oa, "_officeace_gui_running", return_value=False), \
                    mock.patch.object(oa, "_officeace_host_pids", return_value=[]), \
                    mock.patch.object(oa, "_officeace_runtime_state_paths",
                                      return_value=[st]), \
                    mock.patch.object(oa, "_officeace_pid_is_host",
                                      return_value=True), \
                    mock.patch.object(oa.subprocess, "run", self._fake_run(calls)):
                killed = oa._officeace_kill_orphan_host()
            self.assertEqual(killed, [777])
            self.assertTrue(any("taskkill" in c for c in calls))
            self.assertFalse(os.path.exists(st))   # 状态文件必须一并清掉


class _PopenRecorder:
    """记录 spawn 顺序的 Popen 替身；按 exe 名给出进程存活性。

    alive 支持两种形式：
      dict: kind -> bool（全部 spawn 同命运）
      dict: kind -> list[bool]（按 spawn 序号逐个指定，越界默认 True）
    同时暴露 gui_running()：替身版 _officeace_gui_running —— 只有 spawn 过
    且未秒退的 GUI 才算"在跑"（与现实一致：进程在跑才收得到 officeclaw://）。"""
    def __init__(self, alive=None):
        self.spawns = []          # [(args, kind)]
        self.alive = alive or {}  # kind -> bool | list[bool]
        self._gui_alive = False

    def __call__(self, args, **kw):
        exe = os.path.basename(str(args[0]))
        kind = "gui" if exe.lower() == "officeace.exe" else "host"
        idx = len(self.spawns)
        self.spawns.append((args, kind))
        a = self.alive.get(kind, True)
        if isinstance(a, list):
            a = a[idx] if idx < len(a) else True
        if kind == "gui":
            self._gui_alive = bool(a)
        if a:
            return _FakeProc(args)
        return _FakeProc(args, exit_after=0)

    def gui_running(self, *a, **kw):
        return self._gui_alive


class TestAutostartGuiOnly(unittest.TestCase):
    """autostart 只拉 GUI（2026-10-22 二次修复：裸 host 拿不到 officeclaw:// 回调，
    兜底=保证 620s 超时，已删除）。"""

    def setUp(self):
        oa._OFFICEACE_SPAWNED = False
        self.ft = _FakeTime()

    def _probe_seq(self, results):
        it = iter(results)

        def _probe(timeout=5):
            try:
                return next(it)
            except StopIteration:
                return (True, "https://127.0.0.1:3004", {})
        return _probe

    def _common(self, probe, gui_running, rec, kill=None):
        return [
            mock.patch.object(oa, "_officeace_probe", probe),
            mock.patch.object(oa, "_officeace_gui_running", gui_running),
            mock.patch.object(oa, "_officeace_kill_orphan_host",
                              return_value=kill if kill is not None else []),
            mock.patch.object(oa, "_officeace_port_free", return_value=True),
            mock.patch.object(oa, "_officeace_exe_path",
                              return_value=r"E:\OfficeAce\OfficeAce.exe"),
            mock.patch.object(oa.subprocess, "Popen", rec),
            mock.patch.object(oa.time, "sleep", self.ft.sleep),
            mock.patch.object(oa.time, "time", self.ft.time),
        ]

    def test_already_running_returns_immediately(self):
        rec = _PopenRecorder()
        patches = self._common(lambda timeout=5: (True, "https://x", {}),
                               lambda: True, rec)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7]:
            ok, base, note = oa._officeace_autostart(wait=20)
        self.assertTrue(ok)
        self.assertEqual(rec.spawns, [])          # 什么都不拉
        self.assertIn("正在运行", note)

    def test_gui_spawned_no_bare_host_ever(self):
        """probe 失败 → 只拉 GUI → API 就绪：绝不直启裸 host。"""
        rec = _PopenRecorder()
        probe = self._probe_seq([(False, "", {})] * 3 + [(True, "https://x", {})])
        patches = self._common(probe, rec.gui_running, rec)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7]:
            ok, base, note = oa._officeace_autostart(wait=20)
        self.assertTrue(ok)
        self.assertEqual([k for _, k in rec.spawns], ["gui"])   # 只拉了客户端
        self.assertFalse(oa._OFFICEACE_SPAWNED)
        self.assertIn("客户端", note)

    def test_retry_after_gui_exit(self):
        """GUI 首启即退（无其他实例）→ 清孤儿+等端口后重试 → 第二次成功。"""
        rec = _PopenRecorder(alive={"gui": [False, True]})
        state = {"n": 0}

        def _probe(timeout=5):
            state["n"] += 1
            # 第 3 次探测起（第二次 attempt 的 GUI 已拉起）API 就绪
            if state["n"] >= 3:
                return (True, "https://127.0.0.1:3004", {})
            return (False, "", {})
        patches = self._common(_probe, rec.gui_running, rec)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7]:
            ok, base, note = oa._officeace_autostart(wait=20)
        self.assertTrue(ok)
        self.assertEqual([k for _, k in rec.spawns], ["gui", "gui"])
        self.assertIn("第2次尝试", note)

    def test_single_instance_lock_waits_for_main(self):
        """我们的 GUI 被单实例锁秒退、但主实例在跑 → 等主实例的 API，不算失败。"""
        rec = _PopenRecorder(alive={"gui": False})
        probe = self._probe_seq([(False, "", {})] * 2 + [(True, "https://x", {})])
        patches = self._common(probe, lambda: True, rec)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7]:
            ok, base, note = oa._officeace_autostart(wait=20)
        self.assertTrue(ok)
        self.assertEqual([k for _, k in rec.spawns], ["gui"])
        self.assertIn("本就在运行", note)

    def test_main_instance_api_never_ready_fails_clearly(self):
        """主实例在跑但 API 一直不就绪 → 明确失败并指路，不重试不抢启。"""
        rec = _PopenRecorder(alive={"gui": False})
        patches = self._common(lambda timeout=5: (False, "", {}),
                               lambda: True, rec)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7]:
            ok, base, note = oa._officeace_autostart(wait=20)
        self.assertFalse(ok)
        self.assertEqual([k for _, k in rec.spawns], ["gui"])   # 不重试
        self.assertIn("已在运行", note)
        self.assertIn("完全退出客户端", note)

    def test_three_attempts_then_manual_instructions(self):
        """GUI 每次都起不来（无其他实例）→ 重试 3 次 → 明说让手动双击。"""
        rec = _PopenRecorder(alive={"gui": False})
        patches = self._common(lambda timeout=5: (False, "", {}),
                               lambda: False, rec)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7]:
            ok, base, note = oa._officeace_autostart(wait=20)
        self.assertFalse(ok)
        self.assertEqual([k for _, k in rec.spawns], ["gui", "gui", "gui"])
        self.assertIn("重试 3 次", note)
        self.assertIn("手动双击", note)
        self.assertEqual([k for _, k in rec.spawns].count("host"), 0)

    def test_gui_alive_but_slow_never_spawns_host(self):
        """GUI 还活着只是慢 → 每轮等满 per，绝不抢启裸 host 把它顶退。"""
        rec = _PopenRecorder()
        patches = self._common(lambda timeout=5: (False, "", {}),
                               lambda: False, rec)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7]:
            ok, base, note = oa._officeace_autostart(wait=20)
        self.assertFalse(ok)
        self.assertEqual([k for _, k in rec.spawns], ["gui", "gui", "gui"])
        self.assertIn("进程仍在", note)

    def test_kill_orphan_before_each_attempt(self):
        rec = _PopenRecorder(alive={"gui": False})
        patches = self._common(lambda timeout=5: (False, "", {}),
                               lambda: False, rec)
        with patches[0], patches[1], patches[2] as kill, patches[3], \
                patches[4], patches[5], patches[6], patches[7]:
            oa._officeace_autostart(wait=20)
        self.assertEqual(kill.call_count, 3)      # 每轮重试前都清孤儿

    def test_killed_pid_reported_in_note(self):
        rec = _PopenRecorder()
        probe = self._probe_seq([(False, "", {})] * 3 + [(True, "https://x", {})])
        patches = self._common(probe, rec.gui_running, rec, kill=[4321])
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7]:
            ok, base, note = oa._officeace_autostart(wait=20)
        self.assertTrue(ok)
        self.assertIn("4321", note)               # 告知用户清理了遗留进程

    def test_exe_missing(self):
        rec = _PopenRecorder()
        patches = self._common(lambda timeout=5: (False, "", {}),
                               lambda: False, rec)
        patches[4] = mock.patch.object(oa, "_officeace_exe_path", return_value=None)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7]:
            ok, base, note = oa._officeace_autostart(wait=20)
        self.assertFalse(ok)
        self.assertEqual(rec.spawns, [])
        self.assertIn("未找到 OfficeACE 安装", note)


class TestOfficeaceGuard(unittest.TestCase):
    """登录互斥闸（2026-10-22）：登录进行中刷新周期不碰本地服务。"""

    def setUp(self):
        officeace_guard.end_login()      # 兜底清闸（上一用例异常时）

    def tearDown(self):
        officeace_guard.end_login()

    def test_begin_end_cycle(self):
        self.assertFalse(officeace_guard.login_running())
        self.assertTrue(officeace_guard.begin_login())
        self.assertTrue(officeace_guard.login_running())
        officeace_guard.end_login()
        self.assertFalse(officeace_guard.login_running())

    def test_double_begin_rejected(self):
        self.assertTrue(officeace_guard.begin_login())
        self.assertFalse(officeace_guard.begin_login())
        officeace_guard.end_login()
        self.assertTrue(officeace_guard.begin_login())   # 还闸后能再进

    def test_end_login_idempotent(self):
        officeace_guard.begin_login()
        officeace_guard.end_login()
        officeace_guard.end_login()          # 幂素，不抛
        self.assertFalse(officeace_guard.login_running())


class TestSmsJobGuard(unittest.TestCase):
    """start_officeace_sms_job 的互斥闸与失败还闸。"""

    def setUp(self):
        officeace_guard.end_login()

    def tearDown(self):
        officeace_guard.end_login()

    def test_concurrent_rejected(self):
        officeace_guard.begin_login()
        try:
            ok, msg, view = oa.start_officeace_sms_job(
                "13800138000", "x", lambda g: (True, "x", "y"))
            self.assertFalse(ok)
            self.assertIn("已有一个果办登录流程", msg)
            self.assertIsNone(view)
        finally:
            officeace_guard.end_login()

    def test_autostart_failure_releases_guard(self):
        with mock.patch.object(oa, "_officeace_maybe_teardown"), \
                mock.patch.object(oa, "_officeace_probe",
                                  return_value=(False, "", {})), \
                mock.patch.object(oa, "_officeace_autostart",
                                  return_value=(False, "", "客户端拉不起来")):
            ok, msg, view = oa.start_officeace_sms_job(
                "13800138000", "x", lambda g: (True, "x", "y"))
        self.assertFalse(ok)
        self.assertIn("客户端拉不起来", msg)
        self.assertFalse(officeace_guard.login_running())   # 闸已还

    def test_bad_phone_releases_guard(self):
        ok, msg, view = oa.start_officeace_sms_job(
            "123", "x", lambda g: (True, "x", "y"))
        self.assertFalse(ok)
        self.assertIn("11 位手机号", msg)
        self.assertFalse(officeace_guard.login_running())


class TestInnerJobPreCheck(unittest.TestCase):
    """授权前 API 掉线 → 快速失败，别把裸的 HTTP 0 抛给用户。"""

    def test_api_down_before_authorize_fails_fast(self):
        job = {"api": "https://127.0.0.1:3004"}
        with mock.patch.object(oa, "_officeace_probe", return_value=(False, "", {})):
            oa._run_officeace_sms_job_inner(job, "13800138000", "x",
                                            lambda g: (True, "x", "y"))
        self.assertTrue(job["finished"])
        self.assertFalse(job["ok"])
        self.assertIn("发起授权前掉线", job["result"])


if __name__ == "__main__":
    unittest.main()
