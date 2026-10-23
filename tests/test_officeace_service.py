# -*- coding: utf-8 -*-
"""OfficeACE 平台适配器服务管理层单测（2026-10-22 问题2 修复，无真实进程/网络）。

覆盖：
  1. _service_api_port：端口从 runtime-state.json 动态解析（GUI 随机端口不再误判），
     读不到才回退默认 3004。
  2. try_refresh：GUI 在跑时等它自己的 API，绝不直启裸 host（互斥会顶退客户端）；
     GUI 没跑时才直启（无人值守刷新老路径不回归）。
运行：python -m unittest tests.test_officeace_service   （用 pythoncore-3.14-64）
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.argv = [sys.argv[0]]
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import platforms.officeace as po  # noqa: E402
import officeace_guard  # noqa: E402


class TestServiceApiPort(unittest.TestCase):
    """端口动态解析（asar UseRandomFrontendApiPorts → 写死 3004 会误判）。"""

    def _state(self, d):
        tmp = tempfile.mkdtemp()
        st = os.path.join(tmp, "runtime-state.json")
        with open(st, "w", encoding="utf-8") as f:
            json.dump(d, f)
        return st

    def test_apiurl_port_wins(self):
        st = self._state({"ApiUrl": "https://127.0.0.1:35127", "ApiPort": 3004})
        with mock.patch.object(po, "_service_state_paths", return_value=[st]):
            self.assertEqual(po._service_api_port(), 35127)

    def test_apiport_fallback(self):
        st = self._state({"ApiPort": 35222})
        with mock.patch.object(po, "_service_state_paths", return_value=[st]):
            self.assertEqual(po._service_api_port(), 35222)

    def test_default_when_no_state(self):
        with mock.patch.object(po, "_service_state_paths",
                               return_value=[r"E:\no\such\state.json"]):
            self.assertEqual(po._service_api_port(), 3004)

    def test_garbage_state_falls_back(self):
        tmp = tempfile.mkdtemp()
        st = os.path.join(tmp, "runtime-state.json")
        with open(st, "w", encoding="utf-8") as f:
            f.write("{not json")
        with mock.patch.object(po, "_service_state_paths", return_value=[st]):
            self.assertEqual(po._service_api_port(), 3004)


class TestTryRefreshGuiAvoidance(unittest.TestCase):
    """try_refresh 的 GUI 避让（2026-10-22：绝不禁启裸 host 顶退客户端）。"""

    def test_gui_running_waits_and_never_spawns_host(self):
        seq = iter([False, False, True])     # 等 2s 后 GUI 的 API 就绪

        def _up():
            try:
                return next(seq)
            except StopIteration:
                return True
        with mock.patch.object(po, "_service_up", _up), \
                mock.patch.object(po, "_gui_running", return_value=True), \
                mock.patch.object(po, "_service_start") as start, \
                mock.patch.object(po, "_try_refresh_inner",
                                  return_value=(True, "ok")) as inner, \
                mock.patch.object(po.time, "sleep", lambda s: None):
            ok, msg = po.try_refresh("hid_x", {"expires_at": ""})
        self.assertTrue(ok)
        start.assert_not_called()            # 关键：没有直启裸 host
        inner.assert_called_once()

    def test_no_gui_spawns_bare_host_and_reaps(self):
        """GUI 没跑 → 走无人值守老路径：直启 + 用完回收（不回归）。"""
        with mock.patch.object(po, "_service_up", return_value=False), \
                mock.patch.object(po, "_gui_running", return_value=False), \
                mock.patch.object(po, "_service_start",
                                  return_value=(True, "ready")) as start, \
                mock.patch.object(po, "_service_stop") as stop, \
                mock.patch.object(po, "_try_refresh_inner",
                                  return_value=(True, "ok")):
            ok, msg = po.try_refresh("hid_x", {"expires_at": ""})
        self.assertTrue(ok)
        start.assert_called_once()
        stop.assert_called_once()            # 用完必须回收

    def test_gui_running_but_api_never_up_still_tries_host(self):
        """GUI 在跑但 25s 都没拉起 API（卡死）→ 才退直启，刷新不永久卡死。"""
        with mock.patch.object(po, "_service_up", return_value=False), \
                mock.patch.object(po, "_gui_running", return_value=True), \
                mock.patch.object(po, "_service_start",
                                  return_value=(True, "ready")) as start, \
                mock.patch.object(po, "_service_stop"), \
                mock.patch.object(po, "_try_refresh_inner",
                                  return_value=(True, "ok")), \
                mock.patch.object(po.time, "sleep", lambda s: None):
            ok, msg = po.try_refresh("hid_x", {"expires_at": ""})
        self.assertTrue(ok)
        start.assert_called_once()


class TestTryRefreshGuards(unittest.TestCase):
    """try_refresh 三道闸（2026-10-22 二次根因修复）：登录互斥 / 账号前置 / 失败冷却。

    0623 卡号的教训：它不是当前登录号，pick_live_session 必然落空，起裸 host
    纯属白试——但每轮刷新都起停一次 host，把用户双击的客户端顶退
    （13:49 startup-failure.json 实证）。三道闸把无谓的 host 起停压到零。"""

    def setUp(self):
        po._refresh_fail.clear()
        officeace_guard.end_login()          # 兜底清闸

    def tearDown(self):
        po._refresh_fail.clear()
        officeace_guard.end_login()

    @staticmethod
    def _ent(uid="u1"):
        return {"user_id": uid, "expires_at": "", "phone": "13800000000"}

    def test_login_running_skips_refresh(self):
        """短信登录进行中 → 直接跳过，不探账号不起服务。"""
        officeace_guard.begin_login()
        try:
            with mock.patch.object(po, "_current_session_uid") as cur, \
                    mock.patch.object(po, "_service_up") as up, \
                    mock.patch.object(po, "_service_start") as start, \
                    mock.patch.object(po, "_try_refresh_inner") as inner:
                ok, msg = po.try_refresh("hid_x", self._ent())
        finally:
            officeace_guard.end_login()
        self.assertFalse(ok)
        self.assertIn("登录流程进行中", msg)
        cur.assert_not_called()
        up.assert_not_called()
        start.assert_not_called()
        inner.assert_not_called()

    def test_non_current_account_skips_host(self):
        """客户端当前登录的是别的号 → 提前返回，绝不起 host（白试还顶退客户端）。"""
        with mock.patch.object(po, "_current_session_uid", return_value="other"), \
                mock.patch.object(po, "_service_up") as up, \
                mock.patch.object(po, "_service_start") as start, \
                mock.patch.object(po, "_try_refresh_inner") as inner:
            ok, msg = po.try_refresh("hid_x", self._ent("u1"))
        self.assertFalse(ok)
        self.assertIn("其他账号", msg)
        up.assert_not_called()
        start.assert_not_called()
        inner.assert_not_called()

    def test_current_account_proceeds(self):
        """当前号 → 放行：走 服务探活 →（GUI 没跑）直启 → 续期 老路径。"""
        with mock.patch.object(po, "_current_session_uid", return_value="u1"), \
                mock.patch.object(po, "_service_up", return_value=False), \
                mock.patch.object(po, "_gui_running", return_value=False), \
                mock.patch.object(po, "_service_start",
                                  return_value=(True, "ready")) as start, \
                mock.patch.object(po, "_service_stop") as stop, \
                mock.patch.object(po, "_try_refresh_inner",
                                  return_value=(True, "已续期")) as inner:
            ok, msg = po.try_refresh("hid_x", self._ent("u1"))
        self.assertTrue(ok)
        start.assert_called_once()
        stop.assert_called_once()            # 用完回收
        inner.assert_called_once()

    def test_cur_unknown_proceeds(self):
        """读不到当前登录号（库被锁/空）→ 不误伤，照常放行。"""
        with mock.patch.object(po, "_current_session_uid", return_value=None), \
                mock.patch.object(po, "_service_up", return_value=True), \
                mock.patch.object(po, "_try_refresh_inner",
                                  return_value=(True, "ok")) as inner, \
                mock.patch.object(po, "_service_start") as start:
            ok, msg = po.try_refresh("hid_x", self._ent("u1"))
        self.assertTrue(ok)
        inner.assert_called_once()
        start.assert_not_called()

    def test_failure_cooldown(self):
        """续期失败 → 5 分钟冷却：期间直接返回缓存文案，不再碰服务。"""
        with mock.patch.object(po, "_current_session_uid", return_value="u1"), \
                mock.patch.object(po, "_service_up", return_value=True), \
                mock.patch.object(po, "_try_refresh_inner",
                                  return_value=(False, "模拟失败原因")):
            ok1, msg1 = po.try_refresh("hid_x", self._ent("u1"))
        self.assertFalse(ok1)
        with mock.patch.object(po, "_current_session_uid") as cur, \
                mock.patch.object(po, "_service_up") as up, \
                mock.patch.object(po, "_try_refresh_inner") as inner:
            ok2, msg2 = po.try_refresh("hid_x", self._ent("u1"))
        self.assertFalse(ok2)
        self.assertIn("模拟失败原因", msg2)
        self.assertIn("秒后重试", msg2)
        cur.assert_not_called()
        up.assert_not_called()
        inner.assert_not_called()
        self.assertFalse(po._refresh_fail.get("hid_x", (0, ""))[0] <= 0)


class TestServiceStopOwnership(unittest.TestCase):
    """_service_stop 所有权硬化（2026-10-22）：只杀自己拉起的 host。

    致命 race：刷新 finally 来回收时，state 里的 HostPid 可能已被 GUI 接管的
    新 host 改写 → 旧实现一刀把用户的客户端服务杀掉（authorize HTTP 0）。"""

    def setUp(self):
        po._service_owned_pid = None

    def tearDown(self):
        po._service_owned_pid = None

    @staticmethod
    def _fake_run(calls):
        def _run(cmd, *a, **kw):
            calls.append(cmd if isinstance(cmd, str)
                         else " ".join(str(x) for x in cmd))

            class _R:
                stdout = b""
                returncode = 0
            return _R()
        return _run

    def test_stop_kills_owned_host_and_clears_state(self):
        with tempfile.TemporaryDirectory() as td:
            st = os.path.join(td, "runtime-state.json")
            with open(st, "w", encoding="utf-8") as f:
                json.dump({"HostPid": 4242}, f)
            calls = []
            with mock.patch.object(po, "_pid_is_host", return_value=True), \
                    mock.patch.object(po, "_service_state_paths",
                                      return_value=[st]), \
                    mock.patch.object(po.subprocess, "run",
                                      self._fake_run(calls)):
                po._service_owned_pid = 4242
                ok = po._service_stop()
            self.assertTrue(ok)
            self.assertTrue(any("taskkill" in c and "4242" in c
                                for c in calls))
            self.assertFalse(os.path.exists(st))   # 死 pid 状态文件一并清
            self.assertIsNone(po._service_owned_pid)

    def test_stop_skips_when_gui_took_over(self):
        """owned pid 已不是 ServiceHost（GUI 接管/已死）→ 绝不误杀，只清残留。"""
        with tempfile.TemporaryDirectory() as td:
            st = os.path.join(td, "runtime-state.json")
            with open(st, "w", encoding="utf-8") as f:
                json.dump({"HostPid": 4242}, f)
            calls = []
            with mock.patch.object(po, "_pid_is_host", return_value=False), \
                    mock.patch.object(po, "_service_state_paths",
                                      return_value=[st]), \
                    mock.patch.object(po.subprocess, "run",
                                      self._fake_run(calls)):
                po._service_owned_pid = 4242
                ok = po._service_stop()
            self.assertFalse(ok)
            self.assertEqual(calls, [])             # 没有 taskkill
            self.assertFalse(os.path.exists(st))    # 残留 state 仍清掉
            self.assertIsNone(po._service_owned_pid)

    def test_stop_without_owned_pid_is_noop(self):
        """没直启过（_service_owned_pid=None）→ 什么都不做（用户/GUI 的服务绝不动）。"""
        calls = []
        with mock.patch.object(po.subprocess, "run", self._fake_run(calls)):
            self.assertFalse(po._service_stop())
        self.assertEqual(calls, [])


class TestRuntimeHostPidNewLocation(unittest.TestCase):
    """_runtime_host_pid / _clear_stale_state 的 1.4.1 新位置（2026-10-22）。

    客户端 1.4.1 把 runtime-state.json 从 <安装目录>\\.office-claw\\run\\windows\\
    迁到 %USERPROFILE%\\.office-claw\\run\\windows\\。旧实现只读安装目录 →
    1.4.1 下永远找不到 host pid → 记不住归属 → _service_stop 永不回收。"""

    def _state(self, d):
        tmp = tempfile.mkdtemp()
        st = os.path.join(tmp, "runtime-state.json")
        with open(st, "w", encoding="utf-8") as f:
            json.dump(d, f)
        return st

    def test_new_location_state_found(self):
        st = self._state({"HostPid": 9140})
        with mock.patch.object(po, "_service_state_paths", return_value=[st]), \
                mock.patch.object(po, "_pid_is_host", return_value=True):
            self.assertEqual(po._runtime_host_pid(), 9140)

    def test_prefers_live_pid_over_dead(self):
        old = self._state({"HostPid": 111})
        new = self._state({"HostPid": 222})
        with mock.patch.object(po, "_service_state_paths",
                               return_value=[old, new]), \
                mock.patch.object(po, "_pid_is_host",
                                  side_effect=lambda p: p == 222):
            self.assertEqual(po._runtime_host_pid(), 222)

    def test_all_dead_returns_none(self):
        old = self._state({"HostPid": 111})
        new = self._state({"HostPid": 222})
        with mock.patch.object(po, "_service_state_paths",
                               return_value=[old, new]), \
                mock.patch.object(po, "_pid_is_host", return_value=False):
            self.assertIsNone(po._runtime_host_pid())

    def test_clear_stale_state_new_location(self):
        st = self._state({"HostPid": 777})
        with mock.patch.object(po, "_service_state_paths", return_value=[st]):
            self.assertTrue(po._clear_stale_state(777))
        self.assertFalse(os.path.exists(st))

    def test_clear_stale_state_keeps_live_pid(self):
        st = self._state({"HostPid": 888})
        with mock.patch.object(po, "_service_state_paths", return_value=[st]):
            self.assertFalse(po._clear_stale_state(999))   # pid 不匹配不动
        self.assertTrue(os.path.exists(st))


if __name__ == "__main__":
    unittest.main()
