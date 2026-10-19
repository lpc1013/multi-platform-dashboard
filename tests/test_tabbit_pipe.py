# -*- coding: utf-8 -*-
"""Tabbit 本地导入的「LocalAgent 公共管道」兜底路径单测（无真实管道/浏览器）。

背景（2026-10-20 实测修复）：Tabbit 浏览器进程驻留会独占 Cookies sqlite
（用户「关了窗口」也读不到），文件路径必失败。兜底走官方 LocalAgent 公共
命名管道（endpoint.json：address/token/generation），借 nodejs --tab 在
用户默认 profile context 里读 cookie。

覆盖：
  - _tabbit_accounts_from_cookies：国内/国际分组、无 JWT 组跳过、header 拼接
  - _tabbit_find_exe：候选路径 + glob 兜底
  - _TabbitPipe：认证帧/cli 帧格式、EOF → EOFError
  - _tabbit_pipe_accounts 流程：快路径一帧成功；快路径失败 → tabs → claim；
    无窗口自动唤起（Popen）后成功；NO_TAB；finally 必发 finish
  - read_tabbit 集成：locked + 管道成功/失败的文案分流
运行：python -m unittest tests.test_tabbit_pipe   （用 pythoncore-3.14-64）
"""
import base64
import json
import os
import sys
import time
import unittest
from unittest import mock

sys.argv = [sys.argv[0]]  # server/openai_proxy 导入链会把 argv[1] 当端口读
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import local_import as li      # noqa: E402


def _mk_jwt(sub, exp):
    def seg(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return "%s.%s.%s" % (seg({"alg": "HS256", "typ": "JWT"}),
                         seg({"sub": sub, "exp": exp}), "S" * 43)


JWT_DOM = _mk_jwt("uid-dom-1", int(time.time()) + 3600)
JWT_INTL = _mk_jwt("uid-intl-1", int(time.time()) + 3600)

CRED = {"address": r"\\.\pipe\tabbit-public-fake", "token": "t" * 43,
        "generation": "g" * 32}


def _ck_resp(cookies):
    """nodejs 成功响应（result.value = cookie 列表）"""
    return {"ok": True, "value": {"status": "succeeded",
                                  "result": {"value": cookies}}}


def _tabs_resp(tabs):
    return {"ok": True, "value": {"tabs": tabs, "total": len(tabs)}}


class TestAccountsFromCookies(unittest.TestCase):
    def test_groups_dom_and_intl(self):
        accs = li._tabbit_accounts_from_cookies([
            {"name": "token", "value": JWT_DOM, "domain": "web.tabbit.com"},
            {"name": "user_id", "value": "uid-dom-1", "domain": "web.tabbit.com"},
            {"name": "token", "value": JWT_INTL, "domain": "web.tabbit.ai"},
        ])
        self.assertEqual(set(accs.keys()), {"Tabbit·国际版", "Tabbit·国内版"})
        self.assertEqual(accs["Tabbit·国内版"]["base"], "https://web.tabbit.com")
        self.assertEqual(accs["Tabbit·国际版"]["base"], "https://web.tabbit.ai")
        ck = accs["Tabbit·国内版"]["cookie"]
        self.assertIn("token=%s" % JWT_DOM, ck)
        self.assertIn("user_id=uid-dom-1", ck)

    def test_group_without_jwt_skipped(self):
        accs = li._tabbit_accounts_from_cookies([
            {"name": "NEXT_LOCALE", "value": "zh", "domain": "web.tabbit.com"},
        ])
        self.assertEqual(accs, {})

    def test_empty_list(self):
        self.assertEqual(li._tabbit_accounts_from_cookies([]), {})
        self.assertEqual(li._tabbit_accounts_from_cookies(None), {})


class TestFindExe(unittest.TestCase):
    def test_candidate_hit(self):
        with mock.patch("os.path.isfile", return_value=True):
            p = li._tabbit_find_exe()
        self.assertTrue(p.endswith("Tabbit Browser.exe"))

    def test_glob_fallback(self):
        real = os.path.isfile
        with mock.patch("os.path.isfile", side_effect=lambda p: False), \
             mock.patch("glob.glob",
                        side_effect=lambda pat: [r"E:\Tabbit\Tabbit Browser\Application\Tabbit Browser.exe"]
                        if pat.startswith("E:") else []):
            p = li._tabbit_find_exe()
        self.assertEqual(p, r"E:\Tabbit\Tabbit Browser\Application\Tabbit Browser.exe")

    def test_nothing_found(self):
        with mock.patch("os.path.isfile", return_value=False), \
             mock.patch("glob.glob", return_value=[]):
            self.assertIsNone(li._tabbit_find_exe())


class _FakePipeFile:
    """模拟命名管道：记录写入帧，read 一次性返回预置响应行。"""

    def __init__(self, resp_line):
        self.sent = []
        self._resp = resp_line
        self._read = False
        self.closed = False

    def write(self, b):
        self.sent.append(b.decode("utf-8"))

    def flush(self):
        pass

    def read(self, n):
        if self._read:
            return b""
        self._read = True
        return self._resp

    def close(self):
        self.closed = True


class TestTabbitPipe(unittest.TestCase):
    def test_auth_then_cli_frames(self):
        fake = _FakePipeFile(b'{"ok":true,"value":{"running":true}}\n')
        with mock.patch("builtins.open", return_value=fake):
            p = li._TabbitPipe(CRED)
            r = p.cli(["diagnose"])
        p.close()
        self.assertTrue(fake.closed)
        self.assertEqual(len(fake.sent), 2)          # 认证帧 + cli 帧
        auth = json.loads(fake.sent[0])
        self.assertEqual(set(auth.keys()), {"version", "token", "generation"})
        self.assertEqual(auth["version"], 1)
        self.assertEqual(auth["token"], CRED["token"])
        frame = json.loads(fake.sent[1])
        self.assertEqual(frame["op"], "cli")
        self.assertEqual(frame["argv"], ["diagnose"])
        self.assertEqual(frame["stdin"], "")
        self.assertTrue(r["ok"])

    def test_eof_raises(self):
        fake = _FakePipeFile(b"")                    # 立即 EOF
        with mock.patch("builtins.open", return_value=fake):
            p = li._TabbitPipe(CRED)
            with self.assertRaises(EOFError):
                p.cli(["diagnose"], timeout=1)
        p.close()


class TestPipeAccountsFlow(unittest.TestCase):
    """mock li._tabbit_cli，验证 _tabbit_pipe_accounts 的帧序列与分支。"""

    def _enter(self):
        """mock endpoint.json 读取（os.path.isfile + open + json.load）。"""
        p1 = mock.patch("os.path.isfile", return_value=True)
        p2 = mock.patch("builtins.open",
                        mock.mock_open(read_data=json.dumps(CRED)))
        for p in (p1, p2):
            p.start()
            self.addCleanup(p.stop)

    def _patch_cli(self, seq):
        """seq: list of (matcher, response)；按调用顺序消耗。"""
        calls = []

        def fake_cli(cred, argv, stdin="", timeout=60):
            calls.append(argv)
            return seq.pop(0) if seq else {"ok": False}

        return fake_cli, calls

    def test_fast_path_one_frame(self):
        self._enter()
        cookies = [{"name": "token", "value": JWT_DOM, "domain": "web.tabbit.com"}]
        fake_cli, calls = self._patch_cli([_ck_resp(cookies)])
        with mock.patch.object(li, "_tabbit_cli", fake_cli):
            accs = li._tabbit_pipe_accounts("/udir")
        self.assertEqual(list(accs.keys()), ["Tabbit·国内版"])
        self.assertEqual(len(calls), 2)              # nodejs + finish
        self.assertEqual(calls[0][0], "nodejs")
        self.assertNotIn("--tab", calls[0])          # 快路径不 claim

    def test_slow_path_tabs_then_claim(self):
        self._enter()
        cookies = [{"name": "token", "value": JWT_DOM, "domain": "web.tabbit.com"}]
        fake_cli, calls = self._patch_cli([
            {"ok": True, "value": {"status": "failed",
                                   "result": {"error": "no open page"}}},   # 快路径失败
            _tabs_resp([{"tabId": 11, "active": True, "url": "https://web.tabbit.com/"}]),
            _ck_resp(cookies),                                            # claim 成功
        ])
        with mock.patch.object(li, "_tabbit_cli", fake_cli):
            accs = li._tabbit_pipe_accounts("/udir")
        self.assertEqual(list(accs.keys()), ["Tabbit·国内版"])
        self.assertEqual(calls[1][0], "tabs")
        self.assertEqual(calls[2][0], "nodejs")
        self.assertIn("--tab", calls[2])
        self.assertEqual(calls[-1][0], "finish")     # finally 必释放

    def test_no_window_autowake(self):
        self._enter()
        cookies = [{"name": "token", "value": JWT_INTL, "domain": "web.tabbit.ai"}]
        popen_calls = []
        fake_cli, calls = self._patch_cli([
            {"ok": True, "value": {"status": "failed",
                                   "result": {"error": "The task has no open page"}}},
            _tabs_resp([]),                                            # 无窗口
            _tabs_resp([{"tabId": 22, "active": True, "url": "https://web.tabbit.com/"}]),  # 唤起后
            _ck_resp(cookies),
        ])
        with mock.patch.object(li, "_tabbit_cli", fake_cli), \
             mock.patch.object(li, "_tabbit_find_exe", return_value=r"E:\Tabbit\Tabbit Browser.exe"), \
             mock.patch("subprocess.Popen",
                        side_effect=lambda argv, **kw: popen_calls.append(argv)):
            accs = li._tabbit_pipe_accounts("/udir")
        self.assertEqual(list(accs.keys()), ["Tabbit·国际版"])
        self.assertEqual(len(popen_calls), 1)
        self.assertIn("https://web.tabbit.com", popen_calls[0])
        self.assertEqual(calls[-1][0], "finish")

    def test_no_tab_no_exe_raises(self):
        self._enter()
        fake_cli, calls = self._patch_cli([
            {"ok": True, "value": {"status": "failed", "result": {"error": "x"}}},
            _tabs_resp([]),
        ])
        with mock.patch.object(li, "_tabbit_cli", fake_cli), \
             mock.patch.object(li, "_tabbit_find_exe", return_value=None):
            with self.assertRaises(RuntimeError) as cm:
                li._tabbit_pipe_accounts("/udir")
        self.assertIn("NO_TAB", str(cm.exception))
        self.assertEqual(calls[-1][0], "finish")     # 失败也释放

    def test_all_tabs_conflict_raises(self):
        self._enter()
        fake_cli, calls = self._patch_cli([
            {"ok": True, "value": {"status": "failed", "result": {"error": "x"}}},
            _tabs_resp([{"tabId": 1, "active": True}, {"tabId": 2, "active": False}]),
            {"ok": True, "value": {"status": "failed",
                                   "result": {"error": "A requested tab is owned by another session"}}},
            {"ok": True, "value": {"status": "failed",
                                   "result": {"error": "A requested tab is owned by another session"}}},
            {"ok": True, "value": {"status": "failed",
                                   "result": {"error": "A requested tab is owned by another session"}}},
        ])
        with mock.patch.object(li, "_tabbit_cli", fake_cli):
            with self.assertRaises(RuntimeError) as cm:
                li._tabbit_pipe_accounts("/udir")
        self.assertIn("owned by another session", str(cm.exception))
        self.assertEqual(calls[-1][0], "finish")


class TestReadTabbitIntegration(unittest.TestCase):
    """read_tabbit：文件 locked 时的管道分流与文案。"""

    def _run_read(self, pipe_side):
        with mock.patch.object(li, "_chromium_key", return_value=b"k" * 32), \
             mock.patch.object(li, "_tabbit_cookie_dbs",
                               return_value=["/nope/Cookies"]), \
             mock.patch.object(li, "_run_tabbit_pipe", **pipe_side):
            return li.read_tabbit()

    def test_locked_pipe_success(self):
        ok, msg, accs = self._run_read({"return_value": {
            "Tabbit·国内版": {"cookie": "token=%s" % JWT_DOM,
                              "base": "https://web.tabbit.com"}}})
        self.assertTrue(ok)
        self.assertIn("本地运行时管道", msg)
        self.assertIn("Tabbit·国内版", accs)

    def test_locked_pipe_no_tab_message(self):
        ok, msg, accs = self._run_read(
            {"side_effect": RuntimeError("NO_TAB")})
        self.assertFalse(ok)
        self.assertIn("没有打开的窗口", msg)
        self.assertEqual(accs, {})

    def test_locked_pipe_missing_endpoint(self):
        ok, msg, accs = self._run_read(
            {"side_effect": FileNotFoundError("endpoint.json")})
        self.assertFalse(ok)
        self.assertIn("endpoint.json", msg)

    def test_locked_pipe_timeout_message(self):
        ok, msg, accs = self._run_read(
            {"side_effect": TimeoutError("Tabbit 管道响应超时")})
        self.assertFalse(ok)
        self.assertIn("超时", msg)


if __name__ == "__main__":
    unittest.main()
