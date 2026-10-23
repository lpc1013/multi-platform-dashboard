# -*- coding: utf-8 -*-
"""OfficeACE `_req` 连接级重试 + 错误净化单测（2026-10-22 加固，无真实网络）。

覆盖：
  1. ConnectionReset(10054) → 退避重试 3 次 → 返回干净中文，绝不含原始
     'ConnectionResetError(10054...)' / 'Connection aborted.' 这类栈。
  2. HTTP 401/403 是确定响应，不重试（只发一次）。
  3. 成功路径正常返回 json。
  4. read_account 把净化后的文案回写进 error（呼应「别弹原始报错」）。
运行：python -m unittest tests.test_officeace_req   （用 pythoncore-3.14-64）
"""
import os
import sys
import unittest
from unittest import mock

sys.argv = [sys.argv[0]]
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import requests  # noqa: E402
import platforms.officeace as po  # noqa: E402


class FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.text = ""

    def json(self):
        if isinstance(self._payload, dict):
            return self._payload
        raise ValueError("not json")


class TestReqConnRetry(unittest.TestCase):
    @staticmethod
    def _ent():
        return {"ak": "a", "sk": "s", "sts_token": "t", "project_id": "p"}

    def test_reset_retries_then_clean_msg(self):
        err = requests.exceptions.ConnectionError(
            ConnectionResetError(10054, "远程主机强迫关闭了一个现有的连接。"))
        sleeps = []
        with mock.patch.object(po.requests, "request", side_effect=err), \
                mock.patch.object(po.time, "sleep", lambda s: sleeps.append(s)):
            st, j = po._req(self._ent(), "/v1/subscription")
        self.assertEqual(st, 0)
        self.assertIn("云端连接被重置", j["error"])
        self.assertNotIn("ConnectionResetError", j["error"])
        self.assertNotIn("10054", j["error"])
        self.assertEqual(sleeps, [0.5, 1.0])        # 退避两次

    def test_401_not_retried(self):
        resp = FakeResp(401, {"error_code": "APIG.0001", "error_msg": "auth fail"})
        calls = {"n": 0}

        def _fake(*a, **k):
            calls["n"] += 1
            return resp

        with mock.patch.object(po.requests, "request", side_effect=_fake), \
                mock.patch.object(po.time, "sleep", lambda s: None):
            st, j = po._req(self._ent(), "/v1/subscription")
        self.assertEqual(st, 401)
        self.assertEqual(calls["n"], 1)             # 确定响应不重试

    def test_success_returns_json(self):
        resp = FakeResp(200, {"data": {"subscription": {"skus": []}}})
        with mock.patch.object(po.requests, "request", return_value=resp), \
                mock.patch.object(po.time, "sleep", lambda s: None):
            st, j = po._req(self._ent(), "/v1/subscription")
        self.assertEqual(st, 200)
        self.assertEqual(j["data"]["subscription"]["skus"], [])

    def test_clean_conn_err_variants(self):
        self.assertIn("连接被重置", po._clean_conn_err(
            requests.exceptions.ConnectionError(ConnectionResetError(10054, "x"))))
        self.assertIn("超时", po._clean_conn_err(
            requests.exceptions.Timeout("timed out")))
        self.assertIn("被拒绝", po._clean_conn_err(
            requests.exceptions.ConnectionError(ConnectionError(10061, "refused"))))


class TestReadAccountCleanError(unittest.TestCase):
    @staticmethod
    def _ent():
        return {"ak": "a", "sk": "s", "sts_token": "t",
                "project_id": "p", "expires_at": "", "phone": "13800000000"}

    def test_surfaces_clean_msg(self):
        clean = po._clean_conn_err(
            requests.exceptions.ConnectionError(ConnectionResetError(10054, "x")))
        with mock.patch.object(po, "_req", return_value=(0, {"error": clean})):
            res = po.read_account("n", self._ent())
        self.assertFalse(res["ok"])
        self.assertIn("云端连接被重置", res["error"])
        self.assertNotIn("ConnectionResetError", res["error"])
        self.assertNotIn("10054", res["error"])


if __name__ == "__main__":
    unittest.main()
