# -*- coding: utf-8 -*-
"""WB国际版「对话」自检的模型选择单测（不发起任何网络请求）。

回归背景（2026-10-21）：自检写死 `fast-model`——付费行。两号积分包用完后
恒回 14018 Credits exhausted，看板日志因此把「两号都正常、deepseek-v4.1-flash
免费可用」误报成「对话失败/额度耗尽」。修法：自检按反代 auto 链（免费行在前）
逐个试，任一有文本即算通过；401/403 视为账号级失效立即报。

运行：python -m unittest tests.test_wbai_chat
"""
import json
import os
import sys
import unittest
from unittest import mock

sys.argv = [sys.argv[0]]
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

from platforms import workbuddy_ai as wai  # noqa: E402


class _Err(wai.UpstreamErr):
    """沿用适配器真实异常类型（run_task 按 UpstreamErr 分支判定账号级失效）。"""
    pass


def _ok_lines(text):
    """构造上游 SSE 行（与 chat_stream 的产出形状一致）。"""
    return ['data: %s' % json.dumps(
        {"choices": [{"index": 0, "delta": {"content": text}}]}, ensure_ascii=False),
        "data: [DONE]"]


class TestChatSelfCheckModels(unittest.TestCase):
    def test_chain_head_is_free_model(self):
        self.assertEqual(wai._selfcheck_models()[0], "deepseek-v4.1-flash")

    def test_paid_model_14018_falls_through_to_free_model(self):
        """fast-model 报 14018 → 自动换链上首个免费模型并成功。"""
        calls = []

        def fake(ent, body, name=None):
            calls.append(body["model"])
            if body["model"] == "fast-model":
                raise _Err(429, '{"error":{"data":{"code":14018,"msg":"Credits exhausted"}}}')
            return iter(_ok_lines("你好！我是助手"))

        with mock.patch.object(wai, "chat_stream", side_effect=fake):
            r = wai.run_task("A", {}, "chat")
        self.assertTrue(r["ok"], r)
        self.assertIn("deepseek-v4.1-flash", r["msg"])
        self.assertEqual(calls[0], "deepseek-v4.1-flash")   # 不再先打付费行

    def test_all_models_quota_exhausted_reports_clear_reason(self):
        def fake(ent, body, name=None):
            raise _Err(429, '{"error":{"data":{"code":14018,"msg":"Credits exhausted"}}}')

        with mock.patch.object(wai, "chat_stream", side_effect=fake):
            r = wai.run_task("A", {}, "chat")
        self.assertFalse(r["ok"])
        self.assertIn("免费模型链全部失败", r["msg"])

    def test_auth_failure_does_not_try_more_models(self):
        calls = []

        def fake(ent, body, name=None):
            calls.append(body["model"])
            raise _Err(401, "invalid token")

        with mock.patch.object(wai, "chat_stream", side_effect=fake):
            r = wai.run_task("A", {}, "chat")
        self.assertFalse(r["ok"])
        self.assertIn("账号鉴权失效", r["msg"])
        self.assertEqual(len(calls), 1)                     # 账号级失效换模型无意义

    def test_empty_content_falls_through(self):
        seq = {"deepseek-v4.1-flash": ['data: %s' % json.dumps({"choices": []}), "data: [DONE]"]}

        def fake(ent, body, name=None):
            return iter(seq.get(body["model"], _ok_lines("好的")))

        with mock.patch.object(wai, "chat_stream", side_effect=fake):
            r = wai.run_task("A", {}, "chat")
        self.assertTrue(r["ok"], r)
        self.assertNotIn("deepseek-v4.1-flash", r["msg"])   # 落到链上下一个模型


if __name__ == "__main__":
    unittest.main()
