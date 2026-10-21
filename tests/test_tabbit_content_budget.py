# -*- coding: utf-8 -*-
"""Tabbit content 体量预算 + 492 减半重试单测（不发起任何真实网络请求）。

背景（2026-10-21 直连实测）：Tabbit 免费档对**单条 content 字符串的字符数**
有 ~2 万上限，超出返回 code=492 + 推广语「欢迎使用 Tabbit 浏览器……可免费
使用最全最先进的模型」——**不是会员门禁**（同账号同模型在浏览器里正常）。
中文 20016 字符通过、22017 失败；ASCII 24K 也失败 → 按字符计、与字节无关。

覆盖：
  - messages_to_content：单条原文直出（旧语义）、单条超预算硬截断、
    多条按预算保尾装配（末条必保/旧消息省略/截断标记）、budget=None 旧行为
  - chat_stream：流内 492 → 减半预算重建 content 换新会话重试；
    重试后正常出文；连续 492 到 CONTENT_MIN 仍失败 → 正文给准确的
    「免费档单条内容上限」可操作提示（而非误导的「需要 Pro 会员」）
  - _map_upstream_error：492 + 推广语 → 体量上限文案；492 + premium → 会员文案

运行：python -m unittest tests.test_tabbit_content_budget
"""
import json
import os
import sys
import time
import unittest

sys.argv = [sys.argv[0]]  # server/openai_proxy 导入链会把 argv[1] 当端口读
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import platforms.tabbit as tbt      # noqa: E402


def _mk_jwt(sub, exp):
    import base64

    def seg(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")

    return "%s.%s.%s" % (seg({"alg": "HS256", "typ": "JWT"}),
                         seg({"sub": sub, "exp": exp}), "S" * 43)


JWT = _mk_jwt("u_abc123", int(time.time()) + 3600)
PROMO = "欢迎使用 Tabbit 浏览器（https://www.tabbit.com/），可免费使用最全最先进的模型。"

UPSTREAM = [
    'event: thinking\ndata: {"content":"想想"}',
    'data: {"type":"message_chunk","content":"你"}',
    'event: message_chunk\ndata: {"content":"好"}',
    'data: {"type":"usage","usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}',
    'data: {"type":"message_finish"}',
    'data: [DONE]',
]

ERR_492 = ['event: error\ndata: {"type":"error","code":492,"message":"%s"}' % PROMO,
           'data: [DONE]']


class _FakeResp:
    def __init__(self, lines, status=200, ct="text/event-stream"):
        self.status_code = status
        self.text = "\n".join(lines)
        self.encoding = "utf-8"
        self.headers = {"content-type": ct}
        self._lines = lines

    def iter_lines(self, decode_unicode=False):
        for l in self._lines:
            for sub in str(l).split("\n"):
                yield sub

    def json(self):
        return json.loads(self.text)

    def close(self):
        pass


class _ScriptedRequests:
    """按调用次序返回预定响应，并记录每次 POST 的 body（解析后）。"""

    def __init__(self, script):
        self._script = list(script)
        self.bodies = []
        self.n = 0

    def post(self, url, **kw):
        self.n += 1
        try:
            self.bodies.append(json.loads(kw.get("data") or b"{}"))
        except Exception:
            self.bodies.append(None)
        resp = self._script[min(self.n - 1, len(self._script) - 1)]
        return resp() if callable(resp) else resp


class TestMessagesToContent(unittest.TestCase):
    """预算装配逻辑（纯函数，无网络）。"""

    def test_single_message_raw_text_no_label(self):
        # 旧语义回归：单条原文直出，不加 [User] 标签
        c, st = tbt.messages_to_content(
            [{"role": "user", "content": "你好"}], budget=16000)
        self.assertEqual(c, "你好")
        self.assertEqual(st["dropped"], 0)

    def test_single_message_over_budget_hard_truncated(self):
        big = "甲" * 30000
        c, st = tbt.messages_to_content(
            [{"role": "user", "content": big}], budget=16000)
        self.assertLessEqual(len(c), 16000 + 80)     # 预算 + 截断标记
        self.assertIn("内容过长已截断", c)
        self.assertTrue(c.startswith("甲" * 100))     # 保留头部

    def test_multi_under_budget_keeps_all(self):
        msgs = [{"role": "user", "content": "问题一"},
                {"role": "assistant", "content": "回答一"},
                {"role": "user", "content": "问题二"}]
        c, st = tbt.messages_to_content(msgs, budget=16000)
        self.assertEqual(st["dropped"], 0)
        self.assertNotIn("上下文截断", c)
        self.assertIn("[User]\n问题一", c)
        self.assertIn("[Assistant]\n回答一", c)
        self.assertIn("问题二", c)

    def test_multi_over_budget_keeps_newest_drops_oldest(self):
        msgs = ([{"role": "user", "content": "旧问题" + "甲" * 20000}] +
                [{"role": "assistant", "content": "旧回答" + "乙" * 20000}] +
                [{"role": "user", "content": "当前提问：请总结"}])
        c, st = tbt.messages_to_content(msgs, budget=16000)
        self.assertEqual(st["dropped"], 2)            # 两条旧的都装不下
        self.assertIn("当前提问：请总结", c)            # 末条完整保留
        self.assertNotIn("旧问题", c)
        self.assertNotIn("旧回答", c)
        self.assertIn("上下文截断", c)
        self.assertLessEqual(len(c), 16000 + 120)

    def test_multi_over_budget_keeps_recent_window(self):
        # 末条 + 部分较新历史可共存：只丢装不下的最旧一条
        msgs = ([{"role": "user", "content": "甲" * 20000}] +
                [{"role": "assistant", "content": "乙" * 3000}] +
                [{"role": "user", "content": "当前提问"}])
        c, st = tbt.messages_to_content(msgs, budget=16000)
        self.assertEqual(st["dropped"], 1)
        self.assertIn("当前提问", c)
        self.assertIn("乙" * 100, c)                  # 较近历史保留
        self.assertNotIn("甲", c)

    def test_budget_none_is_old_behavior(self):
        msgs = [{"role": "user", "content": "问题"},
                {"role": "assistant", "content": "回答"}]
        c, st = tbt.messages_to_content(msgs)
        self.assertEqual(c, "[User]\n问题\n\n[Assistant]\n回答")
        self.assertEqual(st["dropped"], 0)

    def test_empty_messages_raise(self):
        with self.assertRaises(tbt.UpstreamError):
            tbt.messages_to_content([], budget=16000)


class _ChatCase(unittest.TestCase):
    def setUp(self):
        self.ent = {"cookie": "token=" + JWT, "base": tbt.BASE_DOM}
        self._real_requests = tbt.requests
        self._real_signkey = tbt.fetch_sign_key
        self._real_session = tbt.get_session_id
        tbt.fetch_sign_key = lambda ent, force=False: "k" * 32
        tbt.get_session_id = lambda ent, force=False: "sess-123"
        tbt._sessions.clear()

    def tearDown(self):
        tbt.requests = self._real_requests
        tbt.fetch_sign_key = self._real_signkey
        tbt.get_session_id = self._real_session

    def _chunks(self, lines):
        return [json.loads(l[5:].strip()) for l in lines
                if l.startswith("data:") and "[DONE]" not in l]

    def _text(self, lines):
        return "".join(c["choices"][0]["delta"].get("content", "")
                       for c in self._chunks(lines))


class Test492HalveRetry(_ChatCase):
    """流内 492 → 减半预算重建 content、换新会话重试。"""

    def _big_body(self):
        # 全量装配 ~30K 字符：首条 16000 预算能装下「末条+10K 中间历史」，
        # 减半到 8000 后中间历史也装下 → 借 content 长度变化验证预算真在减半
        msgs = ([{"role": "user", "content": "甲" * 20000}] +
                [{"role": "assistant", "content": "乙" * 10000}] +
                [{"role": "user", "content": "当前提问：请总结"}])
        return {"model": "DeepSeek-V4.1-Flash", "messages": msgs}

    def test_492_halves_budget_and_retries_then_ok(self):
        tbt.requests = _ScriptedRequests([_FakeResp(ERR_492), _FakeResp(UPSTREAM)])
        lines = list(tbt.chat_stream(self.ent, self._big_body()))
        self.assertEqual(tbt.requests.n, 2)
        c0 = tbt.requests.bodies[0]["content"]
        c1 = tbt.requests.bodies[1]["content"]
        self.assertLess(len(c1), len(c0))            # 预算确实减半
        self.assertLessEqual(len(c1), 8000 + 120)
        self.assertIn("当前提问：请总结", c1)          # 末条仍完整
        text = self._text(lines)
        self.assertIn("你好", text)                   # 重试后正常出文
        self.assertNotIn("⚠️", text)

    def test_492_until_min_then_actionable_error(self):
        # 单条 3 万字：每次减半后 content 仍然很大（阈值比预估低的场景），
        # 16000→8000→4000→2000 共 4 次请求后放手，正文给准确文案
        body = {"model": "DeepSeek-V4.1-Flash",
                "messages": [{"role": "user", "content": "甲" * 30000}]}
        tbt.requests = _ScriptedRequests([_FakeResp(ERR_492)])
        lines = list(tbt.chat_stream(self.ent, body))
        self.assertEqual(tbt.requests.n, 4)
        sizes = [len(b["content"]) for b in tbt.requests.bodies]
        self.assertEqual(sizes, sorted(sizes, reverse=True))
        self.assertGreater(sizes[-1], 2000)          # 末次仍 >CONTENT_MIN
        text = self._text(lines)
        self.assertIn("免费档单条内容上限", text)      # 新文案：体量上限
        self.assertNotIn("需要 Pro 会员：", text)      # 不再是误导的会员文案
        self.assertTrue(any(c["choices"][0].get("finish_reason") == "stop"
                            for c in self._chunks(lines)))

    def test_single_oversized_message_truncated_first_try(self):
        # 单条 3 万字提问：首条即按 16000 硬截断，不再 492
        tbt.requests = _ScriptedRequests([_FakeResp(UPSTREAM)])
        body = {"model": "DeepSeek-V4.1-Flash",
                "messages": [{"role": "user", "content": "甲" * 30000}]}
        lines = list(tbt.chat_stream(self.ent, body))
        self.assertEqual(tbt.requests.n, 1)
        c0 = tbt.requests.bodies[0]["content"]
        self.assertLessEqual(len(c0), 16000 + 80)
        self.assertIn("内容过长已截断", c0)
        self.assertIn("你好", self._text(lines))

    def test_normal_small_request_untouched(self):
        # 小请求回归：content 原样、一次成功、无截断标记
        tbt.requests = _ScriptedRequests([_FakeResp(UPSTREAM)])
        body = {"model": "Default",
                "messages": [{"role": "user", "content": "hi"}]}
        lines = list(tbt.chat_stream(self.ent, body))
        self.assertEqual(tbt.requests.n, 1)
        self.assertEqual(tbt.requests.bodies[0]["content"], "hi")
        self.assertIn("你好", self._text(lines))

    def test_492_with_tiny_content_not_retried(self):
        # content 仅 2 字符还 492 → 不是体量问题（真·会员门禁之类），
        # 减半重试无意义：一次请求后直接给可操作提示
        tbt.requests = _ScriptedRequests([_FakeResp(ERR_492)])
        body = {"model": "Default",
                "messages": [{"role": "user", "content": "hi"}]}
        lines = list(tbt.chat_stream(self.ent, body))
        self.assertEqual(tbt.requests.n, 1)
        self.assertIn("免费档单条内容上限", self._text(lines))


class TestMap492Text(unittest.TestCase):
    def test_promo_text_maps_to_size_limit(self):
        st, msg = tbt._map_upstream_error(492, PROMO)
        self.assertEqual(st, 403)
        self.assertIn("单条内容上限", msg)
        self.assertIn("新建任务", msg)

    def test_premium_text_still_maps_to_membership(self):
        st, msg = tbt._map_upstream_error(492, "premium only")
        self.assertEqual(st, 403)
        self.assertIn("Pro", msg)


if __name__ == "__main__":
    unittest.main()
