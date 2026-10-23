# -*- coding: utf-8 -*-
"""豆包平台适配器单测（不发起任何真实网络请求）。

覆盖（2026-10-22 从豆包网页版 bundle 逆向的 API 契约）：
  - 注册表 / cred_store 登记（PLATFORM_IDS / CRED_FILES / IDENT_FIELDS / DEFAULT_LABEL）
  - Cookie 工具：has_login（sessionid 判定）/ stable_uid（uid_tt、odin_tt）
  - ensure_identity 回填 + save_cred 身份语义（同身份换 cookie 沿用键名）
  - _resolve_code：手填活动码优先 > 启动配置自动获取 > 30 分钟缓存
  - read_account：无 Cookie / 登录过期(710012001) / 无活动 / 网络错误 /
    未签(chosen_type=1) / 已签(chosen_type=2) / 奖励文案解析
  - run_task：未知任务 / 无 Cookie / 已签 ALREADY_TODAY /
    签到成功(checked_in=true) / checked_in 缺失判失败 / 业务错误码透传
  - _parse_reward：「200 额度」「100 积分」「1.5 积分点」等
运行：python -m unittest tests.test_doubao   （用 pythoncore-3.14-64）
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.argv = [sys.argv[0]]  # server/openai_proxy 导入链会把 argv[1] 当端口读
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import cred_store as cs            # noqa: E402
import platforms.doubao as dbt     # noqa: E402
import registry                    # noqa: E402

COOKIE = "sessionid=abc123; uid_tt=u_777; sessionid_ss=def456; odin_tt=o_1"


def _launch_ok(code="cg_2026"):
    return (200, {"code": 0, "data": {"ug_campaign_info": {"campaign_group_code": code}}})


def _landing(chosen, title="今日签到领 200 额度", content="PC 端签到活动"):
    key = "complete_page_info" if chosen == dbt.CH_DONE else "main_page_info"
    return (200, {"code": 0, "data": {
        "chosen_type": chosen,
        key: {"title": title, "content": content, "buttons": [{"title": "立即签到"}]}}})


def _fake_req(routes, default=(200, {"code": 0, "data": {}})):
    """按 path 路由的 _req 替身：routes: {path: (status, json)}
    返回带 call_count / call_args_list 的 Mock。"""
    def _req(ent, path, body=None, timeout=25):
        return routes.get(path, default)
    return mock.Mock(side_effect=_req)


class _StatefulReq:
    """有状态 _req：签到前落地页=未签(CH_MAIN)，checkin 成功后=已签(CH_DONE)。
    模拟真实活动页时序（签到动作会翻转 chosen_type）。"""
    def __init__(self, code="cg_2026", reward_title="今日签到领 200 额度",
                 done_title="今日已签到，获得 200 额度"):
        self.code = code
        self.reward_title = reward_title
        self.done_title = done_title
        self.checked = False
        self.calls = []

    def __call__(self, ent, path, body=None, timeout=25):
        self.calls.append((path, body))
        if path == dbt.EP_LAUNCH:
            return _launch_ok(self.code)
        if path == dbt.EP_LANDING_GET:
            return _landing(dbt.CH_DONE if self.checked else dbt.CH_MAIN,
                            self.done_title if self.checked else self.reward_title)
        if path == dbt.EP_LANDING_CHECKIN:
            self.checked = True
            return (200, {"code": 0, "data": {"checked_in": True}})
        return (200, {"code": 0, "data": {}})


class TestRegistration(unittest.TestCase):
    def test_registry(self):
        self.assertIn("doubao", registry.PLATFORM_IDS)
        mod = registry.modules()["doubao"] if hasattr(registry, "modules") else None
        if mod is not None:
            self.assertEqual(mod.LABEL, "豆包")
            self.assertEqual([t["key"] for t in mod.TASKS], ["checkin"])

    def test_cred_store_entries(self):
        self.assertIn("doubao", cs.CRED_FILES)
        self.assertEqual(cs.IDENT_FIELDS["doubao"][0], "user_id")
        self.assertEqual(cs.DEFAULT_LABEL["doubao"], "豆包")
        self.assertTrue(cs.CRED_FILES["doubao"].endswith("doubao_accounts.json"))


class TestCookieIdentity(unittest.TestCase):
    def test_has_login(self):
        self.assertTrue(dbt.has_login("sessionid=abc"))
        self.assertTrue(dbt.has_login("a=1; sessionid_ss=xyz"))
        self.assertTrue(dbt.has_login("a=1;SESSIONID=xyz"))
        self.assertFalse(dbt.has_login("a=1; b=2"))
        self.assertFalse(dbt.has_login(""))

    def test_stable_uid(self):
        self.assertEqual(dbt.stable_uid(COOKIE), "u_777")
        self.assertEqual(dbt.stable_uid("odin_tt=o_9; x=1"), "o_9")
        self.assertEqual(dbt.stable_uid("uid_tt_ss=u_ss1"), "u_ss1")
        self.assertEqual(dbt.stable_uid("sessionid=abc"), "")

    def test_cred_store_stable_uid_alias(self):
        self.assertEqual(cs.doubao_stable_uid(COOKIE), dbt.stable_uid(COOKIE))

    def test_ensure_identity_backfill(self):
        rec = {"cookie": COOKIE}
        cs.ensure_identity("doubao", rec)
        self.assertEqual(rec.get("user_id"), "u_777")

    def test_ensure_identity_keeps_existing_user_id(self):
        rec = {"cookie": COOKIE, "user_id": "manual"}
        cs.ensure_identity("doubao", rec)
        self.assertEqual(rec["user_id"], "manual")

    def test_ensure_identity_no_uid_no_backfill(self):
        rec = {"cookie": "sessionid=abc"}
        cs.ensure_identity("doubao", rec)
        self.assertNotIn("user_id", rec)


class TestSaveCredIdentity(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="doubao_")
        self.path = os.path.join(self.dir, "doubao_accounts.json")
        self.cf = {"doubao": self.path}

    def _save(self, uid, ideal):
        rec = {"cookie": "sessionid=s1; uid_tt=%s" % uid}
        cs.ensure_identity("doubao", rec)
        return cs.save_cred("doubao", rec, ideal, cred_files=self.cf)

    def _read(self):
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def test_same_identity_reuses_key_after_cookie_rotation(self):
        k1 = self._save("u_same", "豆包·主号")
        k2 = self._save("u_same", "豆包·换个名")
        self.assertEqual(k1, k2)
        self.assertEqual(len(self._read()), 1)

    def test_different_identity_new_card(self):
        k1 = self._save("u_a", "豆包·主号")
        k2 = self._save("u_b", "豆包·主号")
        self.assertNotEqual(k1, k2)
        self.assertEqual(len(self._read()), 2)


class TestResolveCode(unittest.TestCase):
    def setUp(self):
        dbt._code_cache.clear()

    def tearDown(self):
        dbt._code_cache.clear()

    def test_manual_code_first(self):
        ent = {"cookie": COOKIE, "campaign_group_code": "manual_cg"}
        with mock.patch.object(dbt, "_req") as m:
            code, err = dbt._resolve_code(ent)
        self.assertEqual((code, err), ("manual_cg", ""))
        m.assert_not_called()          # 手填码不打网络

    def test_auto_from_launch(self):
        with mock.patch.object(dbt, "_req", _fake_req({dbt.EP_LAUNCH: _launch_ok("cg_x")})):
            code, err = dbt._resolve_code({"cookie": COOKIE})
        self.assertEqual((code, err), ("cg_x", ""))

    def test_cache_hit_skips_launch(self):
        routes = {dbt.EP_LAUNCH: _launch_ok("cg_cached")}
        with mock.patch.object(dbt, "_req", _fake_req(routes)) as m:
            c1, _ = dbt._resolve_code({"cookie": COOKIE})
            c2, _ = dbt._resolve_code({"cookie": COOKIE})
        self.assertEqual(c1, "cg_cached")
        self.assertEqual(c2, "cg_cached")
        self.assertEqual(m.call_count, 1)   # 第二次走缓存

    def test_launch_login_expired(self):
        routes = {dbt.EP_LAUNCH: (200, {"code": dbt.ERR_LOGIN, "msg": "登录已过期，请重新登录"})}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            code, err = dbt._resolve_code({"cookie": COOKIE})
        self.assertEqual((code, err), ("", "login"))

    def test_launch_no_campaign(self):
        routes = {dbt.EP_LAUNCH: (200, {"code": 0, "data": None})}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            code, err = dbt._resolve_code({"cookie": COOKIE})
        self.assertEqual((code, err), ("", "nocampaign"))

    def test_launch_network_error(self):
        routes = {dbt.EP_LAUNCH: (-1, "timed out")}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            code, err = dbt._resolve_code({"cookie": COOKIE})
        self.assertEqual((code, err), ("", "net"))

    def test_dig_campaign_code_fallbacks(self):
        self.assertEqual(dbt._dig_campaign_code({"campaign_group_code": "c1"}), "c1")
        self.assertEqual(dbt._dig_campaign_code({"ugCampaignInfo": {"campaignGroupCode": "c2"}}), "c2")
        self.assertEqual(dbt._dig_campaign_code({"ug_campaign_info": {"campaignGroupCode": "c3"}}), "c3")
        self.assertEqual(dbt._dig_campaign_code({}), "")
        self.assertEqual(dbt._dig_campaign_code(None), "")


class TestReadAccount(unittest.TestCase):
    def setUp(self):
        dbt._code_cache.clear()

    def tearDown(self):
        dbt._code_cache.clear()

    def test_no_cookie(self):
        r = dbt.read_account("t", {})
        self.assertFalse(r["ok"])
        self.assertIn("Cookie", r["error"])

    def test_login_expired(self):
        routes = {dbt.EP_LAUNCH: (200, {"code": dbt.ERR_LOGIN, "msg": "登录已过期"})}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            r = dbt.read_account("t", {"cookie": COOKIE})
        self.assertFalse(r["ok"])
        self.assertIn("重新登录", r["error"])

    def test_no_campaign(self):
        routes = {dbt.EP_LAUNCH: (200, {"code": 0, "data": None})}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            r = dbt.read_account("t", {"cookie": COOKIE})
        self.assertFalse(r["ok"])
        self.assertIn("没有进行中的签到活动", r["error"])

    def test_network_error(self):
        routes = {dbt.EP_LAUNCH: (-1, "conn reset")}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            r = dbt.read_account("t", {"cookie": COOKIE})
        self.assertFalse(r["ok"])
        self.assertIn("网络异常", r["error"])

    def test_not_signed_yet(self):
        routes = {dbt.EP_LAUNCH: _launch_ok(),
                  dbt.EP_LANDING_GET: _landing(dbt.CH_MAIN, "今日签到领 200 额度")}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            r = dbt.read_account("t", {"cookie": COOKIE})
        self.assertTrue(r["ok"])
        self.assertFalse(r["signed_today"])
        self.assertTrue(r["extra"]["can_sign_in"])
        self.assertEqual(r["extra"]["campaign_group_code"], "cg_2026")
        self.assertEqual(r["extra"]["today_reward"], 200)
        self.assertEqual(r["extra"]["checkin_title"], "今日签到领 200 额度")
        self.assertEqual(r["credits"]["remain"], 0)   # 无余额接口，不编造

    def test_already_signed(self):
        routes = {dbt.EP_LAUNCH: _launch_ok(),
                  dbt.EP_LANDING_GET: _landing(dbt.CH_DONE, "今日已签到")}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            r = dbt.read_account("t", {"cookie": COOKIE})
        self.assertTrue(r["ok"])
        self.assertTrue(r["signed_today"])
        self.assertFalse(r["extra"]["can_sign_in"])
        self.assertEqual(r["extra"]["checkin_title"], "今日已签到")

    def test_landing_login_expired(self):
        routes = {dbt.EP_LAUNCH: _launch_ok(),
                  dbt.EP_LANDING_GET: (200, {"code": dbt.ERR_LOGIN, "msg": "登录已过期"})}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            r = dbt.read_account("t", {"cookie": COOKIE})
        self.assertFalse(r["ok"])
        self.assertIn("重新登录", r["error"])

    def test_manual_code_skips_launch(self):
        ent = {"cookie": COOKIE, "campaign_group_code": "cg_manual"}
        routes = {dbt.EP_LANDING_GET: _landing(dbt.CH_MAIN)}
        with mock.patch.object(dbt, "_req", _fake_req(routes)) as m:
            r = dbt.read_account("t", ent)
        self.assertTrue(r["ok"])
        paths = [c.args[1] for c in m.call_args_list]
        self.assertNotIn(dbt.EP_LAUNCH, paths)          # 没打 launch
        self.assertIn(dbt.EP_LANDING_GET, paths)


class TestRunTask(unittest.TestCase):
    def setUp(self):
        dbt._code_cache.clear()
        # 浏览器兜底在单测里必须 mock，否则会真拉起 Chromium 卡死；
        # 默认返回失败，各测试可临时改 return_value 验证兜底成功路径。
        self.bc = mock.patch.object(
            dbt, "browser_checkin",
            return_value=(False, "浏览器兜底失败", None)).start()

    def tearDown(self):
        dbt._code_cache.clear()
        mock.patch.stopall()

    def test_unknown_task_key(self):
        r = dbt.run_task("t", {"cookie": COOKIE}, "badkey")
        self.assertFalse(r["ok"])
        self.assertEqual(r["msg"], "未知任务")

    def test_no_cookie(self):
        r = dbt.run_task("t", {}, "checkin")
        self.assertFalse(r["ok"])

    def test_already_today(self):
        routes = {dbt.EP_LAUNCH: _launch_ok(),
                  dbt.EP_LANDING_GET: _landing(dbt.CH_DONE, "今日已签到")}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            r = dbt.run_task("t", {"cookie": COOKIE}, "checkin")
        self.assertTrue(r["ok"])
        self.assertEqual(r["flag"], "ALREADY_TODAY")
        self.assertIn("今日已签到", r["msg"])

    def test_checkin_success_with_reward(self):
        # checkin 响应不带完成页文案 → 补拉落地页（此时已翻转为 CH_DONE）解析奖励
        m = _StatefulReq()
        with mock.patch.object(dbt, "_req", m):
            r = dbt.run_task("t", {"cookie": COOKIE}, "checkin")
        self.assertTrue(r["ok"])
        self.assertEqual(r["flag"], "SUCCESS")
        self.assertEqual(r["gain"], 200)                 # 补拉落地页解析到奖励
        self.assertIn("+200 额度", r["msg"])

    def test_checkin_success_reward_from_checkin_page(self):
        # checkin 响应自带完成页文案时，不再补拉 landing
        done_page = {"title": "今日签到领 100 额度"}

        def _req(ent, path, body=None, timeout=25):
            if path == dbt.EP_LAUNCH:
                return _launch_ok()
            if path == dbt.EP_LANDING_GET:
                return _landing(dbt.CH_MAIN)
            if path == dbt.EP_LANDING_CHECKIN:
                return (200, {"code": 0,
                              "data": {"checked_in": True, "complete_page_info": done_page}})
            return (200, {"code": 0, "data": {}})

        m = mock.Mock(side_effect=_req)
        with mock.patch.object(dbt, "_req", m):
            r = dbt.run_task("t", {"cookie": COOKIE}, "checkin")
        self.assertTrue(r["ok"])
        self.assertEqual(r["gain"], 100)
        paths = [c.args[1] for c in m.call_args_list]
        self.assertEqual(paths.count(dbt.EP_LANDING_GET), 1)   # 只查了 1 次状态

    def test_checkin_missing_checked_in(self):
        routes = {dbt.EP_LAUNCH: _launch_ok(),
                  dbt.EP_LANDING_GET: _landing(dbt.CH_MAIN),
                  dbt.EP_LANDING_CHECKIN: (200, {"code": 0, "data": {}})}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            r = dbt.run_task("t", {"cookie": COOKIE}, "checkin")
        self.assertFalse(r["ok"])
        self.bc.assert_called_once()              # API 未完成 → 降级浏览器
        self.assertIn("浏览器兜底", r["msg"])

    def test_checkin_business_error(self):
        routes = {dbt.EP_LAUNCH: _launch_ok(),
                  dbt.EP_LANDING_GET: _landing(dbt.CH_MAIN),
                  dbt.EP_LANDING_CHECKIN: (200, {"code": 500001, "msg": "活动太火爆"})}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            r = dbt.run_task("t", {"cookie": COOKIE}, "checkin")
        self.assertFalse(r["ok"])
        self.bc.assert_called_once()              # 非登录类业务错误 → 降级浏览器
        self.assertIn("活动太火爆", r["msg"])     # 原因保留原 msg
        self.assertIn("浏览器兜底", r["msg"])

    def test_checkin_login_expired(self):
        routes = {dbt.EP_LAUNCH: _launch_ok(),
                  dbt.EP_LANDING_GET: _landing(dbt.CH_MAIN),
                  dbt.EP_LANDING_CHECKIN: (200, {"code": dbt.ERR_LOGIN, "msg": "登录已过期"})}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            r = dbt.run_task("t", {"cookie": COOKIE}, "checkin")
        self.assertFalse(r["ok"])
        self.bc.assert_not_called()              # 登录态问题兜底也救不了，不拉浏览器
        self.assertIn("重新登录", r["msg"])

    def test_launch_error_paths(self):
        cases = [
            ((-1, "x"), None, "浏览器兜底"),                          # 网络 → 降级浏览器
            ((200, {"code": dbt.ERR_LOGIN}), "重新登录", None),      # 登录 → 直报
            ((200, {"code": 0, "data": None}), "没有进行中的签到活动", None),
        ]
        for resp, expect_msg, expect_fallback in cases:
            routes = {dbt.EP_LAUNCH: resp}
            with mock.patch.object(dbt, "_req", _fake_req(routes)):
                r = dbt.run_task("t", {"cookie": COOKIE}, "checkin")
            self.assertFalse(r["ok"])
            if expect_msg:
                self.assertIn(expect_msg, r["msg"])
            if expect_fallback:
                self.assertIn(expect_fallback, r["msg"])

    def test_fallback_browser_success(self):
        # API 网络失败 → 浏览器兜底成功（验证 SUCCESS_BROWSER 分支）
        self.bc.return_value = (True, "浏览器访问豆包 agent-explore 已完成签到（200 额度）", None)
        routes = {dbt.EP_LAUNCH: (-1, "conn")}
        with mock.patch.object(dbt, "_req", _fake_req(routes)):
            r = dbt.run_task("t", {"cookie": COOKIE}, "checkin")
        self.assertTrue(r["ok"])
        self.assertEqual(r["flag"], "SUCCESS_BROWSER")
        self.assertIn("200 额度", r["msg"])
        self.bc.assert_called_once()


class TestParseReward(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(dbt._parse_reward("今日签到领 200 额度"), 200)
        self.assertEqual(dbt._parse_reward("签到得 100 积分"), 100)
        self.assertEqual(dbt._parse_reward("奖励 1.5 积分点"), 1.5)
        self.assertEqual(dbt._parse_reward("领50个豆"), 50)
        self.assertIsNone(dbt._parse_reward("今日签到"))
        self.assertIsNone(dbt._parse_reward(""))
        self.assertIsNone(dbt._parse_reward(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
