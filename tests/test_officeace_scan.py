# -*- coding: utf-8 -*-
"""OfficeACE 果办 OAuth 回调捕获单测（不发起任何真实网络请求）。

覆盖（2026-10-22 修复 oauth_state_invalid）：
  - _officeace_scan_captured 必须返回「最终」officeclaw://oauth/callback 的 code/state，
    而非华为 OAuth 中间跳板 https://…/oauth/callback?code=HUAWEI&state=… 的 code/state
    （中间跳板被 Network 先捕获，旧逻辑「取第一个带 code 的 URL」会误取它，
     导致 /api/login/callback 报 oauth_state_invalid）。
  - 原生 officeclaw:// 跳转若直接出现在 loc/url，应直接命中。
  - 原生跳转 Playwright 捕获不到时，从 XHR 响应体里的 officeclaw 串兜底捞取。
运行：python -m unittest tests.test_officeace_scan   （用 pythoncore-3.14-64）
"""
import os
import sys
import unittest

sys.argv = [sys.argv[0]]
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import oauth_officeace as oa  # noqa: E402


class _FakeCDP:
    """最小 CDP 桩：只实现 Network.getResponseBody，从预置 bodies 取响应体。"""
    def __init__(self, bodies):
        self.bodies = bodies

    def send(self, method, params):
        if method == "Network.getResponseBody":
            return {"body": self.bodies.get(params.get("requestId"), "")}
        return {}


_HUAWEI_INTERMEDIATE = (
    "https://auth.huaweicloud.com/authui/v1/oauth2/callback"
    "?code=HUAWEI_CODE&state=HUAWEI_STATE"
)
_FINAL_OFFICECLAW = "officeclaw://oauth/callback?code=FINAL_CODE&state=FINAL_STATE&t=1"


def _captured(inter_loc=_HUAWEI_INTERMEDIATE, body_rid=None, body_text=None):
    items = [{
        "rid": "r1",
        "loc": inter_loc,
        "url": "https://auth.huaweicloud.com/authui/v1/oauth2/callback",
        "want_body": False,
        "body_done": False,
    }]
    if body_rid is not None:
        items.append({
            "rid": body_rid,
            "loc": "",
            "url": "https://127.0.0.1:3004/api/some/exchange",
            "want_body": True,
            "body_done": False,
        })
    return items, {body_rid: body_text} if body_rid else {}


class TestOfficeAceScanCaptured(unittest.TestCase):
    def test_ignores_huawei_intermediate_prefers_final_in_body(self):
        cap, bodies = _captured(body_rid="r2",
                                body_text='{"redirect":"%s"}' % _FINAL_OFFICECLAW)
        code, st = oa._officeace_scan_captured(_FakeCDP(bodies), cap)
        self.assertEqual(code, "FINAL_CODE")
        self.assertEqual(st, "FINAL_STATE")

    def test_direct_officeclaw_url_in_loc(self):
        # 原生跳转直接出现在 loc（不依赖 body）
        cap, bodies = _captured(inter_loc=_FINAL_OFFICECLAW)
        code, st = oa._officeace_scan_captured(_FakeCDP(bodies), cap)
        self.assertEqual(code, "FINAL_CODE")
        self.assertEqual(st, "FINAL_STATE")

    def test_intermediate_only_returns_none(self):
        # 只有中间跳板、没有任何 officeclaw 串 → 应返回 None（不要误取华为 code）
        cap, bodies = _captured()
        code, st = oa._officeace_scan_captured(_FakeCDP(bodies), cap)
        self.assertIsNone(code)
        self.assertIsNone(st)

    def test_body_with_oauth_callback_but_no_officeclaw_ignored(self):
        # 响应体里是 https://…/oauth/callback（中间跳板串）而非 officeclaw:// → 不应误取
        cap, bodies = _captured(body_rid="r2",
                                body_text='goto %s' % _HUAWEI_INTERMEDIATE)
        code, st = oa._officeace_scan_captured(_FakeCDP(bodies), cap)
        self.assertIsNone(code)


class TestOfficeAceCbParams(unittest.TestCase):
    """_officeace_cb_params：解析 JS 钩子从 officeclaw:// 客户端跳转里捕获的 code/state。

    2026-10-22 根因：redirect_uri 是标准 HTTPS 回调页，真正的 officeclaw:// 由该页
    JS 跳转抛出（无 HTTP 响应，CDP Network 层抓不到）→ 改由浏览器侧 init script 钩子
    捕获原始 URL，再交本函数解析。"""

    def test_parses_code_and_state(self):
        code, st = oa._officeace_cb_params(_FINAL_OFFICECLAW)
        self.assertEqual(code, "FINAL_CODE")
        self.assertEqual(st, "FINAL_STATE")

    def test_state_optional(self):
        code, st = oa._officeace_cb_params("officeclaw://oauth/callback?code=ONLY_CODE")
        self.assertEqual(code, "ONLY_CODE")
        self.assertEqual(st, "")

    def test_missing_code_returns_none(self):
        self.assertEqual(oa._officeace_cb_params(None), (None, None))
        self.assertEqual(oa._officeace_cb_params("officeclaw://oauth/callback?state=X"),
                         (None, None))

    def test_capture_js_has_required_hooks(self):
        # 注入脚本必须挂齐：location.assign/replace、window.open、锚点点击、MutationObserver，
        # 且守卫只收 officeclaw:// scheme（否则会把华为中间跳板也吞进 __oc_cb）。
        js = oa._OFFICEACE_CAPTURE_JS
        for token in ("location.assign", "location.replace", "window.open",
                      "MutationObserver", "officeclaw://", "__oc_cb", "__oc_parse"):
            self.assertIn(token, js)


if __name__ == "__main__":
    unittest.main()
