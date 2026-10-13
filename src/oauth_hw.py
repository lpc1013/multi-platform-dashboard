# -*- coding: utf-8 -*-
"""华为系登录页共享代点助手（Trae/CodeArts/OfficeACE 三家共用）—— 二期拆分。

华为云统一登录页的填号 / 发码 / 提交验证码全流程 DOM 操作。"""
import json
import time
import os
import uuid
import base64
import hashlib
import secrets
import threading
import subprocess
import urllib.parse
import http.server
import re

try:
    import requests
except ImportError:
    requests = None

try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass
from oauth_common import (
    DEVICE_GRANT_TYPE, PROVIDERS, UA, _CODE_SEL, _JOBS, _OFFSCREEN_ARGS, _PHONE_SEL, _click_consent, _click_text, _consent_checked, _first_sel, _has_captcha, _job_lock, _login_submitted, _new_job, _origin, _pkce, _post_form, _provider, _pull_window_front, _view, get_job, submit_code,
)
from oauth_shared import _CODEARTS_DEBUG_LOCK, _CODEARTS_DEBUG_LOG, _codearts_debug, _qoder_has_captcha, _trae_find_token


# ═════════ Trae / CodeArts / OfficeACE 手机号短信直登（2026-10-08 协议逆向落地）═══════════
# 来源（先看再写，全部实测/实扫）：
# · Trae     ：客户端 main.js 逆向（loginUrlBuilder/vTe/exchangeTokenByAuthCode/OAuthLocalServer）
#              + 本机 storage.json + Trae CN 真实运行日志（成功兑换样本）。
#              授权页 www.trae.cn/authorization、回调端口 **随机 listen(0)**、
#              设备身份 icube-dc 密钥（按线路取：IDE→Trae CN / SOLO→TRAE SOLO CN）、
#              plugin_version=buildVersion(2.3.87416)、x_app_version=appVersion(3.3.104)。
# · CodeArts ：逆向 huaweicloud.authentication/dist/plugin.js v5.4.2：
#              portal/authorize?...&port=&code_challenge(S256)&ticket_id → authui 登录 →
#              302 回 http://127.0.0.1:<port>/oauth/callback?code=..&secret=.. →
#              POST sts /v1/oauth2/tokens（form + DPoP: ES256 dpop+jwt）→ credentials。
#              **自建会话的 refresh_token 归看板独享，刷新不踢客户端 → 修 1h 过期**。
# · OfficeACE：驱动桌面端本地 API（127.0.0.1:3004 自签名 HTTPS）：
#              POST /api/login/authorize → authorizeUrl(华为云 authui) → 登录成功后
#              页面要跳 officeclaw://oauth/callback?code&state（Playwright 捕获不到该
#              scheme 导航，实测）→ 改用 CDP Network 层在 **https 302 的 Location 头 /
#              XHR 响应体**里先拿 code，再 POST /api/login/callback 让 App 自己交换落盘。
# 华为云 authui 登录页（CodeArts/OfficeACE 共用，2026-10-08 实测 DOM，无 iframe）：
#   手机号 tab 默认选中；手机号 input[name="username"]（placeholder 手机号）；
#   验证码 input[placeholder*=验证码]；「获取验证码」.hwid-getAuthCode-input；
#   「登录/注册」.hwid-input-msgcode。
# ⚠⚠ 2026-10-08 实测（决定性）：`input[name="username"]` **命中 2 个**——
#   · [0] 隐藏模板位（rect=[0,0,0,0]、无 placeholder）← 密码登录 tab 的残留/模板
#   · [1] 真实可见位（rect=[138,357,308,38]、placeholder="手机号"）
#   → `loc.first` 拿到的是**隐藏**那个 → `_hw_stage()` 恒 False；
#   → `page.fill(sel, …)` 严格模式直接抛 "locator resolved to 2 elements"。
#   这就是「没找到华为云手机号输入框（页面可能改版）」的真因（不是改版，是多重命中）。
#   **铁律：华为云 authui 一律用「按 placeholder 定位 + 只取可见元素」的 JS 解析**，
#   绝不用裸 CSS 选择器 + .first / page.fill。

import http.server
import re

_HW_PHONE_SEL = 'input[name="username"]'          # 仅作兜底/文档
_HW_CODE_SEL = 'input[placeholder*="验证码"]'
_HW_SEND_TEXTS = ["获取验证码"]
_HW_LOGIN_TEXTS = ["登录/注册", "登录"]

# 按 placeholder 找「唯一可见」的华为云输入框，返回 DOM 元素（JS 侧过滤可见性）
_HW_INPUT_JS = """(phLike) => {
  const norm = s => (s || '').replace(/\\s+/g, '');
  const vis = e => { const r = e.getBoundingClientRect();
    const st = getComputedStyle(e);
    return r.width > 2 && r.height > 2 && st.visibility !== 'hidden'
           && st.display !== 'none' && !e.disabled && !e.readOnly; };
  const all = Array.from(document.querySelectorAll('input'));
  const hit = all.filter(e => vis(e) && norm(e.placeholder).indexOf(phLike) >= 0);
  return hit.length ? hit[hit.length - 1] : null;   // 多个可见时取最后一个（真实表单通常在后）
}"""


def _hw_visible_input(page, ph_like):
    """华为云 authui：返回唯一可见输入框的 ElementHandle（按 placeholder 子串）。"""
    try:
        h = page.evaluate_handle(_HW_INPUT_JS, ph_like)
        el = h.as_element() if h else None
        return el
    except Exception:
        return None


def _hw_fill_phone(page, phone):
    """填手机号（可见位）。返回 True/False。"""
    el = _hw_visible_input(page, "手机号")
    if el is None:
        return False
    try:
        el.click(timeout=1500)
        el.fill("")
        el.type(str(phone), delay=35)
        return True
    except Exception:
        try:
            el.evaluate("(e, v) => { e.focus(); e.value = v;"
                        " e.dispatchEvent(new Event('input', {bubbles:true}));"
                        " e.dispatchEvent(new Event('change', {bubbles:true})); }", str(phone))
            return True
        except Exception:
            return False


def _hw_stage(page):
    """当前页是否已是华为云 authui 登录页（手机号输入框**可见**）。"""
    return _hw_visible_input(page, "手机号") is not None


def _hw_click_visible(page, ph_or_text, cls_hint=""):
    """华为云 authui：点「可见」的 div 按钮。返回 True 表示点击已被页面接受。

    ⚠⚠ 2026-10-08 实测（决定性，勿回退）：
      旧实现按 `norm(innerText) === norm(txt)` 命中 **5 个元素**（祖孙容器 innerText 完全相同），
      再按 innerText 长度排序取 hit[0] —— 但 5 个命中里除了最外层 400×40 大容器外，
      `.hwid-getAuthCode` / `.button-base-box` / `.textBtn` 文本完全一致，排序**不稳定**，
      实测点到的是**不接收点击的容器** → 页面无任何反应，且 `el.click()` 不抛异常
      → **旧实现返回 True = 假成功**（job 谎报「验证码已发送」但 getHwidSMSCode 根本没发出）。
      对照铁证：`page.click('.hwid-getAuthCode')`（69×15 内层）→ 立即发出
      `POST id1.cloud.huawei.com/.../getHwidSMSCode`，页面变「重新获取(57)／短信验证码已经发送至…」。

    策略：① cls_hint 精确 CSS 选择器（取**可见**命中，多个时取**最深/最小**元素）
          ② 文本归一化匹配，同样取**最深**（无可见子元素者）而非任意 hits[0]
          ③ Playwright 原生 click（真实鼠标事件），失败再退回 JS `el.click()`
    """
    import re as _re
    el = None
    # ① 精确 class 选择器（cls_hint 支持空格分隔多候选）
    if cls_hint:
        for sel in [s for s in _re.split(r"[,\s]+", cls_hint) if s]:
            try:
                el = page.evaluate_handle(_HW_PICK_JS, ["." + sel, None]).as_element()
            except Exception:
                el = None
            if el is not None:
                break
    # ② 文本归一化匹配
    if el is None and ph_or_text:
        try:
            el = page.evaluate_handle(_HW_PICK_JS, [None, ph_or_text]).as_element()
        except Exception:
            el = None
    if el is None:
        return False
    for how in ("pw", "js"):
        try:
            if how == "pw":
                el.click(timeout=2000)
            else:
                el.evaluate("e => e.click()")
            return True
        except Exception:
            continue
    return False


# 取「可见且最深（无可见子节点）」的元素：cls 精确 or 文本归一化相等
_HW_PICK_JS = """(args) => {
  const sel = args[0], txt = args[1];
  const norm = s => (s || '').replace(/\\s+/g, '').replace(/\\u3000/g, '');
  const vis = e => { const r = e.getBoundingClientRect();
    const st = getComputedStyle(e);
    return r.width > 2 && r.height > 2 && st.visibility !== 'hidden'
           && st.display !== 'none' && st.pointerEvents !== 'none'; };
  let cands = [];
  if (sel) {
    cands = Array.from(document.querySelectorAll(sel)).filter(vis);
  } else if (txt) {
    const els = Array.from(document.querySelectorAll('div,button,a,[role=button],span'));
    cands = els.filter(e => vis(e) && norm(e.innerText) === norm(txt));
    // 只保留「最内层」：其可见后代中不含同样文本的兄弟节点
    cands = cands.filter(e => !Array.from(e.children).some(c =>
      vis(c) && norm(c.innerText) === norm(txt)));
  }
  if (!cands.length) return null;
  // 取面积最小者（=最内层可点控件，而非外层大容器）
  cands.sort((a, b) => {
    const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
    return (ra.width * ra.height) - (rb.width * rb.height);
  });
  return cands[0];
}"""


def _hw_sms_sent(page):
    """authui 页：判「验证码是否真的发出去了」——按钮文本变「重新获取(NN)」或出现「已经发送」文案。

    ⚠ 不能靠 `_hw_click_visible` 的返回值（click 不抛异常≠前端接受了），必须以页面状态为准。
    """
    try:
        return bool(page.evaluate("""() => {
            const t = (document.body.innerText || '');
            if (/重新获取|重新发送|秒后重新|已经发送|已发送至/.test(t)) return true;
            return false;
        }"""))
    except Exception:
        return False


def _hw_fill_and_send(page, ctx, job, phone):
    """authui 页：填手机号 → 点获取验证码。返回 False=表单没找到（转手动）。"""
    if not _hw_stage(page):
        return False
    if not _hw_fill_phone(page, phone):
        return False
    # 点「获取验证码」：cls 精确 → 文本匹配；点后**校验页面状态**，未发出则重试
    ok = False
    for attempt in range(3):
        _hw_click_visible(page, "获取验证码", "hwid-getAuthCode")
        page.wait_for_timeout(900)
        if _hw_sms_sent(page):
            ok = True
            break
        page.wait_for_timeout(500)
    if not ok:
        ok_click = _click_text(page, _HW_SEND_TEXTS, timeout=3500)
        page.wait_for_timeout(1200)
        ok = _hw_sms_sent(page)
    if not ok:
        job["result"] = "手机号已填入，但没点动「获取验证码」——已把窗口拉回屏幕，请手动点一下。"
        _pull_window_front(ctx)
        job.update(sms_sent=False, need_code=False)
        return True
    cap = _qoder_has_captcha(ctx)
    if cap:
        _pull_window_front(ctx)
    job.update(status="waiting_code", sms_sent=True, need_code=True, captcha=cap,
               result=("登录窗口弹出了滑块/图片验证码，请先在窗口里完成，短信才会发出。"
                       if cap else
                       "验证码已发送 📩 请在下方填入短信验证码"
                       "（若没收到，看看窗口是否弹了滑块）"))
    return True


def _hw_submit_code(page, ctx, job, code):
    """authui 页：填验证码 → 点登录/注册。"""
    el = _hw_visible_input(page, "验证码")
    if el is None:
        try:
            page.fill(_HW_CODE_SEL, str(code), timeout=5000)
        except Exception:
            return False
    else:
        try:
            el.click(timeout=1500)
            el.fill("")
            el.type(str(code), delay=35)
        except Exception:
            try:
                el.evaluate("(e, v) => { e.focus(); e.value = v;"
                            " e.dispatchEvent(new Event('input', {bubbles:true}));"
                            " e.dispatchEvent(new Event('change', {bubbles:true})); }", str(code))
            except Exception:
                return False
    page.wait_for_timeout(300)
    # ⚠⚠ 2026-10-09 无头 recon 实测（authui 线上 DOM，勿回退）：
    #   「登录/注册」= div.hwid-btn.hwid-btn-primary（外层 .hwid-input-msgcode /
    #   .hwid-reg-btn / .button-base-box 同文本不同层），且按钮带 **hwid-disabled**
    #   禁用态 —— Vue 表单校验未通过时点击被**静默忽略**（14:46 实拍：验证码已填、
    #   按钮没点动、15s 后人工点同一按钮立即通过）。所以：①先等按钮脱 disabled
    #   ②点最内层真实按钮 ③点后**校验页面状态变化**，未变则重试（最多 3 轮）。
    _BTN_JS = """() => {
      const norm = s => (s||'').replace(/\\s+/g,'');
      const vis = e => { const r = e.getBoundingClientRect();
        return r.width>2 && r.height>2; };
      let btn = null, ba = 1e9;
      // ⚠ 只查内层真实按钮：hwid-disabled 只挂在 div.hwid-btn 上，
      //   外层 .hwid-reg-btn/.normalBtn/.hwid-input-msgcode 永远没有该类（recon 实证）
      for (const e of document.querySelectorAll('div.hwid-btn,button')) {
        if (!vis(e) || norm(e.innerText||'') !== '登录/注册') continue;
        const r = e.getBoundingClientRect();
        if (r.width*r.height < ba) { ba = r.width*r.height; btn = e; }
      }
      if (!btn) return {found: false};
      return {found: true,
              disabled: /(^|\\s)hwid-disabled(\\s|$)/.test(btn.className||''),
              cls: (btn.className||'').slice(0,90)};
    }"""
    st_info = {}
    for _ in range(10):                      # ① 等按钮脱 disabled（≤5s）
        try:
            st_info = page.evaluate(_BTN_JS) or {}
        except Exception:
            st_info = {}
        if not st_info.get("found") or not st_info.get("disabled"):
            break
        page.wait_for_timeout(500)
    _codearts_debug("submit", "按钮状态: %s" % str(st_info)[:130])
    accepted = False
    for _round in range(3):
        # ② 首选 Playwright 原生 click（可信输入事件，等价真人）点**内层真实按钮**
        #    （cls_hint='hwid-btn' → _HW_PICK_JS 精确命中 div.hwid-btn，非外层容器）
        if not _hw_click_visible(page, "登录/注册", "hwid-btn"):
            _click_text(page, _HW_LOGIN_TEXTS, timeout=2000)
        # ③ 校验：3s 内 URL 跳走 / 按钮消失 = 页面已接受
        for _ in range(6):
            page.wait_for_timeout(500)
            try:
                u2 = page.url or ""
            except Exception:
                u2 = ""
            if u2 and "/authui/login.html" not in u2:
                accepted = True
                break
            try:
                if not (page.evaluate(_BTN_JS) or {}).get("found"):
                    accepted = True
                    break
            except Exception:
                pass
        if accepted:
            break
        # ④ 兜底：验证码框上回车提交（部分表单支持 Enter 直提）
        try:
            el2 = _hw_visible_input(page, "验证码")
            if el2 is not None:
                el2.press("Enter", timeout=1500)
        except Exception:
            pass
        for _ in range(4):
            page.wait_for_timeout(500)
            try:
                u2 = page.url or ""
            except Exception:
                u2 = ""
            if u2 and "/authui/login.html" not in u2:
                accepted = True
                break
        if accepted:
            break
    _codearts_debug("submit", "click accepted=%s url=%s"
                    % (accepted, (page.url or "")[:110]))
    job["code_submitted"] = True
    job["need_code"] = False
    job["result"] = ("已提交验证码，正在登录…"
                     if accepted else
                     "已填验证码并尝试点击「登录/注册」，但页面暂无响应，如 15 秒后仍停留请手动点一下。")
    return True
