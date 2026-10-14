# -*- coding: utf-8 -*-
"""
webapi.py —— HTTP 路由层（2026-10-13 从 server.py 抽出）
Handler：全部 GET/POST 路由（/api/state、/api/run、/api/account/*、/v1/* 反代…）
+ 本机来源防护（防 DNS rebinding / CSRF）。
server.py 保留启动编排（Server / _already_running / main），只负责「起服务」。
"""
import os
import sys
import json
import threading
import http.server
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import data_dir
from errors import DashboardError
from registry import PORT, LOCAL_IMPORT_PLATFORMS
from logstore import log, LOG
import cred_store
from cred_store import (
    CRED_FILES, WB_LOGIN_FILE,
    read_json as _read_json, write_json as _write_json,
    wb_match as _wb_match,
    save_cred as _save_cred,
    alloc_account_name as _alloc_account_name,
    dedupe_store as _dedupe_store,
    cred_store_set as _cred_store_set,
    cred_store_remove as _cred_store_remove,
)
from tasks import (
    collect_state, run_tasks, start_job, JOBS, BLOGINS,
    _invalidate_state, _has_playwright, _new_blogin, _run_blogin,
)
from account_service import (
    _wb_store_append, _oauth_save, _dumate_web_save, _lingxi_web_save,
    _trae_oauth_save, _codearts_oauth_save, _officeace_login_save,
    _teleagent_login_save,
    ensure_identity,
)

try:
    import workbuddy_login as wblogin
except Exception as _e:
    wblogin = None
    print("⚠ 未加载 workbuddy_login，网页端 WorkBuddy 短信登录将不可用：%s" % _e)

# ── oauth 各平铺模块直连（三期拆分：oauth_login.py 薄壳已删除）──────────
# 顶层只牵 stdlib + requests（可选），playwright 全部在函数内延迟导入 → 顶部导入安全。
# 命名冲突注意：tasks.start_job 是「平台签到任务」，oauth 的「登录任务」同名
# → 登录侧一律加 _oauth_ 前缀别名，调用点不再有 oauth_login.* 间接层。
try:
    from oauth_common import PROVIDERS as _OAUTH_PROVIDERS, get_job as _oauth_get_job
    from oauth_jobs import (
        start_job as _oauth_start_job, start_sms_job as _oauth_start_sms_job,
        submit_code as _oauth_submit_code,
    )
    from oauth_zcode import start_zcode_sms_job as _oauth_start_zcode
    from oauth_dumate import start_dumate_web_job as _oauth_start_dumate
    from oauth_lingxi import start_lingxi_sms_job as _oauth_start_lingxi
    from oauth_trae import start_trae_sms_job as _oauth_start_trae
    from oauth_codearts import start_codearts_sms_job as _oauth_start_codearts
    from oauth_officeace import (
        start_officeace_sms_job as _oauth_start_officeace,
        _officeace_autostart, _officeace_probe, _officeace_exe_path,
    )
    from oauth_teleagent import start_teleagent_login as _oauth_start_teleagent
    OAUTH_OK = True
except Exception as _e:
    OAUTH_OK = False
    print("⚠ 未加载 oauth 模块，网页授权（手机号）登录将不可用：%s" % _e)


def _allowed_hosts():
    return ("127.0.0.1:%d" % PORT, "localhost:%d" % PORT)


def _check_host_origin(headers):
    """本地 API 的跨站防护（防 DNS rebinding + 防浏览器 CSRF）。

    背景：服务只监听 127.0.0.1，但**你浏览器里打开的任意网页**都可以向
    http://127.0.0.1:8799 发跨域请求——读状态是因 CORS 被浏览器拦住，
    但「发 POST 触发任务/改凭据」拦不住（简单请求不预检），DNS rebinding
    还能让恶意域名整体接管本端口。两层校验：
      ① Host 头必须为本机（DNS rebinding 时 Host=恶意域名 → 直接拒）
      ② POST 的 Origin/Referer（浏览器必带其一）必须为本机；
         都不带 = 非浏览器客户端（curl / 脚本），放行，不影响命令行用法。
    """
    host = str(headers.get("Host") or "").strip().lower()
    if host not in _allowed_hosts():
        return False
    if headers.get("Origin"):
        origin = str(headers.get("Origin")).strip().lower()
        ok = origin in ("http://127.0.0.1:%d" % PORT, "http://localhost:%d" % PORT)
        return ok
    if headers.get("Referer"):
        ref = str(headers.get("Referer")).strip().lower()
        ok = ref.startswith(("http://127.0.0.1:%d/" % PORT, "http://127.0.0.1:%d" % PORT,
                             "http://localhost:%d/" % PORT, "http://localhost:%d" % PORT))
        return ok
    return True


class Handler(http.server.BaseHTTPRequestHandler):
    def _guard(self):
        if _check_host_origin(self.headers):
            return True
        try:
            self._send(403, {"error": "已拒绝非本机来源的请求（防 DNS rebinding / CSRF）"})
        except Exception:
            pass
        return False

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _begin_stream(self, status=200, ctype="text/event-stream; charset=utf-8"):
        """SSE 响应头（openai_proxy 用）。ThreadingTCPServer 每请求一线程，
        长流式不阻塞看板其它请求。"""
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

    def _write_chunk(self, data):
        try:
            self.wfile.write(data)
            self.wfile.flush()
        except Exception:
            raise

    def log_message(self, fmt, *a):
        pass

    def do_GET(self):
        if not self._guard():
            return
        p = urllib.parse.urlparse(self.path).path
        fn = _GET_ROUTES.get(p)
        if fn is None:
            self._send(404, {"error": "not found"})
            return
        try:
            fn(self)
        except DashboardError as e:
            self._send(e.http_status, e.to_dict())
        except Exception as e:
            self._send(500, {"error": str(e)[:200]})

    def _r_index(self):
        fp = os.path.join(HERE, "index.html")
        try:
            self._send(200, open(fp, "rb").read(), "text/html; charset=utf-8")
        except Exception as e:
            self._send(500, {"error": str(e)})

    def _r_api_state(self):
        try:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            force = "force" in q
            scope = (q.get("platform") or [""])[0] or None
            self._send(200, collect_state(force=force, scope=scope))
        except DashboardError as e:
            self._send(e.http_status, e.to_dict())
        except Exception as e:
            self._send(500, {"error": str(e)[:200]})

    def _r_v1_models(self):
        # OpenAI 兼容：CodeArts 模型目录（内置 + 福利免费额度）+ TeleAgent（星辰）
        # import 在 try 外：若放 try 内，import 失败时 except ox.UpstreamError
        # 会因 ox 未定义抛 NameError，把真实错误搅成 500 迷雾
        import openai_proxy as ox
        if not ox.gate(self):
            return
        data = []
        try:
            _, ent = ox._load_ent()
            builtin, benefit = ox.catalog(ent)
            ids = list(dict.fromkeys((builtin or []) + sorted(benefit)))
            data += [{"id": i, "object": "model",
                      "owned_by": "codearts-benefit" if i in benefit else "codearts"}
                     for i in ids]
        except ox.UpstreamError:
            pass          # CodeArts 不可用不阻塞 TeleAgent 模型列出
        except Exception as e:
            self._send(502, {"error": {"message": str(e)[:200]}})
            return
        try:
            ox._ta_ent()
            data += [{"id": m, "object": "model", "owned_by": "teleagent"}
                     for m in ox.tat.CHAT_MODELS]
        except Exception:
            pass
        try:
            ox._oa_ent()
            data += [{"id": m, "object": "model", "owned_by": "officeace"}
                     for m in sorted(ox.oa_model_ids())]
        except Exception:
            pass    # OfficeACE 不可用不阻塞其余模型列出
        self._send(200, {"object": "list", "data": data})

    def _r_api_proxy_usage(self):
        # 反代用量聚合（openai_proxy._record_usage 写入，按日/按模型）
        uf = data_dir.path("proxy_usage.json")
        d = _read_json(uf, {})
        self._send(200, d)

    def _r_api_proxy_info(self):
        # OpenAI 兼容反代「接入信息」（前端「🔌 API 接入」弹窗数据源）：
        # URL / API Key / 双上游模型目录 / 限流 / 在用账号。
        # 模型目录优先读 openai_proxy 缓存（10min TTL）；缓存冷时才打上游（秒级）。
        import openai_proxy as ox
        # Host 头取访问地址：用户用 localhost 还是 127.0.0.1 打开的看板，示例 URL 跟着一致
        host = str(self.headers.get("Host") or "127.0.0.1:8799")
        base = "http://%s/v1" % host
        out = {"base_url": base,
               "chat_url": base + "/chat/completions",
               "models_url": base + "/models",
               "api_key": ox.PROXY_API_KEY,
               "auth_required": bool(ox.PROXY_API_KEY),
               "rate_limit": {"per_min": int(ox.RATE_PER_MIN), "burst": int(ox.BURST)},
               "default_model": "deepseek-v4.1-flash"}

        # 上游一：CodeArts（福利免费额度 + 内置计积分）
        ca = {"id": "codearts", "label": "CodeArts（华为免费额度）",
              "default_model": "deepseek-v4.1-flash",
              "benefit": sorted(ox._SEED_BENEFIT), "builtin": [],
              "account": None, "error": ""}
        try:
            name, ent = ox._load_ent()
            ca["account"] = name
            builtin, benefit = ox.catalog(ent)
            if builtin:
                ca["builtin"] = builtin
            if benefit:
                ca["benefit"] = sorted(benefit)
        except ox.UpstreamError as e:
            ca["error"] = e.message
        except Exception as e:
            ca["error"] = str(e)[:200]
        ca["models"] = list(dict.fromkeys(ca["builtin"] + ca["benefit"]))

        # 上游二：TeleAgent（星辰，模型名决定路由）
        ta = {"id": "teleagent", "label": "TeleAgent（星辰）",
              "default_model": "chat-max", "models": list(ox.tat.CHAT_MODELS),
              "account": None, "error": ""}
        try:
            tn, _ = ox._ta_ent()
            ta["account"] = tn
        except Exception as e:
            ta["error"] = getattr(e, "message", None) or str(e)[:160]

        # 上游三：OfficeACE（华为云果办，模型网关 Basic 对）
        oa = {"id": "officeace", "label": "OfficeACE（华为云果办）",
              "default_model": "", "models": [], "account": None, "error": ""}
        try:
            on, _ = ox._oa_ent()
            oa["account"] = on
            oa_ids = sorted(ox.oa_model_ids())
            oa["models"] = oa_ids
            # 默认模型选一个「OA 独有」的（交集名走 CodeArts，选它不会路由到本上游）
            ca_ids = set(ca["models"])
            exclusive = [m for m in oa_ids if m not in ca_ids]
            for pref in ("glm-5.3", "kimi-k2.6", "qwen3-32b", "openpangu-2.0-pro"):
                if pref in exclusive:
                    oa["default_model"] = pref
                    break
            if not oa["default_model"] and exclusive:
                oa["default_model"] = exclusive[0]
        except Exception as e:
            oa["error"] = getattr(e, "message", None) or str(e)[:160]

        out["benefit_models"] = ca["benefit"]     # 旧字段保留（向后兼容）
        out["builtin_models"] = ca["builtin"]
        out["models"] = ca["models"]
        out["account"] = ca["account"]
        out["error"] = ca["error"]
        out["providers"] = [ca, ta, oa]
        self._send(200, out)

    def _r_api_progress(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        jid = (q.get("job") or [""])[0]
        job = JOBS.get(jid)
        if not job:
            self._send(404, {"error": "job not found"})
        else:
            self._send(200, {"job": jid, "total": job["total"], "done": job["done"],
                              "current_name": job["current_name"], "current_task": job["current_task"],
                              "steps": job["steps"][-12:], "finished": job["finished"],
                              "error": job["error"], "results": job["results"] if job["finished"] else []})

    def _r_api_log(self):
        self._send(200, {"log": LOG[-120:]})

    def _r_api_account_browser_login_status(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        jid = (q.get("job") or [""])[0]
        job = BLOGINS.get(jid)
        if not job:
            self._send(404, {"error": "job not found"})
        else:
            self._send(200, {"job": jid, "status": job["status"], "text": job["text"],
                             "finished": job["finished"], "ok": job["ok"],
                             "result": job["result"], "name": job["name"],
                             "platform": job["platform"]})

    def _r_api_account_oauth_status(self):
        # 网页授权（手机号登录）任务状态：前端每 1.5 秒轮询一次
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        jid = (q.get("job") or [""])[0]
        if not OAUTH_OK:
            self._send(200, {"finished": True, "ok": False, "text": "后端未加载 oauth 模块"})
        else:
            v = _oauth_get_job(jid)
            if not v:
                self._send(404, {"error": "job not found"})
            else:
                self._send(200, v)

    def _r_api_officeace_status(self):
        # OfficeACE 桌面端本地 API 探活（端口从 runtime-state.json 实时解析）
        if not OAUTH_OK:
            self._send(200, {"ok": False, "msg": "后端未加载 oauth 模块"})
        else:
            try:
                ok, base, info = _officeace_probe(timeout=5)
            except Exception as e:
                ok, base, info = False, "", {"error": str(e)[:120]}
            try:
                exe = _officeace_exe_path()
            except Exception:
                exe = None
            self._send(200, {"ok": bool(ok), "api": base, "exe": exe, "info": info})

    def _r_api_ping(self):
        self._send(200, {"ok": True, "port": PORT})

    def do_POST(self):
        if not self._guard():
            return
        p = urllib.parse.urlparse(self.path).path
        ln = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(ln) or b"{}")
        except Exception:
            body = {}
        fn = _POST_ROUTES.get(p)
        if fn is None:
            self._send(404, {"error": "not found"})
            return
        try:
            fn(self, body)
        except DashboardError as e:
            self._send(e.http_status, e.to_dict())
        except Exception as e:
            self._send(500, {"error": str(e)[:200]})

    def _r_v1_chat_completions(self, body):
        # OpenAI 兼容反代：CodeArts 免费额度模型（详见 openai_proxy.py）
        import openai_proxy as ox
        if not ox.gate(self):
            return
        try:
            ox.relay(self, body)
        except ox.UpstreamError as e:
            self._send(e.status, {"error": {"message": e.message}})
        except Exception as e:
            self._send(502, {"error": {"message": str(e)[:200]}})

    def _r_api_run(self, body):
        platform = body.get("platform")
        names = body.get("names")
        tasks = tuple(body.get("tasks") or ["checkin"])
        if body.get("async"):
            jid, n_acc, n_step = start_job(platform, names, tasks, body.get("chat_text"))
            if not jid:
                self._send(200, {"ok": False,
                                 "error": "未找到该平台凭据或无可执行账号/任务"})
            else:
                self._send(200, {"ok": True, "job": jid, "accounts": n_acc, "total": n_step})
        else:
            self._send(200, run_tasks(platform, names, tasks, body.get("chat_text")))

    def _r_api_refresh(self, body):
        self._send(200, collect_state(force=True, scope=body.get("platform") or None))


    # ── 网页端「添加账号」：WorkBuddy 短信两步登录 ──
    def _r_api_account_wb_send(self, body):
        if not wblogin:
            self._send(200, {"ok": False, "msg": "后端未加载 workbuddy_login"})
        else:
            phone = (body.get("phone") or "").strip()
            if not phone:
                self._send(200, {"ok": False, "msg": "手机号不能为空"})
            else:
                try:
                    ok, msg = wblogin.send_sms(phone)
                    self._send(200, {"ok": ok, "msg": msg})
                except Exception as e:
                    self._send(200, {"ok": False, "msg": str(e)[:120]})

    def _r_api_account_wb_login(self, body):
        if not wblogin:
            self._send(200, {"ok": False, "msg": "后端未加载 workbuddy_login"})
        else:
            phone = (body.get("phone") or "").strip()
            code = (body.get("code") or "").strip()
            if not phone or not code:
                self._send(200, {"ok": False, "msg": "手机号与验证码都不能为空"})
            else:
                try:
                    res = wblogin.login(phone, code)
                except Exception as e:
                    res = None
                if not res:
                    self._send(200, {"ok": False, "msg": "登录失败，请检查验证码或重新发送"})
                else:
                    _wb_store_append(phone, res["accessToken"], res["refreshToken"])
                    _invalidate_state()
                    self._send(200, {"ok": True, "msg": "已保存账号 %s" % phone})


    # ── 批量：多个 WorkBuddy 账号一起发码 / 登录 ──
    def _r_api_account_wb_batch_send(self, body):
        if not wblogin:
            self._send(200, {"ok": False, "msg": "后端未加载 workbuddy_login"})
        else:
            phones = [str(x).strip() for x in (body.get("phones") or []) if str(x).strip()]
            if not phones:
                self._send(200, {"ok": False, "msg": "手机号列表为空"})
            else:
                details = []
                for ph in phones:
                    try:
                        ok, msg = wblogin.send_sms(ph)
                        details.append({"phone": ph, "ok": ok, "msg": msg})
                    except Exception as e:
                        details.append({"phone": ph, "ok": False, "msg": str(e)[:80]})
                self._send(200, {"ok": True, "details": details})

    def _r_api_account_wb_batch_login(self, body):
        if not wblogin:
            self._send(200, {"ok": False, "msg": "后端未加载 workbuddy_login"})
        else:
            phones = [str(x).strip() for x in (body.get("phones") or []) if str(x).strip()]
            codes = [str(x).strip() for x in (body.get("codes") or []) if str(x).strip()]
            res_list = []
            for ph, code in zip(phones, codes):
                if not code:
                    res_list.append({"phone": ph, "ok": False, "msg": "验证码为空"})
                    continue
                try:
                    r = wblogin.login(ph, code)
                except Exception as e:
                    r = None
                if r:
                    _wb_store_append(ph, r["accessToken"], r["refreshToken"])
                    res_list.append({"phone": ph, "ok": True, "msg": "已保存"})
                else:
                    res_list.append({"phone": ph, "ok": False, "msg": "登录失败"})
            _invalidate_state()
            self._send(200, {"ok": True, "results": res_list})


    # ── MiniMax / DuMate：粘贴 token / cookie 直接落盘 ──
    def _r_api_account_add(self, body):
        platform = body.get("platform")
        name = (body.get("name") or "").strip()
        if platform == "minimax":
            token = (body.get("token") or "").strip()
            if not token:
                self._send(200, {"ok": False, "msg": "MINIMAX_TOKEN 不能为空"})
            else:
                use = _save_cred("minimax",
                                 {"access_token": token,
                                  "user_id": (body.get("user_id") or "").strip()}, name)
                _invalidate_state()
                self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
        elif platform == "baidu_dumate":
            cookie = (body.get("cookie") or "").strip()
            if not cookie:
                self._send(200, {"ok": False, "msg": "DuMate Cookie 不能为空"})
            else:
                use = _save_cred("baidu_dumate", {"cookie": cookie}, name)
                _invalidate_state()
                self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
        elif platform == "lingxi":
            sid = (body.get("wps_sid") or "").strip()
            if not sid:
                self._send(200, {"ok": False, "msg": "wps_sid 不能为空"})
            else:
                use = _save_cred("lingxi", {"wps_sid": sid}, name)
                _invalidate_state()
                self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
        elif platform == "trae":
            tok = (body.get("token") or "").strip()
            if not tok:
                self._send(200, {"ok": False, "msg": "Trae token 不能为空"})
            else:
                use = _save_cred("trae",
                                 {"token": tok,
                                  "device_id": (body.get("device_id") or "").strip(),
                                  "user_id": (body.get("user_id") or "").strip(),
                                  "region": (body.get("region") or "CN").strip()}, name)
                _invalidate_state()
                self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
        elif platform == "qoder":
            tok = (body.get("token") or "").strip()
            if not tok:
                self._send(200, {"ok": False, "msg": "Qoder token 不能为空"})
            else:
                use = _save_cred("qoder",
                                 {"token": tok,
                                  "refresh_token": (body.get("refresh_token") or "").strip(),
                                  "expires_at": (body.get("expires_at") or "").strip(),
                                  "user_id": (body.get("user_id") or "").strip(),
                                  "phone": (body.get("phone") or "").strip()}, name)
                _invalidate_state()
                self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
        elif platform == "zcode":
            tok = (body.get("token") or "").strip()
            if not tok:
                self._send(200, {"ok": False, "msg": "ZCode token 不能为空"})
            else:
                use = _save_cred("zcode",
                                 {"token": tok,
                                  "secret": (body.get("secret") or "").strip(),
                                  "user_id": (body.get("user_id") or "").strip(),
                                  "phone": (body.get("phone") or "").strip()}, name)
                _invalidate_state()
                self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
        elif platform == "officeace":
            ak = (body.get("ak") or "").strip()
            sk = (body.get("sk") or "").strip()
            sts = (body.get("sts_token") or "").strip()
            if not (ak and sk and sts):
                self._send(200, {"ok": False, "msg": "OfficeACE 需要 AK / SK / STS 三项都填"})
            else:
                use = _save_cred("officeace",
                                 {"ak": ak, "sk": sk, "sts_token": sts,
                                  "project_id": (body.get("project_id") or "").strip(),
                                  "expires_at": (body.get("expires_at") or "").strip()}, name)
                _invalidate_state()
                self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
        elif platform == "codearts":
            cookie = (body.get("cookie") or "").strip()
            tok = (body.get("token") or "").strip()
            if not (cookie or tok):
                self._send(200, {"ok": False, "msg": "CodeArts 需要 Cookie 或 token"})
            else:
                use = _save_cred("codearts",
                                 {"cookie": cookie, "token": tok,
                                  "device_id": (body.get("device_id") or "").strip()}, name)
                _invalidate_state()
                self._send(200, {"ok": True, "msg": "已保存 %s" % use, "name": use})
        else:
            self._send(200, {"ok": False, "msg": "不支持的平台 %s" % platform})


    # ── 删除账号凭据 ──
    def _r_api_account_remove(self, body):
        platform = body.get("platform")
        name = (body.get("name") or "").strip()
        _del_msg = ""
        if platform == "workbuddy":
            results = _read_json(WB_LOGIN_FILE, [])
            if isinstance(results, list):
                new = [it for it in results if not _wb_match(it, name)]
                removed = len(new) != len(results)
                _write_json(WB_LOGIN_FILE, new)
            else:
                removed = False
        elif platform == "codearts":
            # 墓碑删除：凭据文件条目 + 客户端 vscdb 复活一并抑制（2026-10-09）
            key = (body.get("key") or "").strip()
            import importlib as _il
            try:
                _ca = _il.import_module("platforms.codearts")
                removed, _del_msg = _ca.remove_account(key or name)
            except Exception as _e:
                removed, _del_msg = False, "删除异常：%s" % str(_e)[:80]
        elif platform in CRED_FILES:
            key = (body.get("key") or "").strip()
            removed = _cred_store_remove(CRED_FILES[platform], key) if key else False
            if not removed:
                removed = _cred_store_remove(CRED_FILES[platform], name)
            if not removed and platform == "minimax":
                # 客户端会话卡（v2 auth store，凭据文件里没有条目）：
                # 删除 = 移除该本地登录记录（带备份），否则永远「未找到该账号」
                import importlib as _il
                try:
                    _mm = _il.import_module("platforms.minimax")
                    _ok, _msg = _mm.remove_local_session(name)
                    removed = bool(_ok)
                    _del_msg = _msg
                except Exception as _e:
                    _del_msg = "移除客户端会话失败：%s" % str(_e)[:80]
        else:
            removed = False
        _invalidate_state()
        _msg = "已删除" if removed else (
            _del_msg if _del_msg else "未找到该账号")
        self._send(200, {"ok": removed, "msg": _msg})


    # ── 修改账号备注名（只改本机显示名，不动凭据内容/平台账号） ──
    def _r_api_account_rename(self, body):
        platform = body.get("platform")
        name = (body.get("name") or "").strip()
        new_name = (body.get("new_name") or "").strip()
        if not new_name:
            self._send(200, {"ok": False, "msg": "备注名不能为空"})
        elif "\n" in new_name or len(new_name) > 40:
            self._send(200, {"ok": False, "msg": "备注名过长或含非法字符"})
        elif platform == "workbuddy":
            results = _read_json(WB_LOGIN_FILE, [])
            hit, dup = None, False
            if isinstance(results, list):
                for it in results:
                    if _wb_match(it, name):
                        hit = it
                    elif _wb_match(it, new_name):
                        dup = True
            if hit is None:
                self._send(200, {"ok": False, "msg": "未找到该账号"})
            elif dup and new_name != name:
                self._send(200, {"ok": False, "msg": "已有同名账号，请换一个备注名"})
            else:
                hit["alias"] = new_name
                _write_json(WB_LOGIN_FILE, results)
                _invalidate_state()
                self._send(200, {"ok": True, "msg": "已改名为「%s」" % new_name})
        elif platform in CRED_FILES:
            path = CRED_FILES[platform]
            old_key = (body.get("key") or "").strip() or name
            data = _read_json(path, {})
            if not isinstance(data, dict) or old_key not in data:
                self._send(200, {"ok": False, "msg": "未找到该账号"})
            elif new_name != old_key and new_name in data:
                self._send(200, {"ok": False, "msg": "已有同名账号，请换一个备注名"})
            elif new_name == old_key:
                self._send(200, {"ok": True, "msg": "名称未变化"})
            else:
                # 直接改键名：load_accounts() 以键名作为展示名，各适配器无需改动
                rec = data.pop(old_key)
                data[new_name] = rec
                _write_json(path, data)
                _invalidate_state()
                self._send(200, {"ok": True, "msg": "已改名为「%s」" % new_name})
        else:
            self._send(200, {"ok": False, "msg": "该平台不支持改名"})


    # ── 本地客户端导入：直接读取已登录的桌面端凭据（推荐路径） ──
    def _r_api_account_import_local(self, body):
        platform = body.get("platform")
        name = (body.get("name") or "").strip()
        if platform not in LOCAL_IMPORT_PLATFORMS:
            self._send(200, {"ok": False, "msg": "该平台暂不支持本地导入"})
        else:
            try:
                import local_import
                ok, msg, accs = local_import.read_local(platform)
                if ok and accs:
                    target = CRED_FILES[platform]
                    saved, merged = [], []
                    for i, (nm, ent) in enumerate(accs.items(), 1):
                        rec = {k: v for k, v in dict(ent).items() if k != "name"}
                        # 稳定身份回填（幂等）：本地导入记录只有 cookie/wps_sid，
                        # 不回填 user_id 的话身份退化为轮换令牌 → 重复导入另开新卡
                        ensure_identity(platform, rec)
                        # 理想名：用户填了备注名就优先用它，否则用客户端里的展示名
                        if name and len(accs) == 1:
                            ideal = name
                        elif name:
                            ideal = "%s·%d" % (name, i)
                        else:
                            ideal = nm
                        rec["via_local"] = True
                        # _alloc_account_name：同身份沿用旧名；名字被别的账号占了就加尾号，
                        # 绝不覆盖 → 这样客户端顶掉槽位后，看板里的老账号依旧在
                        use = _alloc_account_name(target, platform, ideal, rec)
                        merged += _dedupe_store(target, platform, use, rec)
                        _cred_store_set(target, use, rec)
                        saved.append(use)
                    after = _read_json(target, {})
                    total = len(after) if isinstance(after, dict) else 0
                    _invalidate_state()
                    self._send(200, {"ok": True, "msg": msg, "names": saved,
                                     "merged_from": merged, "total": total,
                                     "client_count": len(accs),
                                     # 看板里保留、但本地客户端本次已不再暴露的账号数
                                     # （MiniMax 只有 2 个登录槽位，登第 3 个号就会顶掉一个）
                                     "kept": max(0, total - len(accs))})
                else:
                    self._send(200, {"ok": False, "msg": msg})
            except Exception as e:
                self._send(200, {"ok": False, "msg": "本地导入异常：" + str(e)[:150]})


    # ── 手机号登录（OAuth 设备码）：弹网页 → 手机号+验证码 → 自动回填 ──
    # 与 WorkBuddy 的「手机号+验证码」等价，只是那家给了本地短信接口，
    # 这家走标准 OAuth 设备码：后端拿授权码 → 浏览器打开授权页 → 轮询取令牌。
    def _r_api_account_oauth_start(self, body):
        platform = body.get("platform")
        name = (body.get("name") or "").strip()
        sub = (body.get("sub") or "").strip() or None
        if not OAUTH_OK:
            self._send(200, {"ok": False, "msg": "后端未加载 oauth 模块"})
        elif platform not in _OAUTH_PROVIDERS:
            self._send(200, {"ok": False, "msg": "该平台暂不支持网页授权登录"})
        else:
            try:
                ok, msg, view = _oauth_start_job(
                    platform, lambda grant: _oauth_save(platform, name, grant),
                    sub=sub)
            except Exception as e:
                ok, msg, view = False, "发起网页授权登录失败：%s" % str(e)[:150], None
            out = dict(view or {})
            out["ok"] = ok            # view 里也有 ok（任务结果），必须最后覆盖为「发起是否成功」
            out["msg"] = msg
            self._send(200, out)


    # ── 手机号 + 短信验证码直登：看板输手机号 → 收码 → 看板输验证码 ──
    # 后端拉起可见 Chromium 打开 MiniMax 授权页，代用户填手机号 / 填验证码 /
    # 点「获取验证码」/ 点「立即登录」/ 点「授权」，用户只做两步输入。
    # （网页的「获取验证码」有腾讯滑块风控，所以发码动作放在真人可见的窗口里完成）
    def _r_api_account_sms_start(self, body):
        platform = body.get("platform")
        name = (body.get("name") or "").strip()
        phone = (body.get("phone") or "").strip()
        if not OAUTH_OK:
            self._send(200, {"ok": False, "msg": "后端未加载 oauth 模块"})
        elif platform in ("baidu_dumate", "dumate"):
            # DuMate 网页直登：无设备码流程，成功判定 = 百度 cookie 落地
            try:
                ok, msg, view = _oauth_start_dumate(
                    phone, name, lambda g: _dumate_web_save(name, g))
            except Exception as e:
                ok, msg, view = False, "发起 DuMate 登录失败：%s" % str(e)[:150], None
            out = dict(view or {})
            out["ok"] = ok
            out["msg"] = msg
            self._send(200, out)
        elif platform == "lingxi":
            # 灵犀网页短信直登：account.wps.cn 弹窗代点，抓 wps_sid
            try:
                ok, msg, view = _oauth_start_lingxi(
                    phone, name, lambda g: _lingxi_web_save(name, g))
            except Exception as e:
                ok, msg, view = False, "发起灵犀登录失败：%s" % str(e)[:150], None
            out = dict(view or {})
            out["ok"] = ok
            out["msg"] = msg
            self._send(200, out)
        elif platform == "zcode":
            # ZCode 短信直登：cli/init 流 + 弹窗代点（zai / bigmodel 双通道）
            sub = (body.get("sub") or "zai").strip()
            try:
                ok, msg, view = _oauth_start_zcode(
                    phone, sub, lambda g: _oauth_save("zcode", name, g), name)
            except Exception as e:
                ok, msg, view = False, "发起 ZCode 登录失败：%s" % str(e)[:150], None
            out = dict(view or {})
            out["ok"] = ok
            out["msg"] = msg
            self._send(200, out)
        elif platform == "trae":
            # Trae 短信直登：OAuth PKCE + 本地随机回调端口 + 三段兑换链
            # （身份/版本按线取真值：IDE→Trae CN，见 oauth_trae._trae_line_dirs）
            try:
                ok, msg, view = _oauth_start_trae(
                    phone, name, lambda g: _trae_oauth_save(name, g))
            except Exception as e:
                ok, msg, view = False, "发起 Trae 登录失败：%s" % str(e)[:150], None
            out = dict(view or {})
            out["ok"] = ok
            out["msg"] = msg
            self._send(200, out)
        elif platform == "codearts":
            # CodeArts 短信直登：自建 OAuth 会话（DPoP），refresh 归看板独享
            try:
                ok, msg, view = _oauth_start_codearts(
                    phone, name, lambda g: _codearts_oauth_save(name, g))
            except Exception as e:
                ok, msg, view = False, "发起 CodeArts 登录失败：%s" % str(e)[:150], None
            out = dict(view or {})
            out["ok"] = ok
            out["msg"] = msg
            self._send(200, out)
        elif platform == "teleagent":
            # TeleAgent 网页登录：弹可见 Chromium 走天翼 upms OAuth → master-auth
            # 统一登录 → 抓 SPA localStorage 的 console_token/refresh_token。
            # 手机号可空（填了尽力代填代点发码；滑块/验证码在窗口里人工完成）。
            try:
                ok, msg, view = _oauth_start_teleagent(
                    phone, name, lambda g: _teleagent_login_save(name, g))
            except Exception as e:
                ok, msg, view = False, "发起 TeleAgent 登录失败：%s" % str(e)[:150], None
            out = dict(view or {})
            out["ok"] = ok
            out["msg"] = msg
            self._send(200, out)
        elif platform == "officeace":
            # OfficeACE 短信直登：驱动桌面端本地 API（127.0.0.1:3004）完成华为云登录
            try:
                ok, msg, view = _oauth_start_officeace(
                    phone, name, lambda g: _officeace_login_save(name, g))
            except Exception as e:
                ok, msg, view = False, "发起 OfficeACE 登录失败：%s" % str(e)[:150], None
            out = dict(view or {})
            out["ok"] = ok
            out["msg"] = msg
            self._send(200, out)
        elif platform not in _OAUTH_PROVIDERS:
            self._send(200, {"ok": False, "msg": "该平台暂不支持短信验证码登录"})
        elif not _has_playwright():
            self._send(200, {"ok": False, "msg": "缺少依赖 playwright，无法拉起登录窗口。"})
        else:
            try:
                ok, msg, view = _oauth_start_sms_job(
                    platform, phone, lambda grant: _oauth_save(platform, name, grant))
            except Exception as e:
                ok, msg, view = False, "发起短信登录失败：%s" % str(e)[:150], None
            out = dict(view or {})
            out["ok"] = ok
            out["msg"] = msg
            self._send(200, out)

    def _r_api_account_sms_code(self, body):
        jid = (body.get("job") or "").strip()
        code = (body.get("code") or "").strip()
        if not OAUTH_OK:
            self._send(200, {"ok": False, "msg": "后端未加载 oauth 模块"})
        else:
            try:
                ok, msg = _oauth_submit_code(jid, code)
            except Exception as e:
                ok, msg = False, "提交验证码失败：%s" % str(e)[:150]
            self._send(200, {"ok": ok, "msg": msg})


    # ── OfficeACE：一键启动桌面端客户端（本地 API 未就绪时的兜底手段）──
    def _r_api_officeace_launch(self, body):
        if not OAUTH_OK:
            self._send(200, {"ok": False, "msg": "后端未加载 oauth 模块"})
        else:
            try:
                ok, base, note = _officeace_autostart(wait=25)
            except Exception as e:
                ok, base, note = False, "", "启动失败：%s" % str(e)[:150]
            self._send(200, {"ok": bool(ok),
                             "msg": note or ("客户端已就绪（%s）" % base if ok
                                             else "未能启动客户端"),
                             "api": base})

    def _r_api_officeace_status_post(self, body):
        # 见 do_GET（此处保留兜底，允许 POST 形式调用）
        if not OAUTH_OK:
            self._send(200, {"ok": False, "msg": "后端未加载 oauth 模块"})
        else:
            try:
                ok, base, info = _officeace_probe(timeout=5)
            except Exception as e:
                ok, base, info = False, "", {"error": str(e)[:120]}
            self._send(200, {"ok": bool(ok), "api": base,
                             "exe": _officeace_exe_path(),
                             "info": info})


    # ── 浏览器辅助登录（备用）：未安装桌面客户端时，用受控 Chromium 登录后抓凭据 ──
    def _r_api_account_browser_login(self, body):
        platform = body.get("platform")
        name = (body.get("name") or "").strip()
        if platform not in ("lingxi",):
            self._send(200, {"ok": False, "msg": "该平台暂不支持浏览器登录"})
        elif not _has_playwright():
            self._send(200, {"ok": False, "msg": "缺少依赖 playwright，浏览器登录不可用。"
                                                 "请在本看板所用的 Python 下执行： pip install playwright "
                                                 "然后 playwright install chromium；"
                                                 "也可改用「粘贴 token / Cookie」直接添加账号。"})
        else:
            jid = _new_blogin(platform, name)
            threading.Thread(target=_run_blogin, args=(jid, platform, name), daemon=True).start()
            self._send(200, {"ok": True, "job": jid})

    def _r_api_account_browser_login_status_post(self, body):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        jid = (q.get("job") or [""])[0]
        job = BLOGINS.get(jid)
        if not job:
            self._send(404, {"error": "job not found"})
        else:
            self._send(200, {"job": jid, "status": job["status"], "text": job["text"],
                             "finished": job["finished"], "ok": job["ok"],
                             "result": job["result"], "name": job["name"],
                             "platform": job["platform"]})


# ── 路由表（2026-10-13 路由表化：elif 巨链 → 显式分发表）─────────────────
# 新增路由 = 写一个 Handler._r_* 方法 + 在下表注册一行；do_GET/do_POST 不再改动。
_GET_ROUTES = {
    "/": Handler._r_index,
    "/index.html": Handler._r_index,
    "/dashboard": Handler._r_index,
    "/api/state": Handler._r_api_state,
    "/v1/models": Handler._r_v1_models,
    "/api/proxy_usage": Handler._r_api_proxy_usage,
    "/api/proxy_info": Handler._r_api_proxy_info,
    "/api/progress": Handler._r_api_progress,
    "/api/log": Handler._r_api_log,
    "/api/account/browser_login_status": Handler._r_api_account_browser_login_status,
    "/api/account/oauth_status": Handler._r_api_account_oauth_status,
    "/api/officeace/status": Handler._r_api_officeace_status,
    "/api/ping": Handler._r_api_ping,
}

_POST_ROUTES = {
    "/v1/chat/completions": Handler._r_v1_chat_completions,
    "/api/run": Handler._r_api_run,
    "/api/refresh": Handler._r_api_refresh,
    "/api/account/wb_send": Handler._r_api_account_wb_send,
    "/api/account/wb_login": Handler._r_api_account_wb_login,
    "/api/account/wb_batch_send": Handler._r_api_account_wb_batch_send,
    "/api/account/wb_batch_login": Handler._r_api_account_wb_batch_login,
    "/api/account/add": Handler._r_api_account_add,
    "/api/account/remove": Handler._r_api_account_remove,
    "/api/account/rename": Handler._r_api_account_rename,
    "/api/account/import_local": Handler._r_api_account_import_local,
    "/api/account/oauth_start": Handler._r_api_account_oauth_start,
    "/api/account/sms_start": Handler._r_api_account_sms_start,
    "/api/account/sms_code": Handler._r_api_account_sms_code,
    "/api/officeace/launch": Handler._r_api_officeace_launch,
    "/api/officeace/status": Handler._r_api_officeace_status_post,
    "/api/account/browser_login": Handler._r_api_account_browser_login,
    "/api/account/browser_login_status": Handler._r_api_account_browser_login_status_post,
}