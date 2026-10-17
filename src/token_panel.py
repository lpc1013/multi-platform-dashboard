# -*- coding: utf-8 -*-
"""
token_panel.py —— Token 消耗面板的 Python 桥接层

复用 wb-usage-tracker 的 Node 采集内核（lib/gen.js）+ 官方渲染模板（assets/template.html），
由本 Python 看板统一对外提供：

    GET /tokens         → 注入数据后的完整看板页（官方渲染器，两栏自带导航与过滤器）
    GET /api/tokens     → 三源采集的 DATA JSON

设计要点：
    - 采集内核较重（首扫 12–15s、934 个 jsonl 流式解析），故结果做 TTL 缓存，并由后台线程周期刷新；
    - 对外只给已脱敏的展示名（脱敏自检 assertNoLeak 在 Node 侧执行，凭证不跨进程暴露）；
    - 路径可配：环境变量 WB_USAGE_DIR 指向 wb-usage-tracker/dashboard，默认 E:/AI/AInews/wb-usage-tracker/dashboard；
    - node 可执行文件可配：环境变量 NODE_EXE，否则自动探测。

安全：本模块只读数据源、不写回；凭证库仅在 Node 侧内存解锁，Python 侧只拿到脱敏后的 DATA。
"""
import os
import sys
import json
import time
import threading
import subprocess
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))

DEFAULT_DIR = "E:/AI/AInews/wb-usage-tracker/dashboard"
WB_USAGE_DIR = os.environ.get("WB_USAGE_DIR", DEFAULT_DIR).replace("\\", "/")
DUMP_JS = os.path.join(HERE, "token_dump.js")
# 模板解析顺序：环境变量显式指定 > 仓库内副本（src/assets/template.html，规范源）> 旧版外部路径。
# 仓库内副本保证克隆即自包含；对看板改样式请改仓库副本，勿再改外部 wb-usage-tracker 的（已停更）。
_TEMPLATE_REPO = os.path.join(HERE, "assets", "template.html")
_TEMPLATE_EXT = os.path.join(WB_USAGE_DIR, "assets", "template.html")
TEMPLATE = _TEMPLATE_REPO if os.path.isfile(_TEMPLATE_REPO) else _TEMPLATE_EXT

TTL = 60  # 缓存刷新周期（秒）
SCAN_TIMEOUT = 150  # 单次采集超时（秒，含首扫）
NODE_CANDIDATES = [
    os.environ.get("NODE_EXE", ""),
    "node",
    "C:/Users/Pengcheng_Li/.workbuddy-ai/binaries/node/versions/22.22.2-6/node.exe",
    "E:/clx/node.exe",
]

_cache = {"data": None, "ts": 0.0, "err": None, "scanning": False}
_lock = threading.Lock()
_started = {"ok": False}


def _find_node():
    for c in NODE_CANDIDATES:
        if not c:
            continue
        if os.path.isfile(c):
            return c
        if shutil.which(c):
            return c
    return None


NODE = _find_node()


def _run_dump():
    if not NODE:
        raise RuntimeError("未找到 node 可执行文件，无法运行 Token 采集内核（可设环境变量 NODE_EXE）")
    if not os.path.isfile(DUMP_JS):
        raise RuntimeError("缺少 token_dump.js：" + DUMP_JS)
    if not os.path.isfile(TEMPLATE):
        raise RuntimeError("未找到官方渲染模板：" + TEMPLATE)
    env = dict(os.environ)
    env["WB_USAGE_DIR"] = WB_USAGE_DIR
    try:
        out = subprocess.run(
            [NODE, DUMP_JS, WB_USAGE_DIR],
            # Node 永远以 UTF-8 写 stdout：必须显式声明，否则中文 Windows 会按 GBK
            # 解码，触发 subprocess _readerthread 的 UnicodeDecodeError 或截断 JSON。
            capture_output=True, encoding="utf-8", errors="replace",
            timeout=SCAN_TIMEOUT, env=env,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Token 采集超时（>%ss）" % SCAN_TIMEOUT)
    if out.returncode != 0:
        raise RuntimeError("采集内核返回错误(%d)：%s" % (
            out.returncode, (out.stderr or out.stdout or "").strip()[:400]))
    return json.loads(out.stdout)


def collect(force=False):
    """取数据：优先返回新鲜缓存；过期/强制则重新扫描（与后台线程去重）。"""
    now = time.time()
    do_scan = False
    with _lock:
        fresh = (_cache["data"] is not None
                 and (now - _cache["ts"]) < TTL
                 and not force)
        if fresh:
            return _cache["data"]
        if _cache["scanning"]:
            do_scan = False  # 交给在跑的扫描
        else:
            _cache["scanning"] = True
            do_scan = True

    if do_scan:
        try:
            data = _run_dump()
        except Exception as e:
            with _lock:
                _cache["err"] = str(e)
                _cache["scanning"] = False
            return _cache["data"]
        with _lock:
            _cache["data"] = data
            _cache["ts"] = time.time()
            _cache["err"] = None
            _cache["scanning"] = False
        return data

    # 等待在跑的扫描完成（最多 SCAN_TIMEOUT）
    deadline = time.time() + SCAN_TIMEOUT
    while time.time() < deadline:
        with _lock:
            if _cache["data"] is not None:
                return _cache["data"]
            if not _cache["scanning"]:
                break
        time.sleep(0.5)
    with _lock:
        return _cache["data"]


def render_html():
    data = collect()
    if data is None:
        data = {"_notice": (_cache.get("err") or "Token 采集尚未就绪，请稍候重试")}
    html = open(TEMPLATE, "r", encoding="utf-8").read()
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    if "/*__WBD_DATA__*/null" in html:
        html = html.replace("/*__WBD_DATA__*/null", payload)
    elif "/*__WBD_DATA__*/" in html:
        html = html.replace("/*__WBD_DATA__*/", payload)
    else:
        raise RuntimeError("模板缺少数据注入点（请先运行 build_template.js）")
    return html.encode("utf-8")


def _background_refresh():
    while True:
        try:
            collect()
        except Exception:
            pass
        time.sleep(TTL)


def ensure_started():
    """启动后台刷新线程（幂等）。线程首轮即预热缓存，之后每 TTL 秒刷新一次。"""
    if _started["ok"]:
        return
    t = threading.Thread(target=_background_refresh, daemon=True)
    t.start()
    _started["ok"] = True
