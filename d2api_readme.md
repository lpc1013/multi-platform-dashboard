# dumate2api

> 架构与代码详解见 [ARCHITECTURE.md](ARCHITECTURE.md)。

把三个上游的模型能力统一转换成 **OpenAI / Anthropic / Google 兼容 API**，供
Codex CLI、Claude Code、cc-switch 等客户端本地使用：

| 通道 | 上游 | 凭证来源 |
|---|---|---|
| **百度搭子**（DuMate） | 本地 HTTP 上游（客户端自带后端） | 桌面客户端登录态 |
| **千问办公**（QwenWork） | 云端网关，进程内直连 | 自持（OAuth Device Flow 换取） |
| **TRAE Work** | 云端网关，进程内直连 | 自持（OAuth 换取） |

**靠模型名前缀分流**，不猜模型名：

| 调用方传的模型名 | 路由到 |
|---|---|
| `model-text` / `glm-5` 等（无前缀） | 百度搭子 |
| `qwen/pro` / `qwen/flash` | 千问办公 |
| `traework/glm-5.2` | TRAE Work |
| 未知前缀（如 `qwn/pro`） | **400 报错，不静默回落** |

> 用前缀而不是猜名字：两侧模型名会撞车（搭子有 `glm-5`，千问上游也是 GLM 系），
> 猜错了两侧都返回 200，从响应里根本看不出来。未知前缀若静默跑到搭子，
> 会拿到「看起来成功但完全不是想要的结果」，比直接 400 难查得多。

## 快速开始

```bash
git clone <仓库地址> && cd dumate2api
npm start          # 网关，默认 http://127.0.0.1:9080
```

首次运行会自动拉起 DuMate 后端（**不需要打开 DuMate 界面**），看到这行即就绪：

```
✓ DuMate main-server verified on port 8980 (headless, no DuMate GUI needed)
✓ dumate2api listening on http://127.0.0.1:9080
```

自检：`curl http://127.0.0.1:9080/health` 应返回 `"upstream_managed":true`。

```bash
curl http://127.0.0.1:9080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"model-text","messages":[{"role":"user","content":"hello"}]}'
```

## 前置条件

1. **Node.js >= 18**。网关本体**零第三方依赖**，只用内置模块；
   `playwright-core` 仅管理端的浏览器登录器需要。
2. **至少配置一条通道**（三条可同时用，也可只留一条）：

**百度搭子**
   - DuMate 桌面客户端已安装，并且至少登录过一次
   - 下载：https://cloud.baidu.com/doc/Dumate/index.html
   - 用百度账号登录一次即可，之后**不再需要启动客户端界面**
   - 登录态（cookie）保存在 `%APPDATA%\qianfan-desktop-app\auth.json`
   - 若安装目录不是默认位置，设置 `DUMATE_INSTALL_DIR`

**千问办公**（可选，只有要用 `qwen/*` 模型时才需要）
   - 登录一次即可，**之后不依赖官方客户端**（凭证自持，见下文）
   - 需要官方客户端的 wasm 文件（运行时从安装目录读取，**不进仓库**）
   - 若探测不到安装目录，设置 `DUMATE_QWENWORK_INSTALL` 或 `CB_QWENWORK_WASM`
   - 设为 `DUMATE_QWENWORK_AUTOSTART=off` 可完全关闭这条通道

**TRAE Work**（可选，只有要用 `traework/*` 模型时才需要）
   - 独立 OAuth 登录，**不依赖 TRAE 客户端**
   - 设为 `DUMATE_TRAEWORK_AUTOSTART=off` 可完全关闭这条通道

> 三条通道独立降级：任一条不可用时网关仍会监听，`/health` 的
> `channels.*.ready` 会报 false，**不阻断启动**。

## 原理

### 通道一：百度搭子（DuMate）

DuMate 桌面客户端（Electron + Go 后端）内置了一个本地 OpenAI 兼容 API：

```
http://127.0.0.1:<动态端口>/api/qianfanproxy/v1/chat/completions
```

- 端口由 `dumate-main-server.exe` 启动时动态分配（通过 `--port=` 参数）
- 认证使用 `Authorization: Bearer nokey`（走已登录的百度 BCE 会话）
- 支持流式 SSE，响应包含 `reasoning_content`（思维链）

### 通道二：千问办公（QwenWork）

**进程内直连**，不需要任何外部服务。`src/qwenwork/` 调用官方客户端的 wasm
生成请求体，再发到云端网关 `gateway.qwenwork.cn`。

三条硬约束（都是实测踩出来的）：

1. **必须依赖官方 wasm**。请求体必须由 `qoder_auth_wasm_bg.wasm` 生成，
   本地自实现的编码会被服务端拒（`400 Invalid agent chat JSON body`）。
   wasm 文件**不进仓库**——它是客户端二进制资产，运行时从安装目录自动探测
   （取版本号最大的那个，客户端多版本并存）。
2. **不套模型映射**。千问的模型名（`pro`/`flash`）不在搭子别名表里，
   过 `mapModel` 会被兜底成 `model-text`，前缀随之失效。
3. **外层永远 HTTP 200**，真实错误在信封的 `statusCodeValue` 里。且它不发
   `data: [DONE]` 而是用 `event:finish` 收尾——转发时按 OpenAI 规范补发 `[DONE]`，
   否则 Codex 等客户端认为响应未完成。

**凭证自持**：早期版本只读官方客户端的 `auth-v2.dat`（Electron safeStorage 加密），
同一时刻只有一份登录态。现在走客户端自己的 OAuth Device Flow（PKCE），
**可多账号并存、可增删、可指定主账号**，换账号不需要打开千问客户端。

**积分是三个独立的池**：`daily`（每日免费额度，每天 00:00 +08:00 重置）、
`monthly`（订阅套餐）、`longterm`（充值赠送）。三池**不能相加**，
与搭子的积分也**互不相干**。真实消耗在管理端「积分明细 / 请求日志」里按条查看。

> 「每日上限」接口不返回，由「观测峰值 + 配置兜底」推断
> （`DUMATE_QWENWORK_DAILY_CREDITS`），界面会标出来源是 `observed` 还是
> `config-lower-bound`。

### 通道三：TRAE Work

同样是**进程内直连**，凭证由本项目自己走 OAuth 换取（`src/traework/login.js`），
不依赖 TRAE 客户端。单一 credits 体系（签到领取），额度按 `usage_summary` 解析。

### 搭子的两条凭证链路

搭子有两条独立链路，**能力互补但各自有硬伤**——这是本项目最容易误解的地方：

| | 桌面凭证（9080/9082） | 网页凭证（9084） |
|---|---|---|
| 凭证 | `%APPDATA%\qianfan-desktop-app\auth.json` | `data/web-accounts.json`（cookie） |
| 链路 | 经 `dumate-main-server.exe`（8980） | 直连 `dumate-svc.baidu.com` |
| 账号数 | **同一时刻只有一份登录态** | **可多账号并存、轮换** |
| 续期 | 过期必须开客户端重登 | token 自动续（约 1 小时一换） |
| 协议 | OpenAI / Anthropic / **Responses** / Google | OpenAI / Anthropic（**无 Responses**） |
| 三通道前缀分流 | ✅ | ❌ 只有搭子一条通道 |

**为什么不合并成一条**：桌面链路有三个网页链路没有的能力——`responses`
（Codex CLI 0.155+ 只认它）、`count_tokens`、三通道前缀分流。整体切到网页凭证
等于把这些一起丢掉；而桌面凭证唯一的硬伤是「同一时刻只有一份登录态、
过期必须开客户端重登」，那正好是网页链路能补的。

所以做的是**回落**而不是切换（见下文），另外把网页链路单独开一个端口 9084，
需要多账号轮换时用。

### 网页凭证网关（9084）

```bash
start-web-gateway.bat          # 或：node src/web-gateway.js
```

独立进程，对外协议与 9080 一致（OpenAI / Anthropic），**客户端换个 base_url 即可**。
用途是「用网页账号池跑模型」：多账号自动轮换、token 自动续期、**不依赖桌面客户端**。

账号在管理端「账号管理」页添加。**与 9080 是两套独立的东西**：
9080 用桌面凭证（单账号），9084 用网页凭证（多账号），可同时跑。

> 9084 没有 `responses` 端点——Codex CLI 用不了它，请指向 9080。

### 桌面凭证不可用时的自动回落

桌面凭证失效时（cookie 过期），9080 会**自动把请求交给网页凭证池**，
所以「客户端登录态过期」不再等于「服务全挂」：

- 触发条件严格限定为「**还没交给下游**」：后端连不上，或后端回 4xx/5xx
- 一旦开始写响应就不再换链路——半截响应再换链路会让客户端收到两段拼接的内容
- 埋点带 `credential_source`；`/health` 的 `channels.dumate.fallback` 报回落是否可用
- 用 `DUMATE_WEB_FALLBACK=0` 关闭

> **排障要点**：桌面 `ready=false` 而 `fallback.available=true` 时，请求仍会成功，
> 但走的是网页池。不看这一项会以为一切正常。

### 数据流

```
Codex CLI ──── OpenAI/Responses ─┐
                                 ├──→ dumate2api :9080 ──┬──→ DuMate main-server :8980 ──→ 百度千帆
Claude Code ─── Anthropic ───────┤   （桌面凭证）        ├──→ 千问办公云端网关（进程内直连）
任意客户端 ──── Google ──────────┘                       └──→ TRAE Work 云端网关（进程内直连）
                                     └─ 桌面凭证失效时 ──→ 网页凭证池（自动回落）

任意客户端 ──── OpenAI/Anthropic ───→ :9084（网页凭证，多账号轮换）
```

### 进程一览

| 进程 | 端口 | 入口 | 职责 |
|---|---|---|---|
| 网关（稳定版） | 9080 | `stable/src/server.js` | 对外长期服务，冻结快照 |
| 网关（开发） | 9082 | `src/server.js` | 开发调试，改动都在这里 |
| 管理端 | 9083 | `src/admin/server.js` | 管理 API + 托管前端，读 9082 |
| 网页凭证网关 | 9084 | `src/web-gateway.js` | 多账号轮换跑模型 |
| DuMate 后端 | 8980 | 由网关拉起 | 真实模型链路 |

> 管理端**不代理模型协议**——网关已经在做，多一跳只会多一个故障点。
> 所有进程通过 `data/` 目录下的文件通信，不通过 IPC。

## 使用

### 启动 / 停止 / 重启

```bash
node src/server.js        # 直接运行
start.bat                 # 双击（Windows）
stop.bat                  # 停止（不动 DuMate 客户端与 cc-switch，可重复执行）
restart.bat               # 重启

DUMATE2API_PORT=9080 node src/server.js   # 自定义端口
```

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DUMATE2API_PORT` | `9080` | 网关监听端口 |
| `DUMATE2API_HOST` | `127.0.0.1` | 网关监听地址 |
| `DUMATE_REQUIRE_KEY` | 未设置 | 设为 `1` 才校验 API Key。**默认关闭**：不设置时任何来源无需 key 即可调用 |
| `DUMATE_INSTALL_DIR` | DuMate 默认安装路径 | DuMate 安装目录 |
| `DUMATE_UPSTREAM_PORT` | `8980` | 自建后端监听端口 |
| `DUMATE_AUTOSTART` | `auto` | `auto`=无实例时才拉起；`always`=总是自己拉起；`off`=只用已有实例 |
| `DUMATE_UPSTREAM_LOG` | - | 设为 `1` 时把后端日志打到 stdout |
| `DUMATE_MIN_MAX_TOKENS` | `65536` | 输出预算下限，防止思维链吃光正文（`0` 关闭该策略） |
| `DUMATE_MAX_MAX_TOKENS` | `131072` | 输出预算上限 |
| `DUMATE_ADMIN_PORT` | `9081` | 管理端监听端口 |
| `DUMATE_ADMIN_HOST` | `127.0.0.1` | 管理端监听地址 |
| `DUMATE_ADMIN_DATA` | `./data` | 数据目录（账号、key、请求日志） |
| `DUMATE_ADMIN_GATEWAY_PORT` | `9080` | 管理端去读哪个网关的状态；开发实例应设为 `9082` |
| `DUMATE_QWENWORK_AUTOSTART` | `auto` | `auto`=启用千问通道 / `off`=关闭 |
| `DUMATE_QWENWORK_INSTALL` | 自动探测 | 千问办公安装根（wasm 探测失败时手动指定） |
| `CB_QWENWORK_WASM` | 自动探测 | 直接指定 `qoder_auth_wasm_bg.wasm` 的完整路径 |
| `DUMATE_QWENWORK_DAILY_CREDITS` | `100` | 千问每日免费额度的配置兜底下限 |
| `DUMATE_QWENWORK_MIN_MAX_TOKENS` | `16384` | 千问输出预算下限 |
| `DUMATE_QWENWORK_DEFAULT_MAX_TOKENS` | `131072` | 千问默认输出预算（客户端未给 `max_tokens` 时） |
| `DUMATE_TRAEWORK_AUTOSTART` | `auto` | `auto`=启用 TRAE 通道 / `off`=关闭 |
| `DUMATE_TRAEWORK_MIN_MAX_TOKENS` | `16384` | TRAE 输出预算下限 |
| `DUMATE_TRAEWORK_MODELS_CACHE_MS` | `300000` | TRAE 模型表缓存（5 分钟） |
| `DUMATE_AUTO_CHECKIN_HOUR` / `_MINUTE` | `9` / `17` | 每日自动签到时刻。**两个都要设**，只设 HOUR 不生效 |
| `DUMATE_TASK_POLL_MINUTES` | `30` | 任务轮询间隔（`0` 关闭）。低于 5 分钟会被拒绝；同时驱动 TRAE 自动签到 |
| `DUMATE_WEB_FALLBACK` | 未设置（开启） | 设 `0` 关闭「桌面凭证不可用时回落到网页凭证池」 |
| `DUMATE_WEB_GATEWAY_PORT` / `_HOST` | `9084` / `127.0.0.1` | 网页凭证网关监听 |
| `DUMATE_QWENWORK_ACCOUNT` | 未设置 | 指定千问用哪个账号（填账号 **id**）。优先级：环境变量 > 账号文件 `preferred` > 池里第一个 |
| `DUMATE_QWENWORK_AGENT_DISCIPLINE` | 未设置（注入） | 设 `0` 关闭「执行纪律」注入（见下文说明） |
| `DUMATE_QWENWORK_CREDIT_CACHE_MS` | `30000` | 千问余额缓存时长 |
| `DUMATE_POINTS_METER` | 未设置（开启） | 设 `0` 关闭搭子的余额游标采集（关闭后请求日志不再有逐条消耗） |
| `DUMATE_BROWSER_PATH` | 自动探测 Edge/Chrome | 浏览器登录器找不到浏览器时手动指定 |
| `DUMATE_UPSTREAM_TIMEOUT_MS` | `600000` | 上游请求超时 |
| `DUMATE_UPSTREAM_CWD` | DuMate 安装根 | 拉起 `dumate-main-server.exe` 时的工作目录 |
| `DUMATE_ADMIN_SECURE_COOKIE` | 未设置 | 设 `1` 才给会话 cookie 加 `Secure`（本地 http 下会被浏览器丢弃） |
| `DUMATE_DEBUG` | - | 设为 `1` 输出端口发现过程调试信息 |
| `DUMATE_WEB_BASE` / `DUMATE_WEB_TIMEOUT` | `https://www.dumate.cn` / `20000` | 搭子网页端基址与超时 |
| `DUMATE_GATEWAY_HOST` | `dumate-svc.baidu.com` | 网页凭证换模型 token 的目标主机 |

> 完整列表见 [CLAUDE.md](CLAUDE.md)（含网页账号池、任务轮询、自动签到等）。

> `DUMATE2API_KEY` 在早期版本里被文档描述为「代理 API Key」，但代码中从未读取它，
> 设置它并不会带来任何鉴权效果。真实开关是 `DUMATE_REQUIRE_KEY`，配套的 key
> 在管理端「API Key」页创建。

### 管理端（可选但推荐）

另起一个终端：

```bash
npm run admin          # 默认 http://127.0.0.1:9081
```

首次启动会生成管理员口令并打印在终端。**改的是哪个网关端口就要带对应变量**，
否则管理端会读到别的实例的数据：

```bash
DUMATE_ADMIN_GATEWAY_PORT=9082 npm run admin
```

管理端提供：仪表盘、模型管理、API Key、登录态、积分明细、账号管理、
用量统计、请求日志、聊天测试台。

**通道切换**：顶栏可在「百度搭子 / 千问办公 / TRAE Work」间切换，各页面据此
显示对应通道的数据。三条通道的账**各自独立**——搭子靠上游账单 + 余额游标，
千问是三个积分池，TRAE 是每账号独立的 credits，**三边数字不能相加**。

开发时用 `start-dev.bat`（网关 9082 + 管理端 9083），与稳定版 9080 互不干扰。
前端开发：`cd web && npm install && npm run dev`。

### 管理端各页做什么

| 页面 | 回答什么问题 |
|---|---|
| 仪表盘 | 三个通道的健康、用量、账号状态、即将过期积分 |
| 模型管理 | 这条通道有哪些模型、上下文/输出上限多大、倍率多少、额度还剩多少 |
| API Key | 给外部客户端签发密钥（含 IP 白名单、模型白名单、通道绑定） |
| 登录态 | 当前凭证是谁、什么时候过期 |
| 积分明细 | 积分从哪来、怎么没的（含签到/任务/抽奖记录、额度包、签到日历） |
| 账号管理 | 增删账号、跑任务、开轮询（**操作台**，记录在积分明细页） |
| 用量统计 | 请求量/Token 趋势，按通道、模型、路径拆分 |
| 请求日志 | 逐条明细：模型映射、耗时、首字延迟、**这条请求花了多少积分** |
| 聊天测试台 | 不签发密钥直接试调某个模型名能不能跑通 |

**聊天测试台**（`chatlab`）刻意**绕过密钥与 IP 管控**，只要求管理员会话。
定位是「在管理端里验证某个模型名能不能跑通」，不必先去 API Key 页签发密钥、
再配客户端。它走的是与 9084 同一套账号池，**消耗真实积分**，返回便于展示的
结构化数据（含每条回答的实测消耗）。与 9084 的分工：9084 面向外部客户端、
带鉴权、做协议兼容；测试台是内部试调、不做协议翻译。

### API Key 的能力

密钥形如 `dmk_...`，**只存 sha256**（`data/` 被复制走也无法还原明文），
明文仅在创建那一次返回。创建时可限定三个维度：

| 维度 | 说明 |
|---|---|
| `ip_allowlist` | 允许的来源（支持 CIDR）。**fail-closed**：写错一条会让这把 key 对所有来源拒绝，而非意外放行 |
| `model_allowlist` | 允许调用的模型名 |
| `channel` | 绑定通道（`dumate` / `qwenwork` / `traework`，留空不限） |

设了 `channel` 的 key 去调别的通道的模型会返回 **403 `channel_not_allowed`**。

> **鉴权默认关闭**：不设 `DUMATE_REQUIRE_KEY=1` 时任何来源无需 key 即可调用。
> 本地自用够用，**对外暴露必须打开**。

### 使用千问办公 / TRAE 通道

模型名加前缀即可，无需额外配置：

```bash
# 千问办公
curl http://127.0.0.1:9080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen/pro","messages":[{"role":"user","content":"hello"}]}'

# TRAE Work
curl http://127.0.0.1:9080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"traework/glm-5.2","messages":[{"role":"user","content":"hello"}]}'
```

可用模型由上游下发，清单见 `GET /v1/models` 或管理端「模型管理」页。

### 添加账号：浏览器登录器

管理端「账号管理」页可**弹出受控浏览器窗口**登录并自动抓取 cookie
（`src/login-browser.js`，唯一用到 `playwright-core` 的地方）。

**为什么必须自己开窗口**：搭子的登录态载体是浏览器 cookie，而产品上没有面向
第三方程序的登录票据接口（实测 `qianfanproxy` 下只有秒哒的 `login_ticket`，
且它校验跳转目标必须是 `miaoda.cn`）。读系统浏览器（Edge/Chrome）的 cookie 库
也不行——运行中独占文件锁，且新版 Chromium 用了 App-Bound Encryption。

所以程序自己开一个受控窗口：用户在里面登录，我们**从自己这个窗口**读 cookie。
这是唯一既不依赖外部状态、也不碰用户浏览器数据的做法。它复用系统已装的
Edge/Chrome（`playwright-core` 不下载 Chromium），因此只多约 14MB 依赖
而不是 130MB+。找不到浏览器时用 `DUMATE_BROWSER_PATH` 指定。

> 也可以手动粘贴 cookie 添加账号——两条路径都支持。

### 千问的「执行纪律」注入

千问上游是**对话型**产品，其脚手架鼓励「每完成一步汇报一句」；Codex 的
`AGENTS.md` 里也有同样的进度播报要求。两者叠加后模型会把播报当成一次完整回合：
只输出 `进度：N/8｜下一步：写第 N 章` 就结束，**不调用任何工具**——Codex 收到
「无工具调用」的回合即判定任务完成并退出，用户看到的就是「没按要求做完就退出」。

所以网关对**确实带工具**的请求自动注入一段执行纪律（幂等，工具全被过滤掉的
纯对话不注入，避免干扰正常回答）。用 `DUMATE_QWENWORK_AGENT_DISCIPLINE=0` 关闭。

> 相关但不同的一件事：千问 `flash` 档位做重创作/长任务会失败（推理很长、
> 只做「核对」这类准备动作就收尾），**这是档位能力差异，不是提示词能修的**。
> 重创作请用 `qwen/pro`。

## 积分自动化（签到 / 抽奖 / 任务）

网关除了转发模型请求，还能管理上游账号的**积分获取**——签到、抽奖、跑任务。
这些都走**网页端**接口（`dumate.baidu.com`），与本地代理网关是两套东西：
前者拿积分，后者花积分。

> **前提**：需要网页凭证（cookie）。在管理端「账号管理」页添加账号——
> 走浏览器登录，或手动粘贴 cookie。桌面客户端的登录态不参与这些功能。

### 能力一览

| 功能 | 通道 | 幂等 | 可定时 |
|---|---|---|---|
| 签到 | 百度搭子 | ✅ 当天已签则跳过 | ✅ 可自动 |
| 抽奖 | 百度搭子 | ❌ 消耗次数、不可逆 | ❌ **仅手动** |
| 跑任务 | 百度搭子 | ✅ 已完成会被服务端拒 | ✅ 可轮询 |
| 签到 | TRAE Work | ✅ 已签再 claim 不报错 | ✅ 可自动 |

**为什么抽奖不做定时**：签到幂等，多跑无害；抽奖消耗次数且不可逆，
自动跑掉用户可能想留着的次数。所以定时只覆盖签到与任务，抽奖永远手动触发。

### 签到

管理端「账号管理」页有「签到」按钮（单账号）与「一键签到」（全部账号）。
签到结果报的是**到账差值**，不是余额总额——上游 `claim` 只回 `{code:0}`，
从不告诉发了多少，所以网关在签到前后各取一次余额，差值即实际到账。

差值为 **0** 说明奖励延迟入账，为**负数**说明上游结算异常或并发消耗，
两者都如实显示而不是粉饰成 null（0 会被读成「签到没发积分」）。

### 自动签到

管理端可开启每日自动签到，配置落盘到 `data/auto-checkin.json`：

| 变量 | 默认 | 说明 |
|---|---|---|
| `DUMATE_AUTO_CHECKIN_HOUR` | `9` | 自动签到时刻（小时） |
| `DUMATE_AUTO_CHECKIN_MINUTE` | `17` | 自动签到时刻（分钟） |

> **两个都要设**，只设 HOUR 不生效。定时器只活在进程内，配置落盘是为了
> 重启后知道上次开没开、几点跑。

### 任务轮询

任务**不是每日重置**——重复完成会被服务端拒（`code 410121` 该任务次数已发放），
所以轮询的价值是「有新任务出现时自动做完」，而不是每天刷一遍。

能自动化的边界（实测确认，不是推测）：

| 任务类型 | 能否自动 | 说明 |
|---|---|---|
| `QUERY_INPUT` | ✅ | 任务自带 query 提示词，发一条内容匹配的消息再上报 |
| `USE_SKILL` | ✅ | 走一次带技能的对话即可触发上报 |
| `PC_PUSH` | ❌ | 网页端明确提示「请前往桌面端或移动端完成」 |
| `INVITATION` / `INVITED` | ❌ | 需要真人注册 / 别人的邀请码 |

| 变量 | 默认 | 说明 |
|---|---|---|
| `DUMATE_TASK_POLL_MINUTES` | `30` | 轮询间隔分钟（`0` 关闭）。**低于 5 分钟会被拒绝** |

> **TRAE 的签到搭在同一轮轮询里**（与搭子任务串行，不是并发——两边打的是
> 同一批上游，并发只会把瞬时请求量翻倍）。所以开启轮询后，TRAE 账号也会
> 随轮询自动签到；TRAE 通道不可用时静默跳过，不会让轮询因可选通道失败而中断。

> **间隔为什么是 30 分钟**：客户端自己的轮询是 10 秒，但**只在页面可见时**轮询
> （`document.hidden` 就停）——正常用户不会 24 小时持续请求。实测任务接口没有
> 频率限制，但这不等于可以高频：风控通常在设备指纹/行为层，封禁可能延迟触发。
> 而且任务不是每日重置，高频轮询收益为零。所以每次还加 ±20% 随机抖动——
> 固定整点节奏本身就是明显的机器特征。账号之间串行加 2s 延迟，避免并发打同一上游。

### 数据与记录

签到 / 抽奖 / 任务三类记录都写进 `data/activity.jsonl`，在管理端
「积分明细」页按时间轴查看（任务执行明细也在那里，不再单独设页——
它们回答的是同一个问题：积分从哪来）。

`data/points-cursor.jsonl` 记录搭子的余额游标：每条请求结束后记一次余额，
**相邻两次差值即该请求的成本**。上游账单无法把扣费归因到具体请求
（同一时间窗有 1~3 条候选），硬挑一条等于编数字。

## cc-switch 配置教程

### 第 0 步：先把网关跑起来

```bash
cd <你克隆仓库的目录>
npm start
```

自检：`curl http://127.0.0.1:9080/health` 应返回 `"upstream_managed":true`。

### 第 1 步：添加 Claude 供应商

打开 cc-switch → **Claude** 标签 → 添加供应商：

| 字段 | 值 |
|------|-----|
| 名称 | `DuMate 搭子 API (Claude)` |
| API 格式 | `anthropic` |
| Base URL | `http://127.0.0.1:9080`  ← **不要加 `/v1`** |
| API Key | `nokey` |
| 模型 | `model-text`（条目内可切 `model-artifact-validate`） |

完整 env（点「高级/编辑 JSON」时可直接粘贴）：

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:9080",
    "ANTHROPIC_AUTH_TOKEN": "nokey",
    "ANTHROPIC_API_KEY": "nokey",
    "ANTHROPIC_MODEL": "model-text",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "model-text",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "model-text",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "model-text"
  }
}
```

> 必须把 haiku / sonnet / opus 全部设为 `model-text`。否则 Claude Code 切换模型
> 档位时会发来 `claude-haiku-4-5` 之类的名字，虽然会被兜底映射，但显式写死更稳。

### 第 2 步：添加 Codex 供应商

打开 cc-switch → **Codex** 标签 → 添加供应商：

| 字段 | 值 |
|------|-----|
| 名称 | `DuMate 搭子 API (Codex)` |
| API 格式 | `openai_responses`（网关侧翻译成 chat/completions 后再转发上游） |
| Base URL | `http://127.0.0.1:9080/v1`  ← **要加 `/v1`** |
| API Key | `nokey` |
| 模型 | `model-text` |

`config.toml` 内容：

```toml
model_provider = "dumate"
model = "model-text"
model_reasoning_effort = "high"
disable_response_storage = true

[model_providers.dumate]
name = "DuMate local proxy"
base_url = "http://127.0.0.1:9080/v1"
wire_api = "responses"
requires_openai_auth = true
```

> **`wire_api = "responses"`。** Codex CLI 0.155+ 已移除 `chat`（配置加载阶段直接报
> `wire_api = "chat" is no longer supported`）。网关自带 `/v1/responses` 适配层，
> 把 Responses 协议翻译成上游的 `chat/completions`，所以这里填 `responses` 即可。

### 为什么 URL 一个有 `/v1` 一个没有

- Claude 协议：cc-switch 会把 `ANTHROPIC_BASE_URL` 拼上 `/v1/messages`；
  网关同时接受 `/v1/messages` 和裸 `/messages`
- Codex 协议：Codex 要求 base_url 本身已含 `/v1`，它会再拼 `/chat/completions`

### 第 3 步：验证

```bash
node test/verify-ccswitch.js
```

会依次实测 Codex 路径、Claude 路径、裸路径兼容性和模型名映射。
四条都返回 200 且正文非空即为成功。

也可以直接在客户端里问一句「用四个字回答：中国的首都是哪里？」，应回「首都北京」。

### 常见坑

| 现象 | 原因 | 解决 |
|------|------|------|
| 连接被拒绝 | 网关没起 | 先 `npm start` |
| `404 Not found: /v1/responses` | 网关版本过旧，没有 Responses 适配层 | 更新到含 `src/responses.js` 的版本后重启 |
| `wire_api = "chat" is no longer supported` | Codex ≥0.155 移除了 chat 协议 | 配置改成 `wire_api = "responses"` |
| 返回内容为空 | max_tokens 太小，被思维链吃光 | 见下方说明 |
| 报未登录 | 百度 cookie 过期 | 打开一次 DuMate 客户端重新登录 |
| 千问报 402 | 千问额度耗尽 | 与代码无关，换账号或等次日重置 |

**关于空返回**：GLM 的思维链和正文共用同一个 `max_tokens` 预算，而 reasoning
长度不可控（实测同一提示词 57 ~ 8492 tokens 都出现过）。预算给得不够时会出现
两种症状：正文全空（`stop_reason=max_tokens`）或**说到一半停住**（reasoning
把预算吃光，正文被截断在句子中间，对客户端看起来就是「能快就停」）。

网关统一把预算抬到 65536 以上（可用 `DUMATE_MIN_MAX_TOKENS` 调整），
让 reasoning 无论怎么展开都还剩得下正文空间。

## 思考强度与上下文：能调到多大

### 先说结论（实测，不是照抄文档）

| 你想调的东西 | 能不能调 | 实际情况 |
|---|---|---|
| 思考强度 | **调不了** | 上游忽略 `reasoning_effort`。实测 low/medium/high/xhigh 的 reasoning token 数为 31/31/19/31 —— 无差异 |
| 关闭思维链 | **关不掉** | GLM 恒定输出 reasoning。系统提示只能压缩（42→29 字符），不能消除 |
| 上下文窗口 | **192K**（硬上限） | DuMate 配置声明值；32K 级输入实测通过（52K 实际 token） |
| 输出长度 | **128K**（硬上限） | 配置声明值；上游对任意 `max_tokens` 都不校验 |

> 既然上游不认 `reasoning_effort`，配置里的 `xhigh` / `effort=max` 不会让模型真的
> 「更用力想」。它们的实际作用是**让客户端给更大的输出预算**，这在共享预算模型下
> 等价于让正文有更多空间。

### 关键机制：思维链和正文抢同一个预算

GLM 的 reasoning 与正文**共用** `max_tokens`。这是最容易踩的坑：

| 客户端传的 max_tokens | 结果 |
|---|---|
| 150 | 推理吃掉全部 150 → 正文 `""`，`stop_reason=max_tokens` |
| 1024 | 推理吃掉全部 1024 → 正文 `""` |
| 4096 | 多数情况可用，但 reasoning 峰值可到 4000+ → 仍会被截断 |
| 65536 | 实测稳定，正文完整返回 |

网关统一把预算抬到 65536 以上（`DUMATE_MIN_MAX_TOKENS` 可调，`0` 关闭）。
所以**输出预算越大，你能拿到的正文越长**——这是唯一真正有效的「调大」手段。

### 两个模型的区别（实测对比）

上游只暴露两个真实模型，不存在「更强档位」。传别的名字会 404：

```
model `model-ultra` does not exist. api not registered.
```

| | `model-text` | `model-artifact-validate` |
|---|---|---|
| 定位 | 通用主力（Qianfan GLM-5） | 产出校验/审阅 |
| 数学推理 | 正确，1.2s | 正确，1.4s |
| 代码能力 | 正确，推理 133 token | 正确，推理 301 token（更啰嗦） |
| 格式遵循 | 精确，398ms | 精确，1022ms |
| 速度 | **更快** | 慢 2-3 倍 |

**两者答案质量一致**，差别只在 `model-artifact-validate` 推理链更长、更慢。

### 怎么在两个模型间切换

cc-switch 里**每个 app 只保留一个条目**，模型在同一条目内切换，不必建两个供应商。

**Claude Code** —— 用 `/model` 命令，档位即模型：

| 档位 | 实际模型 | 特点 |
|---|---|---|
| sonnet（默认） | `model-text` | 快，日常用 |
| haiku | `model-text` | 同上 |
| opus | `model-artifact-validate` | 推理链更长，慢 2-3 倍 |

**Codex CLI** —— 改 `model` 一行即可：

```toml
model = "model-text"                 # 快（默认）
# model = "model-artifact-validate"  # 更仔细，但慢 2-3 倍
```

### 使用场景建议

- **日常编码 / Codex CLI / Claude Code → 用 `model-text`**（默认）。更快，答案无差别。
- **需要模型自我审查产出**（生成文档/代码后要它自己挑错）→ 试
  `model-artifact-validate`，它的定位就是校验，但代价是慢 2-3 倍。
- **长上下文**：192K 窗口适合整仓代码分析。但实测 128K 级单请求耗时超过 10 分钟
  未返回，**建议把单次输入控制在 32K 以内**（约 5 万实际 token），靠 Codex 的自动
  压缩（180000 阈值）分段处理，别指望一次塞满。
- **不要指望调「思考强度」**：这个模型没有该旋钮。想要更详尽的分析，直接在提示词里
  要求「逐步分析」比调参数有效。

## API 端点

| 端点 | 协议 | 说明 |
|------|------|------|
| `GET /v1/models` | OpenAI | 模型列表（三条通道的模型都列出） |
| `POST /v1/chat/completions` | OpenAI | 聊天补全（透传 + 模型映射） |
| `POST /v1/responses` 或 `/responses` | OpenAI Responses | Codex CLI 0.155+ 专用，翻译成 chat/completions |
| `POST /v1/messages` 或 `/messages` 或 `/api/v1/messages` | Anthropic | Messages API（完整翻译） |
| `POST /v1/messages/count_tokens` | Anthropic | Token 计数（估算，Claude Code 会调用） |
| `GET /v1beta/models` | Google | 模型列表（Generative Language） |
| `POST /v1beta/models/{model}:generateContent` | Google | 生成内容（翻译层） |
| `POST /v1beta/models/{model}:streamGenerateContent` | Google | 流式生成（翻译层） |
| `GET /health` / `GET /ping` | - | 健康检查，含三条通道的就绪状态 |

> 裸路径 `/messages` 必须保留：Claude Code 打的是不带 `/v1` 的路径。
> Google 路径的模型名支持带前缀的 `qwen/pro`（正则不排除 `/`）。

> `count_tokens` 使用 `字节数/4` 的保守估算。DuMate 未暴露分词器，该接口仅用于
> 让 Claude Code 的上下文预算计算不报错，非精确值。

## 模型映射

搭子通道（可经管理端「模型管理」页编辑）：

| 请求模型名 | 实际使用 |
|-----------|---------|
| `model-text` | `model-text`（直通） |
| `model-artifact-validate` | `model-artifact-validate`（直通） |
| `glm-5` | `model-text` |
| `claude-3-5-sonnet-*` | `model-text` |
| `gpt-4o` / `gpt-4` / `o1` / `o3` 等 | `model-text` |

未收录的模型名一律回退为 `fallback`（默认 `model-text`）。

千问办公与 TRAE 通道：**不做映射**，模型表由上游下发，只能按前缀名调用。
这两条通道的模型名走 `mapModel` 会被兜底成 `model-text`，前缀随之失效，
所以刻意跳过映射。

## 注意事项

1. **不需要启动 DuMate 界面**：网关会直接拉起其后端 `dumate-main-server.exe`（无 GUI）。
   只有当登录态过期、需要重新登录时，才要打开一次 DuMate 客户端。
2. **账号额度**：搭子用百度搭子账号的模型额度（免费积分）；千问办公与 TRAE Work
   各用自己的积分体系。**三套账互不相通，不要相加**。
3. **端口动态**：DuMate 每次启动端口可能变化，网关会自动重新发现
   （每 30s 或在发现失败时重试）。
4. **思维链**：搭子返回 `reasoning_content`，Anthropic 端点会翻译为 `thinking` block。
5. **Token 用量**：流式 Anthropic 请求会带上 `stream_options.include_usage`，
   在结尾的 `message_delta` 中返回真实 `input_tokens` / `output_tokens`；
   上游若不支持则该值为 0。
6. **千问的 wasm 不进仓库**：它是官方客户端的二进制资产，运行时从安装目录读取。
7. **仅 Windows**：依赖 PowerShell（进程查询）、`%APPDATA%` 路径、`taskkill`。

## 快速测试

```bash
# OpenAI 格式
curl http://127.0.0.1:9080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer nokey" \
  -d '{"model":"model-text","messages":[{"role":"user","content":"hello"}]}'

# Anthropic 格式
curl http://127.0.0.1:9080/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: nokey" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-3-5-sonnet-20241022","max_tokens":100,"messages":[{"role":"user","content":"hello"}]}'

# 千问办公（前缀路由）
curl http://127.0.0.1:9080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen/pro","messages":[{"role":"user","content":"hello"}]}'
```

## 无 GUI 运行原理

DuMate 的 Go 后端 `dumate-main-server.exe` 本来由 Electron 通过 IPC 注入登录态。
单独启动会报 `loginMode is required`。逆向二进制后发现它可以从环境变量读取登录上下文：

```
DUMATE_LOGIN_MODE=standalone
DUMATE_LOGIN_USER_ID=<bceUserId>
DUMATE_LOGIN_USER_NAME=<displayName>
DUMATE_LOGIN_BCE_ACCOUNT_ID=<bceAccountId>
```

`src/upstream-launcher.js` 会自动从 `%APPDATA%\qianfan-desktop-app\auth.json` 读出
当前活跃账号（`activeProfileId`）并注入这些变量，然后 spawn 后端：

```bash
dumate-main-server.exe -c "<install>\resources\config\desktop-main\config.yml" -port 8980
```

真正的凭证（cookie）仍然来自磁盘上已保存的登录态，本项目不接触也不复制它们。
**cookie 过期后必须打开一次 DuMate 客户端重新登录**，之后又可继续无 GUI 使用。

## 测试

```bash
# 冒烟测试（32 项断言，需要网关在线）
npm test

# 端到端：Codex / Claude / 裸路径 / 模型映射四条链路
node test/verify-ccswitch.js

# 单点探针：只打一种协议，把原始 SSE 打到 stdout
node test/probe-oai.js       # OpenAI 格式
node test/probe-anth.js      # Anthropic 格式（含 x-api-key / anthropic-version）

# 上下文上限实测：往网关发指定 token 量的填充文本，看能否吃下、耗时多少
node probe-ctx.js <model> <目标token>

# 千问「独立登录」可行性探针：验证不开客户端也能拿到可用凭证
node probe-qwen-device-login.js
```

> `probe-oai` / `probe-anth` 用来区分「**网关翻译错**」还是「**上游返回错**」——
> 比跑全套 smoke 更快定位。两者都硬编码打 9080。

**离线验证**（不需要起服务，改完相关代码先跑这些）：

```bash
node test/verify-channel.js             # 通道过滤 + 积分归因配对（13 项）
node test/verify-qwen-discipline.js     # 千问「执行纪律」注入条件与幂等
node test/verify-truncated-toolcall.js  # 工具参数截断判定
node test/verify-traework-gained.js     # TRAE 签到到账差值（含 0/负数边界）
node test/verify-display-name.js        # 账号显示名解析（占位名识别、优先级）
node test/verify-qwen-daily-aggregate.js # 千问每日额度多账号合计口径
node test/verify-qwen-wallets-zero.js   # 千问「三池全 0」可疑响应的重试判据
```

**离线自测完整流程**（无需安装 DuMate）：

```bash
# 终端 1：启动 mock 上游（监听 52890）
npm run mock
# 终端 2：启动网关
npm start
# 终端 3：跑冒烟测试
npm test
```

`test/smoke.js` 覆盖：模型列表、OpenAI 流式/非流式、Anthropic 流式/非流式、
思维链转 `thinking`、token 用量、多轮对话、system/tool_use/tool_result 转换、
`count_tokens`、错误路径与 404。

## 逆向分析要点

- **应用类型**：Electron（`app.asar` 87MB）+ Go 后端（`dumate-main-server.exe` 61MB）
- **关键配置**：`resources/config/opencode/opencode.json` 暴露了内部 API 结构
- **端口发现**：`dumate-main-server.exe --port=<动态>` 命令行参数
- **认证**：`Bearer nokey`（服务本身不做 key 校验，依赖 DuMate 登录态）
- **模型**：`model-text`（Qianfan GLM-5，192K 上下文 / 128K 输出）

## 项目结构

```
src/
  server.js              网关主入口（9080/9082），协议路由与鉴权
  anthropic.js           Anthropic ↔ OpenAI 双向翻译（含 SSE 状态机）
  responses.js           OpenAI Responses ↔ Chat（Codex CLI）
  google.js              Google Generative Language ↔ OpenAI
  budget.js              输出预算策略（三个协议入口共用）
  discovery.js           端口发现 + 后端拉起
  upstream-launcher.js   无 GUI 拉起 dumate-main-server.exe（逆向成果）
  upstream-router.js     模型名前缀 → 通道
  channels.js            通道 id 的单一来源
  keys.js / modelmap.js  API Key 与模型映射（按 mtime 失效，改完不用重启）
  reqlog.js              请求埋点（JSONL，超 32MB 轮转）
  fallback-web.js        桌面凭证失效时回落到网页池
  web-pool.js / accounts.js / dumate-web.js   网页凭证池与网页 API 封装
  points-cursor.js       搭子的余额游标（逐请求成本）
  qwenwork/              千问办公通道（wasm 编码、OAuth 登录、三池积分）
  traework/              TRAE Work 通道（OAuth、设备指纹、签到、credits）
  admin/                 管理端（路由、存储、鉴权）
stable/                  冻结快照：9080 跑的那一份（见下）
web/                     管理端前端（Vue 3 + Vite + ant-design-vue）
test/                    冒烟测试与离线验证脚本
data/                    运行时数据（**已 gitignore**，含凭证）
```

### stable/ 是冻结快照

`stable/` 是网关闭包的**逐字节拷贝**（36 个 `.js`），**不随主目录开发改动**，
保证 9080 不被开发中的代码波及。它有独立启动脚本 `stable/start-stable.bat`。

发布新版时**不要简单地「把 `src/*.js` 覆盖过去」**，两个坑：

1. `src/*.js` 这个 glob **漏掉子目录**——`qwenwork/` 与 `traework/` 共 17 个文件
   不在里面。漏了它们，网关能启动但通道直接不可用。
2. **会把管理端一起带进去**——`web-gateway.js`、`task-runner.js`、`login-browser.js`
   等不属于网关闭包，带进去会让快照无谓膨胀、还引入 playwright 依赖。

正确做法是**按依赖闭包复制**：从 `src/server.js` 出发递归解析 `require('./x')`，
把闭包内的文件逐个复制到 `stable/src/` 同路径。复制后逐字节比对、跑 `node --check`、
并用临时端口独立启动一次确认三条通道就绪。

> **手工启动 `stable/` 会退回到一个空数据目录**：`reqlog.js` 的
> `ROOT = path.resolve(__dirname, '..')`，stable 副本的 `__dirname` 是 `stable/src`，
> 所以未设 `DUMATE_ADMIN_DATA` 时埋点落 `stable/data/`——**里面没有任何凭证**，
> 千问与 TRAE 通道直接不可用。所以启动 9080 必须走 `start-stable.bat`
> （它设了 `DUMATE_ADMIN_DATA=<repo>/data`），或手工带上该变量。

### 数据文件（`data/`，已 gitignore）

| 文件 | 内容 | 敏感度 |
|---|---|---|
| `keys.json` | 签发给调用方的 API Key，**只存 sha256** | 低（明文仅在创建时返回一次） |
| `web-accounts.json` | 网页账号，**cookie 明文存** | **高**（必须原样重放，无法哈希） |
| `qwenwork-accounts.json` | 千问凭证（含 refresh token） | **高**（等同密码） |
| `traework-accounts.json` | TRAE 凭证（含轮换的 refreshToken） | **高** |
| `admin-users.json` / `admin.secret` | 管理员口令（scrypt）与会话签名密钥 | **高** |
| `model-map.json` | 模型别名、上游模型、对外暴露、兜底 | 低 |
| `requests.jsonl` | 网关埋点（超 32MB 轮转一次留 `.1`） | 中（含 prompt 元信息） |
| `activity.jsonl` | 统一操作记录（签到/任务/抽奖） | 中 |
| `points-cursor.jsonl` | 搭子余额游标（逐请求成本） | 低 |
| `qwenwork-credits.jsonl` / `traework-credits.jsonl` | 两条通道的逐请求积分归因 | 低 |
| `task-runs.jsonl` / `task-scheduler.json` / `auto-checkin.json` | 任务历史与定时配置 | 低 |
| `browser-profile/` | 浏览器登录器用的受控 profile | 中 |

> **三种凭证策略不同，是刻意的**：API Key 只存哈希（可验证不可还原）；
> 网页 cookie 必须明文（上游要求原样重放）；管理端口令走 scrypt。
> 所以 `data/` 一旦被复制走，网页与直连通道的凭证是**直接可用**的——
> 这个目录已在 `.gitignore` 里，**不要提交，也不要放进任何备份镜像**。

> `DUMATE_ADMIN_DATA` 决定数据目录，**管理端与网关必须一致**，否则读到的
> 账号/埋点不同。开发实例（9082/9083）与稳定版（9080）默认共用 `<repo>/data`
> ——这是有意的（账号池共用）。

## 许可证

[MIT](LICENSE)

## 免责声明

> **请在使用前完整阅读本节。** 继续使用本项目即表示你已理解并接受以下全部内容。
> 本节不构成法律意见；如有疑问，请咨询你所在司法辖区的执业律师。

### 1. 无关联声明

本项目是**独立的第三方开源项目**，与下列主体**没有任何隶属、合作、赞助或背书关系**：

- 百度、百度智能云、千帆、DuMate（搭子）
- 阿里云、通义千问、千问办公（QwenWork）
- 字节跳动、TRAE / TRAE Work
- Anthropic、OpenAI、Google 及本文档提到的任何其他客户端

文中出现的所有产品名、商标、服务标记均为其各自所有者的财产，此处**仅为指代与说明用途**（指示性合理使用）。本项目不主张任何与之相关的权利，也不代表上述任何公司的立场或观点。

### 2. 逆向工程与互操作性目的

本项目通过**逆向工程与协议适配**实现与本地已安装客户端之间的互操作，目的是让用户能在自己已合法取得使用权的软件上，使用自己偏好的编辑器与命令行工具。

- 本项目**不破解、不绕过**任何付费墙、订阅校验或授权许可机制
- 本项目**不提供**任何上游服务的免费使用权——你仍需自行拥有合法的上游账号
- 本项目**不分发**任何上游的二进制资产。千问办公的 `qoder_auth_wasm_bg.wasm` 等文件**不在仓库内**，而是运行时从你本机已安装的客户端目录读取（`src/qwenwork/wasm-path.js`）；仓库里只有加载它的 JS 代码
- 本项目**不包含**任何反编译所得的源码，所有代码均为本项目自行编写

各上游的软件许可协议（EULA）对逆向工程的规定不尽相同。**是否允许在你所在地区/你的许可协议下进行此类操作，需由你自行判断并承担相应责任。**

### 3. 凭证与数据

**本项目没有服务器，不上报任何数据。** 所有凭证与运行数据都只存在你本机：

| 数据 | 位置 | 说明 |
|---|---|---|
| 桌面登录态 | `%APPDATA%\qianfan-desktop-app\auth.json` | 由客户端自己维护，本项目**只读不写** |
| 网页 cookie | `data/web-accounts.json` | **明文存储**（上游要求原样重放） |
| 直连凭证 | `data/qwenwork-accounts.json`、`data/trae*-accounts.json` | 含 refresh token，**等同密码** |
| API Key | `data/keys.json` | 只存 sha256 |
| 请求日志 | `data/requests.jsonl` 等 | 含模型名、token 用量等元信息 |

**`data/` 目录一旦泄露，等同于凭证泄露。** 该目录已在 `.gitignore` 中，请不要提交、不要放进公开备份、不要打包分享。网络请求只会发往你在源码中可见的上游域名（`dumate-svc.baidu.com`、`gateway.qwenwork.cn`、`trae-api-cn.mchost.guru` 等），**没有任何遥测、统计或回传**。

### 4. 账号风险（请特别注意）

本项目的**积分自动化功能**（自动签到、任务轮询、抽奖）会代替你向**上游服务器**发起请求：

- 这类自动化行为**可能违反上游服务条款**，可能导致账号被限制、封禁或积分被清零
- 轮询间隔虽已按风控考量设为默认 30 分钟并加随机抖动，但**这不能保证不被识别**
- 抽奖等功能**消耗不可逆的资源**，且本项目**不做定时**正是出于此考虑

**是否使用这些功能、以及由此产生的一切账号后果，由你自行承担。** 作者不对账号封禁、积分损失、数据丢失或任何其他损失负责。

### 5. 无担保

本项目按 **「现状」（AS IS）** 提供，不附带任何明示或默示的担保，包括但不限于对**适销性、特定用途适用性、不侵权**的担保。上游接口、协议、字段随时可能变更，本项目**不保证**任何功能持续可用。

### 6. 责任限制

在适用法律允许的最大范围内，**作者及贡献者不对**因使用或无法使用本项目而产生的任何直接、间接、附带、特殊、惩罚性或后果性损害承担责任，包括但不限于：利润损失、数据丢失、账号封禁、服务中断、设备损坏，或任何第三方索赔。**即使已被告知此类损害的可能性**，本限制依然适用。

### 7. 使用者的责任

使用本项目即表示你确认并同意：

1. 你**拥有或以其他方式合法有权使用**所连接的上游账号与服务
2. 你将**自行确保**你的使用行为符合当地法律法规及上游服务条款
3. 你**不会**将本项目用于商业转售上游服务、规避付费、批量注册、爬取数据或其他违反上游条款的用途
4. 你理解本项目**仅供个人学习、研究与互操作性探索**

### 8. 合规与出口

你需自行确保使用行为符合所在国家/地区的法律法规（包括但不限于计算机安全、数据保护、出口管制相关法规）。本项目作者不提供任何合规性保证，也不对使用者的违规使用承担责任。

### 9. 若你是权利方

如果你是本项目所涉及软件或服务的权利方，并认为本项目存在不当之处，请通过仓库 Issue 联系。作者愿意**本着善意沟通解决**，包括在必要时调整或移除相关内容。
