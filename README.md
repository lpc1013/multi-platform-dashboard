# 多平台账号看板 · Multi-Platform Dashboard

一个**纯本地运行**的多平台账号管理看板：集中查看多个 AI / 云服务平台的账号登录状态、积分与额度到期情况，一键执行每日签到；内置一个 **OpenAI 兼容反代**，把 5 个上游的模型额度统一暴露为本机 `/v1` 接口。

> **设计原则**：所有凭据与令牌**只保存在本机**，后端仅监听 `127.0.0.1`，不出回环地址。

---

## 支持的平台

当前接入 **12 个平台**，均为单文件适配器（`src/platforms/*.py`）。

| 平台 | 说明 | 签到 / 任务 |
|---|---|---|
| WorkBuddy | 账号状态与积分 | 每日签到 / 派小猫 / 打招呼 |
| WorkBuddy 国际版 | 网页登录链路（Keycloak SSO → 控制台换 token） | 签到 |
| MiniMax | 多账号（三重身份 + 双令牌，RT 一次性轮换） | 签到 |
| 百度 DuMate | 网页版 + 本地客户端导入（BDUSS 解密） | 签到 |
| 灵犀 / WPS | `wps_sid` cookie 登录 | 签到 |
| Trae | 手机号短信登录（OAuth PKCE） | 签到 |
| Qoder CN | 设备码授权流程 | 领取 Credits |
| ZCode (z.ai) | CLI OAuth 流程 | 领取赠送额度 |
| OfficeACE（华为云） | 本地客户端 API + `runtime-state.json` 端口发现 | 每日登录领取 |
| CodeArts Agent（华为云） | 自建 OAuth + DPoP，STS 临时密钥 | 每日领取积分 |
| TeleAgent（星辰） | 本机客户端凭据 + 请求签名 | 签到 |
| Tabbit | cookie JWT + 会话接口 | 每日签到 / 桌面宠物 |

---

## 架构

```
dashboard_analysis/
├── src/
│   ├── index.html          # 单文件前端（三视图：home / proxy / tokens，实时读盘，改完刷新即生效）
│   ├── server.py           # 薄启动壳（标准库 http.server，127.0.0.1:8799）
│   ├── webapi.py           # 路由与处理器（/api/* 全部端点）
│   ├── registry.py         # 平台注册表（导入即加载 platforms/，失败只告警不拖垮后端）
│   ├── tasks.py            # 任务编排与状态聚合
│   ├── account_service.py  # 各登录通道成功后的统一落盘入口（不覆盖其他账号）
│   ├── cred_store.py       # 凭据存储层（原子写 + 进程内/跨进程双重锁 + 身份指纹键名分配）
│   ├── secret_box.py       # 敏感字段静态加密（Windows DPAPI，落盘即密文）
│   ├── data_dir.py         # 数据目录外移到 %LOCALAPPDATA%\dashboard_analysis\
│   ├── local_import.py     # 各平台本地凭据读取与解密
│   ├── oauth_common.py     # 登录共享基建（job 调度 / PKCE / 浏览器助手）
│   ├── oauth_*.py          # 登录框架平铺模块（设备码 / 各平台短信直登）
│   ├── browser_login.py    # 受控 Chromium 登录
│   ├── backup_creds.py     # 凭据加密备份/恢复（PBKDF2 + Fernet 单文件）
│   ├── fetch_state.py      # 状态抓取
│   ├── token_panel.py      # Token 消耗面板桥接层（Node 内核 + 模板注入）
│   ├── logstore.py         # 运行日志（内存 + backend_run.log，1MB 轮转）
│   ├── errors.py           # 统一异常体系（StorageError / AuthError / UpstreamError）
│   ├── openai_proxy.py     # OpenAI 兼容反代（5 上游统一账号池）
│   ├── workbuddy_login.py  # WorkBuddy 登录
│   ├── assets/template.html# Token 面板渲染模板（仓库内副本，改样式即生效）
│   └── platforms/          # 平台适配器（每个平台一个文件）
│       ├── _util.py        #   共用工具（数值转换 / 凭据加解密）
│       ├── workbuddy.py  workbuddy_ai.py  minimax.py  baidu_dumate.py
│       ├── lingxi.py     trae.py          qoder.py    zcode.py
│       └── officeace.py  codearts.py      teleagent.py  tabbit.py
├── tests/                  # pytest（212 项）
├── 启动看板.bat            # Windows 一键启动（GBK 编码）
└── requirements.txt
```

**平台适配器统一接口**：

```python
PLATFORM, LABEL, TASKS          # 元信息
load_accounts() -> {name: cred} # 读取所有账号凭据
read_account(name, ent) -> dict # 归一化状态（积分 / 额度 / 到期 / 签到情况）
run_task(name, ent, task_key)   # 执行任务（签到等）
```

---

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

> 部分平台（浏览器登录、DuMate cookie 解密）需要：
> ```bash
> pip install playwright cryptography
> playwright install chromium
> ```

### 2. 启动

**Windows（推荐）**：双击 `启动看板.bat`

**跨平台**：
```bash
cd src
python server.py          # 默认 http://127.0.0.1:8799
python server.py 9000     # 指定端口
```

### 3. 添加账号

浏览器打开 `http://127.0.0.1:8799`，在对应平台卡片上：

- **从本地客户端导入**（推荐）—— 直接读取已登录的桌面客户端凭据，无需重新登录
- **网页登录 / 短信登录** —— 由后端拉起受控浏览器完成授权

---

## 安全说明

- 后端**只监听 `127.0.0.1`**，不对外暴露
- **凭据/数据统一存放在 `%LOCALAPPDATA%\dashboard_analysis\`**（`src/data_dir.py` 自动迁移；
  读点兼容旧位置兜底），源码目录不再保存任何凭据
- 凭据文件（`*_accounts.json`）**已在 `.gitignore` 中排除**，不会进入版本库
- 凭据文件**敏感字段已用 Windows DPAPI 静态加密**（`secret_box.py`：token / refresh_token /
  sk / cookie 等落盘即密文 `dpapi:`，身份字段保持明文；同机同用户透明解密。
  `python secret_box.py status|migrate` 可盘点/全量加密）
- 本地回环请求**绕过系统代理**，避免凭据流向代理
- 本仓库**不含任何真实凭据、手机号或账号信息**，所有示例数据均为占位符

### 凭据加密备份（防磁盘损坏/误删）

```bash
cd src
python backup_creds.py save              # 备份 → src/backups/*.creds（默认，已 gitignore）
python backup_creds.py save D:/mybk      # 指定输出目录
python backup_creds.py load <文件>.creds # 恢复（默认不覆盖已有文件，--force 覆盖）
```

- PBKDF2（600k 迭代）+ Fernet 加密，密码不落盘；**忘了密码 = 备份作废**
- 打包全部 `*_accounts.json`、删除墓碑、MiniMax RT 备份等敏感文件
- 备份文件请复制到本机之外（网盘/U盘）才算真备份

---

## 额度与状态面板

平台卡片汇总账号数、登录态与积分；点开任一上游的「额度」弹窗（`/api/pool_quota`）可看**每号明细**。

额度按用途**分池统计**，不做单一百分比合并：

| 维度 | 含义 | 数据来源 |
|---|---|---|
| `daily_free` | 每日免费额度（当天重置） | CodeArts 免费 token / OfficeACE 当日 bucket |
| `long_term` | 长期积分（可累计、有到期） | CodeArts 积分 / OfficeACE 周期额度 |
| `free_models` | 每号可用的限免模型 + 自记账用量 | WorkBuddy 国际版（上游无按模型用量接口） |

- **账号池行**：显示账号名、额度条、剩余天数徽章（≤3 天标红）
- **冷却态可见**：整号冷却与「(账号, 模型)」行级冷却都会在面板上标出剩余时间
- **读取失败如实上报**：上游查不到额度时卡片显示「每日免费额度读取失败」并附上游原文，
  不会静默显示 0
- **接口契约**：`GET /api/pool_quota?provider=<上游>` 的 `provider` 必须显式指定
  （`codearts` / `teleagent` / `officeace` / `tabbit` / `wbai`，国际版别名 `workbuddy_intl`）；
  缺省或拼错返回 **400** 并列出可选值，不会降级成「有账号但查不了额度」的误导结果

---

## Token 消耗面板

看板内置 `/tokens` 路由，按平台汇总本机 token 用量：

- **平台分类**：`WorkBuddy 国内版` / `WorkBuddy 国际版` / `Qoder` / `Codex`；顶部平台卡与下拉框可把整页过滤到单一平台，账号下拉会随平台收敛
- **积分口径**：跨平台时 KPI 标题为「平台积分合计」，金额估算与 API 直购价只按 WorkBuddy 统计（标注 `WB`）；过滤到 Qoder 时标题变「Qoder 积分」，金额与 API 直购价显示「—」，纯估算窗口内缓存命中率也显示「—」
- **环比（上期）**：按当前平台 / 账号过滤后从请求级现算，不再拿全平台总量去比单平台
- **采集内核**：复用 `wb-usage-tracker` 的 Node 内核（`token_dump.js` + 本地 `dashboard` 目录），负责 WorkBuddy / Codex
- **Qoder 合并**：`src/token_panel.py` 读取旧版 IDE `local.db` 的真实 token；新版客户端/CLI 的 `~/.qoder-cn/projects/**/*.jsonl` 只写 credits 与 `context_usage_ratio`，故按压缩事件 `preTokens / ratio` 校准上下文窗口（200k / 400k / 1M），再用 `ratio × 窗口` 估算输入、按回复文本长度估算输出；请求数、会话、积分仍取自日志原文。平台卡与 KPI 脚注会标注「估算」
- **真实 token 开关**：用户环境变量 `QODERCN_EXPOSE_TOKEN_USAGE=1`（同时写入 `QODER_EXPOSE_TOKEN_USAGE=1`），重启 Qoder 后新会话若开始写入 token，解析器会自动优先使用真实值
- **渲染模板**：`src/assets/template.html`（仓库内副本，改样式即生效，无需重启）
- **数据桥接**：`src/token_panel.py` 注入脱敏后的 JSON，做 TTL 缓存与后台刷新；Qoder 日志按文件 mtime 缓存，分钟级刷新不会重复解析
- **视图分区**：概览、量能趋势、工作空间、时段热力、请求分布、积分消耗。分区切换由外层 `src/index.html` 侧栏驱动 iframe 的 `body.dataset.view`，模板自身不含导航按钮

> 积分跨平台不可互换：WorkBuddy 与 Qoder 各自独立计费，单平台过滤下看到的才是该平台真实积分。

最近一次修正：`积分消耗 → 哪个账号在烧` 的会话数改为只统计窗口内有过请求的会话（与 KPI、平台卡同一口径），窗口内无活动的账号不再挂一行 0。

---

## OpenAI 兼容反代（5 上游统一账号池）

后端内置 OpenAI 兼容端点，把 **CodeArts / OfficeACE / TeleAgent / Tabbit / WorkBuddy 国际版**
五个上游的模型额度统一暴露为本机 API。任何支持自定义 `base_url` 的客户端
（Cherry Studio、ChatBox、openai sdk 等）都可直接接入。

### 端点

```
GET  http://127.0.0.1:8799/v1/models            # 模型列表（实测 66 个）
POST http://127.0.0.1:8799/v1/chat/completions  # 流式透传 / 非流式聚合
```

### 客户端配置

| 项 | 值 |
|---|---|
| Base URL | `http://127.0.0.1:8799/v1` |
| API Key | 任意非空字符串（本机代理不校验 key，鉴权走本机凭据） |
| Model | 见下表 |

### 路由规则（按 model 字段选上游）

模型名在多个上游之间大量重复，因此用**命名空间前缀**隔离，客户端改前缀即切上游：

| model 形态 | 上游 | 说明 |
|---|---|---|
| `wb:xxx` | WorkBuddy 国际版 | 如 `wb:auto`、`wb:gpt-6-astra`、`wb:glm-5.3` |
| `tb:xxx` | Tabbit | 如 `tb:默认`、`tb:Kimi-K3`、`tb:GLM-5.3` |
| 命中 TeleAgent 目录 | TeleAgent | 如 `chat-*` |
| 其余 / 空 | CodeArts | 默认上游 |

**CodeArts ↔ OfficeACE 交集名归 CodeArts**（福利免费额度优先）；仅当模型存在于 OfficeACE
目录且不在 CodeArts 目录时，才改走果办网关。

### 模型清单（实测 66 个）

- **CodeArts 福利模型（每日免费额度，自动带 `maas_type: benefit`）**：
  `deepseek-v4.1-flash`、`deepseek-v4-flash-0731`、`deepseek-v4-pro-0813`、`glm-5.3-flash`
- **CodeArts 内置模型（消耗积分）**：`GLM-5.2`、`glm-5.3`、`glm-5.2-sft-harmony`、
  `openpangu-2.0-flash`、`openpangu-2.0-pro`、`Qwen3-VL-235B`、`kimi-k2.6-vl`
- **WorkBuddy 国际版（`wb:` 前缀，31 个）**：含 `wb:auto`、`wb:default-model`、
  `wb:deepseek-v4.1-flash`、`wb:hy3`、`wb:step-5-preview`、`wb:gpt-6-*`、`wb:glm-*`、
  `wb:kimi-*`、`wb:gemini-*`、`wb:grok-4.7` 等
- **Tabbit（`tb:` 前缀，24 个）**：含 `tb:默认`、`tb:Kimi-K3`、`tb:GLM-5.3`、
  `tb:DeepSeek-V4.1-Flash`、`tb:Qwen3.8-Max`、`tb:Doubao-Seed-2.1-*` 等

### `wb:auto` 优先级链

```
deepseek-v4.1-flash → hy3 → step-5-preview → hy4-preview-f
  → 目录内其余 x0.00 免费行 → default-model
```

策略是**先吃每日免费额度、再动可累计积分**。免费行被限流时，先回退同名付费行
（`deepseek-v4.1-flash → deepseek-v4.1-flash-sg`）再换模型；显式指定模型时只试它本身 + 付费退路。

### 账号池与故障切换

五个上游**共用一个账号池实现**（`_open_pool`），不按平台各写一套：

- 同平台账号按「**未冷却优先 → 有效期新到旧**」排序，`wbai` 额外按「免费包 > 积分 > 无」排序
- 换号判定发生在**首个 chunk 到达之前**，客户端完全无感，不会重复输出
- 命中额度耗尽 / 鉴权失效 / 429 → 该号冷却 1800s 并换下一个
- `TM.00001041`（上游并发上限）是**瞬时态**：只做 60s 短冷却 + 排队重试，不拉黑 30 分钟
- 国际版限流时提前开流并发 SSE 心跳注释，避免客户端「转几秒自己取消」

### 行级限流（6004 / 14018 / 14003）

WorkBuddy 网关**按「模型行」限流，不是账号级**。错误 chunk 是顶层
`{"code":6004,"msg":"usage exceeds frequency limit..."}` 或 `{"code":14003,...}`，
与 `error_code/error_msg` 格式并存，代理两种都会解析：

| 错误 | 含义 | 处理 |
|---|---|---|
| `6004` | 该模型行频率超限 | 解析 msg 里的重置时刻 → **(账号, 模型) 级精确冷却**，同号继续试其它模型 |
| `14018` / HTTP 429 外壳 | 该行额度耗尽 | 行级冷却 600s，不整号拉黑 |
| `14003` | 模型繁忙（瞬时） | 行级冷却 60s |
| `401 / 403` | 鉴权失效 | 整号冷却 1800s，换号 |

重置时刻直接从上游文案解析（`will reset at ... UTC+8` / `明天早上 9:30 重置`），
解析失败才退回经验窗口。限流事件与「正在等待」的请求都会在反代面板实时展示。

### 行为与限制

- **鉴权**：复用看板里各平台已登录的凭据，无需额外配置
- **入口网关**：默认对本机开放；设置环境变量 `DASHBOARD_PROXY_API_KEY` 后
  `/v1/*` 须带 `Authorization: Bearer <key>`（为放开局域网监听预留）；
  内置令牌桶限流（默认 60 次/分钟、突发 30，`DASHBOARD_PROXY_RATELIMIT` /
  `DASHBOARD_PROXY_BURST` 可调），超限返回 429
- **统一异常**：`src/errors.py`（DashboardError / StorageError / AuthError / UpstreamError），
  路由层按 `http_status` + `err_code` 返回结构化错误
- **审计**：每次调用落一条 `[proxy:<上游>] <model> acct=<账号> ...` 日志（流式记耗时/行数/token，
  非流式同样记账），看板日志区可见；按日/按模型聚合写入 `proxy_usage.json`，
  并记录 `provider / acct` 维度供额度面板反查
- **思考模型**：`deepseek-v4.1-flash` 等思考模型的 `thinking` 内容会包进
  `<think>…</think>` 并入 `content` 流（多数客户端不渲染 `reasoning_content`），
  出错/中断/只有思考三条路径都会闭合标签
- **续期边界**：代理**不触发**浏览器静默续登（避免客户端启动拉模型列表时随机弹窗）；
  凭据过期返回 503 并提示到看板续期，签到/续期按钮会自动续
- **上游限制**：`tool_choice` 对象形态上游报参数错；超限返回 429 原样透传；每日额度按账号计

```python
# Python 验证
from openai import OpenAI
c = OpenAI(base_url="http://127.0.0.1:8799/v1", api_key="sk-local")
print(c.chat.completions.create(
    model="deepseek-v4.1-flash",
    messages=[{"role": "user", "content": "你好"}]).choices[0].message.content)
```

---

## 测试与自检

```bash
python -m pytest tests/ -q          # 212 项，全绿
```

覆盖：凭据存储原子写与并发、DPAPI 加解密、数据目录迁移、异常体系、
反代账号池切换 / 行级限流解析 / 非流式聚合 / 审计日志、Tabbit 会话与管道、核心状态聚合。

---

## 已知限制

- **CodeArts 每日免费额度**：`/api/v1/user/tokens/balance` 在部分账号上返回
  `error_code 4000 invalid channel, group not found`（上游账号侧 channel/group 未开通或已变更，
  带 `channel` / `group` 参数亦无法绕过）。面板会显式显示「每日免费额度读取失败」并附上游原文，
  积分（`daily_free` 之外的长期积分）不受影响。
- **WorkBuddy 国际版无按模型用量接口**：`summary` / `free-packages` / `request-usage` 均 404，
  限免模型的用量只能靠反代自记账，故只统计**经过本机代理**的调用。
- **OfficeACE 需独占客户端宿主**：无人值守刷新会临时接管 ServiceHost，
  用完必须回收并清理 `runtime-state.json` 里的死 pid，否则客户端 GUI 拒绝启动。

---

## 免责声明

本项目为个人学习与自动化工具，用于管理**自己拥有**的账号。请遵守各平台的服务条款，不要用于任何违反平台规则或法律法规的用途。

---

## License

MIT
