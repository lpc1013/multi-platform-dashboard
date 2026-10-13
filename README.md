# 多平台账号看板 · Multi-Platform Dashboard

一个**纯本地运行**的多平台账号管理看板：集中查看多个 AI / 云服务平台的账号登录状态、积分余额与到期情况，并支持一键执行每日签到等任务。

> **设计原则**：所有凭据与令牌**只保存在本机**，后端仅监听 `127.0.0.1`，不出回环地址。

---

## 支持的平台

| 平台 | 说明 | 签到任务 |
|---|---|---|
| WorkBuddy | 账号状态与积分 | 每日签到 / 派小猫 / 打招呼 |
| MiniMax | 多账号（三重身份 + 双令牌） | 签到 |
| 百度 DuMate | 网页版 + 本地客户端导入 | 签到 |
| 灵犀 / WPS | `wps_sid` cookie 登录 | 签到 |
| Trae | 手机号短信登录（OAuth PKCE） | 签到 |
| Qoder CN | 设备码授权流程 | 领取 Credits |
| ZCode (z.ai) | CLI OAuth 流程 | 领取赠送额度 |
| OfficeACE（华为云） | 本地客户端 API | 每日登录领取 |
| CodeArts Agent（华为云） | 自建 OAuth + DPoP | 每日领取积分 |

---

## 架构

```
dashboard_analysis/
├── src/
│   ├── index.html          # 单文件前端（Stripe 风格，实时读盘，改完刷新即生效）
│   ├── server.py           # 本地后端（标准库 http.server，127.0.0.1:8799）
│   ├── cred_store.py       # 凭据存储层（原子写 + 进程内/跨进程双重锁 + 身份指纹键名分配）
│   ├── local_import.py     # 各平台本地凭据读取与解密
│   ├── oauth_login.py      # 统一登录框架（设备码 / 短信直登 / 浏览器代填）
│   ├── oauth_common.py     # 登录共享基建（job 调度 / PKCE / 浏览器助手）
│   ├── backup_creds.py     # 凭据加密备份/恢复（PBKDF2 + Fernet 单文件）
│   ├── browser_login.py    # 受控 Chromium 登录
│   ├── fetch_state.py      # 状态抓取
│   ├── openai_proxy.py     # OpenAI 兼容反代（CodeArts 免费模型额度本机暴露）
│   ├── workbuddy_login.py  # WorkBuddy 登录
│   └── platforms/          # 平台适配器（每个平台一个文件）
│       ├── minimax.py
│       ├── baidu_dumate.py
│       ├── lingxi.py
│       ├── trae.py
│       ├── qoder.py
│       ├── zcode.py
│       ├── officeace.py
│       ├── codearts.py
│       └── workbuddy.py
├── 启动看板.bat            # Windows 一键启动（GBK 编码）
└── requirements.txt
```

**平台适配器统一接口**：

```python
PLATFORM, LABEL, TASKS          # 元信息
load_accounts() -> {name: cred} # 读取所有账号凭据
read_account(name, ent) -> dict # 归一化状态（积分/到期/签到情况）
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
- **凭据/数据统一存放在 `%LOCALAPPDATA%\dashboard_analysis\`**（2026-10-12 起，`src/data_dir.py`
  自动迁移；读点兼容旧位置兜底），源码目录不再保存任何凭据
- 凭据文件（`*_accounts.json`）**已在 `.gitignore` 中排除**，不会进入版本库
- 凭据文件（`*_accounts.json`）**敏感字段已用 Windows DPAPI 静态加密**（2026-10-13 起，
  `secret_box.py`：token/refresh_token/sk/cookie 等落盘即密文 `dpapi:`，身份字段保持明文；
  同机同用户透明解密。`python secret_box.py status|migrate` 可盘点/全量加密）
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

## 技术要点

- **无第三方 Web 框架**：后端仅用 Python 标准库 `http.server`
- **凭据存储加固**（`cred_store.py`）：临时文件 + `os.replace` 原子写（崩溃不产生半截 JSON）、
  进程内互斥 + 跨进程文件锁（多线程/多实例并发不丢写）、损坏 JSON 自动隔离为 `*.corrupt-*` 留痕
- **前端单文件**：`index.html` 每次请求实时读盘，改动刷新即生效，无需重启
- **多账号不覆盖**：落盘按**身份指纹**分配键名（而非显示名），同人不同源不会互相覆盖
- **令牌续期**：部分平台（CodeArts / MiniMax）支持自动刷新临时凭据

---

## OpenAI 兼容反代（CodeArts 免费额度）

后端内置一个 OpenAI 兼容端点，把 CodeArts Agent 的模型额度（含**每日免费福利额度**）暴露为本机 API。任何支持自定义 OpenAI `base_url` 的客户端（Cherry Studio、ChatBox、openai sdk 等）都可直接接入。

### 端点

```
GET  http://127.0.0.1:8799/v1/models            # 模型列表（内置 + 福利）
POST http://127.0.0.1:8799/v1/chat/completions  # 流式透传 / 非流式聚合
```

### 客户端配置

| 项 | 值 |
|---|---|
| Base URL | `http://127.0.0.1:8799/v1` |
| API Key | 任意非空字符串（本机代理不校验 key，鉴权走本机凭据） |
| Model | 见下表 |

### 模型清单

**福利模型（每日免费额度）**：`deepseek-v4.1-flash`（1M 上下文）、`deepseek-v4-flash-0731`、`deepseek-v4-pro-0813`、`glm-5.3-flash` —— 走 `maas_type: benefit` 头，代理自动处理。

**内置模型（消耗积分）**：`GLM-5.2`、`openpangu-2.0-flash`、`openpangu-2.0-pro`、`glm-5.2-sft-harmony`、`Qwen3-VL-235B`、`kimi-k2.6-vl`。

### 行为与限制

- **鉴权**：请求复用看板里 CodeArts 账号的 AK/SK 签名 + STS 临时令牌，无需额外配置
- **审计**：每次调用落一条 `[proxy]` 日志（模型/账号/耗时/token 用量），看板日志区可见；按日/按模型聚合写入 `proxy_usage.json`，看板显示「今日 token 消耗」卡片
- **续期边界**：代理**不触发**浏览器静默续登（避免客户端启动拉模型列表时随机弹窗）；凭据过期返回 503 并提示到看板续期，签到/续期按钮会自动续
- **多账号**：取 `expires_at` 最晚（最新鲜）的账号
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

## 免责声明

本项目为个人学习与自动化工具，用于管理**自己拥有**的账号。请遵守各平台的服务条款，不要用于任何违反平台规则或法律法规的用途。

---

## License

MIT
