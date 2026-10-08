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
│   ├── local_import.py     # 各平台本地凭据读取与解密
│   ├── oauth_login.py      # 统一登录框架（设备码 / 短信直登 / 浏览器代填）
│   ├── browser_login.py    # 受控 Chromium 登录
│   ├── fetch_state.py      # 状态抓取
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
- 凭据文件（`*_accounts.json`）**已在 `.gitignore` 中排除**，不会进入版本库
- 本地回环请求**绕过系统代理**，避免凭据流向代理
- 本仓库**不含任何真实凭据、手机号或账号信息**，所有示例数据均为占位符

---

## 技术要点

- **无第三方 Web 框架**：后端仅用 Python 标准库 `http.server`
- **前端单文件**：`index.html` 每次请求实时读盘，改动刷新即生效，无需重启
- **多账号不覆盖**：落盘按**身份指纹**分配键名（而非显示名），同人不同源不会互相覆盖
- **令牌续期**：部分平台（CodeArts / MiniMax）支持自动刷新临时凭据

---

## 免责声明

本项目为个人学习与自动化工具，用于管理**自己拥有**的账号。请遵守各平台的服务条款，不要用于任何违反平台规则或法律法规的用途。

---

## License

MIT
