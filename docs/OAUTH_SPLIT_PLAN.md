# oauth_login.py 拆分评估（2026-10-11）

> **进度（2026-10-12）：✅ 第一期已完成**——22 个纯基建符号（常量 + job 调度 +
> PKCE/表单 + 浏览器助手）已抽至 `src/oauth_common.py`（22KB），oauth_login.py
> 减至 203KB，头部显式 `from oauth_common import (...)` 保命名空间。
> 验证：146 个原顶层符号全部可达、`_JOBS` 对象同一、34 单测全绿、
> server 完整加载链路冒烟 200。**`_run_job` 留守**（内部引用 device_poll
> 平台分发，不满足封闭性）。二三期待逐平台真机回归。

## 现状（一期完成前存档：原 222KB / 4552 行 / 146 个顶层符号）
`src/oauth_login.py` ~214KB / 4061 行 / 113 个顶层函数，混合四类内容：
1. 共享 job 基建：`JOBS` 字典、`_new_job`/`_run_job`、`get_job`、`submit_code`
2. 共享浏览器助手：`_click_text`/`_pull_window_front`/`_has_captcha`/`_consent_checked` 等
3. 平台设备流：minimax(device) / zcode(cli_poll) / qoder(qoder_device)
4. 平台短信直登主循环：qoder / zcode / dumate / lingxi / trae / codearts / officeace（各 200~600 行）

## 结论：不在本批执行，分三期拆
盲拆风险：131 处平台前缀函数交叉引用 + JOBS 共享状态 + 循环导入风险；
且登录链路只能真机验证（本批无法逐平台重跑 7 条短信登录）。
项目铁律「交付前必须实测」→ 拆分应配合逐平台真机回归。

- **第一期（低风险）**：只把「共享基建」（job 调度 + 浏览器助手 + `submit_code`/`get_job`）
  提为 `src/oauth_common.py`，oauth_login.py `from oauth_common import *`。行为零变化。
- **第二期**：每平台一个 `src/oauth/<pid>.py`，`oauth_login.py` 变薄壳 re-export
  （server.py 引用不动）。每迁一个平台立即真机登录一次验证。
- **第三期**：删壳，server.py 直接 import 新包。

## 每期验收标准
`python -c "import oauth_login"` 冒烟 + 该平台真机登录成功 + `tests/test_core.py` 全绿。
