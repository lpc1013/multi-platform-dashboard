# oauth_login.py 拆分评估（2026-10-11）

> **进度（2026-10-13）：✅ 第一、二期已完成，待真机回归**
>
> 一期（2026-10-12）：22 个纯基建符号 → `src/oauth_common.py`。
>
> 二期（2026-10-13）：巨石按平台/职责切为 10 个平铺模块，oauth_login.py
> 变 80 行薄壳 re-export（4226 → 80 行）：
> `oauth_shared.py`（验证码探测/JSON 捞 token/调试留痕，解 HW↔CODEARTS 环）、
> `oauth_device.py`（设备流三步 + refresh_grant）、`oauth_jobs.py`（任务调度）、
> `oauth_qoder/zcode/dumate/lingxi/hw/trae/codearts/officeace.py`（各平台直登）。
> 切割由跨段调用矩阵驱动：127 个原顶层符号全覆盖、无跨模块重名；
> JOBS/submit_code 与 oauth_common 同一对象；77 单测全绿；服务冒烟
> /api/ping /api/state 200 + minimax 设备流真实 user_code 下发成功。
> **三期（server/webapi/platforms 改直连、删壳）待逐平台真机回归全过后执行。**

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
