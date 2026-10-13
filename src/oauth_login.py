# -*- coding: utf-8 -*-
"""OAuth 登录统一入口 —— 二期拆分后的薄壳（2026-10-13）。

原 4226 行巨石已按平台/职责拆至：
  oauth_common.py    共享基建（一期：常量/job 存储/浏览器助手/PKCE）
  oauth_shared.py    跨平台共享小助手（验证码探测/JSON 捞 token/调试留痕）
  oauth_device.py    设备码流三步 + refresh_grant 静默续期
  oauth_jobs.py      登录任务调度（start_job/start_sms_job）
  oauth_qoder.py / oauth_zcode.py / oauth_dumate.py / oauth_lingxi.py
  oauth_hw.py        华为系登录页共享代点（trae/codearts/officeace 复用）
  oauth_trae.py / oauth_codearts.py / oauth_officeace.py

本文件只做 re-export：webapi.py / platforms/minimax.py /
platforms/codearts.py 等既有 `import oauth_login` 调用点零改动。
三期（真机回归全过后）调用点改直连后本壳删除。
"""
from oauth_common import (
    DEVICE_GRANT_TYPE, PROVIDERS, UA, _CODE_SEL, _JOBS, _OFFSCREEN_ARGS, _PHONE_SEL, _click_consent, _click_text, _consent_checked, _first_sel, _has_captcha, _job_lock, _login_submitted, _new_job, _origin, _pkce, _post_form, _provider, _pull_window_front, _view, get_job, submit_code,
)
from oauth_shared import (  # oauth_shared.py
    _CODEARTS_DEBUG_LOCK, _CODEARTS_DEBUG_LOG, _codearts_debug, _qoder_has_captcha,
    _trae_find_token,
)
from oauth_device import (  # oauth_device.py
    _QODER_DEBUG_LOG, _cli_poll_once, _cli_poll_start, _qoder_debug,
    _qoder_machine_id, _qoder_pkce, _qoder_poll_once, _qoder_start,
    device_poll, device_start, refresh_grant,
)
from oauth_jobs import (  # oauth_jobs.py
    _run_job, _run_sms_job, start_job, start_sms_job,
)
from oauth_qoder import (  # oauth_qoder.py
    _QODER_ALIYUN_NEXT_TEXTS, _QODER_AUTH_TEXTS, _QODER_SELECT_TEXTS, _qoder_click_aliyun_next,
    _qoder_click_authorize, _qoder_click_where, _qoder_find_sms_frame, _qoder_stage,
    _run_qoder_sms_job,
)
from oauth_zcode import (  # oauth_zcode.py
    _ZCODE_PAGE_SEL, _run_zcode_sms_job, _zcode_captcha_visible, _zcode_click_authorize,
    start_zcode_sms_job,
)
from oauth_dumate import (  # oauth_dumate.py
    _DUMATE_APP_URL, _dumate_cookie_string, _dumate_fetch_user, _dumate_find_login_surface,
    _dumate_new_job, _run_dumate_web_job, start_dumate_web_job,
)
from oauth_lingxi import (  # oauth_lingxi.py
    _LINGXI_LOGIN_URL, _lingxi_finish, _lingxi_new_job, _lingxi_wait_sid,
    _run_lingxi_sms_job, start_lingxi_sms_job,
)
from oauth_hw import (  # oauth_hw.py
    _HW_CODE_SEL, _HW_INPUT_JS, _HW_LOGIN_TEXTS, _HW_PHONE_SEL,
    _HW_PICK_JS, _HW_SEND_TEXTS, _hw_click_visible, _hw_fill_and_send,
    _hw_fill_phone, _hw_sms_sent, _hw_stage, _hw_submit_code,
    _hw_visible_input,
)
from oauth_trae import (  # oauth_trae.py
    _TRAE_API, _TRAE_APP_VERSION, _TRAE_CONSOLE, _TRAE_CRED_MARKERS,
    _TRAE_LINES, _TRAE_OPEN_EXCLUDE, _TRAE_OPEN_TEXTS, _TRAE_PLUGIN_VERSION,
    _TraeCBHandler, _run_trae_sms_job, _trae_account_full_name, _trae_agree_checked,
    _trae_build_authorize_url, _trae_click_agree_row, _trae_click_open, _trae_click_submit,
    _trae_client_running, _trae_device_name, _trae_device_suffix, _trae_ensure_agree,
    _trae_exchange, _trae_jwt_uid, _trae_line_dirs, _trae_oauth_device,
    _trae_out_dirs, _trae_read_build_version, _trae_reg_str, _trae_sms_page_ok,
    _trae_system_facts, start_trae_sms_job,
)
from oauth_codearts import (  # oauth_codearts.py
    _CODEARTS_CLIENT_ID, _CODEARTS_CONSENT_TEXTS, _CODEARTS_PLUGIN, _CODEARTS_PLUGIN_VER,
    _CODEARTS_PORTAL, _CODEARTS_PROFILE_DIR, _CODEARTS_SNAP, _CODEARTS_STS,
    _CodeArtsCBHandler, _codearts_click_consent, _codearts_dpop, _codearts_dpop_keypair,
    _codearts_extract_code, _codearts_extract_credentials, _codearts_pkce, _codearts_secret_exchange,
    _codearts_stage, _codearts_token, _run_codearts_sms_job, codearts_silent_renew,
    start_codearts_sms_job,
)
from oauth_officeace import (  # oauth_officeace.py
    _OFFICEACE_API, _OFFICEACE_EXE_CANDIDATES, _OFFICEACE_INSTALL_HINTS, _OFFICEACE_SPAWNED,
    _officeace_api, _officeace_autostart, _officeace_exe_path, _officeace_gui_running,
    _officeace_maybe_teardown, _officeace_probe, _officeace_resolve_api, _officeace_runtime_state_paths,
    _officeace_scan_captured, _run_officeace_sms_job, _run_officeace_sms_job_inner, start_officeace_sms_job,
)

_JOBS = _JOBS  # 显式保名（jobs 存储同一对象，get_job/submit_code 同源）
