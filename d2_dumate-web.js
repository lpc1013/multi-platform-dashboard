// src/dumate-web.js - 百度搭子网页端接口封装（签到 / 抽奖 / 任务 / 积分）
//
// 这些接口是网页端（dumate.baidu.com）与桌面端内嵌 H5 共用的一套，
// 从客户端 app.asar 与网页 bundle 里提取，两端常量完全一致：
//
//   base = /api/dumate/activity   (growth_plan_2026)
//     签到      POST /api/dumate/points/loginBonus
//     签到信息  GET  /api/dumate/points/loginBonusInfo
//     抽奖状态  GET  /api/dumate/activity/growth-plan/draw/status
//     抽奖      POST /api/dumate/activity/growth-plan/draw
//     领奖      POST /api/dumate/activity/growth-plan/prize/claim
//     任务列表  GET  /api/dumate/activity/growth-plan/tasks
//     完成任务  POST /api/dumate/activity/growth-plan/task/complete
//     积分明细  GET  /api/dumate/points/quota_overview
//     发放记录  GET  /api/dumate/points/records/charge
//     消耗记录  GET  /api/dumate/points/records/usage
//
// 认证：浏览器同源 cookie（BDUSS 等）。桌面端把请求交给 Go 后端的
// cookie-proxy 转发，我们这里直接带 cookie 请求云端。
const https = require('https');

const BASE = process.env.DUMATE_WEB_BASE || 'https://www.dumate.cn';
const TIMEOUT = parseInt(process.env.DUMATE_WEB_TIMEOUT || '20000', 10);

function request(cookie, method, urlPath, body) {
  return new Promise((resolve) => {
    let url;
    try {
      url = new URL(urlPath.startsWith('http') ? urlPath : BASE + urlPath);
    } catch (e) {
      return resolve({ ok: false, error: `URL 非法: ${urlPath}` });
    }

    const payload = body === undefined || body === null ? null : JSON.stringify(body);
    const headers = {
      Cookie: cookie,
      Accept: 'application/json, text/plain, */*',
      'Accept-Language': 'zh-CN,zh;q=0.9',
      // 网页端请求带这个头，缺了会被当成非浏览器来源
      'X-Dumate-Client-Type': 'web',
      Referer: BASE + '/app',
      Origin: BASE,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
    };
    if (payload) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = https.request(
      {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + url.search,
        method,
        timeout: TIMEOUT,
        headers,
      },
      (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { data += c; });
        res.on('end', () => {
          let parsed = null;
          try { parsed = JSON.parse(data); } catch (e) { parsed = null; }
          // 上游用 code 10001 表示登录态失效，单独标出来便于界面提示重新登录
          const expired = res.statusCode === 401 ||
            (parsed && (parsed.code === 10001 || parsed.code === 10006));
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300 && (!parsed || parsed.code === 0 || parsed.success !== false),
            status: res.statusCode,
            expired: !!expired,
            data: parsed,
            raw: parsed ? null : data.slice(0, 300),
          });
        });
      }
    );
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
    if (payload) req.write(payload);
    req.end();
  });
}

// 统一取结果体：云端有的包在 result，有的包在 data，有的直接顶层
function pick(res) {
  if (!res.ok) return null;
  const d = res.data;
  if (!d || typeof d !== 'object') return d;
  if ('result' in d) return d.result;
  if ('data' in d) return d.data;
  return d;
}

function errOf(res) {
  if (res.error) return res.error;
  if (res.expired) return '登录态已失效，请重新登录';
  const d = res.data || {};
  return d.message || d.msg || d.error_message || `HTTP ${res.status}`;
}

const api = {
  // ---- 账号信息 ----
  async userInfo(cookie) {
    const res = await request(cookie, 'GET', '/api/dumate/user/info');
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    const r = pick(res) || {};
    return { ok: true, uid: r.uid || r.userId || '', nickname: r.nickname || r.displayName || r.name || '', raw: r };
  },

  // ---- 签到 ----
  async loginBonusInfo(cookie) {
    const res = await request(cookie, 'GET', '/api/dumate/points/loginBonusInfo');
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    const r = pick(res) || {};
    return {
      ok: true,
      // 上游字段名以实测为准，这里做兼容取值
      has_issued: !!(r.hasIssued ?? r.has_issued),
      total_points: r.totalPoints ?? r.total_points ?? null,
      total_times: r.totalTimes ?? r.total_times ?? null,
      sign_in_days: r.signInDays ?? r.sign_in_days ?? [],
      month_points: r.monthPoints ?? r.month_points ?? null,
      raw: r,
    };
  },

  async claimLoginBonus(cookie) {
    const res = await request(cookie, 'POST', '/api/dumate/points/loginBonus');
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    return { ok: true, result: pick(res) };
  },

  // ---- 积分 ----
  async quotaOverview(cookie) {
    const res = await request(cookie, 'GET', '/api/dumate/points/quota_overview?clientType=desktop&timezone=Asia%2FShanghai');
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    const r = pick(res) || {};
    const total = Number(r.totalPoints || 0);
    const used = Number(r.usedPoints || 0);
    return {
      ok: true,
      total,
      used,
      left: Math.max(0, total - used),
      subscribed: !!r.isSubscribed,
      throttled: !!(r.modelThrottleInfo && r.modelThrottleInfo.throttled),
      packages: [].concat(r.subscription || [], r.incremental || []).map((p) => ({
        kind: (r.subscription || []).includes(p) ? 'subscription' : 'incremental',
        package_type: p.packageType || '',
        source: p.source || '',
        total: Number(p.totalPoints || 0),
        used: Number(p.usedPoints || 0),
        left: Math.max(0, Number(p.totalPoints || 0) - Number(p.usedPoints || 0)),
        granted_at: p.startDate ? p.startDate * 1000 : null,
        expire_at: p.expireDate ? p.expireDate * 1000 : null,
      })),
      raw: r,
    };
  },

  // 积分消耗记录。实测必须带 startAt/endAt，否则报「参数错误:StartAt」。
  // 返回里最有价值的是 consumedPoints（窗口内总扣费）与 totalCount，
  // 计费规则在上游，本地无法从 token 数推算。
  async usageRecords(cookie, opts = {}) {
    const q = new URLSearchParams();
    if (opts.startAt) q.set('startAt', String(opts.startAt));
    if (opts.endAt) q.set('endAt', String(opts.endAt));
    if (opts.page) q.set('page', String(opts.page));
    if (opts.limit) q.set('limit', String(opts.limit));
    const res = await request(cookie, 'GET', '/api/dumate/points/records/usage?' + q.toString());
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    const r = pick(res) || {};
    return {
      ok: true,
      consumed_points: r.consumedPoints !== undefined ? Number(r.consumedPoints) : 0,
      total_count: r.totalCount !== undefined ? Number(r.totalCount) : 0,
      list: r.list || [],
    };
  },

  // 积分充值/发放记录。参数同上。
  async chargeRecords(cookie, opts = {}) {
    const q = new URLSearchParams();
    if (opts.startAt) q.set('startAt', String(opts.startAt));
    if (opts.endAt) q.set('endAt', String(opts.endAt));
    if (opts.page) q.set('page', String(opts.page));
    if (opts.limit) q.set('limit', String(opts.limit));
    const res = await request(cookie, 'GET', '/api/dumate/points/records/charge?' + q.toString());
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    const r = pick(res) || {};
    return {
      ok: true,
      total_count: r.totalCount !== undefined ? Number(r.totalCount) : 0,
      list: r.list || [],
    };
  },

  // ---- 抽奖 ----
  async drawStatus(cookie) {
    const res = await request(cookie, 'GET', '/api/dumate/activity/growth-plan/draw/status');
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    const r = pick(res) || {};
    return {
      ok: true,
      remaining_draws: r.remaining_draws ?? r.remainingDraws ?? 0,
      prizes: r.prizes ?? [],
      my_prizes: r.my_prizes ?? [],
      winning_records: r.winning_records ?? [],
      raw: r,
    };
  },

  // 抽奖需要幂等键：客户端用 randomUUID 生成，服务端据此防重复扣次数。
  // 必须每次生成新的，复用同一个值会让第二次抽奖被当成重复请求。
  async draw(cookie, requestId) {
    const res = await request(cookie, 'POST', '/api/dumate/activity/growth-plan/draw', {
      request_id: requestId,
    });
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    const r = pick(res) || {};
    return { ok: true, remaining_draws: r.remaining_draws ?? r.remainingDraws ?? null, result: r };
  },

  // 领奖。注意：实测积分与会员类奖品抽到即 status=SUCCESS，自动到账，
  // 不需要调这个接口；只有需要填联系方式的实物奖品才用得上。
  // 对已 SUCCESS 的记录调用会报「参数错误:DrawRecordID」。
  async claimPrize(cookie, drawRecordId, contact) {
    const res = await request(cookie, 'POST', '/api/dumate/activity/growth-plan/prize/claim', {
      draw_record_id: drawRecordId,
      ...(contact ? { contact } : {}),
    });
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    return { ok: true, result: pick(res) };
  },

  // ---- 任务 ----
  // 实测返回结构是 { groups: [{ group_code, group_name, tasks: [...] }] }，
  // 不是平铺数组。任务是否完成看 completed_count >= repeat_count——
  // 这是客户端 completedIds 的判定口径（bundle 里就是这么算的）。
  async tasks(cookie) {
    const res = await request(cookie, 'GET', '/api/dumate/activity/growth-plan/tasks');
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    const r = pick(res) || {};
    const groups = Array.isArray(r.groups) ? r.groups : [];
    const flat = [];
    for (const g of groups) {
      for (const t of (g.tasks || [])) {
        flat.push({
          task_id: t.task_id,
          task_type: t.task_type,
          title: t.title,
          sub_title: t.sub_title || '',
          // query 是 QUERY_INPUT 类任务要发的内容；服务端据此校验
          query: t.query || '',
          reward_count: t.reward_count || 0,
          reward_points: t.reward_points || 0,
          repeat_count: t.repeat_count || 1,
          completed_count: t.completed_count || 0,
          done: (t.completed_count || 0) >= (t.repeat_count || 1),
          group_code: g.group_code,
          group_name: g.group_name,
          display_terminal: t.display_terminal || [],
        });
      }
    }
    return { ok: true, groups, tasks: flat };
  },

  async completeTask(cookie, taskId) {
    const res = await request(cookie, 'POST', '/api/dumate/activity/growth-plan/task/complete', {
      task_id: taskId,
    });
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    const r = pick(res);
    // 业务层可能返回 success:false + code（如 410121 该任务次数已发放）。
    // 只看 HTTP 状态会把「已发放」当成完成，所以业务码也要判。
    const biz = res.data || {};
    if (biz.success === false || (typeof biz.code === 'number' && biz.code !== 0)) {
      return { ok: false, code: biz.code, error: biz.message || `业务错误 ${biz.code}`, result: r };
    }
    return { ok: true, result: r };
  },

  async pageStatus(cookie) {
    const res = await request(cookie, 'GET', '/api/dumate/activity/growth-plan/page/status');
    if (!res.ok) return { ok: false, error: errOf(res), expired: res.expired };
    return { ok: true, data: pick(res) };
  },
};

module.exports = { BASE, request, pick, errOf, api };
