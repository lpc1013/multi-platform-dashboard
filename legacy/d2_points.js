// src/admin/routes/points.js - 积分与账号概览
//
// 数据源是 DuMate 后端的 /api/dumate/points/quota_overview，它把套餐订阅
// 与一堆增量包（登录奖励、活动奖励）分开返回，两个数组各自带 usedPoints，
// 界面需要的是「还剩多少」，所以在这里统一算好再吐给前端。
const http = require('http');
const fs = require('fs');
const path = require('path');
const discovery = require('../../discovery');
const pointsAgg = require('../../points-agg');
const { sendJSON } = require('../router');

const CACHE_TTL_MS = 60 * 1000;
let cache = { at: 0, data: null };

function upstreamJSON(port, urlPath, timeout = 8000) {
  return new Promise((resolve) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: urlPath, method: 'GET', timeout },
      (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { data += c; });
        res.on('end', () => {
          try { resolve({ ok: true, status: res.statusCode, data: JSON.parse(data) }); }
          catch (e) { resolve({ ok: false, error: 'invalid json' }); }
        });
      }
    );
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
    req.end();
  });
}

// 账号列表来自客户端的 auth.json。cookie 是加密的，这里只取身份与登录时间，
// 不碰也不回传任何凭证字段。
//
// 同时合并「网页凭证」状态：同一个百度账号可能在桌面端已失效、却在网页端
// 有效（反之亦然）。两套凭证服务于不同的能力——桌面端跑模型对话，网页端
// 跑签到/抽奖/积分——只看一边会得出与实际能力不符的结论，所以并列展示。
function listAccounts() {
  const file = path.join(process.env.APPDATA || '', 'qianfan-desktop-app', 'auth.json');
  let j;
  try { j = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return null; }
  const profiles = j.accountProfiles || [];
  const now = Date.now();

  // 网页凭证按 bceAccountId 建索引。网页 cookie 里的 bce-login-accountid
  // 与桌面 auth.json 的 bceAccountId 是同一个值，可据此关联两套。
  const webAccounts = require('../../accounts');
  const webByAccountId = new Map();
  for (const w of webAccounts.load().accounts) {
    const c = webAccounts.parseCookie(w.cookie);
    const id = c['bce-login-accountid'] || w.uid || '';
    if (id) webByAccountId.set(id, w);
  }

  return profiles.map((p) => {
    const lastLogin = p.lastLogin || 0;
    const ageDays = lastLogin ? Math.floor((now - lastLogin) / 86400000) : null;
    const active = p.profileId === j.activeProfileId;
    // 桌面端同一时刻只有一份登录态（存在顶层 cookies，归属当前活跃账号），
    // 非活跃账号只有自己带 encryptedCookies 才算还能用。
    //
    // 注意这**不等于账号失效**：切到别的账号后，前一个账号在桌面端不可用，
    // 但它的网页凭证（签到/抽奖/积分）通常仍然有效。原先一律标成「失效」，
    // 会被读成「账号坏了」，而实际只是「当前没在用它的桌面凭证」。
    const hasCredentials = !!p.encryptedCookies || active;
    let state;
    if (active) state = 'active';
    else if (hasCredentials) state = ageDays === null ? 'unknown' : 'standby';
    else state = 'no_credential';

    const web = webByAccountId.get(p.bceAccountId || p.bceUserId || '') || null;

    return {
      name: p.displayName || '(未命名)',
      user_id: p.bceUserId || '',
      last_login: lastLogin,
      age_days: ageDays,
      state,
      has_credentials: hasCredentials,
      active,
      // 网页端凭证状态。null 表示没在账号管理里添加过这个账号。
      web: web ? {
        id: web.id,
        name: webAccounts.displayName(web),
        enabled: web.enabled,
        has_error: !!web.last_error,
        last_error: web.last_error || '',
        checkin_result: (web.checkin && web.checkin.last_result) || '',
        points: web.points ? web.points.left : null,
      } : null,
    };
  });
}

async function fetchPoints(opts = {}) {
  // 缓存：积分接口一次往返约 200-800ms，而仪表盘会同时请求 /points 与
  // /accounts，两边都要积分。不缓存就是同一份数据打上游两次。
  const { force = false } = opts;
  if (!force && cache.data && Date.now() - cache.at < CACHE_TTL_MS) {
    return { ok: true, data: cache.data };
  }

  const port = await discovery.discoverPort();
  if (!port) return { ok: false, error: 'upstream not found' };

  const [overview, remaining] = await Promise.all([
    upstreamJSON(port, '/api/dumate/points/quota_overview'),
    upstreamJSON(port, '/api/dumate/points/remaining'),
  ]);

  if (!overview.ok || !overview.data || !overview.data.success) {
    return { ok: false, error: (overview.data && overview.data.message) || overview.error || 'upstream error' };
  }

  const r = overview.data.result || {};
  const total = Number(r.totalPoints || 0);
  const used = Number(r.usedPoints || 0);

  const packages = []
    .concat((r.subscription || []).map((p) => ({ ...p, kind: 'subscription' })))
    .concat((r.incremental || []).map((p) => ({ ...p, kind: 'incremental' })))
    .map((p) => {
      const t = Number(p.totalPoints || 0);
      const u = Number(p.usedPoints || 0);
      return {
        kind: p.kind,
        package_type: p.packageType || '',
        source: p.source || '',
        total: t,
        used: u,
        left: Math.max(0, t - u),
        // 发放时间：分析「每日奖励是否还在发」必须用它，而不是到期时间
        granted_at: p.startDate ? p.startDate * 1000 : null,
        expire_at: p.expireDate ? p.expireDate * 1000 : null,
        status: p.status || '',
      };
    });

  // 派生视图（按来源 / 按发放日 / 临期 / 已过期未用完）与网页账号走同一份
  // 聚合实现，保证两条链路口径一致
  const { packages: pkgs, expiring: exp, sources: srcs, daily_grant: daily, expired_unused: expUnused } =
    pointsAgg.aggregate(packages);

  const result = {
    ok: true,
    data: {
      subscribed: !!r.isSubscribed,
      total,
      used,
      left: Math.max(0, total - used),
      has_remaining: remaining.ok && remaining.data ? !!remaining.data.hasRemainingPoints : null,
      throttled: !!(r.modelThrottleInfo && r.modelThrottleInfo.throttled),
      throttle_reason: (r.modelThrottleInfo && r.modelThrottleInfo.reason) || '',
      packages: pkgs,
      expiring: exp,
      sources: srcs,
      daily_grant: daily,
      // 已过期但还有余额的包：这部分额度实际已经用不上了，单独列出来
      // 说明「总额度」里有多少是已经失效的
      expired_unused: expUnused,
      upstream_port: port,
      // 前端用账号 ID 做切换，网页账号用数字 id，这里给个不会撞的字符串
      account_id: 'local',
      account_name: '本地后端（桌面凭证）',
      fetched_at: Date.now(),
    },
  };
  cache = { at: Date.now(), data: result.data };
  return result;
}

const routes = [
  {
    method: 'GET',
    path: '/points',
    handler: async ({ res, req }) => {
      const force = /[?&]refresh=1/.test(req.url || '');
      if (!force && cache.data && Date.now() - cache.at < CACHE_TTL_MS) {
        return sendJSON(res, 200, { ...cache.data, cached: true });
      }
      const out = await fetchPoints();
      if (!out.ok) return sendJSON(res, 502, { error: out.error });
      cache = { at: Date.now(), data: out.data };
      return sendJSON(res, 200, { ...out.data, cached: false });
    },
  },
  {
    method: 'GET',
    path: '/accounts',
    handler: async ({ res }) => {
      const accounts = listAccounts();
      if (accounts === null) return sendJSON(res, 502, { error: 'auth.json not readable' });

      // 积分只能查到「当前登录的那个账号」：上游的 quota_overview 是按后端
      // 进程内注入的登录态算的，实测传任意 Cookie 头都不影响返回值，
      // 也没有 userId 参数。所以这里只给活跃账号挂积分，其余如实标为不可查，
      // 不拿活跃账号的数字去填别人。
      let activePoints = null;
      let pointsError = null;
      try {
        const out = await fetchPoints();
        if (out.ok) activePoints = { left: out.data.left, total: out.data.total, used: out.data.used };
        else pointsError = out.error;
      } catch (e) {
        pointsError = e.message;
      }

      const withPoints = accounts.map((a) => ({
        ...a,
        points: a.active ? activePoints : null,
        points_note: a.active
          ? (activePoints ? '' : (pointsError || '积分查询失败'))
          : '仅当前登录账号可查',
      }));

      return sendJSON(res, 200, {
        accounts: withPoints,
        total: withPoints.length,
        // 统计口径按新状态名：桌面端只有一个是「当前使用中」，
        // 其余有凭证的是「备用」，没有凭证的才是「无凭证」。
        // 不再叫 stale——那会被读成账号失效，而多数情况下网页端仍可用。
        active: withPoints.filter((a) => a.state === 'active').length,
        standby: withPoints.filter((a) => a.state === 'standby').length,
        no_credential: withPoints.filter((a) => a.state === 'no_credential').length,
        unknown: withPoints.filter((a) => a.state === 'unknown').length,
      });
    },
  },
];

module.exports = { routes };
