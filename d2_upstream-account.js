// src/upstream-account.js - 「这条请求实际用了哪个上游账号」
//
// 请求日志要回答「哪个账号花的」，但这个信息不在 logRequest 手里——它由
// 各通道自己决定：搭子是桌面凭证（或网页凭证池轮询选中的那个）、千问是
// 客户端登录态、TRAE 是多账号池里 pickAccount 选中的那个。
//
// 所以分两路：
//   1. **权威来源**：直连通道的 provider 在发请求前把选中的账号写进
//      `req._upstreamAccount`（见 server.js 的 onAccount 回调）。多账号轮询下
//      「实际用的那个」与「当前登录的那个」不是一回事，只有 provider 知道。
//   2. **兜底**：provider 没报时（如搭子的转发路径），按通道读一次当前凭证。
//
// logRequest 是同步热路径，所以这里的读盘/解密都带 TTL 缓存——搭子的
// auth.json 是小文件、千问的解密要过 DPAPI，都不能每请求做一次。
const fs = require('fs');
const path = require('path');

const TTL_MS = 60000;
// 千问已改为自持凭证多账号（provider 上报，无兜底），这里只留搭子的缓存槽
const cache = { dumate: { at: 0, name: '' } };

function fresh(slot) {
  const c = cache[slot];
  return Date.now() - c.at < TTL_MS ? c : null;
}

function remember(slot, name) {
  cache[slot] = { at: Date.now(), name: name || '' };
  return cache[slot].name;
}

/**
 * 搭子：桌面客户端的当前登录账号。
 * 走 auth.json 的 activeProfileId（与 upstream-launcher 同一口径）。
 * 读不到就返回 ''——界面显示 —，不编一个名字。
 */
function dumateAccount() {
  const hit = fresh('dumate');
  if (hit) return hit.name;
  let name = '';
  try {
    const launcher = require('./upstream-launcher');
    const p = launcher.activeProfile();
    if (p) name = p.name || p.userId || '';
  } catch (e) { /* 读不到就留空 */ }
  return remember('dumate', name);
}

/**
 * 千问办公：**没有兜底**。
 *
 * 它现在是自持凭证的多账号池（data/qwenwork-accounts.json），选号由 provider
 * 做（主账号 + 故障转移），只有 provider 知道这次实际用了哪个。在这里猜一个
 * （比如「池里的第一个」）在转移场景下必然是错的——TRAE Work 也是这么处理的。
 * provider 没上报就返回 ''，界面显示 —。
 */
function qwenworkAccount() {
  return '';
}

/**
 * 兜底解析：provider 没报账号时按通道取当前凭证。
 *
 * 千问与 TRAE 都**没有兜底**——它们是多账号池，选号由 provider 做（主账号 +
 * 故障转移），这里猜一个（比如「池里的第一个」）在转移场景下必然是错的。
 */
function fallback(channel) {
  if (channel === 'dumate') return dumateAccount();
  return '';
}

module.exports = { fallback, dumateAccount, qwenworkAccount };
