'use strict';
/**
 * token_dump.js —— Python 看板与 wb-usage-tracker 之间的桥接脚本
 *
 * 职责：解锁本机绑定凭证库（免口令）→ 三源采集内核 buildData → 输出 DATA JSON。
 * 输出即「官方渲染模板 /tokens 的数据载荷」，由 Python 端注入 assets/template.html。
 *
 * 用法：node token_dump.js [WB_USAGE_DIR]
 *   - 无参时回落到默认目录；也读环境变量 WB_USAGE_DIR。
 *   - 退出码：0 成功 / 2 加载失败 / 3 凭证库需口令 / 4 采集失败 / 5 空数据 / 6 脱敏自检失败。
 */
const os = require('os');
const path = require('path');

const DIR = process.env.WB_USAGE_DIR
  || (process.argv[2])
  || 'E:/AI/AInews/wb-usage-tracker/dashboard';
process.env.WB_USAGE_DIR = DIR;

let Vault, buildData, loadAccountMap, assertNoLeak;
try {
  ({ Vault } = require(path.join(DIR, 'lib', 'vault')));
  ({ buildData } = require(path.join(DIR, 'lib', 'gen')));
  ({ loadAccountMap } = require(path.join(DIR, 'lib', 'accountmap')));
  ({ assertNoLeak } = require(path.join(DIR, 'server')));
} catch (e) {
  console.error('[token_dump] 无法加载 wb-usage-tracker 模块：' + e.message);
  process.exit(2);
}

const ENC = path.join(DIR, 'secrets', 'accounts.enc');

(async () => {
  const vault = new Vault(ENC);
  if (!vault.exists()) {
    // 首次：以本机绑定密钥（免口令、密文落盘）自动创建
    vault.save(loadAccountMap(), '');
  } else {
    try { vault.unlock(''); }           // 免口令自动解锁（机器指纹派生密钥）
    catch (e) {
      console.error('[token_dump] 凭证库需口令且当前非交互环境：' + e.message);
      process.exit(3);
    }
  }

  let data;
  try { data = await buildData(vault, { live: true }); }
  catch (e) { console.error('[token_dump] 采集失败：' + ((e && e.stack) || e)); process.exit(4); }
  if (!data) { console.error('[token_dump] 采集返回空'); process.exit(5); }

  try { assertNoLeak(data); }           // 兜底：脱敏层失效则拒绝输出，避免凭证外泄
  catch (e) { console.error('[token_dump] ' + e.message); process.exit(6); }

  process.stdout.write(JSON.stringify(data));
})().catch(e => { console.error('[token_dump] ' + ((e && e.stack) || String(e))); process.exit(1); });
