/*

 * Sub-Store Bot — Telegram 剪贴板 + 订阅转换

 * 

 * 依赖:

 *   - proxy-utils.esm.js (Sub-Store 引擎 — 由 sync-proxy-utils.yml 从 sub-store-org/Sub-Store 同步构建)

 *   - Cloudflare Workers KV — 短链存储

 *   - BOT_TOKEN — Telegram Bot Token

 * 

 * 引擎版本: 同步自 sub-store-org/Sub-Store，通过 tools/proxy-utils-src/ 构建

 * 

 * 部署格式: ES Module Worker

 * 需要 CF 兼容性标志: nodejs_compat

 */

import { ProxyUtils } from './proxy-utils.esm.js';
import net from 'node:net';

const BOT_VERSION = '2.36.27';

// ==================== 工具函数 ====================

function genId(len = 7) {

  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';

  let s = '';

  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];

  return s;

}

// 上标数字（去同名用：节点² 节点³）

function superscriptNum(n) {

  const sup = '\u2070\u00B9\u00B2\u00B3\u2074\u2075\u2076\u2077\u2078\u2079';

  return String(n).split('').map(d => sup[parseInt(d)]).join('');

}

async function tg(method, token, body) {

  try {

    // 10 秒超时: 防止 TG API 卡死阻塞整个流程(如进度编辑卡住拉取)
    const ctrl = new AbortController();

    const tgTimer = setTimeout(() => ctrl.abort(), 10000);

    const r = await fetch('https://api.telegram.org/bot' + token + '/' + method, {

      method: 'POST',

      headers: { 'Content-Type': 'application/json' },

      body: JSON.stringify(body),

      signal: ctrl.signal,

    });

    clearTimeout(tgTimer);

    const ct = (r.headers.get('content-type') || '').toLowerCase();

    if (ct.includes('json')) return await r.json();

    // TG API 返回非 JSON（如 502 HTML 页）→ 静默失败

    return { ok: false, error_code: r.status, description: await r.text().catch(() => '') };

  } catch (e) {

    return { ok: false, error_code: 0, description: e.message };

  }

}

function escapeHTML(s) {

  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

}

// TTL 秒数 → 中文标签

function formatTtlLabel(s) {

  return s === 0 ? '\u6C38\u4E0D\u8FC7\u671F' : s < 3600 ? Math.round(s / 60) + '\u5206\u949F' : Math.round(s / 3600) + '\u5C0F\u65F6';

}

// ==================== 日志与错误处理 ====================

function log(level, uid, msg, data = null) {

  const entry = {

    ts: new Date().toISOString(),

    uid: String(uid || 'system'),

    level: level.toUpperCase(),

    msg,

    ...(data && { data })

  };

  console.log(JSON.stringify(entry));

}

async function safeExecute(fn, env, uid, cid, mid = null, context = '') {

  try {

    return await fn();

  } catch (err) {

    log('ERROR', uid, `Execution failed in ${context}`, {

      message: err.message,

      context

    });

    let hint = '';

    const lower = (err.message || '').toLowerCase();

    if (lower.includes('fetch') || lower.includes('timeout') || lower.includes('network') || lower.includes('502') || lower.includes('503')) {

      hint = '\n\n\u{1F4A1} \u8BA2\u9605\u94FE\u63A5\u53EF\u80FD\u65E0\u6CD5\u8BBF\u95EE\uFF0C\u5C1D\u8BD5\u66F4\u6362\u94FE\u63A5\u6216\u7A0D\u540E\u91CD\u8BD5';

    } else if (lower.includes('parse') || lower.includes('format') || lower.includes('json')) {

      hint = '\n\n\u{1F4A1} \u8BA2\u9605\u683C\u5F0F\u53EF\u80FD\u4E0D\u652F\u6301\uFF0C\u5C1D\u8BD5\u5176\u4ED6\u5BA2\u6237\u7AEF\u683C\u5F0F';

    } else if (lower.includes('empty') || lower.includes('0 node') || lower.includes('\u6CA1\u6709\u89E3\u6790')) {

      hint = '\n\n\u{1F4A1} \u8BA2\u9605\u4E2D\u6CA1\u6709\u68C0\u6D4B\u5230\u6709\u6548\u8282\u70B9';

    } else if (lower.includes('kv') || lower.includes('d1')) {

      hint = '\n\n\u{1F4A1} \u5B58\u50A8\u670D\u52A1\u5F02\u5E38\uFF0C\u8BF7\u68C0\u67E5 KV \u914D\u7F6E';

    }

    const userErrorMsg = '\u274C \u5904\u7406\u5931\u8D25' + (context ? ' [' + context + ']' : '') +

      '\n\n\u539F\u56E0: ' + (err.message || '\u672A\u77E5\u9519\u8BEF') + hint;

    if (mid) {

      return editMsg(env, cid, mid, userErrorMsg);

    } else {

      return replyMsg(env, uid, cid, userErrorMsg);

    }

  }

}

// ==================== Surge 格式行解析 ====================

function parseSurgeLines(text) {

  const proxies = [];

  const nonSurgeLines = [];

  const knownTypes = ['ss','snell','trojan','vless','vmess','hysteria2','tuic','socks5','http','https','wireguard','hysteria','juicity','anytls'];

  for (const rawLine of text.split('\n')) {

    const line = rawLine.trim();

    if (!line || line.startsWith('#') || line.startsWith('//')) continue;

    const eqIdx = line.indexOf('=');

    if (eqIdx === -1) { nonSurgeLines.push(rawLine); continue; }

    const beforeEq = line.slice(0, eqIdx).trim();

    const afterEq = line.slice(eqIdx + 1).trim();

    // 按逗号分割，但要处理引号内的逗号（如 psk="abc,def"）

    const parts = [];

    let buf = '', inQuote = false;

    for (let i = 0; i < afterEq.length; i++) {

      const ch = afterEq[i];

      if (ch === '"') { inQuote = !inQuote; buf += ch; }

      else if (ch === ',' && !inQuote) { parts.push(buf); buf = ''; }

      else { buf += ch; }

    }

    if (buf) parts.push(buf);

    if (parts.length < 3) { nonSurgeLines.push(rawLine); continue; }

    const type = parts[0].trim().toLowerCase();

    if (!knownTypes.includes(type)) { nonSurgeLines.push(rawLine); continue; }

    const proxy = { name: beforeEq, type, server: parts[1].trim(), port: parseInt(parts[2].trim(), 10) || 0 };

    // 解析剩余 key=value 对

    for (let i = 3; i < parts.length; i++) {

      const kv = parts[i].trim();

      const kidx = kv.indexOf('=');

      if (kidx === -1) continue;

      const k = kv.slice(0, kidx).trim();

      let v = kv.slice(kidx + 1).trim();

      // 去引号

      if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') v = v.slice(1, -1);

      if (k === 'version') proxy.version = parseInt(v, 10) || 0;

      else if (k === 'psk') proxy.psk = v;

      else if (k === 'obfs') proxy.obfs = v;

      else if (k === 'obfs-host') proxy['obfs-host'] = v;

      else if (k === 'obfs-uri') proxy['obfs-uri'] = v;

      else if (k === 'tfo') proxy.tfo = v === 'true' || v === true;

      else if (k === 'udp-relay') proxy.udp = v === 'true' || v === true;

      else if (k === 'ip-version') proxy['ip-version'] = v;

      else if (k === 'reuse') proxy.reuse = v === 'true' || v === true;

      else if (k === 'interface') proxy.interface = v;

      else proxy[k] = v;

    }

    proxies.push(proxy);

  }

  return { proxies, nonSurgeLines };

}

function parseProxies(text) {

  return parseProxiesWithSurge(text, false);

}

function parseProxiesWithSurge(text, skipSurge) {

  if (!skipSurge) {

    const { proxies: surge } = parseSurgeLines(text);

    if (surge.length > 0) return surge;

  }

  // parseClashYaml 优先（快 20-30 倍，CF Workers 10s 限制必须）

  try { const y = parseClashYaml(text); if (y.length > 0) return y; } catch {}

  // parseSingboxYaml：sing-box/Egern YAML 格式

  try { const s = parseSingboxYaml(text); if (s.length > 0) return s; } catch {}

  // parseSingboxJson：sing-box 官方 JSON 格式（outbounds 数组）

  try { const j = parseSingboxJson(text); if (j.length > 0) return j; } catch {}

  // ProxyUtils.parse 兜底（慢但全，处理非 YAML 格式）

  try { const r = ProxyUtils.parse(text); if (r && r.length > 0) return r; } catch {}

  return [];

}

// ==================== sing-box/Egern YAML 解析器 ====================

function parseSingboxYaml(text) {

  const proxies = [];

  if (!text || !text.includes('proxies:')) return proxies;

  const lines = text.split('\n');

  let inProxies = false;

  let currentProxy = null;

  let currentType = '';

  const typeMap = { shadowsocks: 'ss', vmess: 'vmess', vless: 'vless', trojan: 'trojan', wireguard: 'wireguard', hysteria2: 'hysteria2', tuic: 'tuic', http: 'http', socks5: 'socks5', snell: 'snell' };

  for (let i = 0; i < lines.length; i++) {

    const line = lines[i];

    if (/^proxies:\s*$/.test(line)) { inProxies = true; continue; }

    if (inProxies && /^\S/.test(line) && !line.startsWith('-')) { inProxies = false; continue; }

    if (!inProxies) continue;

    // 顶级列表项：- shadowsocks: 或 - wireguard:

    const topMatch = line.match(/^-\s+(\w+):\s*$/);

    if (topMatch) {

      if (currentProxy && currentProxy.type && currentProxy.server) proxies.push(currentProxy);

      currentType = topMatch[1];

      currentProxy = { name: '', type: typeMap[currentType] || currentType, server: '', port: 0 };

      continue;

    }

    // 子属性：    name: xxx

    if (currentProxy && /^\s{2,}\S/.test(line)) {

      const km = line.match(/^\s+(\S[\w-]*):\s*(.+)$/);

      if (!km) continue;

      const k = km[1], v = km[2].trim().replace(/^['"]|['"]$/g, '');

      if (k === 'name') currentProxy.name = v;

      else if (k === 'server') currentProxy.server = v;

      else if (k === 'port') currentProxy.port = parseInt(v, 10) || 0;

      else if (k === 'method') currentProxy.cipher = v;

      else if (k === 'password') currentProxy.password = v;

      else if (k === 'user_id') currentProxy.uuid = v;

      else if (k === 'uuid') currentProxy.uuid = v;

      else if (k === 'sni' || k === 'servername') currentProxy.sni = v;

      else if (k === 'network') currentProxy.network = v;

      else if (k === 'flow') currentProxy.flow = v;

      else if (k === 'tls') currentProxy.tls = v === 'true' || v === true;

      else if (k === 'udp_relay' || k === 'udp') currentProxy.udp = v === 'true' || v === true;

      else if (k === 'tfo') currentProxy.tfo = v === 'true' || v === true;

      else if (k === 'skip_tls_verify') currentProxy['skip-cert-verify'] = v === 'true' || v === true;

      else if (k === 'private_key') currentProxy['private-key'] = v;

      else if (k === 'peer_public_key') currentProxy['public-key'] = v;

      else if (k === 'local_ipv4') currentProxy.ip = v;

      else if (k === 'local_ipv6') currentProxy.ipv6 = v;

      else if (k === 'obfs') currentProxy.plugin = 'obfs';

      else if (k === 'obfs_host') { currentProxy.plugin = 'obfs'; currentProxy['plugin-opts'] = { ...(currentProxy['plugin-opts'] || {}), host: v }; }

      else if (k === 'obfs_password') currentProxy['obfs-password'] = v;

      else currentProxy[k] = v;

    }

  }

  if (currentProxy && currentProxy.type && currentProxy.server) proxies.push(currentProxy);

  return proxies;

}

// sing-box 官方 JSON 格式解析器(outbounds 数组), 通用能力
function parseSingboxJson(text) {

  const proxies = [];

  if (!text || typeof text !== 'string') return proxies;

  let obj = null;

  try { obj = JSON.parse(text); } catch { return proxies; }

  if (!obj || !Array.isArray(obj.outbounds)) return proxies;

  const skipTypes = new Set(['selector', 'urltest', 'direct', 'block', 'dns-out', 'dns', 'tun', 'redirect', 'mixed', 'shadowtls', 'hysteria']);

  const typeMap = { shadowsocks: 'ss', socks: 'socks5', 'socks5': 'socks5', https: 'https', 'http': 'http' };

  for (const o of obj.outbounds) {

    if (!o || typeof o !== 'object') continue;

    if (skipTypes.has(o.type)) continue;

    if (!o.server || !o.server_port) continue;

    const p = { name: o.tag || o.server, type: typeMap[o.type] || o.type, server: o.server, port: o.server_port, udp: true };

    if (o.password) p.password = o.password;

    if (o.method) p.cipher = o.method;

    if (o.uuid) p.uuid = o.uuid;

    if (o.flow) p.flow = o.flow;

    if (o.username) p.username = o.username;

    if (o.private_key) p['private-key'] = o.private_key;

    if (o.peer_public_key) p['public-key'] = o.peer_public_key;

    if (o.local_address && o.local_address.length > 0) p.ip = o.local_address[0];

    if (o.tls && typeof o.tls === 'object') {

      if (o.tls.server_name) p.sni = o.tls.server_name;

      if (o.tls.insecure) p['skip-cert-verify'] = true;

      if (o.tls.uuid) p.uuid = o.tls.uuid;

      if (o.tls.alpn && Array.isArray(o.tls.alpn)) p.alpn = o.tls.alpn.join(',');

    }

    if (o.transport && typeof o.transport === 'object') {

      if (o.transport.type) p.network = o.transport.type;

      if (o.transport.path) p['ws-path'] = o.transport.path;

      if (o.transport.host) p['ws-host'] = o.transport.host;

      if (o.transport.service_name) p['grpc-service-name'] = o.transport.service_name;

    }

    proxies.push(p);

  }

  return proxies;

}

function parseClashYaml(text) {

  const proxies = [];

  // Find proxies: section (with or without leading newline)

  let proxyIdx = text.indexOf('\nproxies:');

  if (proxyIdx === -1 && text.trimStart().startsWith('proxies:')) proxyIdx = 0;

  if (proxyIdx === -1) return proxies;

  let remaining = proxyIdx === 0 ? text.slice(9) : text.slice(proxyIdx + 10);

  // Find all "- name:" entries (0-4 space indent)

  const nameRe = /^(\s{0,4})- name: (.+)$/gm;

  let m;

  const entries = [];

  const pgIdx = remaining.indexOf('\nproxy-groups:');

  while ((m = nameRe.exec(remaining)) !== null) {

    if (pgIdx !== -1 && m.index > pgIdx) break;

    entries.push({ start: m.index, indent: m[1].length, name: m[2].trim().replace(/^['"]|['"]$/g, '') });

  }

  for (let i = 0; i < entries.length; i++) {

    const start = entries[i].start;

    const end = i + 1 < entries.length ? entries[i + 1].start : remaining.indexOf('\nproxy-groups:');

    const block = remaining.slice(start, end > 0 ? end : undefined);

    const proxy = { name: entries[i].name, type: '', server: '', port: 0 };

    // Dynamic indent: field indent = entry indent + 2 (e.g. 0→2, 2→4, 4→6)

    const fLo = entries[i].indent + 2, fHi = fLo + 4;

    const fieldRe = new RegExp(`^\\s{${fLo},${fHi}}([\\w][\\w-]*?):([ \\t]*[^\\n]*)$`, 'gm');

    let fm;

    // Nested object keys: plugin-opts, ws-opts, h2-opts, http-opts, grpc-opts
    const nestedKeys = new Set(['plugin-opts', 'ws-opts', 'h2-opts', 'http-opts', 'grpc-opts', 'obfs-opts', 'reality-opts', 'vless-opts', 'trojan-opts', 'shadowsocks-opts', 'mkcp-opts', 'mekya-opts', 'xhttp-opts', 'ech-opts', 'restls-opts', 'shadow-tls-opts', 'jls-opts']);
    const nestedObjs = {};

    while ((fm = fieldRe.exec(block)) !== null) {

      const k = fm[1];

      let v = fm[2].trim().replace(/^['"]|['"]$/g, '');

      if (nestedKeys.has(k) && !v) {
        // Empty value = nested object: collect sub-lines with deeper indent
        const afterNl = block.indexOf('\n', fm.index);
        const subLines = block.slice(afterNl + 1).split('\n');
        const obj = {};
        for (let si = 0; si < subLines.length; si++) {
          const line = subLines[si];
          const trimmed = line.trimStart();
          if (!trimmed) continue;
          const lineIndent = line.length - trimmed.length;
          if (lineIndent <= fLo) break;
          const kv = trimmed.match(/^([\w][\w-]*?):\s*(.*)/);
          if (!kv) continue;
          const sk = kv[1], sv = kv[2].trim();
          if (!sv) {
            // No value = check for array or sub-object
            const subBase = lineIndent + 2;
            let isArray = false;
            // Check if next non-empty line is an array item
            for (let sj = si + 1; sj < subLines.length; sj++) {
              const st2 = subLines[sj].trimStart();
              if (!st2) continue;
              const slIndent2 = subLines[sj].length - st2.length;
              if (slIndent2 <= lineIndent) break;
              if (st2.startsWith('- ')) { isArray = true; break; }
              break; // non-array sub-object
            }
            if (isArray) {
              const arr = [];
              for (let sj = si + 1; sj < subLines.length; sj++) {
                const sl = subLines[sj];
                const st = sl.trimStart();
                if (!st) continue;
                const slIndent = sl.length - st.length;
                if (slIndent <= lineIndent) break;
                const itemMatch = st.match(/^-\s+(.+)/);
                if (itemMatch) arr.push(itemMatch[1].trim().replace(/^['"]|['"]$/g, ''));
                else if (st === '-') arr.push('');
                else break;
              }
              obj[sk] = arr;
            } else {
              // Sub-object (e.g. headers:)
              const subObj = {};
              for (let sj = si + 1; sj < subLines.length; sj++) {
                const sl = subLines[sj];
                const st = sl.trimStart();
                if (!st) continue;
                const slIndent = sl.length - st.length;
                if (slIndent < subBase) break;
                const skv = st.match(/^([\w][\w-]*?):\s*(.+)/);
                if (skv) subObj[skv[1]] = skv[2].trim().replace(/^['"]|['"]$/g, '');
              }
              obj[sk] = subObj;
            }
          } else {
            obj[sk] = sv.replace(/^['"]|['"]$/g, '');
          }
        }
        nestedObjs[k] = obj;
      }
      else if (k === 'type') proxy.type = v.toLowerCase();

      else if (k === 'server') proxy.server = v;

      else if (k === 'port') proxy.port = parseInt(v, 10) || 0;

      else if (k === 'password') proxy.password = v;

      else if (k === 'uuid') proxy.uuid = v;

      else if (k === 'cipher') proxy.cipher = v;

      else if (k === 'sni' || k === 'servername') proxy.sni = v;

      else if (k === 'network') proxy.network = v;

      else if (k === 'flow') proxy.flow = v;

      else if (k === 'tls') proxy.tls = v === 'true' || v === true;

      else if (k === 'udp') proxy.udp = v === 'true' || v === true;

      else if (k === 'skip-cert-verify') proxy['skip-cert-verify'] = v === 'true' || v === true;

      else if (k === 'alpn') {
        if (!v) {
          // Empty value = YAML array: collect subsequent "- item" lines
          const afterNl = block.indexOf('\n', fm.index);
          const subLines = block.slice(afterNl + 1).split('\n');
          const arr = [];
          for (const sl of subLines) {
            const trimmed = sl.trimStart();
            const lineIndent = sl.length - trimmed.length;
            if (lineIndent <= fLo) break;
            const itemMatch = trimmed.match(/^-\s+(.+)/);
            if (itemMatch) arr.push(itemMatch[1].trim().replace(/^['"]|['"]$/g, ''));
            else if (trimmed.startsWith('-')) arr.push('');
            else break;
          }
          proxy.alpn = arr.length > 0 ? arr : [];
        } else {
          proxy.alpn = typeof v === 'string' ? v.split(',').map(s => s.trim().replace(/^['"]|['"]$/g, '')) : v;
        }
      }

      else if (k === 'client-fingerprint') proxy['client-fingerprint'] = v;

      else if (k === 'plugin') proxy.plugin = v;
      else if (k === 'idle-session-check-interval') proxy['idle-session-check-interval'] = parseInt(v) || 0;
      else if (k === 'idle-session-timeout') proxy['idle-session-timeout'] = parseInt(v) || 0;
      else if (k === 'min-idle-session') proxy['min-idle-session'] = parseInt(v) || 0;
      else if (k === 'udp-over-tcp') proxy['udp-over-tcp'] = v === 'true' || v === true;
      else if (k === 'udp-relay-mode') proxy['udp-relay-mode'] = v;
      else if (k === 'ip-version') proxy['ip-version'] = v;
      else if (k === 'alterId') proxy['alterId'] = parseInt(v) || 0;
      else if (k === 'psk') proxy.psk = v;
      else if (k === 'obfs') proxy.obfs = v;
      else if (k === 'version') proxy.version = parseInt(v) || 0;
      else if (k === 'username') proxy.username = v;
      else if (k === 'dialer-proxy') proxy['dialer-proxy'] = v;
      else if (k === 'fingerprint') proxy.fingerprint = v;
      else if (k === 'encryption') proxy.encryption = v;
      else if (k === 'smux') proxy.smux = v;

      else if (k === 'tfo') proxy.tfo = v === 'true' || v === true;

      else if (k === 'reality') proxy.reality = v === 'true' || v === true;

      else if (v === 'true') proxy[k] = true;

      else if (v === 'false') proxy[k] = false;

      else proxy[k] = v;

    }

    // Merge nested objects (plugin-opts, ws-opts, etc.)
    Object.assign(proxy, nestedObjs);

    if (proxy.type && proxy.server && proxy.port) {

      // Normalize: fill implicit fields for engine compatibility

      if (!proxy.network && ['trojan','vless','vmess'].includes(proxy.type)) proxy.network = 'tcp';

      proxies.push(proxy);

    }

  }

  return proxies;

}

// ==================== 国家旗帜 ====================

// 国家数据：code, 旗帜 emoji, 别名列表
// 别名按长度降序匹配，短英文（≤3 纯字母）自动加 \b 词边界防误触
const COUNTRY_FLAGS = {
  HK: { emoji: '🇭🇰', aliases: ['香港', 'Hong Kong', 'HK'] },
  TW: { emoji: '🇹🇼', aliases: ['台湾', '台灣', 'Taiwan', 'TW'] },
  JP: { emoji: '🇯🇵', aliases: ['日本', 'Japan', 'JP', '东京', '大阪', '埼玉'] },
  KR: { emoji: '🇰🇷', aliases: ['韩国', 'Korea', 'KR', '首尔', '春川'] },
  SG: { emoji: '🇸🇬', aliases: ['新加坡', 'Singapore', 'SG', '狮城'] },
  US: { emoji: '🇺🇸', aliases: ['美国', 'United States', 'US', '洛杉矶', '圣何塞', '纽约', '西雅图', '芝加哥', '波特兰', '达拉斯'] },
  GB: { emoji: '🇬🇧', aliases: ['英国', 'United Kingdom', 'UK', 'GB', '伦敦'] },
  DE: { emoji: '🇩🇪', aliases: ['德国', 'Germany', 'DE', '法兰克福'] },
  FR: { emoji: '🇫🇷', aliases: ['法国', 'France', 'FR', '巴黎'] },
  NL: { emoji: '🇳🇱', aliases: ['荷兰', 'Netherlands', 'NL', '阿姆斯特丹'] },
  RU: { emoji: '🇷🇺', aliases: ['俄罗斯', 'Russia', 'RU', '莫斯科'] },
  IN: { emoji: '🇮🇳', aliases: ['印度', 'India', 'IN', '孟买'] },
  AU: { emoji: '🇦🇺', aliases: ['澳大利亚', 'Australia', 'AU', '悉尼'] },
  CA: { emoji: '🇨🇦', aliases: ['加拿大', 'Canada', 'CA', '蒙特利尔'] },
  BR: { emoji: '🇧🇷', aliases: ['巴西', 'Brazil', 'BR'] },
  ZA: { emoji: '🇿🇦', aliases: ['南非', 'South Africa', 'ZA'] },
  AR: { emoji: '🇦🇷', aliases: ['阿根廷', 'Argentina', 'AR'] },
  TR: { emoji: '🇹🇷', aliases: ['土耳其', 'Turkey', 'TR'] },
  CH: { emoji: '🇨🇭', aliases: ['瑞士', 'Switzerland', 'CH'] },
  SE: { emoji: '🇸🇪', aliases: ['瑞典', 'Sweden', 'SE'] },
  IT: { emoji: '🇮🇹', aliases: ['意大利', 'Italy', 'IT'] },
  ES: { emoji: '🇪🇸', aliases: ['西班牙', 'Spain', 'ES'] },
  IE: { emoji: '🇮🇪', aliases: ['爱尔兰', 'Ireland', 'IE'] },
  MY: { emoji: '🇲🇾', aliases: ['马来西亚', 'Malaysia', 'MY'] },
  TH: { emoji: '🇹🇭', aliases: ['泰国', 'Thailand', 'TH'] },
  VN: { emoji: '🇻🇳', aliases: ['越南', 'Vietnam', 'VN'] },
  PH: { emoji: '🇵🇭', aliases: ['菲律宾', 'Philippines', 'PH'] },
  ID: { emoji: '🇮🇩', aliases: ['印度尼西亚', 'Indonesia', 'ID'] },
  NZ: { emoji: '🇳🇿', aliases: ['新西兰', 'New Zealand', 'NZ'] },
  AE: { emoji: '🇦🇪', aliases: ['阿联酋', 'United Arab Emirates', 'AE'] },
};

// 编列正则列表，按别名长度降序
const flagRules = [];
for (const code in COUNTRY_FLAGS) {
  for (const alias of COUNTRY_FLAGS[code].aliases) {
    const esc = alias.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
    const pat = alias.length <= 3 && /^[A-Za-z]+$/.test(alias) ? '\\b' + esc + '\\b' : esc;
    flagRules.push({ re: new RegExp(pat, 'i'), emoji: COUNTRY_FLAGS[code].emoji });
  }
}
flagRules.sort((a, b) => b.re.source.length - a.re.source.length);

function addFlag(name) {
  name = String(name || '').trim() || '未命名';
  if (/[\u{1F1E6}-\u{1F1FF}]{2}/u.test(name)) return name;
  for (const { re, emoji } of flagRules) {
    if (re.test(name)) return emoji + ' ' + name;
  }
  return name;
}

// ==================== Egern JSON-in-YAML → proper YAML ====================

function egernToProperYaml(text) {

  if (!text || !text.includes('{"')) return text;

  const lines = text.split('\n');

  const out = [];

  for (const line of lines) {

    const m = line.match(/^(\s*)- (\{.*\})$/);

    if (m) {

      try {

        const obj = JSON.parse(m[2]);

        const entries = objToYaml(obj);

        out.push('- ' + entries[0]);

        for (let i = 1; i < entries.length; i++) out.push('  ' + entries[i]);

        continue;

      } catch {}

    }

    out.push(line);

  }

  return out.join('\n');

}

function objToYaml(obj) {

  const lines = [];

  for (const [k, v] of Object.entries(obj)) {

    if (v && typeof v === 'object' && !Array.isArray(v)) {

      lines.push(k + ':');

      for (const l of objToYaml(v)) lines.push('  ' + l);

    } else if (Array.isArray(v)) {

      lines.push(k + ':');

      for (const item of v) {

        if (item && typeof item === 'object') {

          const sub = objToYaml(item);

          lines.push('  - ' + sub[0]);

          for (let i = 1; i < sub.length; i++) lines.push('    ' + sub[i]);

        } else {

          lines.push('  - ' + JSON.stringify(item));

        }

      }

    } else if (typeof v === 'string') {

      const needQuote = /[:{}\[\],&*?|>!%#@`]/.test(v) || v === '' || /^\s|\s$/.test(v);

      lines.push(k + ': ' + (needQuote ? JSON.stringify(v) : v));

    } else if (v === null || v === undefined) {

      lines.push(k + ': null');

    } else {

      lines.push(k + ': ' + v);

    }

  }

  return lines;

}

// ==================== 本地订阅收集系统 ====================

function collectionText(collection) {

  const items = collection?.items || [];

  const mode = collection?.mode || 'file';

  let lines = ['\u{1F4C1} ' + (mode === 'url' ? '远程订阅收集' : '本地订阅') + '  \u26A0\uFE0F 数据临时有效，请尽快处理', ''];

  lines.push('\u{1F4CA} 已收集: ' + items.length + ' \u6761');

  if (items.length === 0) {

    lines.push('');

    lines.push(mode === 'url' ? '请发送订阅链接' : '请发送节点文件或粘贴订阅内容');

  } else {

    lines.push('');

    items.forEach((item, i) => {

      const prefix = (i + 1) + '.\u3000';

      if (item.name) {

        const sizeStr = item.size > 1024 ? Math.round(item.size / 1024) + 'KB' : item.size + 'B';

        lines.push(prefix + '\u{1F4C4} ' + item.name + ' (' + sizeStr + ')');

      } else if (item.url) {

        lines.push(prefix + '\u{1F310} ' + item.url.slice(0, 80) + (item.url.length > 80 ? '...' : ''));

      } else {

        const preview = item.content.slice(0, 80).replace(/\n/g, ' ').replace(/</g, '&lt;');

        lines.push(prefix + '\u{1F4DD} "' + preview + '..."');

      }

    });

    lines.push('');

    lines.push('完成后点击\u300C\u2705 \u5F00\u59CB\u5904\u7406\u300D');

    lines.push('');

    lines.push('\u26A0\uFE0F 数据临时有效，回收后需重新收集');

  }

  return lines.join('\n');

}

function collectionKb(hasItems) {

  const buttons = [];

  if (hasItems) {

    buttons.push({ text: '\u2705 开始处理', callback_data: 'collection_process' });

  }

  buttons.push({ text: '\u{1F519} 返回', callback_data: 'menu' });

  return { inline_keyboard: [buttons] };

}

// Atomic IP counting + access limit (PR #1, burn handled at route level)

async function atomicTrackIP(env, id, clientIP, maxIPs, ttl) {

  const key = 'share_' + id;

  for (let i = 0; i < 5; i++) {

    let data;

    try {

      data = await env.KV.getWithMetadata(key, { type: 'json' });

    } catch { return { consumed: false, isNewIP: false, error: 'kv_read' }; }

    if (!data || !data.value) return { consumed: false, isNewIP: false, error: 'not_found' };

    const raw = data.value || {};

    if (raw.consumed) return { consumed: true, isNewIP: false };

    const ips = Array.isArray(raw.accessedIPs) ? raw.accessedIPs : [];

    if (!ips.includes(clientIP)) {

      const next = [...ips, clientIP];

      const updated = { ...raw, accessedIPs: next };

      const opts = {};

      if (ttl && ttl > 0) opts.expirationTtl = ttl;

      if (data.metadata && data.metadata.version !== undefined) opts.ifVersion = data.metadata.version;

      try {

        await env.KV.put(key, JSON.stringify(updated), opts);

        return { consumed: false, isNewIP: true, count: next.length, exceeded: maxIPs > 0 && next.length > maxIPs };

      } catch { continue; }

    } else {

      return { consumed: false, isNewIP: false, count: ips.length, exceeded: maxIPs > 0 && ips.length >= maxIPs };

    }

  }

  return { consumed: false, isNewIP: false, error: 'max_retries' };

}

// ==================== 按钮布局 ====================

function mainKb() {

  return {

    inline_keyboard: [

      [

        { text: '\u{1F310} 远程订阅', callback_data: 'input_url' },

        { text: '\u{1F4CE} 本地订阅', callback_data: 'input_file' },

      ],

      [

        { text: '\u{1F310} UA 轮询', callback_data: 'ua_menu' },

        { text: '\u{23F1} \u77ED\u94FE\u65F6\u9650', callback_data: 'limit_menu' },

      ],

      [

        { text: '\u{1F4CB} 我的短链', callback_data: 'my_links_0' },

        { text: '\u{1F4DD} \u6A21\u677F\u7BA1\u7406', callback_data: 'tmpl_menu' },

      ],

    ],

  };

}

const FORMAT_OPTIONS = [

  { id: 'clashmeta', label: 'Clash Meta' },

  { id: 'uri', label: 'URI 标准链' },

  { id: 'json', label: 'JSON' },

  { id: 'v2ray', label: 'V2Ray' },

  { id: 'singbox', label: 'sing-box' },

  { id: 'surfboard', label: 'Surfboard' },

  { id: 'qx', label: 'Quantumult X' },

  { id: 'shadowrocket', label: 'Shadowrocket' },

  { id: 'surge', label: 'Surge' },

  { id: 'Loon', label: 'Loon' },

  { id: 'stash', label: 'Stash' },

  { id: 'egern', label: 'Egern' },

  { id: 'b64', label: 'Base64' },

  { id: 'native', label: '自定 YAML' },

];

function fmtKb(allowed, convTtl, ttlDefault, u) {

  const formats = allowed || FORMAT_OPTIONS;

  const rows = [];

  let row = [];

  for (const f of formats) {

    row.push({ text: f.label, callback_data: 'conv_fmt:' + f.id });

    if (row.length === 2) {

      rows.push(row);

      row = [];

    }

  }

  if (row.length) rows.push(row);

  const ttlVal = convTtl != null ? convTtl : (ttlDefault != null ? ttlDefault : 0);

  const ttlLabel = formatTtlLabel(ttlVal);

  const effAcc = u?._convAccessLimit != null ? u._convAccessLimit : (u?._accessLimit != null ? u._accessLimit : 0);

  const accLabel = effAcc === 0 ? '\u4E0D\u9650' : effAcc + ' IP';

  rows.push([{ text: '\u{23F1} \u672C\u6B21\u65F6\u9650: ' + ttlLabel + ' / ' + accLabel, callback_data: 'conv_limit_menu' }]);

  rows.push([{ text: (u?._checkAlive ? '\u2705 ' : '') + '\u{1F52C} \u6D4B\u6D3B\u8F93\u51FA\u3010\u5B9E\u9A8C\u3011', callback_data: 'conv_toggle_check' }]);

  rows.push([{ text: (u?._burn ? '\u2705 ' : '') + '\u{1F525} \u9605\u540E\u5373\u711A', callback_data: 'conv_toggle_burn' }]);

  rows.push([{ text: (u?._landing ? '\u2705 ' : '') + '\u{1F504} \u6885\u5F00\u4E8C\u5EA6', callback_data: 'conv_toggle_landing' }]);

  rows.push([{ text: '\u2190 返回', callback_data: 'menu' }]);

  return { inline_keyboard: rows };

}

function ttlKb(current, prefix, backCb) {

  const cbPrefix = prefix || 'ttl_set:';

  const opts = [

    { s: 0, l: '\u6C38\u4E0D\u8FC7\u671F' },

    { s: 300, l: '5\u5206\u949F' },

    { s: 900, l: '15\u5206\u949F' },

    { s: 3600, l: '1\u5C0F\u65F6' },

    { s: 21600, l: '6\u5C0F\u65F6' },

    { s: 86400, l: '1\u5929' },

    { s: 604800, l: '7\u5929' },

    { s: 2592000, l: '30\u5929' },

  ];

  const rows = [];

  let row = [];

  for (const o of opts) {

    const selected = o.s === current;

    const icon = selected ? '\u2705 ' : '';

    row.push({ text: icon + o.l, callback_data: cbPrefix + o.s });

    if (row.length === 2) {

      rows.push(row);

      row = [];

    }

  }

  if (row.length) rows.push(row);

  // 返回按钮：优先使用传入的 backCb

  let backBtn;

  if (backCb) {

    backBtn = backCb;

  } else if (prefix && prefix.startsWith('chg_ttl_')) {

    backBtn = 'link_' + prefix.slice(8, -1);

  } else if (prefix && prefix.startsWith('conv_ttl_set:')) {

    backBtn = 'conv_back';

  } else {

    backBtn = 'menu';

  }

  rows.push([{ text: '\u2190 \u8FD4\u56DE', callback_data: backBtn }]);

  return { inline_keyboard: rows };

}

function accKb(current, prefix, backCb) {

  const opts = [

    { v: 0, l: '\u4E0D\u9650' },

    { v: 10, l: '10 IP' },

    { v: 50, l: '50 IP' },

    { v: 100, l: '100 IP' },

    { v: 500, l: '500 IP' },

    { v: 1000, l: '1000 IP' },

    { v: 10000, l: '10000 IP' },

  ];

  const cbPrefix = prefix || 'acc_set:';

  const rows = [];

  let row = [];

  for (const o of opts) {

    const selected = o.v === current;

    row.push({ text: (selected ? '\u2705 ' : '') + o.l, callback_data: cbPrefix + o.v });

    if (row.length === 2) { rows.push(row); row = []; }

  }

  if (row.length) rows.push(row);

  // 返回按钮：优先使用传入的 backCb

  let backBtn;

  if (backCb) {

    backBtn = backCb;

  } else if (prefix && prefix.startsWith('chg_acc_')) {

    backBtn = 'link_' + prefix.slice(8, -1);

  } else if (prefix && prefix.startsWith('conv_acc_set:')) {

    backBtn = 'conv_back';

  } else {

    backBtn = 'menu';

  }

  rows.push([{ text: '\u2190 \u8FD4\u56DE', callback_data: backBtn }]);

  return { inline_keyboard: rows };

}

function backKb() {

  return { inline_keyboard: [[{ text: '\u2190 返回', callback_data: 'menu' }]] };

}

// ===== 通用消息工具 =====

// 回调场景：直接编辑原消息

async function editMsg(env, cid, mid, text, kb) {

  return tg('editMessageText', env.BOT_TOKEN, {

    chat_id: cid, message_id: mid, text, parse_mode: 'HTML',

    reply_markup: kb || backKb(),

  });

}

// 文本输入场景：优先编辑主页消息，失败则发新消息

async function replyMsg(env, uid, cid, text, kb) {

  const u = getState(uid);

  if (u.promptCid && u.promptMid) {

    const ok = await tg('editMessageText', env.BOT_TOKEN, {

      chat_id: u.promptCid, message_id: u.promptMid, text, parse_mode: 'HTML',

      reply_markup: kb || backKb(),

    }).catch(() => null);

    if (ok && ok.ok !== false) return ok;

  }

  return tg('sendMessage', env.BOT_TOKEN, {

    chat_id: cid, text, parse_mode: 'HTML',

    reply_markup: kb || backKb(),

  });

}

function resultKb(url) {

  return {

    inline_keyboard: [

      [

        { text: '\u{1F517} \u4E3B\u94FE', url: url },

        { text: '\u{1F4E4} \u5206\u4EAB', url: 'https://t.me/share/url?url=' + encodeURIComponent(url) },

      ],

      [

        { text: '\u{1F3E0} \u4E3B\u9875', callback_data: 'menu' },

      ],

    ],

  };

}

function multiResultKb(mainUrl, extraUrls) {

  const kb = [

    [

      { text: '\u{1F517} \u4E3B\u94FE', url: mainUrl },

      { text: '\u{1F4E4} \u5206\u4EAB', url: 'https://t.me/share/url?url=' + encodeURIComponent(mainUrl) },

    ],

  ];

  for (const ext of (extraUrls || [])) {

    kb.push([

      ext,

      { text: '\u{1F4E4} \u5206\u4EAB', url: 'https://t.me/share/url?url=' + encodeURIComponent(ext.url) },

    ]);

  }

  kb.push([

    { text: '\u{1F3E0} \u4E3B\u9875', callback_data: 'menu' },

  ]);

  return { inline_keyboard: kb };

}

// ==================== 主页文字 ====================

function mainPageText() {

  return '<b>\u{1F916} Sub-Store Bot</b>  <code>v' + BOT_VERSION + '</code>\n\n' +

    '\u{1F310} <b>\u8FDC\u7A0B\u8BA2\u9605</b> \u2014 \u53D1\u94FE\u63A5\uFF0C\u81EA\u52A8\u62C9\u53D6\u8F6C\u6362\n' +

    '\u{1F4CE} <b>\u672C\u5730\u8BA2\u9605</b> \u2014 \u53D1\u8282\u70B9/\u6587\u4EF6\uFF0C\u81EA\u52A8\u89E3\u6790\u8F6C\u6362\n' +

    '\u2705 \u666E\u901A\u6587\u672C \u2014 \u81EA\u52A8\u4FDD\u5B58\u4E3A\u77ED\u94FE\n\n' +

    '\u{1F4E6} <b>\u8F93\u51FA\u683C\u5F0F (' + FORMAT_OPTIONS.length + ')</b>\n\n' +

    '\u{1F517} \u8F6C\u6362\u7ED3\u679C\u4EE5\u77ED\u94FE\u5F62\u5F0F\u8FD4\u56DE';

}

// ==================== 用户状态管理 ====================

const stateMap = new Map();

function getState(uid) {

  if (!stateMap.has(uid)) {

    if (stateMap.size >= 100) {

      const first = stateMap.keys().next().value;

      stateMap.delete(first);

    }

    stateMap.set(uid, { _uid: uid });

  }

  return stateMap.get(uid);

}


// Helper: get collectMode (memory + KV fallback)
async function getCollectModeSync(uid, u, env) {
  if (u._collectMode) return u._collectMode;
  const mode = await getCollectMode(uid, env);
  if (mode) u._collectMode = mode;
  return mode;
}

// Helper: set collectMode (memory + KV)
async function setCollectMode(uid, u, mode, env) {
  u._collectMode = mode;
  await saveCollectMode(uid, mode, env);
}

// ==================== 收集器 KV 持久化（解决多 isolate 内存隔离问题） ====================

async function getCollected(uid, env) {
  const raw = await env.KV.get('collected:' + uid, { type: 'json' }).catch(() => null);
  return raw || [];
}

async function saveCollected(uid, items, env) {
  await env.KV.put('collected:' + uid, JSON.stringify(items), { expirationTtl: 7200 });
}

async function clearCollected(uid, env) {
  await env.KV.delete('collected:' + uid).catch(() => {});
}

async function getCollectMode(uid, env) {
  return await env.KV.get('collectmode:' + uid, { type: 'text' }).catch(() => null);
}

async function saveCollectMode(uid, mode, env) {
  if (mode) {
    await env.KV.put('collectmode:' + uid, mode, { expirationTtl: 7200 });
  } else {
    await env.KV.delete('collectmode:' + uid).catch(() => {});
  }
}

// ==================== 用户配置持久化（KV 存储） ====================

async function loadUserConfig(uid, env) {

  try {

    const raw = await env.KV.get('cfgu:' + uid, { type: 'json' }) || {};

    // 如果 cfgu 里没有 _flowHeader/_flowName，从 tmpl_flow_active 重建

    if (!raw._flowHeader && !raw._flowName) {

      try {

        const activeIdx = parseInt(await env.KV.get('tmpl_flow_active:' + uid));

        if (!isNaN(activeIdx) && activeIdx >= 0) {

          const templates = JSON.parse(await env.KV.get('tmpl_flow:' + uid)) || [];

          if (activeIdx < templates.length) {

            raw._flowHeader = templates[activeIdx].header;

            raw._flowName = templates[activeIdx].name;

            // 回写到 cfgu，下次不用再重建

            await env.KV.put('cfgu:' + uid, JSON.stringify(raw)).catch(() => {});

          }

        }

      } catch {}

    }

    return raw;

  } catch { return {}; }

}

async function saveUserConfig(uid, env, state) {

  // 读取现有配置，合并更新（避免丢失未改动的字段）

  let existing = {};

  try { const raw = await env.KV.get('cfgu:' + uid, { type: 'json' }); if (raw) existing = raw; } catch {}

  const cfg = { ...existing };

  // 只更新明确传入的字段（不覆盖未传入的）

  if ('ttl' in state) cfg.ttl = state.ttl;

  if ('_accessLimit' in state) cfg._accessLimit = state._accessLimit;

  if ('_flowHeader' in state) cfg._flowHeader = state._flowHeader;

  if ('_flowName' in state) cfg._flowName = state._flowName;

  if ('_checkAlive' in state) cfg._checkAlive = state._checkAlive;

  await env.KV.put('cfgu:' + uid, JSON.stringify(cfg)).catch(() => {});

}

// ==================== TG 请求限流 ====================

const rateLimitMap = new Map();

function applyRateLimit(uid, allowedUsers) {

  // 有 ALLOWED_USERS（部署者单人用）→ 不限流

  if (allowedUsers) return false;

  const now = Date.now();

  // 定期清理过期条目（每 100 次请求清理一次）

  if (rateLimitMap.size > 0 && rateLimitMap.size % 100 === 0) {

    for (const [k, v] of rateLimitMap) {

      if (now - v.start > 60000) rateLimitMap.delete(k);

    }

  }

  const key = uid;

  const entry = rateLimitMap.get(key);

  if (!entry) {

    rateLimitMap.set(key, { count: 1, start: now });

    if (rateLimitMap.size > 1000) {

      const first = rateLimitMap.keys().next().value;

      rateLimitMap.delete(first);

    }

    return false;

  }

  if (now - entry.start > 30000) {

    // 超过 30 秒窗口 → 重置

    entry.count = 1;

    entry.start = now;

    return false;

  }

  entry.count++;

  return entry.count > 5; // 30 秒内超过 5 次 → 限流

}

// ==================== 订阅拉取（多 UA 轮询，支持用户自定义） ====================

const FETCH_UAS = [

  'Karing', 'FLClash', 'clash-verge', 'sing-box', 'clashmeta', 'shadowrocket', 'surge',

];

// 获取用户 UA 配置

async function getUaConfig(uid, env) {

  try {

    const raw = await env.KV.get('ua:' + uid, { type: 'json' });

    return raw || { custom: [], disabled: [] };

  } catch { return { custom: [], disabled: [] }; }

}

async function saveUaConfig(uid, env, cfg) {

  await env.KV.put('ua:' + uid, JSON.stringify(cfg));

}

function showUaSettings(cid, mid, uid, env) {

  return getUaConfig(uid, env).then(async (cfg) => {

    let text = '<b>\u{1F310} UA \u8F6E\u8BE2 \u8BBE\u7F6E</b>\n\n';

    text += '\u{1F504} \u5F53\u524D <b>' + (cfg.custom || []).length + '</b> \u4E2A\u81EA\u5B9A\u4E49\u3001<b>' + (FETCH_UAS.length - (cfg.disabled || []).length) + '</b>/' + FETCH_UAS.length + ' \u4E2A\u9ED8\u8BA4\n\n';

    const rows = [];

    // 默认 UA — 两列

    let row = [];

    for (let i = 0; i < FETCH_UAS.length; i++) {

      const enabled = !(cfg.disabled || []).includes(i);

      const icon = enabled ? '\u2705' : '\u274C';

      const ua = FETCH_UAS[i];

      const short = ua.length > 14 ? ua.slice(0, 12) + '..' : ua;

      row.push({ text: icon + ' ' + short, callback_data: 'ua_toggle:' + i });

      if (row.length === 2) {

        rows.push(row);

        row = [];

      }

    }

    if (row.length) rows.push(row);

    // 自定义 UA — 每行一个，右侧带删除

    for (let ci = 0; ci < (cfg.custom || []).length; ci++) {

      const ua = cfg.custom[ci];

      const short = ua.length > 20 ? ua.slice(0, 18) + '..' : ua;

      rows.push([

        { text: '\u{1F4DD} ' + escapeHTML(short), callback_data: 'noop' },

        { text: '\u{1F5D1}', callback_data: 'ua_del:' + ci },

      ]);

    }

    rows.push([

      { text: '\u2795 \u6DFB\u52A0\u81EA\u5B9A\u4E49', callback_data: 'ua_add' },

      { text: '\u21A9 \u6062\u590D\u9ED8\u8BA4', callback_data: 'ua_reset' },

    ]);

    rows.push([{ text: '\u2190 \u8FD4\u56DE', callback_data: 'menu' }]);

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: text,

      parse_mode: 'HTML',

      reply_markup: { inline_keyboard: rows },

    });

  });

}

// 构建有效 UA 列表（自定义 UA 与默认 UA 不区分大小写去重）

async function getUaList(uid, env) {

  const cfg = await getUaConfig(uid, env);

  const disabledSet = new Set(cfg.disabled || []);

  const list = [];

  const seen = new Set();

  for (let i = 0; i < FETCH_UAS.length; i++) {

    if (!disabledSet.has(i)) {

      const ua = FETCH_UAS[i];

      list.push(ua);

      seen.add(ua.toLowerCase());

    }

  }

  for (const ua of (cfg.custom || [])) {

    if (!seen.has(ua.toLowerCase())) {

      list.push(ua);

      seen.add(ua.toLowerCase());

    }

  }

  return list;

}

async function fetchSub(url, uid, env, progress) {
  // 自己域名的短链：直接从 KV 读取，避免 CF 无法 fetch 自己域名
  const clipBase = env._clipBase || '';
  if (clipBase && url.startsWith(clipBase + '/share/')) {
    const id = url.split('/share/')[1]?.split(/[?#]/)[0];
    if (id) {

      if (progress) await Promise.race([progress({ type: 'kv' }).catch(() => {}), new Promise(r => setTimeout(r, 5000))]);

      const kvData = await env.KV.get('share_' + id, { type: 'json' }).catch(() => null);
      if (kvData && kvData.text) {
        return { text: kvData.text, ua: 'KV_DIRECT' };
      }
      return { text: '', ua: 'KV_NOT_FOUND' };
    }
  }

  const uaList = await getUaList(uid, env);

  if (uaList.length === 0) uaList.push(FETCH_UAS[0]);

  const seen = new Set();

  let bestText = '';

  let bestUa = '';

  let bestCount = 0;


  let bestParsed = null;

  const BATCH_SIZE = 5;

  for (let batchStart = 0; batchStart < uaList.length; batchStart += BATCH_SIZE) {

    const batch = uaList.slice(batchStart, batchStart + BATCH_SIZE);

    const results = await Promise.allSettled(

      batch.map(async (ua) => {

        try {

          const text = await Promise.race([

            fetch(url, { headers: { 'User-Agent': ua } }).then(r => r.text()),

            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 10000)),

          ]);

          return { text, ua };

        } catch { return { text: '', ua }; }

      })

    );

    for (const r of results) {

      if (r.status !== 'fulfilled') continue;

      const text = r.value.text;

      if (!text || text.length < 50) continue;

      if (text.includes('访问被拒绝') || text.includes('不支持浏览器') || text.includes('<html') || text.includes('<HTML') || text.includes('<!DOC')) continue;

      const key = text.slice(0, 200);

      if (seen.has(key)) continue;

      seen.add(key);

      try {

        // 完整解析链(含 Surge 配置解析), 避免 Surge 格式订阅被判 0 节点
        let parsed = null;

        try { parsed = parseProxies(text); } catch {}

        if (!parsed || parsed.length === 0) {

          try { parsed = ProxyUtils.parse(text); } catch {}

        }

        const count = parsed?.length || 0;

        if (count > bestCount) {

          bestCount = count;

          bestText = text;

          bestUa = r.value.ua;

          bestParsed = parsed;

        }

      } catch { /* parse fail, skip */ }

    }

  


    // 批次进度报告
    if (progress) await Promise.race([progress({ type: 'ua', done: Math.min(batchStart + BATCH_SIZE, uaList.length), total: uaList.length, found: bestCount, ua: bestUa }).catch(() => {}), new Promise(r => setTimeout(r, 5000))]);

}

  // 直连全失败 → 走反代（绕过 CF Worker 被 CF 防护拦截）
  // PROXY_URL 支持逗号分隔多个反代, 按序尝试, 第一个成功即停
  const proxyList = (env.PROXY_URL || '').split(',').map(s => s.trim()).filter(Boolean);

  for (const oneProxy of proxyList) {

    if (bestText) break;

    if (progress) await Promise.race([progress({ type: 'proxy', which: oneProxy }).catch(() => {}), new Promise(r => setTimeout(r, 5000))]);

    try {

      // 自动补 url= 前缀，兼容 PROXY_URL 以 & 结尾或缺 url= 的配置
      let proxyBase = oneProxy;
      if (!/url=/.test(proxyBase)) {
        if (!proxyBase.endsWith('&') && !proxyBase.endsWith('?')) proxyBase += (proxyBase.includes('?') ? '&' : '?');
        proxyBase += 'url=';
      }
      const proxyUrl = proxyBase + encodeURIComponent(url);

      const proxyText = await Promise.race([

        fetch(proxyUrl).then(r => r.text()),

        new Promise((_, reject) => setTimeout(() => reject(new Error('proxy timeout')), 15000)),

      ]);

      if (proxyText && proxyText.length >= 50 && !proxyText.includes('<html') && !proxyText.includes('Just a moment')) {

        try {

          const parsed = ProxyUtils.parse(proxyText);

          const count = parsed?.length || 0;

          if (count > 0) {

            bestText = proxyText;

            bestUa = String(oneProxy).includes('/t5') ? 'T5节点' : 'proxy';

            bestCount = count;

            bestParsed = parsed;

          }

        } catch { /* parse fail */ }

      }

    } catch { /* this proxy fail, try next */ }

  }

  return { text: bestText, ua: bestUa, count: bestCount, proxies: bestParsed };

}

// ==================== 机场私有 DNS 注入（mihomo proxy-server-nameserver → sing-box） ====================
// 用途：mihomo 订阅里的 dns.proxy-server-nameserver（机场私有 DNS，解析节点真实 IP）在转 sing-box 时默认丢失。
// 此函数从原始订阅文本提取该段，注入 sing-box 输出的 dns.servers，并给域名型 outbound 加 domain_resolver。

function isIPAddr(v) {
  if (!v) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return true;
  if (v.indexOf(':') >= 0) return true; // IPv6
  return false;
}

// 提取 mihomo 订阅文本里的 dns.proxy-server-nameserver（或 nameserver 兜底）
function extractProxyServerNameserver(subText) {
  if (!subText || typeof subText !== 'string') return [];
  const lines = subText.split('\n');
  const inDns = [];
  let found = false;
  for (const line of lines) {
    const m = line.match(/^(\s*)dns:/);
    if (m) { found = true; continue; }
    if (found) {
      const indent = line.match(/^(\s*)\S/);
      if (!indent || indent[1].length <= 0) break; // dns 段结束
      inDns.push(line);
    }
  }
  const dnsText = inDns.join('\n');
  // 提取 proxy-server-nameserver 下的列表（支持多行）
  let section = null;
  const list = [];
  for (const line of inDns) {
    const m = line.match(/^(\s*)proxy-server-nameserver:\s*(.*)$/);
    if (m) {
      section = m[1].length;
      const inline = m[2].trim();
      if (inline) {
        // 行内列表: "proxy-server-nameserver: [a, b]" 或 "proxy-server-nameserver: a, b"
        const clean = inline.replace(/^\[|\]$/g, '');
        clean.split(',').map(s => s.trim()).filter(Boolean).forEach(s => list.push(s));
        section = null; // 行内已处理完
      }
      continue;
    }
    if (section !== null) {
      if (!line.trim() || line.trim().startsWith('#')) continue;
      const sm = line.match(/^(\s*)(-\s*)?(\S.*)$/);
      if (sm && sm[1].length > section) {
        list.push(sm[3].trim());
      } else {
        break;
      }
    }
  }
  if (list.length > 0) return list;
  // fallback: nameserver
  for (const line of inDns) {
    const m = line.match(/^(\s*)nameserver:\s*(.*)$/);
    if (m) {
      const after = m[2].trim();
      if (after) {
        const clean = after.replace(/^\[|\]$/g, '');
        const l = clean.split(',').map(s => s.trim()).filter(Boolean);
        if (l.length > 0) return l;
      }
      return null; // 多行列表，简单起见不深入
    }
  }
  return null;
}

// mihomo DNS 地址 → sing-box DNS server 配置
function mihomoDnsToSingboxServer(addr) {
  if (addr == null || addr === '') return null;
  const raw = String(addr).trim();
  const hashIdx = raw.indexOf('#');
  const base = hashIdx >= 0 ? raw.slice(0, hashIdx) : raw;
  const params = {};
  if (hashIdx >= 0) {
    raw.slice(hashIdx + 1).split('&').filter(Boolean).forEach(function (p) {
      const eq = p.indexOf('=');
      if (eq >= 0) params[p.slice(0, eq)] = p.slice(eq + 1);
      else params[p] = true;
    });
  }
  if (base === 'system' || base === 'system://') return { type: 'local' };
  if (/^rcode:/.test(base)) return null;
  let scheme = '';
  let rest = base;
  const m = base.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.*)$/);
  if (m) { scheme = m[1].toLowerCase(); rest = m[2]; }
  if (scheme === 'dhcp') {
    const server = { type: 'dhcp' };
    if (rest && rest !== 'system') server.interface = rest;
    return server;
  }
  let port = 0;
  let path = '';
  const slash = rest.indexOf('/');
  if (slash >= 0) { path = rest.slice(slash); rest = rest.slice(0, slash); }
  let host = rest;
  if (rest.charAt(0) === '[') {
    const close = rest.indexOf(']');
    if (close > 0) {
      host = rest.slice(1, close);
      const pm = rest.slice(close + 1).match(/^:(\d+)$/);
      if (pm) port = parseInt(pm[1], 10);
    }
  } else {
    const idx = rest.lastIndexOf(':');
    if (idx > 0 && /^\d+$/.test(rest.slice(idx + 1))) {
      host = rest.slice(0, idx);
      port = parseInt(rest.slice(idx + 1), 10);
    }
  }
  if (!host) return null;
  let type = scheme || 'udp';
  if (params.h3) type = 'h3';
  const server = { type: type, server: host };
  if (port) server.server_port = port;
  if ((type === 'https' || type === 'h3') && path) server.path = path;
  if (params['skip-cert-verify']) server.insecure = true;
  return server;
}

// 判断是否为公共 DNS（纯 IP 或知名公共 DNS 域名）
// 返回 true = 公共 DNS；false = 私有/未知
function isPublicDnsAddr(addr) {
  if (!addr) return true;
  const raw = String(addr).trim();
  const hashIdx = raw.indexOf('#');
  const base = hashIdx >= 0 ? raw.slice(0, hashIdx) : raw;
  let rest = base;
  const m = base.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.*)$/);
  if (m) rest = m[2];
  else rest = base.replace(/^tls\+/, '').replace(/^https\+/, '').replace(/^udp\+/, '');
  // 去掉端口
  let host = rest;
  const slash = rest.indexOf('/');
  if (slash >= 0) host = rest.slice(0, slash);
  if (host.charAt(0) === '[') {
    const close = host.indexOf(']');
    if (close > 0) host = host.slice(1, close);
  } else {
    const idx = host.lastIndexOf(':');
    if (idx > 0 && /^\d+$/.test(host.slice(idx + 1))) host = host.slice(0, idx);
  }
  if (!host) return true;
  // 纯 IP → 视为公共（机场私有 DNS 几乎不会用裸 IP，且 IP 解析无依赖）
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
  if (host.indexOf(':') >= 0) return true; // IPv6
  // 知名公共 DNS 域名
  const h = host.toLowerCase();
  if (/cloudflare-dns\.com$/.test(h)) return true;
  if (/dns\.google$/.test(h)) return true;
  if (/doh\.pub$/.test(h)) return true;
  if (/alidns\.com$/.test(h)) return true;
  if (/one\.one\.one\.one$/.test(h)) return true;
  if (/dns\.sb$/.test(h)) return true;
  if (/dot\.sb$/.test(h)) return true;
  if (/doh\.dns\.sb$/.test(h)) return true;
  if (/quad9\.net$/.test(h)) return true;
  if (/dns\.unfiltered\.adguard\.com$/.test(h)) return true;
  return false; // 未知域名 → 视为私有
}

// 判断 psn 列表是否"全部是公共 DNS"
function isAllPublicDns(list) {
  if (!list || list.length === 0) return true;
  return list.every(isPublicDnsAddr);
}

// 注入 sing-box JSON 输出：dns.servers + 域名型 outbound 的 domain_resolver
function injectPrivateDns(singboxOutput, subText, opts = {}) {
  if (!singboxOutput || !subText) return singboxOutput;
  let config;
  try { config = JSON.parse(singboxOutput); } catch { return singboxOutput; }
  const psnRaw = extractProxyServerNameserver(subText);
  if (!psnRaw) return singboxOutput;
  // psnRaw 可能是数组（多行/行内列表）或单值字符串
  let list = [];
  if (Array.isArray(psnRaw)) {
    list = psnRaw.map(s => String(s).trim()).filter(Boolean);
  } else if (typeof psnRaw === 'string') {
    list = psnRaw.split(',').map(s => s.trim()).filter(Boolean);
  }
  // 纯公共 DNS → 不注入（无意义，避免画蛇添足）
  if (opts.allowPublic !== true && isAllPublicDns(list)) return singboxOutput;
  if (list.length === 0) return singboxOutput;
  const servers = list.map(mihomoDnsToSingboxServer).filter(Boolean);
  if (servers.length === 0) return singboxOutput;
  const tagPrefix = opts.tagPrefix || 'psn';
  const detour = opts.detour || '';
  const config2 = config;
  config2.dns = config2.dns || {};
  config2.dns.servers = config2.dns.servers || [];
  const existing = {};
  config2.dns.servers.forEach(function (s) { if (s && s.tag) existing[s.tag] = true; });
  const freeTag = function (want) {
    let tag = want; let n = 1;
    while (existing[tag]) { tag = want + '-' + (n++); }
    return tag;
  };
  const entries = servers.map(function (s, i) {
    const tag = freeTag(servers.length > 1 ? tagPrefix + '-' + i : tagPrefix);
    const entry = Object.assign({ tag: tag }, s);
    if (detour) entry.detour = detour;
    if (!isIPAddr(entry.server)) entry.domain_resolver = 'local';
    existing[tag] = true;
    return entry;
  });
  entries.forEach(function (e) { config2.dns.servers.push(e); });
  let resolverTag = entries[0].tag;
  if (servers.length > 1) {
    const groupTag = freeTag(tagPrefix);
    const group = { type: 'group', tag: groupTag, servers: entries.map(function (e) { return e.tag; }) };
    existing[groupTag] = true;
    config2.dns.servers.push(group);
    resolverTag = groupTag;
  }
  // 给域名型 outbound 加 domain_resolver
  (config2.outbounds || []).forEach(function (o) {
    if (o && o.tag && o.server && !isIPAddr(o.server) && !o.domain_resolver) {
      o.domain_resolver = resolverTag;
    }
  });
  return JSON.stringify(config2, null, 2);
}

// 注入 Clash Meta (mihomo) YAML 输出：补 dns.proxy-server-nameserver 段
// 输入订阅的私有 DNS 在转 clashmeta 时会丢失，这里补回
function injectPrivateDnsClash(clashOutput, subText) {
  if (!clashOutput || !subText) return clashOutput;
  const psnRaw = extractProxyServerNameserver(subText);
  if (!psnRaw) return clashOutput;
  let list = [];
  if (Array.isArray(psnRaw)) {
    list = psnRaw.map(s => String(s).trim()).filter(Boolean);
  } else if (typeof psnRaw === 'string') {
    list = psnRaw.split(',').map(s => s.trim()).filter(Boolean);
  }
  if (list.length === 0) return clashOutput;
  if (isAllPublicDns(list)) return clashOutput; // 纯公共 DNS 不注入
  // 输出已有 dns 段 → 合并追加到 proxy-server-nameserver（不顶掉用户模板 DNS）
  const dnsMatch = clashOutput.match(/^dns:/m);
  if (dnsMatch) {
    const idx = dnsMatch.index;
    // 找 dns 段的结束（下一个顶层 key）
    let dnsEnd = clashOutput.length;
    const topKeys = clashOutput.match(/^[a-zA-Z][a-zA-Z0-9_-]*:/gm);
    for (const m of clashOutput.matchAll(/^[a-zA-Z][a-zA-Z0-9_-]*:/gm)) {
      if (m.index > idx) { dnsEnd = m.index; break; }
    }
    const dnsBlock = clashOutput.slice(idx, dnsEnd);
    // 检查 dns 段内是否已有 proxy-server-nameserver
    const psnMatch = dnsBlock.match(/^(\s*)proxy-server-nameserver:/m);
    if (psnMatch) {
      // 已有 psn 列表 → 在其后追加（去重）
      const psnIdx = dnsBlock.indexOf(psnMatch[0]);
      let psnEnd = dnsBlock.length;
      const psnInner = dnsBlock.slice(psnIdx + psnMatch[0].length);
      const indentMatch = psnMatch[1].match(/^(\s*)/);
      const psnIndent = indentMatch[1].length;
      // 找 psn 子列表结束
      const subLines = psnInner.split('\n');
      let added = '';
      for (const ln of subLines.slice(1)) {
        const im = ln.match(/^(\s*)/);
        if (!ln.trim() || im[1].length <= psnIndent || ln.trim().startsWith('#')) break;
        added += ln + '\n';
      }
      // 已有项去重
      const existing = new Set();
      const exLines = dnsBlock.split('\n');
      for (const ln of exLines) {
        const lm = ln.match(/^\s*-\s*(\S.*)$/);
        if (lm) existing.add(lm[1].trim());
      }
      const toAdd = list.filter(a => !existing.has(a));
      if (toAdd.length === 0) return clashOutput;
      const addBlock = '\n' + toAdd.map(a => ' '.repeat(psnIndent + 2) + '- ' + a).join('\n') + '\n';
      // psnIdx 相对 dnsBlock, 需加回 dns 段全局偏移 idx
      const insertAt = idx + psnIdx + psnMatch[0].length + added.length;
      return clashOutput.slice(0, insertAt) + addBlock + clashOutput.slice(insertAt);
    } else {
      // dns 段内无 psn → 在 dns 段末尾追加 proxy-server-nameserver 子段
      const indentMatch = dnsBlock.match(/^(\s*)\S/m);
      const dnsIndent = indentMatch ? indentMatch[1].length : 0;
      const addBlock = '  '.repeat(dnsIndent + 1) + 'proxy-server-nameserver:\n' +
        list.map(a => '  '.repeat(dnsIndent + 2) + '- ' + a).join('\n') + '\n';
      return clashOutput.slice(0, dnsEnd) + addBlock + clashOutput.slice(dnsEnd);
    }
  }
  // 输出无 dns 段 → 构建完整 dns 段（原逻辑）
  const lines = [];
  lines.push('dns:');
  lines.push('  enable: true');
  lines.push('  proxy-server-nameserver:');
  for (const addr of list) {
    lines.push('    - ' + addr);
  }
  const dnsBlock = lines.join('\n') + '\n';
  if (clashOutput.startsWith('proxies:')) {
    return dnsBlock + clashOutput;
  }
  return dnsBlock + clashOutput;
}

function parseSubInfo(header) {

  if (!header) return null;

  const map = {};

  for (const part of header.split(';')) {

    const trimmed = part.trim();

    const eq = trimmed.indexOf('=');

    if (eq === -1) continue;

    const k = trimmed.slice(0, eq).trim();

    const v = trimmed.slice(eq + 1).trim();

    if (v && /^\d+$/.test(v)) map[k] = parseInt(v, 10);

  }

  if (Object.keys(map).length === 0) return null;

  const fmt = (bytes) => {

    if (bytes == null) return '?';

    if (bytes < 1024) return bytes + ' B';

    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';

    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';

    return (bytes / 1073741824).toFixed(2) + ' GB';

  };

  const now = Math.floor(Date.now() / 1000);

  const upload = map.upload || 0;

  const download = map.download || 0;

  const total = map.total || 0;

  const used = upload + download;

  const remain = total - used;

  const expire = map.expire || 0;

  let expireText = '未知';

  let remainTime = '';

  if (expire > 0) {

    const d = new Date(expire * 1000);

    expireText = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0') + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');

    const diff = expire - now;

    if (diff > 0) {

      const days = Math.floor(diff / 86400);

      const hours = Math.floor((diff % 86400) / 3600);

      remainTime = days + '天' + hours + '小时';

    } else {

      remainTime = '已过期';

    }

  } else {

    expireText = '长期有效';

  }

  return { upload: fmt(upload), download: fmt(download), total: fmt(total), used: fmt(used), remain: fmt(remain < 0 ? 0 : remain), expire: expireText, remainTime, isExpired: expire > 0 && expire < now, isExhausted: total > 0 && used >= total };

}

// ==================== Gost Tunnel 检测 ====================

function isGostSocksContent(text) {

  const lines = text.split(/\n/);

  let socksCount = 0;

  let gostCount = 0;

  for (const line of lines) {

    const s = line.trim();

    if (!s.startsWith('socks://')) continue;

    socksCount++;

    if (s.includes('gost=')) gostCount++;

  }

  return socksCount > 0 && gostCount > 0 ? { total: socksCount, gostCount } : null;

}

// 从文本中提取 Gost 行，返回 { gostLines, otherLines }

function splitGostLines(text) {

  const lines = text.split(/\n/);

  const gostLines = [];

  const otherLines = [];

  for (const line of lines) {

    const s = line.trim();

    if (s.startsWith('socks://') && s.includes('gost=')) {

      gostLines.push(s);

    } else {

      otherLines.push(line);

    }

  }

  return { gostLines, otherLines: otherLines.join('\n') };

}

// ==================== 节点去重（按特征而非节点名） ====================

function deduplicateProxies(proxies) {

  const seen = new Set();

  return proxies.filter(p => {

    let key;

    switch (p.type) {

      case 'vmess':

      case 'vless':

        key = p.server + ':' + p.port + ':' + p.type + ':' + (p.uuid || '') + ':' + (p.sni || '') + ':' + ((p['ws-opts']?.path || p.path || '')) + ':' + (p.network || '');

        break;

      case 'ss':

        key = p.server + ':' + p.port + ':' + p.type + ':' + p.password + ':' + p.cipher;

        break;

      case 'trojan':

        key = p.server + ':' + p.port + ':' + p.type + ':' + p.password;

        break;

      case 'hysteria2':

      case 'hy2':

        key = p.server + ':' + p.port + ':' + p.type + ':' + (p.password || p.auth || '');

        break;

      default:

        key = p.server + ':' + p.port + ':' + p.type;

    }

    if (seen.has(key)) return false;

    seen.add(key);

    return true;

  });

}

// ==================== 编辑提示消息或发新消息 ====================

async function replyOrEdit(u, cid, env, opts) {

  let pCid = u.promptCid;

  let pMid = u.promptMid;

  if (!pCid && !pMid) {

    try {

      const raw = await env.KV.get('prompt:' + (u._uid || ''), { type: 'json' });

      if (raw && raw.cid && raw.mid) { pCid = raw.cid; pMid = raw.mid; }

    } catch {}

  }

  if (pCid && pMid) {

    const r = await tg('editMessageText', env.BOT_TOKEN, {

      chat_id: pCid, message_id: pMid,

      text: opts.text, parse_mode: opts.parse_mode, reply_markup: opts.reply_markup,

    });

    if (r && r.ok) {

      if (u._uid) env.KV.put('prompt:' + u._uid, JSON.stringify({ cid: pCid, mid: pMid })).catch(() => {});

      return { ...r, message_id: pMid, from_edit: true };

    }

  }

  const sent = await tg('sendMessage', env.BOT_TOKEN, {

    chat_id: cid, text: opts.text, parse_mode: opts.parse_mode, reply_markup: opts.reply_markup,

  });

  if (sent && sent.ok && sent.result && sent.result.message_id) {

    u.promptCid = cid;

    u.promptMid = sent.result.message_id;

    if (u._uid) env.KV.put('prompt:' + u._uid, JSON.stringify({ cid, mid: sent.result.message_id })).catch(() => {});

  }

  return sent;

}

// ==================== 用户短链索引 ====================

async function getUserLinks(uid, env) {

  try {

    const raw = await env.KV.get('ulinks:' + uid, { type: 'json' });

    return raw || [];

  } catch { return []; }

}

async function addUserLink(uid, env, entry) {

  const links = await getUserLinks(uid, env);

  links.unshift(entry);

  if (links.length > 50) links.length = 50;

  await env.KV.put('ulinks:' + uid, JSON.stringify(links));

}

async function removeUserLink(uid, env, id) {

  const links = await getUserLinks(uid, env);

  const idx = links.findIndex(l => l.id === id);

  if (idx === -1) return false;

  links.splice(idx, 1);

  await env.KV.put('ulinks:' + uid, JSON.stringify(links));

  // 同时删除 KV 中的短链内容

  await env.KV.delete('share_' + id);

  return true;

}

function linkStatusIcon(entry) {

  if (entry.ttl === 0) return '\u{1F535}';  // 🔵 永久

  if (!entry.expiresAt) return '\u{1F535}'; // 安全兜底

  const now = Date.now();

  if (now >= entry.expiresAt) return '\u{26AB}'; // ⚫ 已过期

  const remain = Math.round((entry.expiresAt - now) / 60000);

  if (remain < 60) return '\u{1F7E0} ' + remain + 'm'; // 🟠 <1h

  return '\u{1F7E0} ' + Math.round(remain / 60) + 'h'; // 🟠

}

function formatRemaining(expiresAt) {

  const remain = Math.round((expiresAt - Date.now()) / 1000);

  if (remain <= 0) return '\u26AB \u5DF2\u8FC7\u671F';

  if (remain < 60) return '\u{1F7E0} ' + remain + '\u79D2';

  if (remain < 3600) return '\u{1F7E0} ' + Math.round(remain / 60) + '\u5206\u949F';

  if (remain < 86400) {

    const h = Math.floor(remain / 3600);

    const m = Math.round((remain % 3600) / 60);

    return '\u{1F7E0} ' + h + '\u5C0F\u65F6' + (m > 0 ? m + '\u5206' : '');

  }

  const d = Math.floor(remain / 86400);

  const h = Math.round((remain % 86400) / 3600);

  return '\u{1F7E0} ' + d + '\u5929' + (h > 0 ? h + '\u5C0F\u65F6' : '');

}

function getEffectiveTtl(u) {

  return u._convTtl != null ? u._convTtl : (u.ttl != null ? u.ttl : 0);

}

function getEffectiveMaxAccess(u) {

  // conv 临时覆盖优先，其次主页默认，最后 0（不限）

  return u._convAccessLimit != null ? u._convAccessLimit : (u._accessLimit != null ? u._accessLimit : 0);

}

// ==================== 保存到短链 ====================

async function saveToClip(text, ttl, env, maxAccess, extra = {}) {

  const id = genId();

  const data = JSON.stringify({

    text,

    maxAccess: maxAccess || 0,

    accessedIPs: [],

    ttl: ttl || 0,

    burn: extra.burn || false,

    landing: extra.landing || false,

    nodeCount: extra.nodeCount || 0,

    flowHeader: extra.flowHeader || null,

    flowName: extra.flowName || null,

    _createdAt: Date.now(),

  });

  const kvOpts = {};

  if (ttl > 0) kvOpts.expirationTtl = ttl < 60 ? 60 : ttl;

  await env.KV.put('share_' + id, data, kvOpts);

  return id;

}

// 保存短链并记录到用户索引

async function saveToClipAndTrack(text, ttl, env, uid, extra, maxAccess) {

  const id = await saveToClip(text, ttl, env, maxAccess, extra);

  const clipUrl = (env._clipBase || '') + '/share/' + id;

  const entry = {

    id,

    ...extra,

    ttl: ttl,

    maxAccess: maxAccess || 0,

    createdAt: Date.now(),

    expiresAt: ttl > 0 ? Date.now() + ttl * 1000 : null,

  };

  await addUserLink(uid, env, entry);

  return { id, url: clipUrl };

}

// ==================== 用户白名单 ====================

function isAllowed(uid, env) {

  const adminId = env.ADMIN_ID;

  const allowedRaw = env.ALLOWED_USERS;

  if (!adminId && !allowedRaw) return true;

  if (adminId && uid === adminId.trim()) return true;

  if (allowedRaw) {

    const list = allowedRaw.split(',').map((s) => s.trim());

    if (list.includes(uid)) return true;

  }

  return false;

}

// ==================== 远程订阅拉取（独立函数，供 onMsg / cb_collection_process 调用） ====================

async function processRemoteUrls(urls, cid, uid, u, env) {

  const ttl = u.ttl !== undefined ? u.ttl : 0;

  const totalInputUrls = urls.length;

  // URL 归一化: 去掉末尾 / 避免相同链接被当两条
        const uniqueUrls = [...new Set(urls.map(u => u.replace(/\/+$/, '')))];

  if (uniqueUrls.length === 0) {

    return replyOrEdit(u, cid, env, {

      text: '\u274C \u672A\u68C0\u6D4B\u5230\u6709\u6548\u8BA2\u9605\u94FE\u63A5',

    });

  }

  // --- 拉取 ---

  let allProxies = [];
  let totalSkipped = 0;

  let rawTexts = [];

  const usedUas = [];

  const errors = [];

  let dupSubCount = 0;

  if (uniqueUrls.length === 1) {

    // 单 URL

    try {

      await replyOrEdit(u, cid, env, { text: '\u{1F504} \u6B63\u5728\u62C9\u53D6\u8BA2\u9605...' });

      const fetchWithTimeout = fetchSub(uniqueUrls[0], uid, env, async (info) => {

        // 拉取进度实时显示 (UA 尝试 / 反代)
        try {

          if (info.type === 'ua') {

            const pct = Math.round(info.done * 100 / info.total);

            const filled = Math.round(pct / 5);

            const bar = '\u2593'.repeat(filled) + '\u2591'.repeat(20 - filled) + ' ' + info.done + '/' + info.total + ' ' + pct + '%';

            let note = '\u23F3 \u5C1D\u8BD5 UA ' + info.done + '/' + info.total;

            if (info.found > 0) note += ' \u00B7 \u2705 ' + info.found + ' \u8282\u70B9 (' + info.ua + ')';

            else note += ' \u00B7 \u6682\u65E0\u7ED3\u679C';

            await replyOrEdit(u, cid, env, { text: '\u{1F504} \u6B63\u5728\u62C9\u53D6\u8BA2\u9605...\n' + bar + '\n\n' + note, parse_mode: 'HTML' }).catch(() => {});

          } else if (info.type === 'proxy') {

            // 标注当前在试哪个反代(区分旧反代 / T5 节点)
            const which = info.which ? String(info.which).replace(/https?:\/\//, '').split(/[?\/]/)[0] : '';
            const isT5 = String(info.which || '').includes('/t5');
            await replyOrEdit(u, cid, env, { text: '🔄 直连失败, 走反代...\n\n' + (isT5 ? '🌐 T5 节点: ' : '🔁 反代: ') + which, parse_mode: 'HTML' }).catch(() => {});

          }

        } catch {}

      });

      // 加 10 分钟超时, 防止单条拉取卡死
      const subResult = await Promise.race([
        fetchWithTimeout,
        new Promise(r => setTimeout(() => r({ text: null, ua: null }), 600000)),
      ]);

      const subText = subResult.text;

      u._lastUrlCount = 1;

      u._lastFetchUa = subResult.ua === 'proxy' ? '\u53CD\u4EE3 (Karing)' : (subResult.ua === 'T5\u8282\u70B9' ? 'T5\u8282\u70B9' : subResult.ua);

      // HTML <pre> 提取

      const preMatch = subText.match(/<pre[^>]*>([\s\S]*?)(?:<\/pre>|$)/i);

      const cleanText = preMatch

        ? preMatch[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"')

        : subText;

      let parsed = null;
      try { parsed = ProxyUtils.parse(cleanText); } catch { parsed = null; }
      // ProxyUtils 失败时 fallback 到 parseClashYaml
      if (!parsed || parsed.length === 0) {
        try { const y = parseClashYaml(cleanText); if (y.length > 0) parsed = y; } catch {}
      }
      if (parsed && parsed.length > 0) {

        allProxies = parsed;

        rawTexts.push(cleanText);

        // 拉取订阅流量信息（HEAD 请求，3秒超时）

        let subInfo = null;

        try {

          const resp = await Promise.race([

            fetch(uniqueUrls[0], { headers: { 'User-Agent': 'ClashforWindows/0.19.21', 'Range': 'bytes=0-0' } }),

            new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000)),

          ]);

          subInfo = resp.headers.get('subscription-userinfo') || null;

        } catch { /* ignore */ }

        const si = subInfo ? parseSubInfo(subInfo) : null;

        let siLine = '';

        if (si) {

          siLine = '\n    \u{1F4CA} ' + si.used + ' / ' + si.total + ' (\u5269\u4F59 ' + si.remain + ')' + (si.expire !== '未知' ? '  \u5230\u671F: ' + si.expire + (si.remainTime ? ' (' + si.remainTime + ')' : '') : '  \u5230\u671F: ' + si.expire);

          if (si.isExpired) siLine += ' \u26A0\uFE0F';

          if (si.isExhausted) siLine += ' \u26A0\uFE0F';

        }

        usedUas.push(uniqueUrls[0] + ' \u2192 ' + (subResult.ua === 'proxy' ? '\u53CD\u4EE3' : (subResult.ua === 'T5\u8282\u70B9' ? 'T5\u8282\u70B9' : subResult.ua)) + ' \u2192 ' + parsed.length + siLine);

      } else {

        errors.push('\u2022 ' + uniqueUrls[0] + ': \u65E0\u6709\u6548\u8282\u70B9');

      }

    } catch (e) {

      return replyOrEdit(u, cid, env, { text: '\u274C \u62C9\u53D6\u5931\u8D25: ' + e.message });

    }

  } else {

    // 多 URL

    if (uniqueUrls.length >= 2) {

      // 2+ URL：批量并行拉取

      const allUas = await getUaList(uid, env);

      const primary = allUas[0] || FETCH_UAS[0];

      const fallbacks = allUas.slice(1);

      const contentSeen = new Map();

      const BATCH_SIZE = 5;

      const PARALLEL_LIMIT = 10;

      // 分批并行 fetch

      for (let batchStart = 0; batchStart < uniqueUrls.length; batchStart += PARALLEL_LIMIT) {

        const batch = uniqueUrls.slice(batchStart, batchStart + PARALLEL_LIMIT);

        const fetchedCount = batchStart + batch.length;

        await replyOrEdit(u, cid, env, { text: '\u{1F504} \u6B63\u5728\u62C9\u53D6 [' + fetchedCount + '/' + uniqueUrls.length + ']' });

        // 任务池: 并发拉取, 每个 URL 完成时更新进度消息
        const results = new Array(batch.length);

        const statusList = batch.map(url => ({ url, status: '\u23F3 \u7B49\u5F85' }));

        let nextIdx = 0;

        let doneCount = 0;

        let lastRender = 0;

        const renderProgress = async (force) => {

          const now = Date.now();

          if (!force && now - lastRender < 600) return;

          lastRender = now;

          const pct = Math.round(doneCount * 100 / batch.length);

          const filled = Math.round(pct / 5);

          const bar = '\u2593'.repeat(filled) + '\u2591'.repeat(20 - filled) + ' ' + doneCount + '/' + batch.length + ' ' + pct + '%';

          const lines = statusList.map(s => {

            const short = s.url.length > 45 ? s.url.slice(0, 45) + '\u2026' : s.url;

            return s.status + ' ' + short;

          }).join('\n');

          await replyOrEdit(u, cid, env, { text: '\u{1F504} \u6B63\u5728\u62C9\u53D6\u8BA2\u9605 ' + uniqueUrls.length + ' \u4E2A\n' + bar + '\n\n' + lines, parse_mode: 'HTML' }).catch(() => {});

        };

        const worker = async () => {

          while (nextIdx < batch.length) {

            const myIdx = nextIdx++;

            const url = batch[myIdx];

            statusList[myIdx].status = '\u23F3 \u62C9\u53D6\u4E2D...';

            await renderProgress(false);

            let text = '';

            let usedUa = primary;

            // 自己域名的短链：直接从 KV 读取

            const clipBase2 = env._clipBase || '';

            if (clipBase2 && url.startsWith(clipBase2 + '/share/')) {

              const sid = url.split('/share/')[1]?.split(/[?#]/)[0];

              const kvD = sid ? await env.KV.get('share_' + sid, { type: 'json' }).catch(() => null) : null;

              text = (kvD && kvD.text) ? kvD.text : '';

              usedUa = 'KV_DIRECT';

            } else {

              try {

                text = await Promise.race([

                  fetch(url, { headers: { 'User-Agent': primary } }).then(r => r.text()),

                  new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000)),

                ]);

              } catch { text = ''; }

              if (!text || text.length < 50 || text.includes('\u8BBF\u95EE\u88AB\u62D2\u7EDD') || text.includes('\u4E0D\u652F\u6301\u6D4F\u89C8\u5668') || text.includes('<html') || text.includes('<HTML') || text.includes('<!DOC')) {

                text = '';

                for (const fb of fallbacks) {

                  try {

                    text = await Promise.race([

                      fetch(url, { headers: { 'User-Agent': fb } }).then(r => r.text()),

                      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000)),

                    ]);

                    if (text && text.length >= 50 && !text.includes('<html') && !text.includes('<!DOC')) {

                      usedUa = fb;

                      break;

                    }

                  } catch { continue; }

                }

              }

            }

            results[myIdx] = { url, text, usedUa };

            statusList[myIdx].status = text ? '\u2705 \u62C9\u53D6\u5B8C\u6210' : '\u274C \u65E0\u6570\u636E';

            doneCount++;

            await renderProgress(true);

          }

        };

        await Promise.all(Array.from({ length: Math.min(PARALLEL_LIMIT, batch.length) }, worker));

        // 处理结果

        for (const r of results) {

          if (!r || !r.url) continue;

          const { url, text, usedUa } = r;

          if (!text) {

            usedUas.push(url + ' \u2192 \u274C \u65E0\u6570\u636E');

            errors.push('\u2022 ' + url + ': \u65E0\u6570\u636E');

            continue;

          }

          const contentKey = text.slice(0, 200).replace(/\d+/g, '');

          if (contentSeen.has(contentKey)) {

            const first = contentSeen.get(contentKey);

            usedUas[first.index] = first.entry + '\n    \u26A0\uFE0F \u91CD\u590D: ' + url;

            dupSubCount++;

            continue;

          }

          const entryIndex = usedUas.length;

          rawTexts.push(text);

          let parsed = null;

          // 完整解析链(含 Surge 配置), 避免 Surge 订阅在多订阅流程被判无有效节点
          try { parsed = parseProxies(text); } catch {}

          if (!parsed || parsed.length === 0) {

            try { parsed = ProxyUtils.parse(text); } catch {}

          }

          if (parsed && parsed.length > 0) {

            // 拉取流量信息

            let subInfo = null;

            if (usedUa === 'KV_DIRECT') {

              const sidFlow = url.split('/share/')[1]?.split(/[?#]/)[0];

              if (sidFlow) {

                const kvFlow = await env.KV.get('share_' + sidFlow, { type: 'json' }).catch(() => null);

                if (kvFlow && kvFlow.flowHeader) subInfo = kvFlow.flowHeader;

              }

            } else {

              try {

                const resp = await Promise.race([

                  fetch(url, { headers: { 'User-Agent': 'ClashforWindows/0.19.21', 'Range': 'bytes=0-0' } }),

                  new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000)),

                ]);

                subInfo = resp.headers.get('subscription-userinfo') || null;

              } catch { /* ignore */ }

            }

            const si = subInfo ? parseSubInfo(subInfo) : null;

            // 过期或流量用尽的订阅不合并节点

            if (si && (si.isExpired || si.isExhausted)) {

              const reason = si.isExpired ? '\u5DF2\u8FC7\u671F' : '\u6D41\u91CF\u5DF2\u7528\u5C3D';

              totalSkipped += parsed.length;

              let siLine = '';

              if (si) {

                siLine = '  ' + reason;

                if (si.expire !== '\u672A\u77E5') siLine += ' (' + si.expire + ')';

                if (si.isExhausted) siLine += '  \u5269\u4F59 ' + si.remain + '/' + si.total;

              }

              usedUas.push(url + ' \u2192 ' + usedUa + ' \u2192 \u26A0\uFE0F ' + parsed.length + '\u4E2A\u8282\u70B9\u5DF2\u8DF3\u8FC7' + siLine);

              continue;

            }

            const types = {};

            for (const p of parsed) types[p.type] = (types[p.type] || 0) + 1;

            const ts = Object.entries(types).map(([k, v]) => k + ':' + v).join(', ');

            let siLine = '';

            if (si) {

              siLine = '\n    \u{1F4CA} ' + si.used + ' / ' + si.total + ' (\u5269\u4F59 ' + si.remain + ')' + (si.expire !== '\u672A\u77E5' ? '  \u5230\u671F: ' + si.expire + (si.remainTime ? ' (' + si.remainTime + ')' : '') : '  \u5230\u671F: ' + si.expire);

            }

            allProxies = allProxies.concat(parsed);

            const entryText = url + ' \u2192 ' + usedUa + ' \u2192 ' + parsed.length + ' (' + ts + ')' + siLine;

            contentSeen.set(contentKey, { url, index: entryIndex, entry: entryText });

            usedUas.push(entryText);

          } else {

            const entryText = url + ' \u2192 ' + usedUa + ' \u2192 0';

            contentSeen.set(contentKey, { url, index: entryIndex, entry: entryText });

            usedUas.push(entryText);

            errors.push('\u2022 ' + url + ': \u65E0\u6709\u6548\u8282\u70B9');

          }

        }

      }

    }

  }

  // --- 拉取完成 ---
  const totalRaw = allProxies.length;
  await replyOrEdit(u, cid, env, { text: '\u2705 \u5168\u90E8\u62C9\u53D6\u5B8C\u6210  \u{1F4E5} ' + allProxies.length + ' \u8282\u70B9' + (totalSkipped > 0 ? '  \u{1F6AB} \u8DF3\u8FC7 ' + totalSkipped : '') });

  // --- 去重 + 统计 ---
  allProxies = deduplicateProxies(allProxies);
  if (allProxies.length === 0) {

    return replyOrEdit(u, cid, env, {

      text: '\u274C \u6240\u6709\u8BA2\u9605\u90FD\u62C9\u53D6\u5931\u8D25:\n' + errors.join('\n'),

    });

  }

  let report = '\u2705 \u5408\u5E76 ' + allProxies.length + ' \u4E2A\u8282\u70B9';
  if (totalRaw > allProxies.length) report += ' (\u539F\u59CB ' + totalRaw + '\uFF0C\u53BB\u91CD ' + (totalRaw - allProxies.length) + ')';

  report += ' \u6765\u81EA ' + rawTexts.length + '/' + totalInputUrls + ' \u4E2A\u6E90';

  if (totalSkipped > 0) report += ' (\u8DF3\u8FC7 ' + totalSkipped + ')';

  if (errors.length > 0) report += '\n\n\u26A0\uFE0F \u5931\u8D25:\n' + errors.join('\n');

  await replyOrEdit(u, cid, env, { text: report });

  // 二次去重 + 统计

  const totalNodes = totalRaw + totalSkipped;

  const dupUrlCount = totalInputUrls - uniqueUrls.length;

  const before = allProxies.length;

  allProxies = deduplicateProxies(allProxies);

  u._lastStats = {
    totalNodes,
    actualNodes: allProxies.length,
    subSources: rawTexts.length + '/' + totalInputUrls,
    dupSubs: dupSubCount,
    dupUrls: dupUrlCount,
    dupNodes: before - allProxies.length,
    firstDedup: totalRaw - before,
    skipped: totalSkipped,
  };

  u._lastUrlCount = rawTexts.length + '/' + totalInputUrls;

  u._lastFetchUa = usedUas.length > 0 ? usedUas.join('\n') : null;

  // --- 设置状态 + 显示格式选择 ---

  const mergedStd = allProxies;

  u._lastProxies = mergedStd;

  u._lastSubInput = rawTexts.join('\n');

  u._lastRawContent = rawTexts.join('\n');

  u._lastProxiesRaw = allProxies;

  u._fmtMsg = null;

  // 统计类型

  const types = {};

  for (const p of mergedStd) { types[p.type] = (types[p.type] || 0) + 1; }

  let typeStr = Object.entries(types).map(([k, v]) => k + ': ' + v).join(', ');

  const wgCount = mergedStd.filter(p => p.type === 'wireguard').length;

  if (wgCount > 0) typeStr += '\n\u26A1 WireGuard \u00D7 ' + wgCount + ' \u2014 Surge \u4E0D\u652F\u6301\uFF0C\u5C06\u81EA\u52A8\u4EE5\u539F\u751F YAML \u5206\u94FE';

  if (u._gostInput && u._gostCount) typeStr += '\n\u{1F504} Gost \u00D7 ' + u._gostCount + ' \u2014 \u5EFA\u8BAE\u9009 Shadowrocket';

  const statsLine = u._lastStats

    ? '\n\u{1F4CA} <b>' + u._lastStats.actualNodes + '</b> \u5B9E\u9645 (\u603B: ' + u._lastStats.totalNodes +

      (u._lastStats.dupUrls > 0 ? ', \u53BB\u91CD\u94FE\u63A5: ' + u._lastStats.dupUrls : '') +

      (u._lastStats.dupSubs > 0 ? ', \u91CD\u590D\u8BA2\u9605: ' + u._lastStats.dupSubs : '') +

      (u._lastStats.firstDedup > 0 ? ', \u53BB\u91CD: ' + u._lastStats.firstDedup : '') +

      (u._lastStats.dupNodes > 0 ? ', \u91CD\u590D\u8282\u70B9: ' + u._lastStats.dupNodes : '') +

      (u._lastStats.skipped > 0 ? ', \u8DF3\u8FC7: ' + u._lastStats.skipped : '') + ')'

    : '';

  const uaInfo = u._lastFetchUa ? '\n\u{1F916} ' + escapeHTML(u._lastFetchUa) : '';

  // 加载用户选择的流量信息模板

  if (!u._flowHeader) {

    try {

      const flowIdx = parseInt(await env.KV.get('tmpl_flow_active:' + uid));

      if (!isNaN(flowIdx)) {

        const flowTmpls = await getFlowTemplates(uid, env);

        if (flowTmpls[flowIdx]) {

          u._flowHeader = flowTmpls[flowIdx].header;

          u._flowName = flowTmpls[flowIdx].name;

        }

      }

    } catch {}

  }

  const fmtText =

    '\u{1F504} <b>\u68C0\u6D4B\u5230\u8BA2\u9605\u5185\u5BB9</b>\n\n' +

    statsLine + '\n' +

    '\u{1F4CD} ' + typeStr + '\n' +

    '\n\u{1F517} ' + rawTexts.length + '/' + totalInputUrls + ' \u4E2A\u8BA2\u9605\u6E90' + uaInfo + '\n' +

    '\u8BF7\u9009\u62E9\u8F93\u51FA\u683C\u5F0F:';

  const sent = await replyOrEdit(u, cid, env, {

    text: fmtText, parse_mode: 'HTML',

    reply_markup: fmtKb(null, u._convTtl, u.ttl, u),

  });

  const msgId = sent?.result?.message_id || (sent?.from_edit ? u.promptMid : null);

  u._fmtMsg = msgId ? { cid, id: msgId } : null;

  u._fmtText = fmtText;

}

// ==================== 消息处理 ====================

async function onMsg(msg, env) {

  const cid = msg.chat.id;

  const uid = String(msg.from.id);

  if (!isAllowed(uid, env)) return;

  const u = getState(uid);

  // /start

  if (msg.text && msg.text.trim() === '/start') {

    return tg('sendMessage', env.BOT_TOKEN, {

      chat_id: cid,

      text: mainPageText(),

      parse_mode: 'HTML',

      reply_markup: mainKb(),

    });

  }

  // UA 添加模式

  if (u.state === 'UA_ADD') {

    const uaStr = (msg.text || msg.caption || '').trim();

    if (!uaStr) {

      return tg('sendMessage', env.BOT_TOKEN, {

        chat_id: cid,

        text: '\u274C \u8BF7\u53D1\u9001\u6709\u6548\u7684 User-Agent',

      });

    }

    const cfg = await getUaConfig(uid, env);

    if (!cfg.custom) cfg.custom = [];

    cfg.custom.push(uaStr);

    await saveUaConfig(uid, env, cfg);

    u.state = null;

    if (u.promptCid && u.promptMid) {

      return showUaSettings(u.promptCid, u.promptMid, uid, env);

    }

    return tg('sendMessage', env.BOT_TOKEN, {

      chat_id: cid,

      text: '\u2705 \u5DF2\u6DFB\u52A0\u81EA\u5B9A\u4E49 UA: ' + escapeHTML(uaStr),

      reply_markup: mainKb(),

    });

  }

  // YAML 模板编辑模式

  if (u.state === 'TMPL_EDIT') {

    const input = (msg.text || '').trim();

    u.state = null;

    if (input === '/cancel' || !input) {

      return replyMsg(env, uid, cid, '✖ 已取消');

    }

    let tmplText = input;

    let tmplName = '自定义';

    // 自动拉取 URL 内容

    if (/^https?:\/\//i.test(input)) {

      try {

        const resp = await fetch(input);

        if (resp.ok) {

          const noomCleaned = cleanYamlForTemplate(await resp.text());

          tmplText = noomCleaned;

          // 从 URL 提取模板名

          const urlParts = input.split('/');

          tmplName = urlParts[urlParts.length - 1].replace(/\.[^.]+$/, '') || 'URL 导入';

        }

      } catch {}

    }

    // 尝试从 JSON 提取名称

    try {

      const parsed = JSON.parse(tmplText);

      if (parsed.name) tmplName = parsed.name;

      if (parsed.text) tmplText = parsed.text;

    } catch {}

    let templates = [];

    try { templates = JSON.parse(await env.KV.get('tmpls:' + uid)) || []; } catch {}

    templates.push({ name: tmplName, text: tmplText, active: false });

    const cleanedTmpl = cleanYamlForTemplate(tmplText);

    tmplText = cleanedTmpl;

    await env.KV.put('tmpls:' + uid, JSON.stringify(templates));

    return replyMsg(env, uid, cid, '✅ 模板已添加：' + tmplName + '\n去 YAML 模板管理切换', mainKb());

  }

  // 备注模式 — 只改 preview（列表名字），不碰短链内容

  if (u.state && u.state.startsWith('RENAME_')) {

    const linkId = u.state.replace('RENAME_', '');

    const remark = (msg.text || '').trim();

    u.state = null;

    if (remark === '/cancel' || !remark) {

      return replyMsg(env, uid, cid, '\u2716 \u5DF2\u53D6\u6D88', { inline_keyboard: [[{ text: '\u2190 \u8FD4\u56DE\u5217\u8868', callback_data: 'my_links_0' }]] });

    }

    const links = await getUserLinks(uid, env);

    const l = links.find(x => x.id === linkId);

    if (!l) return replyMsg(env, uid, cid, '\u274C \u77ED\u94FE\u5DF2\u4E0D\u5B58\u5728');

    l.preview = remark;

    await env.KV.put('ulinks:' + uid, JSON.stringify(links));

    const clipUrl = (env._clipBase || '') + '/share/' + l.id;

    const text = '\u2705 \u5DF2\u66F4\u65B0\u540D\u79F0\uFF1A' + escapeHTML(remark) + '\n\n' + linkStatusIcon(l) + ' <b>' + escapeHTML(l.preview) + '</b>\n\u{1F517} <code>' + escapeHTML(clipUrl) + '</code>';

    return replyMsg(env, uid, cid, text, { inline_keyboard: [[{ text: '\u2190 \u8FD4\u56DE\u5217\u8868', callback_data: 'my_links_0' }]] });

  }

  if (u.state && u.state.startsWith('SHORTCODE_')) {

    const oldId = u.state.replace('SHORTCODE_', '');

    const newCode = (msg.text || '').trim();

    u.state = null;

    if (newCode === '/cancel' || !newCode) {

      return replyMsg(env, uid, cid, '\u2716 \u5DF2\u53D6\u6D88', { inline_keyboard: [[{ text: '\u2190 \u8FD4\u56DE\u5217\u8868', callback_data: 'my_links_0' }]] });

    }

    if (!/^[a-zA-Z0-9_-]{3,20}$/.test(newCode)) {

      return replyMsg(env, uid, cid, '\u274C \u683C\u5F0F\u9519\u8BEF\uFF0C\u53EA\u5141\u8BB8\u5B57\u6BCD\u3001\u6570\u5B57\u3001\u77ED\u6A2A\u7EBF\uFF0C3-20\u5B57\u7B26', { inline_keyboard: [[{ text: '\u2716 \u53D6\u6D88', callback_data: 'link_' + oldId }]] });

    }

    if (newCode === oldId) {

      return replyMsg(env, uid, cid, '\u274C \u77ED\u7801\u672A\u53D8', { inline_keyboard: [[{ text: '\u2190 \u8FD4\u56DE', callback_data: 'link_' + oldId }]] });

    }

    const links = await getUserLinks(uid, env);

    const l = links.find(x => x.id === oldId);

    if (!l) return replyMsg(env, uid, cid, '\u274C \u77ED\u94FE\u5DF2\u4E0D\u5B58\u5728');

    if (links.some(x => x.id === newCode)) {

      return replyMsg(env, uid, cid, '\u274C \u77ED\u7801\u5DF2\u5B58\u5728\uFF0C\u8BF7\u6362\u4E00\u4E2A', { inline_keyboard: [[{ text: '\u2716 \u53D6\u6D88', callback_data: 'link_' + oldId }]] });

    }

    const kvRaw = await env.KV.get('share_' + oldId, { type: 'json' }).catch(() => null);

    if (kvRaw) {

      await env.KV.put('share_' + newCode, JSON.stringify(kvRaw));

      await env.KV.delete('share_' + oldId);

    }

    l.id = newCode;

    await env.KV.put('ulinks:' + uid, JSON.stringify(links));

    const clipUrl = (env._clipBase || '') + '/share/' + newCode;

    const text = '\u2705 \u77ED\u7801\u5DF2\u66F4\u65B0\uFF1A<code>' + escapeHTML(newCode) + '</code>\n\n' + linkStatusIcon(l) + ' <b>' + escapeHTML(l.preview) + '</b>\n\u{1F517} <code>' + escapeHTML(clipUrl) + '</code>';

    return replyMsg(env, uid, cid, text, { inline_keyboard: [[{ text: '\u2190 \u8FD4\u56DE\u5217\u8868', callback_data: 'my_links_0' }]] });

  }

  // 流量信息模板输入

  if (u.state === 'WAITING_FLOW_TEMPLATE') {

    const input = (msg.text || '').trim();

    u.state = null;

    if (input === '/cancel' || !input) {

      return replyMsg(env, uid, cid, '\u2716 \u5DF2\u53D6\u6D88', { inline_keyboard: [[{ text: '\u2190 \u8FD4\u56DE', callback_data: 'flow_menu' }]] });

    }

    const parts = input.split('|');

    if (parts.length < 2 || !parts[0].trim() || !parts[1].trim()) {

      return replyMsg(env, uid, cid, '\u274C \u683C\u5F0F\u9519\u8BEF\uFF0C\u9700\u8981: \u540D\u79F0|upload\uFF1Bdownload\uFF1Btotal\uFF1Bexpire', { inline_keyboard: [[{ text: '\u2716 \u53D6\u6D88', callback_data: 'flow_menu' }]] });

    }

    const name = parts[0].trim();

    const values = parts.slice(1).join('|').split(/[；;]/);

    if (values.length < 4) {

      return replyMsg(env, uid, cid, '\u274C \u9700\u8981 4 \u4E2A\u503C: upload\uFF1Bdownload\uFF1Btotal\uFF1Bexpire', { inline_keyboard: [[{ text: '\u2716 \u53D6\u6D88', callback_data: 'flow_menu' }]] });

    }

    // \u89E3\u6790\u6D41\u91CF\u503C\uFF08\u652F\u6301 g/m \u540E\u7F00\uFF09

    function parseBytes(str) {

      str = str.trim().toLowerCase();

      if (str === '0') return 0;

      const m = str.match(/^([\d.]+)\s*(g|gb|m|mb)?$/);

      if (!m) return parseInt(str) || 0;

      const num = parseFloat(m[1]);

      const unit = m[2] || '';

      if (unit === 'g' || unit === 'gb') return Math.round(num * 1073741824);

      if (unit === 'm' || unit === 'mb') return Math.round(num * 1048576);

      return Math.round(num);

    }

    // \u89E3\u6790\u5230\u671F\u65F6\u95F4\uFF08\u652F\u6301 YYYY-MM-DD \u6216 Unix \u65F6\u95F4\u6233\uFF09

    function parseExpire(str) {

      str = str.trim();

      if (str === '0') return 0;

      // YYYY-MM-DD

      const dm = str.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);

      if (dm) {

        return Math.floor(new Date(`${dm[1]}-${dm[2].padStart(2,'0')}-${dm[3].padStart(2,'0')}T00:00:00Z`).getTime() / 1000);

      }

      return parseInt(str) || 0;

    }

    const upload = parseBytes(values[0]);

    const download = parseBytes(values[1]);

    const total = parseBytes(values[2]);

    const expire = parseExpire(values[3]);

    const header = `upload=${upload}; download=${download}; total=${total}; expire=${expire}`;

    const templates = await getFlowTemplates(uid, env);

    templates.push({ name, header });

    await saveFlowTemplates(uid, env, templates);

    u._flowHeader = header;

    u._flowName = name;

    // \u663E\u793A\u89E3\u6790\u7ED3\u679C

    const dlGB = (download / 1073741824).toFixed(1);

    const totalGB = (total / 1073741824).toFixed(1);

    const expireStr = expire === 0 ? '\u957F\u671F\u6709\u6548' : new Date(expire * 1000).toISOString().slice(0, 10);

    return replyMsg(env, uid, cid, `\u2705 \u5DF2\u6DFB\u52A0\u6A21\u677F: ${name}\n\n\u{1F4CA} \u4E0A\u4F20: ${(upload/1048576).toFixed(1)}MB\n\u{1F4E5} \u4E0B\u8F7D: ${dlGB}GB\n\u{1F4CA} \u603B\u91CF: ${totalGB}GB\n\u{1F4C5} \u5230\u671F: ${expireStr}`, { inline_keyboard: [[{ text: '\u2190 \u8FD4\u56DE', callback_data: 'flow_menu' }]] });

  }

  // 获取输入内容

  let content = '';

  if (msg.text) {

    content = msg.text.trim();

  } else if (msg.document) {

    // 非收集模式 → 提示使用收集器，不下载文件

    if (!await getCollectModeSync(uid, u, env)) {
      // 非收集模式 → 下载文件并弹确认框
      const f = await tg('getFile', env.BOT_TOKEN, { file_id: msg.document.file_id });
      if (!f.ok) return;
      const r = await fetch('https://api.telegram.org/file/bot' + env.BOT_TOKEN + '/' + f.result.file_path);
      const fileContent = await r.text();
      if (!fileContent || fileContent.length < 10) {
        return tg('sendMessage', env.BOT_TOKEN, { chat_id: cid, text: '❌ 文件内容为空或太小', reply_markup: mainKb() });
      }
      u._pendingContent = fileContent;
      u._pendingFileName = msg.document?.file_name || '文件';
      return tg('sendMessage', env.BOT_TOKEN, {
        chat_id: cid,
        text: '📁 <b>收到文件</b>\n\n📄 ' + escapeHTML(u._pendingFileName) + ' · ' + (fileContent.length / 1024).toFixed(1) + ' KB\n\n是否转为短链？',
        parse_mode: 'HTML',
        reply_markup: { inline_keyboard: [
          [{ text: '✅ 转短链', callback_data: 'shortlink_confirm:yes' }, { text: '❌ 取消', callback_data: 'shortlink_confirm:no' }],
        ] },
      });
    }

    // 收集模式 → 下载文件

    const f = await tg('getFile', env.BOT_TOKEN, {

      file_id: msg.document.file_id,

    });

    if (!f.ok) return;

    const r = await fetch(

      'https://api.telegram.org/file/bot' +

        env.BOT_TOKEN +

        '/' +

        f.result.file_path

    );

    content = await r.text();

  } else {

    return;

  }

  if (!content) return;

  // 收集模式（本地订阅/远程订阅）— KV 持久化 + 容错
  if (await getCollectModeSync(uid, u, env)) {
    // 内存优先，KV 兜底：避免每次文件都读 KV（429 限流）
    if (!u._collected) u._collected = await getCollected(uid, env);
    const items = u._collected;

    if (u._collectMode === 'file') {
      items.push({ name: msg.document?.file_name || '', size: msg.document?.file_size || content.length, content });
    } else if (u._collectMode === 'url' && msg.text) {
      const urls = msg.text.trim().split(/[\s,;\n]+/).filter(s => /^https?:\/\//i.test(s));
      for (const url of urls) items.push({ url, content: '', size: 0 });
      if (urls.length === 0) return;
    } else {
      return;
    }

    // 异步写 KV（不阻塞，429 容错）
    saveCollected(uid, items, env).catch(() => {});

    const targetCid = u.promptCid || cid;
    const colMsg = collectionText({ items, mode: u._collectMode });
    await tg('editMessageText', env.BOT_TOKEN, {
      chat_id: targetCid, message_id: u.promptMid, text: colMsg, parse_mode: 'HTML',
      reply_markup: collectionKb(items.length > 0),
    }).catch(async () => {
      const sent = await tg('sendMessage', env.BOT_TOKEN, { chat_id: cid, text: colMsg, parse_mode: 'HTML', reply_markup: collectionKb(items.length > 0) });
      if (sent?.result?.message_id) {
        u.promptCid = cid; u.promptMid = sent.result.message_id;
      }

    });

    return;

  }

  // ===== 非收集模式 =====
  return await safeExecute(async () => {
    // 弹确认框，不直接创建短链
    u._pendingContent = content;
    u._pendingFileName = '';
    const preview = content.length > 100 ? content.slice(0, 100) + '...' : content;
    return tg('sendMessage', env.BOT_TOKEN, {
      chat_id: cid,
      text: '\u{1F4DD} <b>\u6536\u5230\u6587\u672C</b>\n\n<code>' + escapeHTML(preview) + '</code>\n\n\u662F\u5426\u8F6C\u4E3A\u77ED\u94FE\uFF1F',
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [
        [{ text: '\u2705 \u8F6C\u77ED\u94FE', callback_data: 'shortlink_confirm:yes' }, { text: '\u274C \u53D6\u6D88', callback_data: 'shortlink_confirm:no' }],
      ] },
    });
  }, env, uid, cid, null, '\u6587\u672C\u786E\u8BA4');
}


// ==================== 回调处理 ====================

async function onCb(q, env) {

  const uid = String(q.from.id);

  if (!isAllowed(uid, env)) return;

  const cid = q.message.chat.id;

  const mid = q.message.message_id;

  const u = getState(uid);

  const d = q.data;

  await tg('answerCallbackQuery', env.BOT_TOKEN, {

    callback_query_id: q.id,

  });

  // === dispatch ===

  if (d === 'menu') return cb_menu(env, uid, cid, mid, u, d, q);
  if (d.startsWith('shortlink_confirm:')) return cb_shortlink_confirm(env, uid, cid, mid, u, d, q);

  if (d === 'input_url') return cb_input_url(env, uid, cid, mid, u, d, q);

  if (d === 'input_file') return cb_input_file(env, uid, cid, mid, u, d, q);

  if (d === 'collection_process') return cb_collection_process(env, uid, cid, mid, u, d, q);

  if (d === 'ua_menu') return cb_ua_menu(env, uid, cid, mid, u, d, q);

  if (d.startsWith('ua_toggle:')) return cb_ua_toggle(env, uid, cid, mid, u, d, q);

  if (d.startsWith('ua_del:')) return cb_ua_del(env, uid, cid, mid, u, d, q);

  if (d === 'ua_reset') return cb_ua_reset(env, uid, cid, mid, u, d, q);

  if (d === 'ua_add') return cb_ua_add(env, uid, cid, mid, u, d, q);

  if (d.startsWith('my_links_')) return cb_my_links(env, uid, cid, mid, u, d, q);
  if (d === 'kv_usage') return cb_kv_usage(env, uid, cid, mid, u, d, q);
    if (d === 'changelog') return cb_changelog(env, uid, cid, mid, u, d, q);

  if (d.startsWith('link_')) return cb_link(env, uid, cid, mid, u, d, q);

  if (d.startsWith('del_confirm_')) return cb_del_confirm(env, uid, cid, mid, u, d, q);

  if (d.startsWith('do_del_')) return cb_do_del(env, uid, cid, mid, u, d, q);

  if (d.startsWith('mod_ttl_')) return cb_mod_ttl(env, uid, cid, mid, u, d, q);

  if (d.startsWith('chg_ttl_')) return cb_chg_ttl(env, uid, cid, mid, u, d, q);

  if (d.startsWith('rename_')) {

    const linkId = d.replace('rename_', '');

    u.state = 'RENAME_' + linkId;

    u.promptCid = cid;

    u.promptMid = mid;

    return editMsg(env, cid, mid,

      '\u{1F4DD} <b>\u4FEE\u6539\u5217\u8868\u540D\u79F0</b>\n\n\u53D1\u9001\u65B0\u540D\u79F0\uFF0C\u6216\u53D1\u9001 /cancel \u53D6\u6D88\u3002',

      { inline_keyboard: [[{ text: '\u2716 \u53D6\u6D88', callback_data: 'link_' + linkId }]] },

    );

  }

  if (d.startsWith('mod_shortcode_')) {

    const linkId = d.replace('mod_shortcode_', '');

    u.state = 'SHORTCODE_' + linkId;

    u.promptCid = cid;

    u.promptMid = mid;

    return editMsg(env, cid, mid,

      '\u270F <b>\u4FEE\u6539\u77ED\u7801</b>\n\n\u5F53\u524D\u77ED\u7801: <code>' + linkId + '</code>\n\n\u53D1\u9001\u65B0\u77ED\u7801\uFF08\u53EA\u5141\u8BB8\u5B57\u6BCD\u3001\u6570\u5B57\u3001\u77ED\u6A2A\u7EBF\uFF0C3-20\u5B57\u7B26\uFF09\uFF0C\u6216\u53D1\u9001 /cancel \u53D6\u6D88\u3002',

      { inline_keyboard: [[{ text: '\u2716 \u53D6\u6D88', callback_data: 'link_' + linkId }]] },

    );

  }

  if (d.startsWith('mod_acc_')) return cb_mod_acc(env, uid, cid, mid, u, d, q);

  if (d.startsWith('chg_acc_')) return cb_chg_acc(env, uid, cid, mid, u, d, q);

  if (d === 'limit_menu') return cb_limit_menu(env, uid, cid, mid, u, d, q);

  if (d === 'ttl_menu') return cb_ttl_menu(env, uid, cid, mid, u, d, q);

  if (d.startsWith('ttl_set:')) return cb_ttl_set(env, uid, cid, mid, u, d, q);

  if (d === 'acc_menu') return cb_acc_menu(env, uid, cid, mid, u, d, q);

  if (d.startsWith('acc_set:')) return cb_acc_set(env, uid, cid, mid, u, d, q);

  if (d === 'conv_toggle_burn') return cb_conv_toggle_burn(env, uid, cid, mid, u, d, q);

  if (d === 'conv_toggle_check') return cb_conv_toggle_check(env, uid, cid, mid, u, d, q);

  if (d.startsWith('alive_cancel:')) return cb_alive_cancel(env, uid, cid, mid, u, d, q);

  if (d === 'conv_toggle_landing') return cb_conv_toggle_landing(env, uid, cid, mid, u, d, q);


  if (d.startsWith('flow_pick:')) return cb_flow_pick(env, uid, cid, mid, u, d, q);


  if (d === 'conv_back') return cb_conv_back(env, uid, cid, mid, u, d, q);

  if (d === 'conv_limit_menu') return cb_conv_limit_menu(env, uid, cid, mid, u, d, q);
  if (d === 'conv_flow_menu') return cb_conv_flow_menu(env, uid, cid, mid, u, d, q);

  if (d === 'conv_ttl_menu') return cb_conv_ttl_menu(env, uid, cid, mid, u, d, q);

  if (d.startsWith('conv_ttl_set:')) return cb_conv_ttl_set(env, uid, cid, mid, u, d, q);

  if (d === 'conv_acc_menu') return cb_conv_acc_menu(env, uid, cid, mid, u, d, q);

  if (d.startsWith('conv_acc_set:')) return cb_conv_acc_set(env, uid, cid, mid, u, d, q);

  if (d.startsWith('tmpl_')) {

    if (d === 'tmpl_menu') return cb_tmpl_menu(env, uid, cid, mid, u, d, q);

    if (d === 'tmpl_edit') return cb_tmpl_edit(env, uid, cid, mid, u, d, q);

    if (d === 'tmpl_sync') return cb_tmpl_sync(env, uid, cid, mid, u, d, q);

    if (d.startsWith('tmpl_select_r:')) return cb_tmpl_select_r(env, uid, cid, mid, u, d, q);

    if (d.startsWith('tmpl_select_u:')) return cb_tmpl_select_u(env, uid, cid, mid, u, d, q);

    if (d.startsWith('tmpl_del:')) return cb_tmpl_del(env, uid, cid, mid, u, d, q);

  }

  if (d === 'yaml_menu') return cb_yaml_menu(env, uid, cid, mid, u, d, q);

  if (d === 'flow_menu') return cb_flow_menu(env, uid, cid, mid, u, d, q);

  if (d === 'flow_edit') return cb_flow_edit(env, uid, cid, mid, u, d, q);

  if (d.startsWith('flow_select:')) return cb_flow_select(env, uid, cid, mid, u, d, q);

  if (d.startsWith('flow_del:')) return cb_flow_del(env, uid, cid, mid, u, d, q);

  if (d.startsWith('conv_fmt:')) return cb_conv_fmt(env, uid, cid, mid, u, d, q);

}

// ==================== onCb 路由处理函数 ====================

async function cb_menu(env, uid, cid, mid, u, d, q) {

    return await safeExecute(async () => {

  // 返回主页 → 清理所有收集/临时状态

  await clearCollected(uid, env);
  u._collected = null;

  await setCollectMode(uid, u, null, env);

  u._fmtMsg = null; u._lastProxies = null; u._lastSubInput = null;

  u._isGost = null; u._gostInput = null; u._gostCount = null; u._lastStats = null; u._lastFetchUa = null; u._lastSubInfo = null;

  return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: mainPageText(),

      parse_mode: 'HTML',

      reply_markup: mainKb(),

    });

    }, env, uid, cid, mid, '格式转换');}

// ==================== 非收集模式 → 确认转短链 ====================

async function cb_shortlink_confirm(env, uid, cid, mid, u, d, q) {
  const parts = d.split(':');
  const type = parts[1]; // file, text, link
  const content = u._pendingContent || '';
  const fileName = u._pendingFileName || '';

  if (type === 'yes') {
    // 确认创建短链
    const ttl = u._convTtl || 0;
    const { id, url: clipUrl } = await saveToClipAndTrack(content, ttl, env, uid, {}, 0);
    
    // 获取用户链接数
    const links = await getUserLinks(uid, env);
    
    const text = '✅ <b>短链已创建</b>\n\n' +
      '🔗 <code>' + clipUrl + '</code>\n\n' +
      '📄 ' + (fileName || '内容') + ' · ' + (content.length / 1024).toFixed(1) + ' KB\n' +
      '📊 我的短链: ' + links.length + ' 条';
    
    u._pendingContent = null;
    u._pendingFileName = null;

    return tg('editMessageText', env.BOT_TOKEN, {
      chat_id: cid, message_id: mid, text, parse_mode: 'HTML',
      reply_markup: resultKb(clipUrl),
    });
  } else {
    // 取消
    u._pendingContent = null;
    u._pendingFileName = null;
    return cb_menu(env, uid, cid, mid, u, d, q);
  }
}

async function cb_input_url(env, uid, cid, mid, u, d, q) {

  await setCollectMode(uid, u, 'url', env);

    u.promptCid = cid;

    u.promptMid = mid;

    await saveCollected(uid, [], env);

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid, text: collectionText({ items: [], mode: 'url' }), parse_mode: 'HTML',

      reply_markup: collectionKb(false),

    });

}

async function cb_input_file(env, uid, cid, mid, u, d, q) {

  await setCollectMode(uid, u, 'file', env);

    u.promptCid = cid;

  u._collected = [];
    u.promptMid = mid;

    await saveCollected(uid, [], env); // 重置内存收集

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid, text: collectionText({ items: [] }), parse_mode: 'HTML',

      reply_markup: collectionKb(false),

    });

}

async function cb_collection_process(env, uid, cid, mid, u, d, q) {

  return await safeExecute(async () => {

    const mode = await getCollectModeSync(uid, u, env);

    const items = await getCollected(uid, env);

    await setCollectMode(uid, u, null, env);

  u._collected = null;
    await clearCollected(uid, env);

    if (items.length === 0) {

      return tg('editMessageText', env.BOT_TOKEN, {

        chat_id: cid, message_id: mid, text: '\u274C 没有收集到任何内容', parse_mode: 'HTML',

        reply_markup: backKb(),

      });

    }

    if (mode === 'url') {

      // ===== 远程订阅：直接调用 processRemoteUrls 拉取解析 =====

      const urls = items.filter(i => i.url).map(i => i.url);

      if (urls.length === 0) {

        return editMsg(env, cid, mid, '\u274C 没有有效的订阅链接');

      }

      return processRemoteUrls(urls, cid, uid, u, env);

    }

    // ===== 本地文件/文本：继续原有解析流程 =====

    let proxies = [];

    let gostInput = '';

    for (const item of items) {

      const content = item.content || '';

      // 检测 Gost 隧道行

      if (isGostSocksContent(content)) {

        const { gostLines: gostParts, otherLines: restParts } = splitGostLines(content);

        if (gostParts.length > 0) {

          gostInput += (gostInput ? '\n' : '') + gostParts.join('\n');

        }

        if (restParts.trim().length > 0) {

          const parsed = parseProxies(restParts);

          if (parsed && parsed.length > 0) proxies.push(...parsed);

        }

      } else {

        let parsed = parseProxies(content);

        if (parsed && parsed.length > 0) proxies.push(...parsed);

      }

    }

    u._gostInput = gostInput || u._gostInput || null;

    if (proxies.length === 0) {

      // 回退：从原始文本提取 Surge 行

      const surgeLines = [];

      for (const item of items) {

        const sr = parseSurgeLines(item.content);

        if (sr.proxies.length > 0) surgeLines.push(...sr.proxies);

      }

      if (surgeLines.length > 0) proxies = surgeLines;

    }

    // 清理 KV

    env.KV.delete('collect:' + uid).catch(() => {});

    if (!proxies || proxies.length === 0) {

      // 没解析到标准节点但有 Gost 隧道 → 走 Gost 流程

      if (gostInput || u._gostInput) {

        u._isGost = true;

        u._gostInput = gostInput || u._gostInput;

        u._gostCount = (gostInput || u._gostInput || '').split('\n').filter(Boolean).length;

        u._lastProxies = [];

        const text = '\u{1F504} \u68C0\u6D4B\u5230 Gost \u8F93\u5165\n\n\u{1F4CA} Gost: ' + u._gostCount + ' \u6761\n\u26A0\uFE0F \u4EC5 Shadowrocket / URI \u683C\u5F0F\u80FD\u8F6C\u6362 Gost\uFF0C\u5176\u4ED6\u683C\u5F0F\u5C06\u8F93\u51FA\u539F\u59CB\u5185\u5BB9\n\n\u8BF7\u9009\u62E9\u8F93\u51FA\u683C\u5F0F:';

        return tg('editMessageText', env.BOT_TOKEN, {

          chat_id: cid, message_id: mid, text, parse_mode: 'HTML',

          reply_markup: fmtKb(null, null, null, u),

        });

      }

      return editMsg(env, cid, mid, '\u274C 无法从收集的内容中解析出任何节点');

    }

    // 保存原始输入文本（供 sing-box 私有 DNS 注入等使用）
    u._lastSubInput = items.map(i => i.content || '').join('\n');

    // 去重

    const mergedStd = deduplicateProxies(proxies).map(p => ({ ...p, name: addFlag(p.name) }));

    const dedupCount = proxies.length - mergedStd.length;

    u._lastProxies = mergedStd;

    u._fmtMsg = null;

    // 计算 Gost 数量（如有）

    if (u._gostInput && !u._gostCount) {

      u._gostCount = u._gostInput.split('\n').filter(Boolean).length;

    }

    // 显示格式选择

    if (mergedStd.length === 0) {

      return editMsg(env, cid, mid, '\u274C \u89E3\u6790\u540E\u6CA1\u6709\u8282\u70B9');

    }

    const types = {};

    for (const p of mergedStd) types[p.type] = (types[p.type] || 0) + 1;

    let typeStr = Object.entries(types).sort((a,b) => b[1]-a[1]).map(([t,c]) => t + ': ' + c).join(', ');

    const wgCount = mergedStd.filter(p => p.type === 'wireguard').length;

    if (wgCount > 0) typeStr += '\n\u26A1 WireGuard \u00D7 ' + wgCount + ' — Surge \u4E0D\u652F\u6301\uFF0C\u5C06\u81EA\u52A8\u4EE5\u539F\u751F YAML \u5206\u94FE';

    if (u._gostInput && u._gostCount) typeStr += '\n\u{1F504} Gost \u00D7 ' + u._gostCount + ' — \u5EFA\u8BAE\u9009 Shadowrocket';

    const text = '\u{1F504} \u68C0\u6D4B\u5230\u8BA2\u9605\u5185\u5BB9\n\n\u{1F4CA} \u8282\u70B9\u6570: ' + mergedStd.length +

      (u._gostCount ? ' + Gost ' + u._gostCount : '') +

      (dedupCount > 0 ? '\u3001\u53BB\u91CD: ' + dedupCount : '') +

      '\n\n\u{1F4CD} ' + typeStr + '\n\n\u8BF7\u9009\u62E9\u8F93\u51FA\u683C\u5F0F:';

    const formats = FORMAT_OPTIONS;

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid, text, parse_mode: 'HTML',

      reply_markup: fmtKb(formats, u._convTtl, u.ttl, u),

    });

  }, env, uid, cid, mid, '订阅处理');}

async function cb_ua_menu(env, uid, cid, mid, u, d, q) {

  return showUaSettings(cid, mid, uid, env);

}

async function cb_ua_toggle(env, uid, cid, mid, u, d, q) {

  const idx = parseInt(d.split(':')[1]);

    const cfg = await getUaConfig(uid, env);

    const dis = cfg.disabled || [];

    const pos = dis.indexOf(idx);

    if (pos >= 0) {

      dis.splice(pos, 1);

    } else {

      dis.push(idx);

    }

    cfg.disabled = dis;

    await saveUaConfig(uid, env, cfg);

    return showUaSettings(cid, mid, uid, env);

}

async function cb_ua_del(env, uid, cid, mid, u, d, q) {

  const ci = parseInt(d.split(':')[1]);

    const cfg = await getUaConfig(uid, env);

    if (ci >= 0 && ci < (cfg.custom || []).length) {

      (cfg.custom || []).splice(ci, 1);

      await saveUaConfig(uid, env, cfg);

    }

    return showUaSettings(cid, mid, uid, env);

}

async function cb_ua_reset(env, uid, cid, mid, u, d, q) {

  await saveUaConfig(uid, env, { custom: [], disabled: [] });

    return showUaSettings(cid, mid, uid, env);

}

async function cb_ua_add(env, uid, cid, mid, u, d, q) {

  u.state = 'UA_ADD';

    u.promptCid = cid;

    u.promptMid = mid;

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: '\u{1F310} \u8BF7\u53D1\u9001\u81EA\u5B9A\u4E49 User-Agent \u5B57\u7B26\u4E32\n\n\u8F93\u5165\u540E\u6211\u5C06\u628A\u5B83\u52A0\u5230 UA \u8F6E\u8BE2\u6C60\u4E2D\u3002',

      parse_mode: 'HTML',

      reply_markup: { inline_keyboard: [[{ text: '\u2190 \u53D6\u6D88', callback_data: 'ua_menu' }]] },

    });

}

async function cb_changelog(env, uid, cid, mid, u, d, q) {
  const REPO_URL = 'https://raw.githubusercontent.com/Linsars/sub-store-bot/main/CHANGELOG.md';
  const REPO_PAGE = 'https://github.com/Linsars/sub-store-bot';
  let changelog = '';
  let fetchError = null;
  try {
    const resp = await fetch(REPO_URL);
    if (resp.ok) {
      changelog = await resp.text();
    } else {
      fetchError = 'HTTP ' + resp.status;
    }
  } catch (e) {
    fetchError = e.message || '网络异常';
  }
  if (!changelog) {
    return tg('editMessageText', env.BOT_TOKEN, {
      chat_id: cid, message_id: mid,
      text: '📋 <b>更新日志</b>\n\n⚠️ 拉取失败' + (fetchError ? ': ' + fetchError : ''),
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [
        [{ text: '🔄 重试', callback_data: 'changelog' }],
        [{ text: '⬅️ 返回', callback_data: 'my_links_0' }],
      ] },
    });
  }
  // 提取最新版本号
  const versionMatch = changelog.match(/^## v([\d.]+)/m);
  const latestVersion = versionMatch ? versionMatch[1] : '';
  const isUpdated = latestVersion === BOT_VERSION;
  let header = '';
  const kb = [[{ text: '⬅️ 返回', callback_data: 'my_links_0' }]];
  if (isUpdated) {
    header = '✅ 恭喜已是最新版本\n\n';
  } else {
    header = '⚠️ 版本有更新，请移步仓库手动更新\n\n';
    kb.unshift([{ text: '📦 前往仓库', url: REPO_PAGE }]);
  }
  // 只截取最新版本的内容
  let latestChangelog = changelog;
  const sections = changelog.split(/^## /m);
  if (sections.length > 2) {
    // sections[0] 是空的或头部，sections[1] 是最新版本
    latestChangelog = '## ' + sections[1].trim();
  }
  // 截断到 1500 字符
  if (latestChangelog.length > 1500) {
    latestChangelog = latestChangelog.substring(0, 1500) + '\n\n...';
  }
  const text = header + '📋 <b>更新日志</b>\n\n' + latestChangelog;
  return tg('editMessageText', env.BOT_TOKEN, {
    chat_id: cid, message_id: mid, text, parse_mode: 'HTML',
    reply_markup: { inline_keyboard: kb },
  });
}

async function cb_my_links(env, uid, cid, mid, u, d, q) {

  const page = parseInt(d.split('_')[2]) || 0;

    const links = await getUserLinks(uid, env);

    if (links.length === 0) {

      return tg('editMessageText', env.BOT_TOKEN, {

        chat_id: cid,

        message_id: mid,

        text: '\u{1F4CB} <b>\u6211\u7684\u77ED\u94FE</b>\n\n\u{1F4A4} \u8FD8\u6CA1\u6709\u77ED\u94FE\n\u8F6C\u6362\u8BA2\u9605\u6216\u4FDD\u5B58\u6587\u672C\u540E\uFF0C\u77ED\u94FE\u4F1A\u81EA\u52A8\u8BB0\u5F55\u5728\u8FD9\u91CC\u3002',

        parse_mode: 'HTML',

        reply_markup: { inline_keyboard: [[{ text: '\u2190 \u8FD4\u56DE', callback_data: 'menu' }]] },

      });

    }

    const pageSize = 5;

    const totalPages = Math.ceil(links.length / pageSize);

    const start = page * pageSize;

    const pageLinks = links.slice(start, start + pageSize);

    const rows = [];

    for (const l of pageLinks) {

      let icon = linkStatusIcon(l);

      // 读 KV 确认生死（阅后即焚 / IP 超限已删）

      if (icon !== '\u26AB') {

        try {

          const raw = await env.KV.get('share_' + l.id, { type: 'json' });

          if (!raw || raw.consumed) icon = '\u26AB';

        } catch {}

      }

      const label = l.remark ? icon + ' ' + escapeHTML(l.remark) : icon + ' ' + escapeHTML(l.preview);

      rows.push([{ text: label, callback_data: 'link_' + l.id }]);

    }

    const navRow = [];

    if (page > 0) navRow.push({ text: '\u25C0 \u4E0A\u4E00\u9875', callback_data: 'my_links_' + (page - 1) });

    if (page < totalPages - 1) navRow.push({ text: '\u4E0B\u4E00\u9875 \u25B6', callback_data: 'my_links_' + (page + 1) });

    if (navRow.length) rows.push(navRow);

    rows.push([{ text: '\u{1F4DD} 更新日志', callback_data: 'changelog' }, { text: '\u{1F4CA} KV', callback_data: 'kv_usage' }]);
    rows.push([{ text: '\u{1F519} 返回', callback_data: 'menu' }]);

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: '\u{1F4CB} <b>\u6211\u7684\u77ED\u94FE</b>  <i>' + links.length + '\u6761</i>\n\n\u70B9\u51FB\u67E5\u770B\u8BE6\u60C5:',

      parse_mode: 'HTML',

      reply_markup: { inline_keyboard: rows },

    });

}

async function cb_kv_usage(env, uid, cid, mid, u, d, q) {
  try {
    // 获取用户链接
    const links = await getUserLinks(uid, env);
    let shareSize = 0;
    let shareCount = 0;
    for (const l of links) {
      const val = await env.KV.get('share_' + l.id);
      if (val) { shareSize += val.length; shareCount++; }
    }
    
    // 获取用户配置
    const cfgKeys = ['cfgu:' + uid, 'ua:' + uid, 'ulinks:' + uid];
    let cfgSize = 0;
    let cfgList = [];
    for (const k of cfgKeys) {
      const val = await env.KV.get(k);
      if (val) {
        cfgSize += val.length;
        const name = k.split(':')[0];
        const labels = { cfgu: '用户配置', ua: 'UA 列表', ulinks: '链接索引' };
        cfgList.push(labels[name] || name + ': ' + (val.length / 1024).toFixed(1) + ' KB');
      }
    }
    
    // 获取模板缓存
    const tmplCache = await env.KV.get('tmpl_repo_cache');
    let tmplSize = 0;
    if (tmplCache) tmplSize = tmplCache.length;
    
    const totalSize = shareSize + cfgSize + tmplSize;
    
    const text = '\u{1F4CA} <b>KV 存储用量</b>\n\n' +
      '\u2022 短链 (share_): ' + shareCount + ' 条 \u00B7 ' + (shareSize / 1024).toFixed(1) + ' KB\n' +
      '\u2022 用户配置: ' + cfgList.join(', ') + '\u00B7 ' + (cfgSize / 1024).toFixed(1) + ' KB\n' +
      '\u2022 模板缓存: ' + (tmplSize > 0 ? (tmplSize / 1024).toFixed(1) + ' KB' : '无') + '\n\n' +
      '\u2022 总占用: ' + (totalSize / 1024).toFixed(1) + ' KB\n' +
      '\u2022 KV 限额: 1 GB\n' +
      '\u2022 使用率: ' + (totalSize / 1024 / 1024 / 1024 * 100).toFixed(3) + '%';
    
    return tg('editMessageText', env.BOT_TOKEN, {
      chat_id: cid,
      message_id: mid,
      text,
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [[{ text: '\u2190 返回', callback_data: 'my_links_0' }]] },
    });
  } catch (e) {
    return tg('editMessageText', env.BOT_TOKEN, {
      chat_id: cid,
      message_id: mid,
      text: '\u274C 获取失败: ' + e.message,
      reply_markup: { inline_keyboard: [[{ text: '\u2190 返回', callback_data: 'my_links_0' }]] },
    });
  }
}

async function cb_link(env, uid, cid, mid, u, d, q) {

  const linkId = d.replace('link_', '');

    const links = await getUserLinks(uid, env);

    const l = links.find(x => x.id === linkId);

    if (!l) {

      return tg('editMessageText', env.BOT_TOKEN, {

        chat_id: cid, message_id: mid,

        text: '\u274C \u77ED\u94FE\u5DF2\u4E0D\u5B58\u5728',

        parse_mode: 'HTML',

        reply_markup: mainKb(),

      });

    }

    const clipUrl = (env._clipBase || '') + '/share/' + l.id;

    // 读 KV 判断链接实际状态

    let kvAlive = false;

    let kvConsumed = false;

    let accessedCount = 0;

    let accessedLimit = l.maxAccess || 0;

    try {

      const raw = await env.KV.get('share_' + l.id, { type: 'json' });

      if (raw) {

        kvAlive = true;

        kvConsumed = !!raw.consumed;

        accessedCount = Array.isArray(raw.accessedIPs) ? raw.accessedIPs.length : 0;

        accessedLimit = raw.maxAccess || l.maxAccess || 0;

      }

    } catch {}

    // 确定生死：KV 被删或 consumed=true = 已消耗

    const isConsumed = kvConsumed || (!kvAlive && (l.maxAccess > 0 || l.burn));

    const isExpired = l.ttl > 0 && l.expiresAt && Date.now() > l.expiresAt;

    const isDead = isExpired || isConsumed || (!kvAlive && l.ttl > 0);

    let statusIcon, statusText;

    if (isDead) {

      statusIcon = '\u26AB';

      statusText = isConsumed ? '\u26AB \u5DF2\u6D88\u8017' : '\u26AB \u5DF2\u8FC7\u671F';

    } else if (l.ttl === 0) {

      statusIcon = '\u{1F535}';

      statusText = '\u{1F535} \u6C38\u4E45\u6709\u6548';

    } else if (l.burn) {

      statusIcon = '\u{1F525}';

      statusText = '\u{1F525} \u9605\u540E\u5373\u711A';

    } else {

      statusIcon = '\u{1F7E0}';

      statusText = formatRemaining(l.expiresAt);

    }

    let text = '\u{1F4CB} <b>\u77ED\u94FE\u8BE6\u60C5</b>\n\n';

    text += statusIcon + ' <b>' + escapeHTML(l.preview) + '</b>\n';

    text += '\u{1F4CA} ' + (l.nodeCount || 0) + ' \u8282\u70B9  \u00B7 ' + statusText + '\n';

    if (kvAlive) {

      text += '\u{1F4F1} \u8BBF\u95EE: ' + accessedCount + ' \u8BBE\u5907';

      if (accessedLimit > 0) text += ' / ' + accessedLimit + ' IP';

      text += '\n';

    }

    text += '\n\u{1F517} <code>' + escapeHTML(clipUrl) + '</code>';

    const ttlRow = isDead

      ? [{ text: '\u26AB \u5DF2\u6D88\u8017/\u8FC7\u671F', callback_data: 'noop' }]

      : [{ text: '\u23F1 \u4FEE\u6539\u6642\u6548', callback_data: 'mod_ttl_' + l.id }];

    const accRow = isDead

      ? []

      : [{ text: '\u{1F4CA} \u4FEE\u6539\u6B21\u6570', callback_data: 'mod_acc_' + l.id }];

    const rows = [

      [

        { text: '\u{1F4E4} \u5206\u4EAB', url: 'https://t.me/share/url?url=' + encodeURIComponent(clipUrl) },

        { text: '\u{1F4DD} \u5907\u6CE8', callback_data: 'rename_' + l.id },

      ],

      [

        ttlRow[0],

        ...(accRow.length ? [accRow[0]] : []),

      ],

      [

        { text: '\u270F \u4FEE\u6539\u77ED\u7801', callback_data: 'mod_shortcode_' + l.id },

        { text: '\u{1F5D1} \u5220\u9664\u77ED\u94FE', callback_data: 'del_confirm_' + l.id },

      ],

      [

        { text: '\u2190 \u8FD4\u56DE\u5217\u8868', callback_data: 'my_links_0' },

      ],

    ];

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: text,

      parse_mode: 'HTML',

      reply_markup: { inline_keyboard: rows },

    });

}

async function cb_del_confirm(env, uid, cid, mid, u, d, q) {

  const linkId = d.replace('del_confirm_', '');

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: '\u{2757} \u786E\u5B9A\u5220\u9664\u8FD9\u6761\u77ED\u94FE\uFF1F\n\n\u5220\u9664\u540E\u94FE\u63A5\u5C06\u5B8C\u5168\u5931\u6548\uFF0C\u65E0\u6CD5\u6062\u590D\u3002',

      parse_mode: 'HTML',

      reply_markup: {

        inline_keyboard: [

          [{ text: '\u2705 \u786E\u5B9A\u5220\u9664', callback_data: 'do_del_' + linkId }],

          [{ text: '\u2190 \u53D6\u6D88', callback_data: 'link_' + linkId }],

        ],

      },

    });

}

async function cb_do_del(env, uid, cid, mid, u, d, q) {

  const linkId = d.replace('do_del_', '');

    try { await env.KV.delete('share_' + linkId); } catch (e) { /* ignore */ }

    const ok = await removeUserLink(uid, env, linkId);

    const links = await getUserLinks(uid, env);

    if (links.length === 0) {

      return tg('editMessageText', env.BOT_TOKEN, {

        chat_id: cid,

        message_id: mid,

        text: '\u{1F4CB} <b>\u6211\u7684\u77ED\u94FE</b>\n\n\u{1F4A4} \u8FD8\u6CA1\u6709\u77ED\u94FE',

        parse_mode: 'HTML',

        reply_markup: { inline_keyboard: [[{ text: '\u2190 \u8FD4\u56DE', callback_data: 'menu' }]] },

      });

    }

    return cb_my_links(env, uid, cid, mid, u, 'my_links_0', q);

}

async function cb_mod_ttl(env, uid, cid, mid, u, d, q) {

  const linkId = d.replace('mod_ttl_', '');

    const links = await getUserLinks(uid, env);

    const l = links.find(x => x.id === linkId);

    const curTtl = l ? (l.ttl || 0) : 0;

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: '\u23F1 <b>\u4FEE\u6539\u77ED\u94FE\u6642\u6548</b>\n\n\u9009\u62E9\u65B0\u7684\u6642\u6548\uFF0C\u5DF2\u8FC7\u671F\u7684\u77ED\u94FE\u65E0\u6CD5\u6062\u590D\u3002',

      parse_mode: 'HTML',

      reply_markup: ttlKb(curTtl, 'chg_ttl_' + linkId + ':'),

    });

}

async function cb_chg_ttl(env, uid, cid, mid, u, d, q) {

  const rest = d.replace('chg_ttl_', '');

    const colonIdx = rest.lastIndexOf(':');

    const linkId = rest.slice(0, colonIdx);

    const newTtl = parseInt(rest.slice(colonIdx + 1));

    try {

      const data = await env.KV.get('share_' + linkId, 'json');

      if (data && data.text) {

        const kvOpts = newTtl > 0 ? { expirationTtl: newTtl } : {};

        await env.KV.put('share_' + linkId, JSON.stringify({ ...data, ttl: newTtl }), kvOpts);

      } else {

        return editMsg(env, cid, mid, '\u274C \u77ED\u94FE\u5DF2\u8FC7\u671F\uFF0C\u65E0\u6CD5\u4FEE\u6539\n\n\u5DF2\u8FC7\u671F\u7684\u77ED\u94FE\u65E0\u6CD5\u6062\u590D\uFF0C\u8BF7\u8FD4\u56DE\u5217\u8868\u5220\u9664\u3002',

          { inline_keyboard: [[{ text: '\u2190 \u8FD4\u56DE\u5217\u8868', callback_data: 'my_links_0' }]] });

      }

    } catch (e) { /* ignore */ }

    const links = await getUserLinks(uid, env);

    const idx = links.findIndex(x => x.id === linkId);

    if (idx >= 0) {

      links[idx].ttl = newTtl;

      links[idx].expiresAt = newTtl > 0 ? Date.now() + newTtl * 1000 : null;

      await env.KV.put('ulinks:' + uid, JSON.stringify(links));

    }

    const l = links.find(x => x.id === linkId);

    if (l) {

      const clipUrl = (env._clipBase || '') + '/share/' + l.id;

      let text = '\u{1F4CB} <b>\u77ED\u94FE\u8BE6\u60C5</b>\n\n';

      text += linkStatusIcon(l) + ' <b>' + escapeHTML(l.preview) + '</b>\n';

      text += '\u{1F4CA} ' + (l.nodeCount || 0) + ' \u8282\u70B9  \u00B7 ' + (l.ttl === 0 ? '\u{1F535} \u6C38\u4E45\u6709\u6548' : (l.expiresAt && Date.now() > l.expiresAt ? '\u26AB \u5DF2\u8FC7\u671F' : formatRemaining(l.expiresAt))) + '\n';

      if (l.flowName) text += '\u{1F310} \u6B64\u94FE\u4FE1\u606F: ' + escapeHTML(l.flowName) + '\n';

      text += '\n\u{1F517} <code>' + escapeHTML(clipUrl) + '</code>';

      const shareUrl = 'https://t.me/share/url?url=' + encodeURIComponent(clipUrl);

      const isExpired = l.ttl > 0 && l.expiresAt && Date.now() > l.expiresAt;

      const rows = [

        [{ text: '\u{1F4E4} \u5206\u4EAB', url: shareUrl },

         { text: '\u{1F4DD} \u5907\u6CE8', callback_data: 'rename_' + l.id }],

        [{ text: '\u23F1 \u65F6\u6548', callback_data: isExpired ? 'noop' : 'mod_ttl_' + l.id },

         { text: '\u{1F4CA} \u6B21\u6570', callback_data: 'mod_acc_' + l.id }],

        [{ text: '\u{1F5D1} \u5220\u9664\u77ED\u94FE', callback_data: 'del_confirm_' + l.id }],

        [{ text: '\u2190 \u8FD4\u56DE\u5217\u8868', callback_data: 'my_links_0' }],

      ];

      return editMsg(env, cid, mid, text, { inline_keyboard: rows });

    }

    return editMsg(env, cid, mid, '\u2705 \u5DF2\u4FEE\u6539');

}

async function cb_mod_acc(env, uid, cid, mid, u, d, q) {

  const linkId = d.replace('mod_acc_', '');

    const links = await getUserLinks(uid, env);

    const l = links.find(x => x.id === linkId);

    if (!l) {

      return tg('editMessageText', env.BOT_TOKEN, {

        chat_id: cid, message_id: mid,

        text: '\u274C \u77ED\u94FE\u5DF2\u4E0D\u5B58\u5728',

        parse_mode: 'HTML',

        reply_markup: mainKb(),

      });

    }

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid,

      text: '\u{1F4CA} <b>\u4FEE\u6539\u8BBF\u95EE\u6B21\u6570\u9650\u5236</b>',

      parse_mode: 'HTML',

      reply_markup: accKb(l.maxAccess || 0, 'chg_acc_' + linkId + ':', 'link_' + linkId),

    });

}

async function cb_chg_acc(env, uid, cid, mid, u, d, q) {

  const rest = d.replace('chg_acc_', '');

    const colonIdx = rest.lastIndexOf(':');

    const linkId = rest.slice(0, colonIdx);

    const newAcc = parseInt(rest.slice(colonIdx + 1));

    // 更新 KV 中 maxAccess

    try {

      const data = await env.KV.get('share_' + linkId, 'json');

      if (data && data.text) {

        const updated = { ...data, maxAccess: newAcc };

        const ttl = data.ttl || 0;

        const kvOpts = ttl > 0 ? { expirationTtl: ttl < 60 ? 60 : ttl } : {};

        await env.KV.put('share_' + linkId, JSON.stringify(updated), kvOpts);

      }

    } catch (e) { /* ignore */ }

    // 更新用户索引

    const links = await getUserLinks(uid, env);

    const idx = links.findIndex(x => x.id === linkId);

    if (idx >= 0) {

      links[idx].maxAccess = newAcc;

      await env.KV.put('ulinks:' + uid, JSON.stringify(links));

    }

    const l = links.find(x => x.id === linkId);

    if (l) {

      const clipUrl = (env._clipBase || '') + '/share/' + l.id;

      let text = '\u{1F4CB} <b>\u77ED\u94FE\u8BE6\u60C5</b>\n\n';

      text += linkStatusIcon(l) + ' <b>' + escapeHTML(l.preview) + '</b>\n';

      text += '\u{1F4CA} ' + (l.nodeCount || 0) + ' \u8282\u70B9  \u00B7 ' + (l.ttl === 0 ? '\u{1F535} \u6C38\u4E45\u6709\u6548' : (l.expiresAt && Date.now() > l.expiresAt ? '\u26AB \u5DF2\u8FC7\u671F' : formatRemaining(l.expiresAt))) + '\n';

      if (l.flowName) text += '\u{1F310} \u6B64\u94FE\u4FE1\u606F: ' + escapeHTML(l.flowName) + '\n';

      text += '\n\u{1F517} <code>' + escapeHTML(clipUrl) + '</code>';

      const shareUrl = 'https://t.me/share/url?url=' + encodeURIComponent(clipUrl);

      const isExpired = l.ttl > 0 && l.expiresAt && Date.now() > l.expiresAt;

      const rows = [

        [{ text: '\u{1F4E4} \u5206\u4EAB', url: shareUrl },

         { text: '\u{1F4DD} \u5907\u6CE8', callback_data: 'rename_' + l.id }],

        [{ text: '\u23F1 \u65F6\u6548', callback_data: isExpired ? 'noop' : 'mod_ttl_' + l.id },

         { text: '\u{1F4CA} \u6B21\u6570', callback_data: 'mod_acc_' + l.id }],

        [{ text: '\u{1F5D1} \u5220\u9664\u77ED\u94FE', callback_data: 'del_confirm_' + l.id }],

        [{ text: '\u2190 \u8FD4\u56DE\u5217\u8868', callback_data: 'my_links_0' }],

      ];

      return editMsg(env, cid, mid, text, { inline_keyboard: rows });

    }

    return editMsg(env, cid, mid, '\u2705 \u5DF2\u4FEE\u6539');

}

async function cb_limit_menu(env, uid, cid, mid, u, d, q) {

  const defTtl = u.ttl != null ? u.ttl : 0;

    const defAcc = u._accessLimit != null ? u._accessLimit : 0;

    const ttlLabel = formatTtlLabel(defTtl);

    const accLabel = defAcc === 0 ? '\u4E0D\u9650' : defAcc + ' IP';

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid,

      text: '\u23F1 <b>\u77ED\u94FE\u65F6\u9650</b>\n\n\u2022 \u23F1 \u6642\u6548: ' + ttlLabel + '\n\u2022 \u{1F4CA} \u6B21\u6570: ' + accLabel + '\n\n\u4E24\u8005\u5171\u540C\u751F\u6548\uFF0C\u5148\u5230\u5148\u5931\u6548\u3002',

      parse_mode: 'HTML',

      reply_markup: {

        inline_keyboard: [

          [{ text: '\u23F1 \u6642\u6548', callback_data: 'ttl_menu' }],

          [{ text: '\u{1F4CA} \u6B21\u6570', callback_data: 'acc_menu' }],

          [{ text: '\u2190 \u8FD4\u56DE', callback_data: 'menu' }],

        ],

      },

    });

}

async function cb_ttl_menu(env, uid, cid, mid, u, d, q) {

  const curTtl = u.ttl || 0;

    const curLabel = formatTtlLabel(curTtl);

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: '\u23F1 <b>\u9ED8\u8BA4\u6642\u6548</b>\n\n\u4F60\u53D1\u9001\u7ED9\u5217\u8868\u7684\u94FE\u63A5\u5C06\u4F7F\u7528\u8BE5\u65F6\u6548\u3002\n\u2705 \u5F53\u524D\u8BBE\u7F6E: <b>' + curLabel + '</b>',

      parse_mode: 'HTML',

      reply_markup: ttlKb(curTtl, '', 'limit_menu'),

    });

}

async function cb_ttl_set(env, uid, cid, mid, u, d, q) {

  const ttlVal = parseInt(d.split(':')[1]);

    u.ttl = ttlVal;

    await saveUserConfig(uid, env, u);

    u._lastTtlSet = Date.now();

    const ttlLabel = formatTtlLabel(ttlVal);

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: '\u23F1 <b>\u9ED8\u8BA4\u6642\u6548</b>\n\n\u4F60\u53D1\u9001\u7ED9\u5217\u8868\u7684\u94FE\u63A5\u5C06\u4F7F\u7528\u8BE5\u65F6\u6548\u3002\n\u2705 \u5F53\u524D\u8BBE\u7F6E: <b>' + ttlLabel + '</b>',

      parse_mode: 'HTML',

      reply_markup: ttlKb(u.ttl || 0, '', 'limit_menu'),

    });

}

async function cb_acc_menu(env, uid, cid, mid, u, d, q) {

  const curAcc = u._accessLimit != null ? u._accessLimit : 0;

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid,

      text: '\u{1F4CA} <b>\u6B21\u6570\u8BBE\u7F6E</b>\n\n\u5F53\u524D\u9ED8\u8BA4\u8BBF\u95EE\u6B21\u6570\u9650\u5236\u3002',

      parse_mode: 'HTML',

      reply_markup: accKb(curAcc, '', 'limit_menu'),

    });

}

async function cb_acc_set(env, uid, cid, mid, u, d, q) {

  const accVal = parseInt(d.split(':')[1]);

    u._accessLimit = accVal;

    await saveUserConfig(uid, env, u);

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid,

      text: '\u2705 \u5DF2\u8BBE\u7F6E\u9ED8\u8BA4\u8BBF\u95EE\u6B21\u6570: ' + (accVal === 0 ? '\u4E0D\u9650' : accVal + ' IP'),

      parse_mode: 'HTML',

      reply_markup: accKb(accVal, '', 'limit_menu'),

    });

}

async function cb_conv_toggle_burn(env, uid, cid, mid, u, d, q) {

  u._burn = !u._burn;

    return tg('editMessageReplyMarkup', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid,

      reply_markup: fmtKb(null, u._convTtl, u.ttl, u),

    });

}

async function cb_conv_toggle_check(env, uid, cid, mid, u, d, q) {

  u._checkAlive = !u._checkAlive;

  await saveUserConfig(uid, env, { _checkAlive: u._checkAlive }).catch(() => {});

  await tg('answerCallbackQuery', env.BOT_TOKEN, {

    callback_query_id: q.id,

    text: u._checkAlive ? '\u2705 \u6D4B\u6D3B\u8F93\u51FA\u5DF2\u5F00\u542F\uFF08\u4EC5\u8F93\u51FA\u5B58\u6D3B\u8282\u70B9\uFF09' : '\u6D4B\u6D3B\u8F93\u51FA\u5DF2\u5173\u95ED',

  }).catch(() => {});

    return tg('editMessageReplyMarkup', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid,

      reply_markup: fmtKb(null, u._convTtl, u.ttl, u),

    });

}

async function cb_conv_toggle_landing(env, uid, cid, mid, u, d, q) {

  u._landing = !u._landing;

    return tg('editMessageReplyMarkup', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid,

      reply_markup: fmtKb(null, u._convTtl, u.ttl, u),

    });

}

async function cb_conv_flow_menu(env, uid, cid, mid, u, d, q) {
  // 从本次时限菜单进入的流量信息模板选择
  const templates = await getFlowTemplates(uid, env);
  if (templates.length === 0) {
    return tg('answerCallbackQuery', env.BOT_TOKEN, { callback_query_id: q.id, text: '\u26A0\uFE0F \u8BF7\u5148\u5728 \u4E3B\u9875 \u2192 \u6A21\u677F\u7BA1\u7406 \u2192 \u6D41\u91CF\u4FE1\u606F \u6DFB\u52A0\u6A21\u677F', show_alert: true });
  }
  const lines = ['\u{1F310} <b>\u9009\u62E9\u6D41\u91CF\u4FE1\u606F\u6A21\u677F</b>', ''];
  for (let i = 0; i < templates.length; i++) {
    const t = templates[i];
    const isActive = (u._convFlowName || u._flowName) === t.name;
    lines.push((isActive ? '\u25CF ' : '\u25CB ') + t.name);
  }
  lines.push('', '\u9009\u62E9\u540E\u5C06\u9644\u52A0\u5230\u77ED\u94FE\u8F93\u51FA');
  const rows = [];
  for (let i = 0; i < templates.length; i++) {
    rows.push([{ text: templates[i].name, callback_data: 'flow_pick:' + i }]);
  }
  rows.push([{ text: '\u274C \u4E0D\u4F7F\u7528', callback_data: 'flow_pick:none' }]);
  rows.push([{ text: '\u2190 \u8FD4\u56DE', callback_data: 'conv_back' }]);
  return tg('editMessageText', env.BOT_TOKEN, { chat_id: cid, message_id: mid, text: lines.join('\n'), parse_mode: 'HTML', reply_markup: { inline_keyboard: rows } });
}

async function cb_flow_pick(env, uid, cid, mid, u, d, q) {
  const val = d.split(':')[1];
  const templates = await getFlowTemplates(uid, env);

  // 返回本次时限菜单（从 conv_flow_menu 进入时）
  const goBack = () => {
    const effConvTtl = u._convTtl != null ? u._convTtl : (u.ttl != null ? u.ttl : 0);
    const ttlLabel = formatTtlLabel(effConvTtl);
    const effConvAcc = u._convAccessLimit != null ? u._convAccessLimit : (u._accessLimit != null ? u._accessLimit : 0);
    const accLabel = effConvAcc === 0 ? '\u4E0D\u9650' : effConvAcc + ' IP';
    const effFlowName = u._convFlowName || u._flowName || null;
    const flowLabel = effFlowName ? '\u2705 ' + effFlowName : '\u274C \u4E0D\u4F7F\u7528';
    return tg('editMessageText', env.BOT_TOKEN, {
      chat_id: cid, message_id: mid,
      text: '\u23F1 <b>\u672C\u6B21\u65F6\u9650</b>\n\n\u2022 \u23F1 \u6642\u6548: ' + ttlLabel + '\n\u2022 \u{1F4CA} \u6B21\u6570: ' + accLabel + '\n\u2022 \u{1F310} \u6B64\u94FE\u4FE1\u606F: ' + flowLabel + '\n\n\u4EC5\u5F71\u54CD\u672C\u6B21\u8F6C\u6362\uFF0C\u4E0D\u4F1A\u6539\u53D8\u4E3B\u9875\u7684\u9ED8\u8BA4\u503C\u3002',
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [{ text: '\u23F1 \u672C\u6B21\u6642\u6548', callback_data: 'conv_ttl_menu' }],
          [{ text: '\u{1F4CA} \u672C\u6B21\u6B21\u6570', callback_data: 'conv_acc_menu' }],
          [{ text: '\u{1F310} \u6B64\u94FE\u4FE1\u606F', callback_data: 'conv_flow_menu' }],
          [{ text: '\u2190 \u8FD4\u56DE', callback_data: 'conv_back' }],
        ],
      },
    });
  };

  if (val === 'none') {
    u._convFlowHeader = null;
    u._convFlowName = null;
    await tg('answerCallbackQuery', env.BOT_TOKEN, { callback_query_id: q.id, text: '\u274C \u5DF2\u53D6\u6D88\u6B64\u94FE\u4FE1\u606F' });
    return goBack();
  }

  const idx = parseInt(val);
  if (idx >= 0 && idx < templates.length) {
    u._convFlowHeader = templates[idx].header;
    u._convFlowName = templates[idx].name;
    await tg('answerCallbackQuery', env.BOT_TOKEN, { callback_query_id: q.id, text: '\u2705 \u5DF2\u8BBE\u7F6E: ' + templates[idx].name });
    return goBack();
  }

  return tg('editMessageReplyMarkup', env.BOT_TOKEN, {
    chat_id: cid, message_id: mid,
    reply_markup: fmtKb(null, u._convTtl, u.ttl, u),
  });
}


async function cb_conv_back(env, uid, cid, mid, u, d, q) {

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: u._fmtText || '\u8BF7\u9009\u62E9\u8F93\u51FA\u683C\u5F0F:',

      parse_mode: 'HTML',

      reply_markup: fmtKb(null, u._convTtl, u.ttl, u),

    });

}

async function cb_conv_limit_menu(env, uid, cid, mid, u, d, q) {
  const effConvTtl = u._convTtl !== undefined ? u._convTtl : (u.ttl || 0);

    const ttlLabel = formatTtlLabel(effConvTtl);

    const effConvAcc = u._convAccessLimit != null ? u._convAccessLimit : (u._accessLimit != null ? u._accessLimit : 0);

    const accLabel = effConvAcc === 0 ? '\u4E0D\u9650' : effConvAcc + ' IP';

    const effFlowName = u._convFlowName || u._flowName || null;

    const flowLabel = effFlowName ? '\u2705 ' + effFlowName : '\u274C \u4E0D\u4F7F\u7528';

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: '\u23F1 <b>\u672C\u6B21\u65F6\u9650</b>\n\n\u2022 \u23F1 \u6642\u6548: ' + ttlLabel + '\n\u2022 \u{1F4CA} \u6B21\u6570: ' + accLabel + '\n\u2022 \u{1F310} \u6B64\u94FE\u4FE1\u606F: ' + flowLabel + '\n\n\u4EC5\u5F71\u54CD\u672C\u6B21\u8F6C\u6362\uFF0C\u4E0D\u4F1A\u6539\u53D8\u4E3B\u9875\u7684\u9ED8\u8BA4\u503C\u3002',

      parse_mode: 'HTML',

      reply_markup: {

        inline_keyboard: [

          [{ text: '\u23F1 \u672C\u6B21\u6642\u6548', callback_data: 'conv_ttl_menu' }],

          [{ text: '\u{1F4CA} \u672C\u6B21\u6B21\u6570', callback_data: 'conv_acc_menu' }],

          [{ text: '\u{1F310} \u6B64\u94FE\u4FE1\u606F', callback_data: 'conv_flow_menu' }],

          [{ text: '\u2190 \u8FD4\u56DE', callback_data: 'conv_back' }],

        ],

      },

    });

}

async function cb_conv_ttl_menu(env, uid, cid, mid, u, d, q) {

  return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: '\u23F1 <b>\u8BBE\u7F6E\u5F53\u524D\u8F6C\u6362\u7684\u6642\u6548</b>\n\n\u4EC5\u5F71\u54CD\u672C\u6B21\u8F6C\u6362\u3002',

      parse_mode: 'HTML',

      reply_markup: ttlKb(u._convTtl != null ? u._convTtl : (u.ttl != null ? u.ttl : 0), 'conv_ttl_set:', 'conv_limit_menu'),

    });

}

async function cb_conv_ttl_set(env, uid, cid, mid, u, d, q) {

  const ttlVal = parseInt(d.split(':')[1]);

    u._convTtl = ttlVal;

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: '\u2705 \u5DF2\u8BBE\u7F6E\u5F53\u524D\u6642\u6548: ' + formatTtlLabel(ttlVal),

      parse_mode: 'HTML',

      reply_markup: fmtKb(null, u._convTtl, u.ttl, u),

    });

}

async function cb_conv_acc_menu(env, uid, cid, mid, u, d, q) {

  const current = u._convAccessLimit != null ? u._convAccessLimit : (u._accessLimit != null ? u._accessLimit : 0);

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: '\u{1F4CA} <b>\u8BBE\u7F6E\u5F53\u524D\u8F6C\u6362\u7684\u8BBF\u95EE\u6B21\u6570\u9650\u5236</b>\n\n\u8D85\u8FC7\u8BBF\u95EE\u6B21\u6570\u540E\u77ED\u94FE\u81EA\u52A8\u5931\u6548\u3002',

      parse_mode: 'HTML',

      reply_markup: accKb(current, 'conv_acc_set:', 'conv_limit_menu'),

    });

}

async function cb_conv_acc_set(env, uid, cid, mid, u, d, q) {

  const accVal = parseInt(d.split(':')[1]);

    u._convAccessLimit = accVal;

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid,

      message_id: mid,

      text: '\u2705 \u5DF2\u8BBE\u7F6E\u5F53\u524D\u8BBF\u95EE\u6B21\u6570: ' + (accVal === 0 ? '\u4E0D\u9650' : accVal + ' IP'),

      parse_mode: 'HTML',

      reply_markup: fmtKb(null, u._convTtl, u.ttl, u),

    });

}

async function cb_conv_fmt(env, uid, cid, mid, u, d, q) {

  const fmt = d.split(':')[1];

    const fmtLabel = FORMAT_OPTIONS.find((f) => f.id === fmt)?.label || fmt;

    // 纯 Gost（无标准节点）：直接输出原始内容

    if (u._isGost && (!u._lastProxies || u._lastProxies.length === 0)) {

      const rawText = u._gostInput || u._lastSubInput || '';

      try {

        const { id, url: clipUrl } = await saveToClipAndTrack(rawText, getEffectiveTtl(u), env, uid, {

          preview: fmtLabel + ' · ' + (u._gostCount || '?') + ' 节点 (Gost)',

          nodeCount: u._gostCount || 0,

          source: 'gost',

          burn: u?._burn || false,

          landing: u?._landing || false,
          flowHeader: u._convFlowHeader || u._flowHeader || null,
          flowName: u._convFlowName || u._flowName || null,

        }, getEffectiveMaxAccess(u));

        u._lastContent = rawText;

        const effTtl = getEffectiveTtl(u);

        const effAcc = getEffectiveMaxAccess(u);

        const gostFlowName = u._convFlowName || u._flowName;

        u._convTtl = null;

        u._convFlowHeader = null;

        u._convFlowName = null;

        env.KV.delete('collect:' + uid).catch(() => {});

        u._convAccessLimit = null;

        const ttlT = formatTtlLabel(effTtl);

        const accT = effAcc === 0 ? '' : '\n\u{1F4CA} ' + effAcc + ' IP';

        const gostFlowT = gostFlowName ? '\n\u{1F310} \u6B64\u94FE\u4FE1\u606F: ' + gostFlowName : '';

        await tg('editMessageText', env.BOT_TOKEN, {

          chat_id: cid,

          message_id: mid,

          text:

            '\u2705 <b>\u8F6C\u6362\u5B8C\u6210</b>\n' +

            '\u{1F4CA} ' + (u._gostCount || '?') + ' Gost \u8282\u70B9 \u2192 <b>' + fmtLabel + '</b>\n\n' +

            '\u{1F517} <code>' + clipUrl + '</code>\n\n' +

            '\u23F1 ' + ttlT + accT + gostFlowT,

          parse_mode: 'HTML',

          reply_markup: resultKb(clipUrl),

        });

        return;

      } catch (e) {

        return tg('editMessageText', env.BOT_TOKEN, {

          chat_id: cid,

          message_id: mid,

          text: '\u274C \u4FDD\u5B58\u5931\u8D25: ' + e.message,

          parse_mode: 'HTML',

          reply_markup: mainKb(),

        });

      }

    }

    if (!u._lastProxies || u._lastProxies.length === 0) {

      return tg('editMessageText', env.BOT_TOKEN, {

        chat_id: cid,

        message_id: mid,

        text: '\u274C \u6CA1\u6709\u53EF\u8F6C\u6362\u7684\u8282\u70B9\uFF0C\u8BF7\u91CD\u65B0\u53D1\u9001',

        parse_mode: 'HTML',

        reply_markup: mainKb(),

      });

    }


    // 测活输出开关: 开启时先测活, cron 分批执行, 完成后仅输出存活节点
    if (u._checkAlive) {

      return startAliveCheck(env, uid, cid, mid, u, fmt, fmtLabel);

    }

    // 标准转换输出（含私有 DNS 注入等）
    return convertAndOutput(env, uid, cid, mid, u, fmt, u._lastProxies || [], {});

}

// ==================== 标准节点转换输出（供 cb_conv_fmt / 测活 cron 共用） ====================
async function convertAndOutput(env, uid, cid, mid, u, fmt, proxies, opts) {

  opts = opts || {};

  const fmtLabel = FORMAT_OPTIONS.find((f) => f.id === fmt)?.label || fmt;

    // 非 gost 格式的标准节点转换

    let proxiesForConvert = proxies;

    // 输出时统一加旗帜 + 去同名

    const nameCount = {};

    proxiesForConvert = proxiesForConvert.map(p => {

      const base = (p.name || '').trim() || '未命名';

      const flagged = addFlag(base);

      nameCount[flagged] = (nameCount[flagged] || 0) + 1;

      const idx = nameCount[flagged];

      const dupCount = idx - 1;

      const renamed = dupCount > 0 ? { ...p, name: flagged + superscriptNum(dupCount) } : { ...p, name: flagged };

      return renamed;

    });

    let output;

    if (fmt === 'b64') {

      // Base64 输出：取原始订阅内容（已是 base64 base64 或可截取

      // 优先用原始文本（直连或反代拿到的最初内容）

      let rawText = u._lastRawContent || '';

      // 如果原始内容不是 base64（是 URI 列表），先转 base64

      if (rawText && !/^[A-Za-z0-9+/=\s\r\n]+$/.test(rawText.trim())) {

        rawText = btoa(unescape(encodeURIComponent(rawText)));

      }

      if (!rawText) {

        // 兜底：从 parsed proxies 拼接

        let std = '';

        try { std = ProxyUtils.produce(proxiesForConvert, 'uri'); } catch {}

        const gostRaw = u._gostInput || '';

        rawText = btoa(unescape(encodeURIComponent([std, gostRaw].filter(Boolean).join('\n'))));

      }

      output = rawText;

    } else if (fmt === 'native') {

      // 自定 YAML：优先用用户模板（块格式），处理 Sub 引擎解析不了的畸形节点

      output = 'proxies:\n' + proxiesForConvert.map(p => {

        const order = ['name','type','server','port','password','uuid','alterId','cipher','network','tls','sni','servername','skip-cert-verify','flow','udp','udp-over-tcp','udp-relay-mode','ip-version','tfo','alpn','client-fingerprint','fingerprint','plugin','plugin-opts','psk','version','obfs','username','dialer-proxy','smux','reality','encryption','reality-opts','grpc-opts','ws-opts','http-opts','h2-opts','mkcp-opts','mekya-opts','obfs-opts','vless-opts','trojan-opts','shadowsocks-opts','xhttp-opts','ech-opts','restls-opts','shadow-tls-opts','jls-opts'];

        const seen = new Set();

        const lines = [];

        let isFirst = true;

        const wl = (indent, k, v) => {

          if (isFirst) { lines.push('  - ' + k + ': ' + v); isFirst = false; }

          else lines.push(' '.repeat(indent) + k + (v === '' ? ':' : ': ' + v));

        };

        for (const k of order) {

          if (p[k] === undefined || p[k] === null) continue;

          seen.add(k);

          const v = p[k];

          if (typeof v === 'boolean') wl(4, k, v);

          else if (typeof v === 'number') wl(4, k, v);

          else if (typeof v === 'string') {

            const needsQuote = /[:#\[\]{},&*!|>'"%@` ]/.test(v) || v === '';

            if (needsQuote) wl(4, k, '"' + v.replace(/\\/g,'\\\\').replace(/"/g,'\\"') + '"');

            else wl(4, k, v);

          } else if (Array.isArray(v)) {
            if (v.length === 0) continue;
            wl(4, k, '');
            for (const item of v) {
              const nq = typeof item === 'string' && (item.includes(':') || item.includes('#'));
              lines.push('      - ' + (nq ? '"' + item.replace(/"/g,'\\"') + '"' : String(item)));
            }
          } else if (typeof v === 'object') {
            wl(4, k, '');
            for (const [sk, sv] of Object.entries(v)) {
              if (sv === undefined || sv === null) continue;
              if (Array.isArray(sv)) {
                lines.push('      ' + sk + ':');
                for (const item of sv) {
                  const nq = typeof item === 'string' && (item.includes(':') || item.includes('#'));
                  lines.push('        - ' + (nq ? '"' + item.replace(/"/g,'\\"') + '"' : String(item)));
                }
              } else if (typeof sv === 'object') {
                lines.push('      ' + sk + ':');
                for (const [tk, tv] of Object.entries(sv)) {
                  if (tv !== undefined && tv !== null) {
                    const nq = typeof tv === 'string' && (tv.includes(':') || tv.includes('#') || tv.includes('"') || tv.includes(' '));
                    lines.push('        ' + tk + ': ' + (nq ? '"' + tv.replace(/"/g,'\\"') + '"' : String(tv)));
                  }
                }
              } else {
                const nq = typeof sv === 'string' && (sv.includes(':') || sv.includes('#'));
                lines.push('      ' + sk + ': ' + (nq ? '"' + sv.replace(/"/g,'\\"') + '"' : String(sv)));
              }
            }
          }

        }

        // 有序字段中没出现的其他字段
        const nestedChildKeys = new Set(['mode','host','path','headers','max-early-data','early-data-header-name','v2ray-http-upgrade','v2ray-http-upgrade-fast-open','grpc-service-name','grpc-user-agent','ping-interval','max-connections','min-streams','max-streams','padding','statistic','only-tcp','method','tls','fingerprint','certificate','private-key','skip-cert-verify','name-cert-verify','mux','ech','password','version','version-hint','restls-script','alpn','host','username','primary-key','explicit-nonce-ciphersuites','defer-instance-derived-write-time','transport-layer-padding','connection-enrolment','sequence-watermarking-enabled','embedded-traffic-generator','steps','url','max-write-delay','max-request-size','polling-interval-initial','h2-pool-size','mtu','tti','uplink-capacity','downlink-capacity','congestion','write-buffer','read-buffer','seed','header','key','crypt','mode','conn','autoexpire','scavengettl','ratelimit','sndwnd','rcvwnd','datashard','parityshard','dscp','nocomp','acknodelay','nodelay','interval','resend','sockbuf','smuxver','smuxbuf','framesize','streambuf','keepalive']);
        const anyNestedOpts = p['plugin-opts'] || p['ws-opts'] || p['http-opts'] || p['h2-opts'] || p['obfs-opts'] || p['grpc-opts'] || p['reality-opts'] || p['vless-opts'] || p['trojan-opts'] || p['shadowsocks-opts'] || p['mkcp-opts'] || p['mekya-opts'] || p['xhttp-opts'] || p['ech-opts'] || p['restls-opts'] || p['shadow-tls-opts'] || p['jls-opts'];
        for (const k of Object.keys(p)) {
          if (seen.has(k)) continue;
          const v = p[k];
          if (v === undefined || v === null || k.startsWith('_')) continue;
          if (nestedChildKeys.has(k) && anyNestedOpts) continue;
          if (typeof v === 'boolean') wl(4, k, v);
          else if (typeof v === 'number') wl(4, k, v);
          else if (typeof v === 'string') wl(4, k, '"' + String(v).replace(/"/g,'\\"') + '"');
          else if (Array.isArray(v)) {
            if (v.length === 0) continue;
            wl(4, k, '');
            for (const item of v) {
              const nq = typeof item === 'string' && (item.includes(':') || item.includes('#'));
              lines.push('      - ' + (nq ? '"' + item.replace(/"/g,'\\"') + '"' : String(item)));
            }
          } else if (typeof v === 'object') {
            wl(4, k, '');
            for (const [sk, sv] of Object.entries(v)) {
              if (sv === undefined || sv === null) continue;
              if (Array.isArray(sv)) {
                lines.push('      ' + sk + ':');
                for (const item of sv) {
                  const nq = typeof item === 'string' && (item.includes(':') || item.includes('#'));
                  lines.push('        - ' + (nq ? '"' + item.replace(/"/g,'\\"') + '"' : String(item)));
                }
              } else if (typeof sv === 'object') {
                lines.push('      ' + sk + ':');
                for (const [tk, tv] of Object.entries(sv)) {
                  if (tv !== undefined && tv !== null) {
                    const nq = typeof tv === 'string' && (tv.includes(':') || tv.includes('#') || tv.includes('"') || tv.includes(' '));
                    lines.push('        ' + tk + ': ' + (nq ? '"' + tv.replace(/"/g,'\\"') + '"' : String(tv)));
                  }
                }
              } else {
                const nq = typeof sv === 'string' && (sv.includes(':') || sv.includes('#'));
                lines.push('      ' + sk + ': ' + (nq ? '"' + sv.replace(/"/g,'\\"') + '"' : String(sv)));
              }
            }
          }
          else {
            const numVal = Number(v);
            if (!isNaN(numVal) && String(numVal) === String(v)) wl(4, k, numVal);
            else wl(4, k, '"' + String(v).replace(/\\/g,'\\\\').replace(/"/g,'\\"') + '"');
          }
        }

        return lines.join('\n');

      }).join('\n');

      // 智能模板替换：找到 proxies: 段，替换其中的节点内容

      let templates = [];

      try { templates = JSON.parse(await env.KV.get('tmpls:' + uid)) || []; } catch {}

      let activeTmpl = templates.find(t => t.active);

      if (!activeTmpl) {

        let builtinIdx = 0;

        try { builtinIdx = parseInt(await env.KV.get('tmpl_repo_active:' + uid)) || 0; } catch {}

        // 从 KV 缓存获取仓库模板

        let repoTmpls = [];

        try { repoTmpls = JSON.parse(await env.KV.get('tmpl_repo_cache')) || []; } catch {}

        if (builtinIdx >= 0 && builtinIdx < repoTmpls.length) activeTmpl = repoTmpls[builtinIdx];

      }

      if (activeTmpl && activeTmpl.text) {

        try {

          let tmplText = activeTmpl.text;

          if (tmplText && tmplText.includes('proxies:')) {

            // 检测模板 proxy 格式

            const proxyFormat = /- \{/.test(tmplText.split('proxies:')[1].split('\nproxy-groups')[0] || '') ? 'inline' : 'block';

            const tmplLines = tmplText.split('\n');

            let proxiesStart = -1;

            let proxiesEnd = tmplLines.length;

            for (let i = 0; i < tmplLines.length; i++) {

              if (/^proxies:\s*$/.test(tmplLines[i])) { proxiesStart = i; continue; }

              if (proxiesStart >= 0 && /^\w/.test(tmplLines[i]) && !/^\s/.test(tmplLines[i])) {

                proxiesEnd = i;

                break;

              }

            }

            if (proxiesStart >= 0) {

              // 生成匹配格式的 proxies

              let proxiesYaml = '';

              if (proxyFormat === 'inline') {

                proxiesYaml = proxiesForConvert.map(p => {

                  const parts = ['name: ' + JSON.stringify(p.name), 'type: ' + p.type, 'server: ' + p.server, 'port: ' + p.port];

                  if (p.password) parts.push('password: ' + p.password);

                  if (p.uuid) parts.push('uuid: ' + p.uuid);

                  if (p.cipher) parts.push('cipher: ' + p.cipher);

                  if (p.network) parts.push('network: ' + p.network);

                  if (p.tls) parts.push('tls: true');

                  if (p.sni) parts.push('sni: ' + p.sni);

                  if (p['skip-cert-verify']) parts.push('skip-cert-verify: true');

                  if (p.udp) parts.push('udp: true');

                  return '  - { ' + parts.join(', ') + ' }';

                }).join('\n');

              } else {

                // 块格式 - 用现有的 output

                proxiesYaml = output.replace(/^proxies:\n/, '').split('\n').join('\n');

              }

              tmplLines.splice(proxiesStart + 1, proxiesEnd - proxiesStart - 1, ...proxiesYaml.split('\n'));

              output = tmplLines.join('\n');

              // __ALL_NODES__ 占位符 → 实际节点名（provider 架构模板内联化）
              if (output.includes('__ALL_NODES__')) {

                const nodeNames = (proxiesForConvert || []).map(p => '"' + String(p.name || '').replace(/"/g, '\\"') + '"').join(', ');

                output = output.split('__ALL_NODES__').join(nodeNames);

              }

            }

          }

          // 自定 YAML：订阅有私有 DNS 时，合并追加到模板 dns 段（不顶掉模板 DNS）
          if (output && u._lastSubInput) {
            try {
              output = injectPrivateDnsClash(String(output), u._lastSubInput);
            } catch { /* 注入失败不影响主流程 */ }
          }

        } catch {}

      }

    } else {

      // Sub 引擎产出（Surge 特殊处理 WG）

      const surgeWg = proxiesForConvert.filter(p => p.type === 'wireguard');

      const surgeStd = proxiesForConvert.filter(p => p.type !== 'wireguard');

      try {

        if ((fmt === 'surge' || fmt === 'surfboard') && surgeWg.length > 0) {

          output = surgeStd.length > 0 ? ProxyUtils.produce(surgeStd, fmt) : '';

        } else {

          output = ProxyUtils.produce(proxiesForConvert, fmt);

        }

        // egern 后处理：JSON-in-YAML → proper YAML

        if (output && fmt === 'egern') {

          output = egernToProperYaml(output);

        }

        // v2ray/URI 后处理：修复插件名称兼容性

        if (output && (fmt === 'v2ray' || fmt === 'uri')) {

          if (Array.isArray(output)) output = output.join('\n');

          // v2ray 返回 base64，需要解码→替换→重编码

          if (fmt === 'v2ray' && /^[A-Za-z0-9+/=\s\r\n]+$/.test(output.trim())) {

            try {

              const decoded = decodeURIComponent(escape(atob(output.trim())));

              output = btoa(unescape(encodeURIComponent(decoded.replace(/simple-obfs/g, 'obfs-local').replace(/\/\?plugin=/g, '?plugin='))));

            } catch {}

          } else {

            output = output.replace(/simple-obfs/g, 'obfs-local').replace(/\/\?plugin=/g, '?plugin=');

          }

        }

      } catch (e) {

        return tg('editMessageText', env.BOT_TOKEN, {

          chat_id: cid, message_id: mid,

          text: '\u274C \u8F6C\u6362\u5931\u8D25: ' + e.message,

          parse_mode: 'HTML', reply_markup: fmtKb(null, u._convTtl, u.ttl, u),

        });

      }

    }

    // Surge/Surfboard + WG：以原生 YAML 为主输出或分链

    const surgeWgAll = proxiesForConvert.filter(p => p.type === 'wireguard');

    if (!output && (fmt === 'surge' || fmt === 'surfboard') && surgeWgAll.length > 0) {

      // 全节点都是 WG → 直接以原生 YAML 为主输出

      output = 'proxies:\n' + proxiesForConvert.map(p => {

        const order = ['name','type','server','port','uuid','server_port','ip','mtu'];

        const seen = new Set();

        const lines = [];

        let isFirst = true;

        const wl = (indent, k, v) => {

          if (isFirst) { lines.push('  - ' + k + ': ' + v); isFirst = false; }

          else lines.push(' '.repeat(indent) + k + (v === '' ? ':' : ': ' + v));

        };

        for (const k of order) {

          if (p[k] === undefined || p[k] === null) continue;

          seen.add(k);

          const v = p[k];

          if (typeof v === 'boolean' || typeof v === 'number') wl(4, k, v);

          else if (typeof v === 'string') {

            const needsQuote = /[:#\[\]{},&*!|>'"%@` ]/.test(v) || v === '';

            if (needsQuote) wl(4, k, '"' + v.replace(/\\/g,'\\\\').replace(/"/g,'\\"') + '"');

            else wl(4, k, v);

          } else if (typeof v === 'object') {

            wl(4, k, '');

            for (const [sk, sv] of Object.entries(v)) {

              if (sv !== undefined && sv !== null) {

                const nq = typeof sv === 'string' && (sv.includes(':') || sv.includes('#') || sv.includes(' '));

                lines.push('      ' + sk + ': ' + (nq ? '"' + sv.replace(/"/g,'\\"') + '"' : String(sv)));

              }

            }

          }

        }

        for (const k of Object.keys(p)) {

          if (seen.has(k)) continue;

          const v = p[k];

          if (v === undefined || v === null || k.startsWith('_')) continue;

          if (typeof v === 'boolean' || typeof v === 'number') wl(4, k, v);

          else wl(4, k, '"' + String(v).replace(/"/g,'\\"') + '"');

        }

        return lines.join('\n');

      }).join('\n');

    }

    if (!output) {

      return tg('editMessageText', env.BOT_TOKEN, {

        chat_id: cid, message_id: mid,

        text: '\u274C \u8F6C\u6362\u7ED3\u679C\u4E3A\u7A7A',

        parse_mode: 'HTML', reply_markup: fmtKb(null, u._convTtl, u.ttl, u),

      });

    }

    tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid,

      text: '\u{1F504} \u8F6C\u6362\u4E2D... (' + fmtLabel + ')', parse_mode: 'HTML',

    });

    try {

      const extraUrls = [];

      // sing-box 输出：注入机场私有 DNS（mihomo proxy-server-nameserver）
      if (fmt === 'singbox' && output && u._lastSubInput) {
        try {
          output = injectPrivateDns(String(output), u._lastSubInput);
        } catch { /* 注入失败不影响主流程 */ }
      }
      // Clash Meta (mihomo) 输出：补回 dns.proxy-server-nameserver 段
      if ((fmt === 'clashmeta' || fmt === 'clash') && output && u._lastSubInput) {
        try {
          output = injectPrivateDnsClash(String(output), u._lastSubInput);
        } catch { /* 注入失败不影响主流程 */ }
      }

      const { id, url: clipUrl } = await saveToClipAndTrack(String(output), getEffectiveTtl(u), env, uid, {

        preview: fmtLabel + ' · ' + proxiesForConvert.length + ' 节点',

        nodeCount: proxiesForConvert.length, source: 'convert',

        burn: u?._burn || false,

        landing: u?._landing || false,
        flowHeader: u._convFlowHeader || u._flowHeader || null,
        flowName: u._convFlowName || u._flowName || null,

      }, getEffectiveMaxAccess(u));

      u._lastContent = String(output);

      // Surge/Surfboard + 混合节点：主输出已含非 WG，WG 节点分链输出原生 YAML

      const nonWgCount = proxiesForConvert.filter(p => p.type !== 'wireguard').length;

      if ((fmt === 'surge' || fmt === 'surfboard') && surgeWgAll.length > 0 && output && nonWgCount > 0) {

        let wgYaml;

        try { wgYaml = ProxyUtils.produce(surgeWgAll, 'clashmeta'); } catch {}

        if (!wgYaml) wgYaml = 'proxies:\n' + surgeWgAll.map(p => '  - {name: "' + p.name + '", type: wireguard, server: ' + p.server + '}').join('\n');

        const { url: wgUrl } = await saveToClipAndTrack(String(wgYaml), getEffectiveTtl(u), env, uid, {

          preview: 'WireGuard × ' + surgeWgAll.length + ' (原生 YAML)', nodeCount: surgeWgAll.length, source: 'wg',

          burn: u?._burn || false,

          landing: u?._landing || false,
          flowHeader: u._convFlowHeader || u._flowHeader || null,
          flowName: u._convFlowName || u._flowName || null,

        }, getEffectiveMaxAccess(u));

        extraUrls.push({ text: '⚡ WireGuard (原生 YAML)', url: wgUrl });

      }

      // Gost 侧链

      if (u._gostInput) {

        const { url: gostUrl } = await saveToClipAndTrack(u._gostInput, getEffectiveTtl(u), env, uid, {

          preview: 'Gost Tunnel × ' + u._gostCount, nodeCount: u._gostCount, source: 'gost',

          burn: u?._burn || false,

          landing: u?._landing || false,
          flowHeader: u._convFlowHeader || u._flowHeader || null,
          flowName: u._convFlowName || u._flowName || null,

        }, getEffectiveMaxAccess(u));

        extraUrls.push({ text: '🔄 Gost', url: gostUrl });

      }

      const effTtl2 = getEffectiveTtl(u);

      const effAcc = getEffectiveMaxAccess(u);

      const resFlowName = u._convFlowName || u._flowName;

      u._convTtl = null;

      u._convFlowHeader = null;

      u._convFlowName = null;

      env.KV.delete('collect:' + uid).catch(() => {});

      u._convAccessLimit = null;

      const ttlT = formatTtlLabel(effTtl2);

      const accT = effAcc === 0 ? '' : '\n\u{1F4CA} ' + effAcc + ' IP';

      const flowT = resFlowName ? '\n\u{1F310} \u6B64\u94FE\u4FE1\u606F: ' + resFlowName : '';

      let resText = '\u2705 <b>\u8F6C\u6362\u5B8C\u6210</b>\n\n\u{1F4CA} ' + proxiesForConvert.length + ' \u8282\u70B9 \u2192 <b>' + fmtLabel + '</b>\n\n\u{1F517} <code>' + clipUrl + '</code>\n';
      if (opts && opts.aliveText) resText = '\u2705 <b>\u8F6C\u6362\u5B8C\u6210</b>\n\n' + opts.aliveText + '\n\n\u{1F4CA} ' + proxiesForConvert.length + ' \u8282\u70B9 \u2192 <b>' + fmtLabel + '</b>\n\n\u{1F517} <code>' + clipUrl + '</code>\n';

      for (const e of extraUrls) resText += '\n' + e.text + '\n<code>' + e.url + '</code>\n';

      resText += '\n\n\u23F1 ' + ttlT + accT + flowT;

      await tg('editMessageText', env.BOT_TOKEN, {

        chat_id: cid, message_id: mid,

        text: resText, parse_mode: 'HTML',

        reply_markup: multiResultKb(clipUrl, extraUrls),

      }).catch(() => {});

    } catch (e) {

      const preview = String(output).length > 300 ? String(output).slice(0, 300) + '...' : String(output);

      await tg('editMessageText', env.BOT_TOKEN, {

        chat_id: cid, message_id: mid,

        text: '\u274C \u9519\u8BEF: ' + escapeHTML(e.message || e.toString()) + '\n\n<code>' + escapeHTML(preview) + '</code>',

        parse_mode: 'HTML',

        reply_markup: mainKb(),

      });

    }

    return;
}



// ==================== 测活输出（check-host.net TCP connect 批量探测） ====================

function aliveTargets(proxies) {

  const map = {};

  const order = [];

  for (let i = 0; i < proxies.length; i++) {

    const p = proxies[i];

    if (!p || !p.server || !p.port) continue;

    const key = String(p.server) + ':' + Number(p.port);

    if (!map[key]) { map[key] = { key, server: p.server, port: Number(p.port), idxs: [] }; order.push(key); }

    map[key].idxs.push(i);

  }

  return { targets: order.map(k => map[k]) };

}

function aliveBar(done, total) {

  const pct = total === 0 ? 0 : Math.max(0, Math.min(100, Math.round(done * 100 / total)));

  const filled = Math.round(pct / 5);

  return '\u2593'.repeat(filled) + '\u2591'.repeat(20 - filled) + ' ' + done + '/' + total + ' ' + pct + '%';

}

function aliveKb(taskId) {

  return { inline_keyboard: [[{ text: '\u2716 \u53D6\u6D88\u6D4B\u6D3B', callback_data: 'alive_cancel:' + taskId }]] };

}

async function startAliveCheck(env, uid, cid, mid, u, fmt, fmtLabel) {

  const proxies = u._lastProxies || [];

  const { targets } = aliveTargets(proxies);

  if (targets.length === 0) {

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: cid, message_id: mid,

      text: '\u274C \u6CA1\u6709\u53EF\u6D4B\u6D3B\u7684\u8282\u70B9\uFF08\u7F3A\u5C11 server/port\uFF09',

      parse_mode: 'HTML', reply_markup: fmtKb(null, u._convTtl, u.ttl, u),

    });

  }

  // 快照转换上下文（cron 侧重建 u 用）

  const snapshot = {

    _proxies: proxies,

    _clipBase: env._clipBase || null,

    _lastSubInput: u._lastSubInput || null,

    _burn: u?._burn || false,

    _landing: u?._landing || false,

    _convTtl: u._convTtl != null ? u._convTtl : null,

    _convAccessLimit: u._convAccessLimit != null ? u._convAccessLimit : null,

    _flowHeader: u._convFlowHeader || u._flowHeader || null,

    _flowName: u._convFlowName || u._flowName || null,

    _gostInput: u._gostInput || null,

    _gostCount: u._gostCount || 0,

    ttl: u.ttl != null ? u.ttl : 0,

    _accessLimit: u._accessLimit != null ? u._accessLimit : 0,

  };

  const task = {

    taskId: 'a' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),

    uid, cid, mid, fmt, fmtLabel,

    createdAt: Date.now(), updatedAt: Date.now(),

    targets, results: {},

    done: 0, total: targets.length, nodeCount: proxies.length,

    status: 'running', snapshot,

  };

  await env.KV.put('alive:' + task.taskId, JSON.stringify(task), { expirationTtl: 7200 });

  // 指针 key: scheduled 每分钟 get 这个(读额度)即可, 不用 list(独立额度)
  await env.KV.put('alive:running', task.taskId, { expirationTtl: 7200 }).catch(() => {});

  return tg('editMessageText', env.BOT_TOKEN, {

    chat_id: cid, message_id: mid,

    text: '\u{1F52C} <b>\u6D4B\u6D3B\u8F93\u51FA\u5DF2\u5F00\u542F</b>\n\n\u8282\u70B9: ' + proxies.length + ' | \u76EE\u6807: ' + targets.length + '\n\n' + aliveBar(0, targets.length) + '\n\n\u23F3 \u6BCF\u6279\u6700\u591A 30 \u4E2A\u76EE\u6807, \u6BCF\u5206\u949F\u4E00\u6279, \u5B8C\u6210\u540E\u81EA\u52A8\u8F93\u51FA\u77ED\u94FE\uFF08\u4EC5\u5B58\u6D3B\u8282\u70B9\uFF09',

    parse_mode: 'HTML',

    reply_markup: aliveKb(task.taskId),

  });

}

function isCloudflareIp(ip) {

  // Cloudflare 内部 Anycast 网段（Workers SSRF 保护禁止连接, 用户实际可达, 探测时保留不误杀）
  const parts = String(ip).split('.');

  if (parts.length !== 4) return false;

  const a = parseInt(parts[0]), b = parseInt(parts[1]);

  if (a === 1 && (b === 0 || b === 1)) return true;

  if (a === 104 && b >= 16 && b <= 31) return true;

  if (a === 172 && b === 64) return true;

  if (a === 141 && b === 101) return true;

  if (a === 162 && b === 158) return true;

  if (a === 173 && b === 245) return true;

  if (a === 188 && b === 114) return true;

  if (a === 190 && b === 93) return true;

  if (a === 103 && (b === 21 || b === 22 || b === 31)) return true;

  if (a === 198 && b === 41) return true;

  if (a === 199 && b === 27) return true;

  if (a === 197 && b === 234) return true;

  return false;

}

function isHostname(s) {

  // 非纯 IP 即为域名
  return !/^\d+\.\d+\.\d+\.\d+$/.test(String(s || ''));

}

function isPrivateIp(ip) {

  // 私网/回环/保留地址: 任何真实客户端都无法连接（机场节点绝不可能是这些地址）
  const parts = String(ip).split('.');

  if (parts.length !== 4) return false;

  const a = parseInt(parts[0]), b = parseInt(parts[1]);

  if (a === 0) return true;                         // 0.0.0.0/8

  if (a === 10) return true;                        // 10.0.0.0/8

  if (a === 127) return true;                       // 127.0.0.0/8 回环

  if (a === 169 && b === 254) return true;          // 169.254.0.0/16 link-local

  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12

  if (a === 192 && b === 168) return true;          // 192.168.0.0/16

  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT

  if (a >= 224) return true;                        // 组播/保留

  return false;

}

function checkTcpDirect(server, port, timeoutMs) {

  // CF Workers 原生 TCP connect（node:net），真实三次握手，不受外部 API 限流影响
  const tmo = timeoutMs || 4000;

  return new Promise((resolve) => {

    const started = Date.now();

    let settled = false;

    let socket = null;

    const done = (ok, time, blocked) => {

      if (settled) return;

      settled = true;

      try { if (socket) socket.destroy(); } catch {}

      resolve({ ok, time, blocked: !!blocked });

    };

    try {

      socket = new net.Socket();

      socket.setTimeout(tmo);

      socket.once('connect', () => done(true, (Date.now() - started) / 1000, null));

      socket.once('timeout', () => done(false, null, null));

      socket.once('error', (e) => done(false, null, false));

      socket.connect(Number(port), String(server));

    } catch (e) {

      done(false, null, false);

    }

  });

}

async function processAliveBatch(env, task) {

  // retryOnce 的域名目标等待下一批重测
  const pending = task.targets.filter(t => !(task.results[t.key] && !task.results[t.key].retryOnce));

  if (pending.length === 0) return finishAliveCheck(env, task);

  // 每批最多 30 个, 分 5 波 × 6 并发（CF 免费版同时最多 6 个等待响应头的连接, 每波 ≤4s）
  const batch = pending.slice(0, 30);

  for (let w = 0; w < batch.length; w += 6) {

    const wave = batch.slice(w, w + 6);

    // 地址分类: 私网/回环直接判死(任何客户端都连不上); CF 自家 IP 无法从 Workers 探测, 保留不误杀
    const queries = await Promise.all(wave.map(t => {

      if (isPrivateIp(t.server)) return { key: t.key, ok: false, time: null, blocked: false };

      if (isCloudflareIp(t.server)) return { key: t.key, ok: false, time: null, blocked: true };

      return checkTcpDirect(t.server, t.port).then(res => ({ key: t.key, ok: res.ok, time: res.time, blocked: res.blocked })).catch(() => ({ key: t.key, ok: false, time: null, blocked: false }));

    }));

    for (const q of queries) {

      const prev = task.results[q.key];

      if (prev && prev.retryOnce) {

        // 重试结果为准
        task.results[q.key] = { ok: !!q.ok, time: q.time, blocked: !!q.blocked };

      } else if (!q.ok && !q.blocked && isHostname(q.key.split(':')[0])) {

        // 域名探测失败(可能是 DNS/网络偶发), 标记重试一次
        task.results[q.key] = { ok: false, time: null, blocked: false, retryOnce: true };

      } else {

        task.results[q.key] = { ok: !!q.ok, time: q.time, blocked: !!q.blocked };

      }

    }

  }

  task.done = Object.keys(task.results).filter(k => !task.results[k].retryOnce).length;

  task.updatedAt = Date.now();

  await env.KV.put('alive:' + task.taskId, JSON.stringify(task), { expirationTtl: 7200 });

  const bar = aliveBar(task.done, task.total);

  await tg('editMessageText', env.BOT_TOKEN, {

    chat_id: task.cid, message_id: task.mid,

    text: '\u{1F52C} <b>\u6D4B\u6D3B\u8FDB\u884C\u4E2D</b>\n\n\u8282\u70B9: ' + task.nodeCount + ' | \u76EE\u6807: ' + task.total + '\n' + bar + '\n\n\u23F3 \u5DF2\u6D4B ' + task.done + ', \u5269\u4F59 ' + (task.total - task.done) + '...',

    parse_mode: 'HTML', reply_markup: aliveKb(task.taskId),

  }).catch(() => {});

  if (task.done >= task.total) return finishAliveCheck(env, task);

}

async function finishAliveCheck(env, task) {

  const all = task.snapshot._proxies || [];

  const alive = [], dead = [];

  for (const p of all) {

    if (!p || !p.server || !p.port) { alive.push(p); continue; }

    const key = String(p.server) + ':' + Number(p.port);

    const r = task.results[key];

    // blocked = CF 自家 Anycast IP(用户可达但 CF 测不了), 保留; 其余失败(含重试后仍失败)全部剔除
    if (r && (r.ok || r.blocked)) alive.push(p); else dead.push(p);

  }

  task.status = 'done';

  task.updatedAt = Date.now();

  await env.KV.put('alive:' + task.taskId, JSON.stringify(task), { expirationTtl: 7200 });

  // 清指针: scheduled 每分钟 get 到 null 就直接 return, 不再 list
  await env.KV.delete('alive:running').catch(() => {});

  const u = Object.assign({}, task.snapshot);

  delete u._proxies;

  // cron 路径无 fetch 入口, 从任务快照恢复短链域名
  if (task.snapshot._clipBase) env._clipBase = task.snapshot._clipBase;

  const aliveText = '\u{1F52C} \u6D4B\u6D3B: ' + task.nodeCount + ' \u2192 ' + alive.length + ' \u5B58\u6D3B\uFF08' + dead.length + ' \u79BB\u7EBF\uFF09';

  if (alive.length === 0) {

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: task.cid, message_id: task.mid,

      text: '\u274C <b>\u6D4B\u6D3B\u5B8C\u6210</b>\n\n' + aliveText + '\n\n\u6CA1\u6709\u5B58\u6D3B\u8282\u70B9, \u672A\u751F\u6210\u77ED\u94FE',

      parse_mode: 'HTML', reply_markup: mainKb(),

    });

  }

  await tg('editMessageText', env.BOT_TOKEN, {

    chat_id: task.cid, message_id: task.mid,

    text: '\u{1F52C} \u6D4B\u6D3B\u5B8C\u6210: ' + task.nodeCount + ' \u2192 ' + alive.length + ' \u5B58\u6D3B, \u6B63\u5728\u8F6C\u6362...',

    parse_mode: 'HTML',

  }).catch(() => {});

  return convertAndOutput(env, task.uid, task.cid, task.mid, u, task.fmt, alive, { aliveText });

}

async function cb_alive_cancel(env, uid, cid, mid, u, d, q) {

  const taskId = d.split(':')[1];

  await env.KV.delete('alive:' + taskId).catch(() => {});

  await env.KV.delete('alive:running').catch(() => {});

  return tg('editMessageText', env.BOT_TOKEN, {

    chat_id: cid, message_id: mid,

    text: '\u2716 \u5DF2\u53D6\u6D88\u6D4B\u6D3B, \u8BF7\u91CD\u65B0\u9009\u62E9\u8F93\u51FA\u683C\u5F0F:',

    parse_mode: 'HTML', reply_markup: fmtKb(null, u._convTtl, u.ttl, u),

  });

}

// 读指针 key 取当前 running 任务(get 走 read 额度, 避免每分钟 list 烧 list 额度)
// 指针悬空(任务 key 已过期)时清理并 fallback 扫描一次
async function getRunningTaskId(env) {

  const tid = await env.KV.get('alive:running').catch(() => null);

  // 无指针 = 无任务(创建任务必写指针): 直接 return, 绝不 list
  if (!tid) return null;

  const t = await env.KV.get('alive:' + tid, { type: 'json' }).catch(() => null);

  if (t && t.status === 'running') return tid;

  // 指针悬空(任务已过期/已完成): 清指针即可, 任务 key 有 TTL 自动消失, 不 list
  await env.KV.delete('alive:running').catch(() => {});

  return null;

}

// 有 taskId 直取(省 list); 无则 fallback 扫描
async function processAliveQueue(env, taskId) {

  let best = null;

  if (taskId) {

    best = await env.KV.get('alive:' + taskId, { type: 'json' }).catch(() => null);

  } else {

    // 无 taskId 的兼容路径(仅手动调用): 指针缺失才扫一次
    const tid = await env.KV.get('alive:running').catch(() => null);

    best = tid ? await env.KV.get('alive:' + tid, { type: 'json' }).catch(() => null) : null;

  }

  if (!best || best.status !== 'running') return;

  if (Date.now() - best.createdAt > 60 * 60 * 1000) {

    best.status = 'error';

    await env.KV.put('alive:' + best.taskId, JSON.stringify(best), { expirationTtl: 7200 });

    await env.KV.delete('alive:running').catch(() => {});

    return tg('editMessageText', env.BOT_TOKEN, {

      chat_id: best.cid, message_id: best.mid,

      text: '\u274C \u6D4B\u6D3B\u8D85\u65F6\uFF08\u8D85\u8FC7 60 \u5206\u949F\uFF09, \u5DF2\u7EC8\u6B62\u3002\u8BF7\u91CD\u65B0\u53D1\u8D77\u3002',

      parse_mode: 'HTML', reply_markup: mainKb(),

    }).catch(() => {});

  }

  return processAliveBatch(env, best);

}



// ==================== YAML 模板管理 ====================

// --- Repo template helpers ---

function getLandingBase(env) {

  const dir = env.LANDING_DIR;

  if (dir) return 'https://raw.githubusercontent.com/' + dir.replace(/^https?:\/\/[^/]+\//, '');

  return 'https://raw.githubusercontent.com/Linsars/sub-store-bot/main/landing';

}

async function fetchRepoTemplates(env) {

  const base = getLandingBase(env);

  try {

    const resp = await fetch(base + '/templates.json');

    if (!resp.ok) return { templates: [], error: 'HTTP ' + resp.status };

    const list = await resp.json();

    if (!Array.isArray(list)) return { templates: [], error: 'JSON 格式错误' };

    const templates = [];

    for (const item of list) {

      if (!item.file) continue;

      try {

        const tResp = await fetch(base + '/' + encodeURIComponent(item.file));

        if (tResp.ok) {

          const text = await tResp.text();

          templates.push({ name: item.name || item.file.replace(/\.[^.]+$/, ''), text, file: item.file });

        }

      } catch {}

    }

    return { templates, error: null };

  } catch (e) { return { templates: [], error: e.message || '网络异常' }; }

}

async function cb_tmpl_menu(env, uid, cid, mid, u, d, q) {

  const lines = ['\u{1F4DD} <b>模板管理</b>', '', '选择要管理的模板类型：'];

  const kb = { inline_keyboard: [

    [{ text: '\u{1F4DD} YAML 模板', callback_data: 'yaml_menu' }],

    [{ text: '\u{1F310} 流量信息', callback_data: 'flow_menu' }],

    [{ text: '\u2190 返回', callback_data: 'menu' }],

  ] };

  return tg('editMessageText', env.BOT_TOKEN, { chat_id: cid, message_id: mid, text: lines.join('\n'), parse_mode: 'HTML', reply_markup: kb });

}

async function cb_yaml_menu(env, uid, cid, mid, u, d, q) {

  let repoTmpls = [];

  try { repoTmpls = JSON.parse(await env.KV.get('tmpl_repo_cache')) || []; } catch {}

  let templates = [];

  try { templates = JSON.parse(await env.KV.get('tmpls:' + uid)) || []; } catch {}

  let builtinActive = 0;

  try { builtinActive = parseInt(await env.KV.get('tmpl_repo_active:' + uid)) || 0; } catch {}

  const activeIdx = templates.findIndex(t => t.active);

  const lines = ['\u{1F4DD} <b>YAML 模板</b>', ''];

  const rows = [];

  for (let i = 0; i < repoTmpls.length; i++) {

    const t = repoTmpls[i];

    const isActive = activeIdx === -1 && builtinActive === i;

    const icon = isActive ? '\u25CF' : '\u25CB';

    lines.push(icon + ' ' + t.name);

    rows.push([{ text: (isActive ? '\u2705 ' : '') + t.name, callback_data: 'tmpl_select_r:' + i }]);

  }

  // 用户模板

  for (let i = 0; i < templates.length; i++) {

    const t = templates[i];

    const isActive = activeIdx === i;

    const icon = isActive ? '\u25CF' : '\u25CB';

    lines.push(icon + ' ' + t.name);

    rows.push([

      { text: (isActive ? '\u2705 ' : '') + t.name, callback_data: 'tmpl_select_u:' + i },

      { text: '\u2716', callback_data: 'tmpl_del:' + i },

    ]);

  }

  lines.push('', '点击切换模板，\u2716 删除用户模板');

  const kb = { inline_keyboard: [...rows, [{ text: '🔄 同步仓库', callback_data: 'tmpl_sync' }, { text: '+ 添加模板', callback_data: 'tmpl_edit' }], [{ text: '\u2190 返回', callback_data: 'tmpl_menu' }]] };

  return tg('editMessageText', env.BOT_TOKEN, { chat_id: cid, message_id: mid, text: lines.join('\n'), parse_mode: 'HTML', reply_markup: kb });

}

async function cb_tmpl_edit(env, uid, cid, mid, u, d, q) {

  u.state = 'TMPL_EDIT';

  u.promptCid = cid;

  u.promptMid = mid;

  return tg('editMessageText', env.BOT_TOKEN, {

    chat_id: cid, message_id: mid,

    text: '\u270F\uFE0F \u53D1\u9001\u4F60\u7684 Clash YAML \u6A21\u677F\uFF08\u5B8C\u6574 YAML \u6216\u53EA\u8981 proxy-groups/rules \u90E8\u5206\uFF09\n\n\u793A\u4F8B\uFF1A\nproxy-groups:\n  - name: \u81EA\u52A8\u9009\u62E9\n    type: url-test\n    proxies:\n      - \u8282\u70B91\nrules:\n  - MATCH,DIRECT',

    parse_mode: 'HTML',

    reply_markup: { inline_keyboard: [[{ text: '\u2716 \u53D6\u6D88', callback_data: 'tmpl_menu' }]] },

  });

}

async function cb_tmpl_select_r(env, uid, cid, mid, u, d, q) {

  const idx = parseInt(d.split(':')[1]);

  // 清除用户模板 active

  let templates = [];

  try { templates = JSON.parse(await env.KV.get('tmpls:' + uid)) || []; } catch {}

  templates.forEach(t => t.active = false);

  await env.KV.put('tmpls:' + uid, JSON.stringify(templates));

  // 存储仓库模板选择

  await env.KV.put('tmpl_repo_active:' + uid, String(idx));

  return cb_yaml_menu(env, uid, cid, mid, u, d, q);

}

async function cb_tmpl_select_u(env, uid, cid, mid, u, d, q) {

  const idx = parseInt(d.split(':')[1]);

  // 清除内置模板选择

  await env.KV.delete('tmpl_repo_active:' + uid);

  let templates = [];

  try { templates = JSON.parse(await env.KV.get('tmpls:' + uid)) || []; } catch {}

  templates.forEach((t, i) => t.active = (i === idx));

  await env.KV.put('tmpls:' + uid, JSON.stringify(templates));

  return cb_yaml_menu(env, uid, cid, mid, u, d, q);

}

async function cb_tmpl_del(env, uid, cid, mid, u, d, q) {

  const idx = parseInt(d.split(':')[1]);

  let templates = [];

  try { templates = JSON.parse(await env.KV.get('tmpls:' + uid)) || []; } catch {}

  templates.splice(idx, 1);

  await env.KV.put('tmpls:' + uid, JSON.stringify(templates));

  return cb_yaml_menu(env, uid, cid, mid, u, d, q);

}

async function cb_tmpl_sync(env, uid, cid, mid, u, d, q) {

  await tg('answerCallbackQuery', env.BOT_TOKEN, { callback_query_id: mid, text: '🔄 正在同步仓库模板...' });

  const { templates: repoTmpls, error: fetchErr } = await fetchRepoTemplates(env);

  if (repoTmpls.length === 0) {

    const errMsg = fetchErr ? '拉取失败: ' + fetchErr : '未找到模板';

    return tg('editMessageText', env.BOT_TOKEN, { chat_id: cid, message_id: mid, text: '⚠️ ' + errMsg + '\n\n请确认：\n1. 已设置 LANDING_DIR 变量\n2. 仓库 landing/ 目录下有 templates.json', reply_markup: { inline_keyboard: [[{ text: '🔄 同步仓库', callback_data: 'tmpl_sync' }], [{ text: '\u2190 返回', callback_data: 'menu' }]] } });

  }

  await env.KV.put('tmpl_repo_cache', JSON.stringify(repoTmpls));

  await tg('answerCallbackQuery', env.BOT_TOKEN, { callback_query_id: mid, text: '✅ 已同步 ' + repoTmpls.length + ' 个模板' });

  return cb_yaml_menu(env, uid, cid, mid, u, d, q);

}

// Clean YAML template: remove proxies section content

function cleanYamlForTemplate(text) {

  if (!text || !text.includes('proxies:')) return text;

  const ls = text.split('\n');

  let ps = -1, pe = ls.length;

  for (let i = 0; i < ls.length; i++) {

    if (/^proxies:\s*$/.test(ls[i])) { ps = i; continue; }

    if (ps >= 0 && /^\w/.test(ls[i]) && !/^\s/.test(ls[i])) { pe = i; break; }

  }

  if (ps >= 0) ls.splice(ps + 1, pe - ps - 1);

  return ls.join('\n');

}

// ==================== 流量信息模板管理 ====================

async function getFlowTemplates(uid, env) {

  try { return JSON.parse(await env.KV.get('tmpl_flow:' + uid)) || []; } catch { return []; }

}

async function saveFlowTemplates(uid, env, templates) {

  await env.KV.put('tmpl_flow:' + uid, JSON.stringify(templates));

}

async function cb_flow_menu(env, uid, cid, mid, u, d, q) {

  const templates = await getFlowTemplates(uid, env);

  let activeIdx = -1;

  try { activeIdx = await (async () => { const v = parseInt(await env.KV.get('tmpl_flow_active:' + uid)); return isNaN(v) ? -1 : v; })(); } catch {}

  if (activeIdx >= templates.length) activeIdx = -1;

  const lines = ['\u{1F310} <b>流量信息模板</b>', '', '添加自定义流量头信息，导出短链时自动附加。', ''];

  const rows = [];

  // "不使用" 始终是第一个选项

  const noneActive = activeIdx === -1;

  lines.push((noneActive ? '\u25CF' : '\u25CB') + ' 不使用');

  rows.push([{ text: (noneActive ? '\u2705 ' : '') + '不使用', callback_data: 'flow_select:-1' }]);

  for (let i = 0; i < templates.length; i++) {

    const t = templates[i];

    const isActive = activeIdx === i;

    const icon = isActive ? '\u25CF' : '\u25CB';

    lines.push(icon + ' ' + t.name);

    rows.push([

      { text: (isActive ? '\u2705 ' : '') + t.name, callback_data: 'flow_select:' + i },

      { text: '\u2716', callback_data: 'flow_del:' + i },

    ]);

  }

  lines.push('', '格式: upload=X; download=Y; total=Z; expire=T');

  const kb = { inline_keyboard: [...rows, [{ text: '+ 添加模板', callback_data: 'flow_edit' }], [{ text: '\u2190 返回', callback_data: 'tmpl_menu' }]] };

  return tg('editMessageText', env.BOT_TOKEN, { chat_id: cid, message_id: mid, text: lines.join('\n'), parse_mode: 'HTML', reply_markup: kb });

}

async function cb_flow_edit(env, uid, cid, mid, u, d, q) {

  u.state = 'WAITING_FLOW_TEMPLATE';

  return tg('editMessageText', env.BOT_TOKEN, { chat_id: cid, message_id: mid, text: '\u{1F4DD} <b>\u6DFB\u52A0\u6D41\u91CF\u4FE1\u606F\u6A21\u677F</b>\n\n\u683C\u5F0F: <code>\u540D\u79F0|upload\uFF1Bdownload\uFF1Btotal\uFF1Bexpire</code>\n\n\u6D41\u91CF\u5355\u4F4D: \u6570\u5B57\u6216\u5E26 g/m \u540E\u7F00\n\u5230\u671F\u65F6\u95F4: YYYY-MM-DD \u683C\u5F0F\u6216 Unix \u65F6\u95F4\u6233\n\n\u793A\u4F8B:\n<code>100GB\u6708\u4ED8|0\uFF1B0\uFF1B100g\uFF1B2026-12-31</code>\n<code>\u65E0\u9650\u6D41\u91CF|0\uFF1B0\uFF1B0\uFF1B0</code>\n<code>50GB\u534A\u5E74|0\uFF1B10g\uFF1B50g\uFF1B1767196800</code>', parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '\u2190 \u53D6\u6D88', callback_data: 'flow_menu' }]] } });

}

async function cb_flow_select(env, uid, cid, mid, u, d, q) {

  const idx = parseInt(d.split(':')[1]);

  const templates = await getFlowTemplates(uid, env);

  if (idx === -1) {

    // 选择"不使用"

    await env.KV.delete('tmpl_flow_active:' + uid);

    u._flowHeader = null;

    u._flowName = null;

    await saveUserConfig(uid, env, u);

    await tg('answerCallbackQuery', env.BOT_TOKEN, { callback_query_id: mid, text: '✅ 已取消流量信息' });

    return cb_flow_menu(env, uid, cid, mid, u, d, q);

  }

  if (idx < 0 || idx >= templates.length) return cb_flow_menu(env, uid, cid, mid, u, d, q);

  await env.KV.put('tmpl_flow_active:' + uid, String(idx));

  u._flowHeader = templates[idx].header;

  u._flowName = templates[idx].name;

  await saveUserConfig(uid, env, u);

  await tg('answerCallbackQuery', env.BOT_TOKEN, { callback_query_id: mid, text: '✅ 已选择: ' + templates[idx].name });

  return cb_flow_menu(env, uid, cid, mid, u, d, q);

}

async function cb_flow_del(env, uid, cid, mid, u, d, q) {

  const idx = parseInt(d.split(':')[1]);

  const templates = await getFlowTemplates(uid, env);

  if (idx >= 0 && idx < templates.length) {

    templates.splice(idx, 1);

    await saveFlowTemplates(uid, env, templates);

    let activeIdx = -1;

    try { activeIdx = await (async () => { const v = parseInt(await env.KV.get('tmpl_flow_active:' + uid)); return isNaN(v) ? -1 : v; })(); } catch {}

    if (activeIdx === idx) {

      await env.KV.delete('tmpl_flow_active:' + uid);

      u._flowHeader = null;

      u._flowName = null;

      await saveUserConfig(uid, env, u);

    } else if (activeIdx > idx) {

      await env.KV.put('tmpl_flow_active:' + uid, String(activeIdx - 1));

    }

  }

  return cb_flow_menu(env, uid, cid, mid, u, d, q);

}

  // ==================== Worker 入口 ====================

// 自动激活 webhook + 注册命令(webhook 路径统一 /webhookbot)
async function setupWebhook(env, base) {

  const result = { webhook: false, commands: false };

  if (!env.BOT_TOKEN) return result;

  try {

    const wh = base + '/webhookbot';

    const params = { url: wh };

    if (env.WEBHOOK_SECRET) params.secret_token = env.WEBHOOK_SECRET;

    const r1 = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/setWebhook`, {

      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(params),

    });

    result.webhook = (await r1.json()).ok === true;

    const r2 = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/setMyCommands`, {

      method: 'POST', headers: { 'Content-Type': 'application/json' },

      body: JSON.stringify({ commands: [{ command: 'start', description: '启动 / 主页' }] }),

    });

    result.commands = (await r2.json()).ok === true;

  } catch (e) { result.error = e.message; }

  return result;

}

export default {

  // ===== 测活调度：每分钟处理一个测活任务的一批（check-host TCP connect） =====
  async scheduled(event, env, ctx) {

    // 先检查是否有 running 任务: 没有 → 直接 return, 不写 lock(省写额度)
    const lock = await env.KV.get('alive:lock').catch(() => null);

    if (lock) return;

    // get 指针(走 read 额度)替代每分钟 list(独立 list 额度只有 1000/天)
    let taskId = null;

    try {

      taskId = await getRunningTaskId(env);

    } catch {}

    if (!taskId) return;

    await env.KV.put('alive:lock', '1', { expirationTtl: 50 }).catch(() => {});

    try {

      await processAliveQueue(env, taskId);

    } catch { /* 单批失败不影响后续 */ }

    finally {

      await env.KV.delete('alive:lock').catch(() => {});

    }

  },

  async fetch(request, env, ctx) {

    const url = new URL(request.url);

    const path = url.pathname;

    // 短链域名: CLIP_URL 可选覆盖(向后兼容), 默认 worker 自身域名(webhook 回调域名)
    env._clipBase = (env.CLIP_URL || '').replace(/\/+$/, '') || url.origin;

    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };

    if (request.method === 'OPTIONS') return new Response('', { headers: cors });

    // 调试路由（需设置 DEBUG_TOKEN 环境变量）

    if (path === '/debug-fetch') {

      if (!env.DEBUG_TOKEN || url.searchParams.get('token') !== env.DEBUG_TOKEN) return new Response('', { status: 403 });

      const target = url.searchParams.get('url');

      if (!target) return new Response('missing url', { status: 400 });

      const r = await fetch(target, { headers: { 'User-Agent': 'Karing' } });

      const text = await r.text();

      let count = 0;

      try { const parsed = ProxyUtils.parse(text); count = parsed?.length || 0; } catch {}

      return new Response(JSON.stringify({ status: r.status, len: text.length, count }), { headers: { 'Content-Type': 'application/json', ...cors } });

    }

    // API: 文本保存

    if (path === '/save' && request.method === 'POST') {

      try {

        const body = await request.text();

        const id = await saveToClip(body, 86400, env);

        const clipUrl = (env._clipBase || '') + '/share/' + id;

        return new Response(JSON.stringify({ success: true, id, url: clipUrl }), { headers: { 'Content-Type': 'application/json', ...cors } });

      } catch (e) {

        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json', ...cors } });

      }

    }

    // API: 链接状态查询（落地页使用）

    if (path.startsWith('/api/link-status/')) {

      const id = path.replace('/api/link-status/', '');

      const raw = await env.KV.get('share_' + id, { type: 'json' });

      if (!raw) {

        return new Response(JSON.stringify({ alive: false, landingAlive: false }), { headers: { 'Content-Type': 'application/json', ...cors } });

      }

      const consumed = raw.consumed || false;

      const landingConsumed = raw.landingConsumed || false;

      const accessedIPs = Array.isArray(raw.accessedIPs) ? raw.accessedIPs : [];

      const nodeCount = raw.nodeCount || 0;

      return new Response(JSON.stringify({

        alive: !consumed,               // 真链状态

        landingAlive: !landingConsumed,  // 假链（落地页）状态

        consumed,

        landingConsumed,

        nodeCount,

        maxAccess: raw.maxAccess || 0,

        accessCount: accessedIPs.length,

        ttl: raw.ttl || 0,

        createdAt: raw._createdAt || 0,

      }), { headers: { 'Content-Type': 'application/json', ...cors } });

    }

    // API: 短链读取（支持 落地页/阅后即焚/独立IP按次/伪装流量）

    if (path.startsWith('/share/')) {

      const id = path.replace('/share/', '').replace(/\?raw.*$/, '');

      const isRaw = url.searchParams.has('raw');

      const raw = await env.KV.get('share_' + id, { type: 'json' });

      if (!raw) {

        return Response.redirect('https://www.google.com', 302);

      }

      const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

      const burn = raw.burn || false;

      const landing = raw.landing || false;

      const maxIPs = raw.maxAccess || 0;

      const ttl = raw.ttl || 0;

      const consumed = raw.consumed || false;

      const landingConsumed = raw.landingConsumed || false;

      // --- 获取落地页 HTML 辅助函数 ---

      async function getLandingHtml() {

        let html = await env.KV.get('_landing_v1');

        if (!html) {

          const LANDING_HTML_URL = getLandingBase(env) + '/index.html';

          const allowedHosts = ['raw.githubusercontent.com', 'github.com', 'github.githubassets.com'];

          let urlOk = false;

          try { const u = new URL(LANDING_HTML_URL); urlOk = allowedHosts.includes(u.hostname); } catch {}

          if (urlOk) {

            try {

              const ghResp = await fetch(LANDING_HTML_URL);

              if (ghResp.ok) { html = await ghResp.text(); await env.KV.put('_landing_v1', html, { expirationTtl: 86400 }); }

            } catch {}

          }

          if (!html) html = '<html><body><h1>Service Unavailable</h1></body></html>';

        }

        return html;

      }

      // --- 渲染落地页（假链详情）---

      // realStatus: 'alive' | 'consumed' | 'expired'

      // landingStatus: 'alive' | 'consumed' | 'expired'

      async function renderLandingPage(realStatus, landingStatus) {

        let html = await getLandingHtml();

        html = html.replace(/__ID__/g, id)

          .replace(/__STATUS__/g, realStatus)

          .replace(/__LANDING_STATUS__/g, landingStatus);

        return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });

      }

      // --- 真链是否已失效 ---

      const realDead = consumed || !raw.text;

      // ===== ?raw 请求（真链）=====

      if (isRaw) {

        if (realDead) {

          // 真链已失效 → 显示落地页

          if (landing) {

            // 有落地页 → 渲染落地页（假链可能也过期了）

            const lStatus = landingConsumed ? 'consumed' : 'alive';

            return renderLandingPage('consumed', lStatus);

          }

          // 无落地页 → 跳 google

          return Response.redirect('https://www.google.com', 302);

        }

        if (burn) {

          // 阅后即焚：清空 text，标记 consumed，记录访问 IP

          const burnAccessed = Array.isArray(raw.accessedIPs) ? raw.accessedIPs : [];

          const burnNew = !burnAccessed.includes(clientIP);

          const burnData = { ...raw, consumed: true, text: '', accessedIPs: burnNew ? [...burnAccessed, clientIP] : burnAccessed };

          ctx.waitUntil(env.KV.put('share_' + id, JSON.stringify(burnData), ttl > 0 ? { expirationTtl: ttl < 60 ? 60 : ttl } : {}));

        }

        const respHeaders = { 'Content-Type': 'text/plain; charset=utf-8' };

        if (raw.flowHeader) respHeaders['subscription-userinfo'] = raw.flowHeader;

        return new Response(raw.text, { headers: respHeaders });

      }

      // ===== 落地页模式（landing + 非 ?raw）=====

      if (landing) {

        // 检查假链是否已过期（IP 上限或 TTL）

        let myLandingConsumed = landingConsumed;

        if (!myLandingConsumed && maxIPs > 0) {

          const ipResult = await atomicTrackIP(env, id, clientIP, maxIPs, ttl);

          if (ipResult.consumed) {

            myLandingConsumed = true;

            // 落地页消耗 + 阅后即焚 → 同时销毁真链

            const kvData = burn ? { ...raw, landingConsumed: true, consumed: true, text: '' } : { ...raw, landingConsumed: true };

            await env.KV.put('share_' + id, JSON.stringify(kvData), ttl > 0 ? { expirationTtl: ttl < 60 ? 60 : ttl } : {});

          }

        } else if (!myLandingConsumed) {

          await atomicTrackIP(env, id, clientIP, 0, ttl);

        }

        // 真链状态

        const realStatus = realDead ? 'consumed' : 'alive';

        // 假链状态

        const lStatus = myLandingConsumed ? 'consumed' : 'alive';

        // 三振规则：失败的落地页被访问 3 次后彻底删 KV

        if (realDead || myLandingConsumed) {

          const failCount = (raw._failAccess || 0) + 1;

          if (failCount >= 3) {

            ctx.waitUntil(env.KV.delete('share_' + id).catch(() => {}));

            return renderLandingPage(realStatus, lStatus);

          }

          ctx.waitUntil(env.KV.put('share_' + id, JSON.stringify({ ...raw, _failAccess: failCount }), ttl > 0 ? { expirationTtl: ttl < 60 ? 60 : ttl } : {}));

        }

        return renderLandingPage(realStatus, lStatus);

      }

      // ===== 非落地页、非 ?raw → 直接返回内容 =====

      // 阅后即焚（无 landing 时）

      if (burn) {

        if (realDead) {

          return Response.redirect('https://www.google.com', 302);

        }

        ctx.waitUntil(env.KV.put('share_' + id, JSON.stringify({ ...raw, consumed: true, text: '' }), ttl > 0 ? { expirationTtl: ttl < 60 ? 60 : ttl } : {}));

        const respHeaders = { 'Content-Type': 'text/plain; charset=utf-8' };

        if (raw.flowHeader) respHeaders['subscription-userinfo'] = raw.flowHeader;

        return new Response(raw.text, { headers: respHeaders });

      }

      // 独立 IP 上限

      const accessedIPs = Array.isArray(raw.accessedIPs) ? raw.accessedIPs : [];

      if (maxIPs > 0 && accessedIPs.length >= maxIPs) {

        return Response.redirect('https://www.google.com', 302);

      }

      // 新 IP 才加入列表

      const isNewIP = !accessedIPs.includes(clientIP);

      // 只在新 IP 时写入(旧逻辑 maxIPs>0 时每次访问都写, 幂等写烧穿 KV 额度)
      if (isNewIP) {

        const kvOpts = ttl > 0 ? { expirationTtl: ttl < 60 ? 60 : ttl } : {};

        ctx.waitUntil(env.KV.put('share_' + id,

          JSON.stringify({ ...raw, accessedIPs: [...accessedIPs, clientIP] }),

          kvOpts

        ).catch(() => {}));

      }

      const respHeaders = { 'Content-Type': 'text/plain; charset=utf-8' };

      if (raw.flowHeader) respHeaders['subscription-userinfo'] = raw.flowHeader;

      return new Response(raw.text, { headers: respHeaders });

    }

    // Telegram Webhook

    // /webhookbot: 浏览器访问即自动激活(拼接 BOT_TOKEN + setWebhook)
    if (path === '/webhookbot' && request.method === 'GET') {

      const setupResult = await setupWebhook(env, url.origin);

      return new Response(

        JSON.stringify({

          service: 'sub-store-bot',

          version: '3.0',

          bot: typeof env.BOT_TOKEN !== 'undefined',

          clipUrl: env._clipBase || '',

          webhook: setupResult.webhook ? '✅ 已激活' : '❌ 未激活',

          commands: setupResult.commands ? '✅ 已注册' : '⚠️ 未注册',

          setupError: setupResult.error || null,

        }, null, 2),

        { headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors } }

      );

    }

if ((path === '/webhook' || path === '/webhookbot') && request.method === 'POST') {

      const body = await request.json();

      if (!body) return new Response('ok');

      // 验证 X-Telegram-Bot-Api-Secret-Token

      if (env.WEBHOOK_SECRET && request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.WEBHOOK_SECRET) {

        return new Response('unauthorized', { status: 401 });

      }

      ctx.waitUntil(

        (async () => {

          try {

            if (body.message) {

              const uid = String(body.message.from?.id || '');

              if (applyRateLimit(uid, env.ALLOWED_USERS)) {

                await tg('sendMessage', env.BOT_TOKEN, {

                  chat_id: String(body.message.chat?.id || uid),

                  text: '\u26A0\uFE0F \u8BF7\u52FF\u9891\u7E41\u8BF7\u6C42\uFF0C\u6BCF 30 \u79D2\u6700\u591A 5 \u6B21',

                });

                return;

              }

              // 加载持久化配置到 stateMap

              const cfg = await loadUserConfig(uid, env);

              if (Object.keys(cfg).length > 0) {

                const s = getState(uid);

                Object.assign(s, cfg);

              }

              await onMsg(body.message, env);

            } else if (body.callback_query) {

              const uid = String(body.callback_query.from?.id || '');

              if (applyRateLimit(uid, env.ALLOWED_USERS)) {

                await tg('answerCallbackQuery', env.BOT_TOKEN, {

                  callback_query_id: body.callback_query.id,

                  text: '\u26A0\uFE0F \u8BF7\u52FF\u9891\u7E41\u64CD\u4F5C',

                });

                return;

              }

              // 加载持久化配置到 stateMap

              const cfg = await loadUserConfig(uid, env);

              if (Object.keys(cfg).length > 0) {

                const s = getState(uid);

                Object.assign(s, cfg);

              }

              await onCb(body.callback_query, env);

            }

          } catch (e) {

            await tg('sendMessage', env.BOT_TOKEN, {

              chat_id: String(body.message?.from?.id || body.callback_query?.from?.id || ''),

              text: '\u274C \u62A5\u9519: ' + e.message,

            });

          }

        })()

      );

      return new Response('ok');

    }

    // API: 订阅转换 (给外部调)

    if (path === '/api/convert' && request.method === 'POST') {

      try {

        const body = await request.json();

        const input = body.input;

        const target = body.target || 'clashmeta';

        if (!input) {

          return new Response(JSON.stringify({ error: 'input required' }), {

            status: 400,

            headers: { 'Content-Type': 'application/json', ...cors },

          });

        }

        let proxies;

        try {

          proxies = ProxyUtils.parse(input);

        } catch (e) {

          proxies = null;

        }

        if (!proxies || proxies.length === 0) {

          return new Response(

            JSON.stringify({ success: false, count: 0, output: '' }),

            { headers: { 'Content-Type': 'application/json', ...cors } }

          );

        }

        const output = ProxyUtils.produce(proxies, target);

        return new Response(

          JSON.stringify({ success: true, count: proxies.length, output: String(output), target }),

          { headers: { 'Content-Type': 'application/json', ...cors } }

        );

      } catch (e) {

        return new Response(JSON.stringify({ error: e.message }), {

          status: 400,

          headers: { 'Content-Type': 'application/json', ...cors },

        });

      }

    }

    // 根路由：设了 CLIP_URL → 跳 google 防泄露

    // 不设 CLIP_URL → 自动激活 webhook + 显示状态（参考 glados-discourse-bot）

    if (url.pathname === '/') {

      // 根路由无条件跳 google 防泄露; 激活只走 /webhookbot
      return Response.redirect('https://www.google.com', 302);

    }

    // /setup: 自动激活 webhook + 注册命令（给部署者用）

    if (url.pathname === '/setup') {

      const setupResult = await setupWebhook(env, url.origin);

      return new Response(

        JSON.stringify({

          service: 'sub-store-bot',

          version: '3.0',

          bot: typeof env.BOT_TOKEN !== 'undefined',

          clipUrl: env._clipBase || '',

          engine: 'Sub-Store',

          formats: FORMAT_OPTIONS.map(f => f.id),

          webhook: setupResult.webhook ? '✅ 已激活' : '❌ 未激活',

          commands: setupResult.commands ? '✅ 已注册' : '⚠️ 未注册',

          setupError: setupResult.error || null,

        }),

        { headers: { 'Content-Type': 'application/json', ...cors } }

      );

    }

    // Health (fallback)

    return new Response(

      JSON.stringify({

        service: 'sub-store-bot',

        version: '3.0',

        bot: typeof env.BOT_TOKEN !== 'undefined',

        clipUrl: env._clipBase || '',

        engine: 'Sub-Store',

        formats: FORMAT_OPTIONS.map(f => f.id),

      }),

      { headers: { 'Content-Type': 'application/json', ...cors } }

    );

  },

};

// Simple Clash YAML proxies extractor
