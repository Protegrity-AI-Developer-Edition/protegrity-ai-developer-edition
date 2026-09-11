/**
 * blocklist.js — Local IP blocklist (bitwire-it/ipblocklist)
 *
 * Downloads aggregated blocklists (updated upstream every 2 h):
 *   • inbound.txt  — IPs known for scanning, brute-force, exploits (attack sources)
 *   • outbound.txt — C2 servers, botnet controllers, malware drop sites (bad destinations)
 *
 * No API key required. Lists are cached to disk so lookups work offline.
 * Source: https://github.com/bitwire-it/ipblocklist (data: CC BY-NC-SA 4.0)
 */

'use strict';

const https = require('https');
const fs    = require('fs');
const path  = require('path');

const LISTS = {
  inbound:  'https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt',
  outbound: 'https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt',
};

const REFRESH_MS = 2 * 60 * 60 * 1000; // upstream updates every 2 h

let cacheDir = null;
// Per list: exact IPs in a Set, CIDR ranges as [start, end] uint32 pairs
const db = {
  inbound:  { exact: new Set(), cidrs: [], updated: 0 },
  outbound: { exact: new Set(), cidrs: [], updated: 0 },
};

// ── IPv4 helpers ──────────────────────────────────────────────────────────────

function ipToInt(ip) {
  const p = ip.split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const o of p) {
    const v = +o;
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n * 256) + v;
  }
  return n;
}

// ── Parsing ───────────────────────────────────────────────────────────────────

function parseList(text, entry) {
  const exact = new Set();
  const cidrs = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.includes('/')) {
      const [ip, bitsStr] = line.split('/');
      const base = ipToInt(ip);
      const bits = +bitsStr;
      if (base === null || !(bits >= 0 && bits <= 32)) continue;
      const size = 2 ** (32 - bits);
      const start = Math.floor(base / size) * size;
      cidrs.push([start, start + size - 1]);
    } else {
      if (ipToInt(line) !== null) exact.add(line);
    }
  }
  cidrs.sort((a, b) => a[0] - b[0]);
  entry.exact = exact;
  entry.cidrs = cidrs;
  entry.updated = Date.now();
}

// ── Download & cache ──────────────────────────────────────────────────────────

function download(url, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'CyberGuard/1.0' } }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return download(res.headers.location, timeoutMs).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => resolve(data));
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

function cachePath(name) {
  return path.join(cacheDir, `blocklist-${name}.txt`);
}

/** Load lists from disk cache (instant, offline-safe). */
function loadFromCache() {
  for (const name of Object.keys(LISTS)) {
    try {
      const file = cachePath(name);
      if (fs.existsSync(file)) {
        parseList(fs.readFileSync(file, 'utf8'), db[name]);
        db[name].updated = fs.statSync(file).mtimeMs;
      }
    } catch (e) {
      console.warn(`[blocklist] cache load ${name}:`, e.message);
    }
  }
}

/** Download fresh copies of both lists and update cache. */
async function refresh() {
  for (const [name, url] of Object.entries(LISTS)) {
    try {
      const text = await download(url);
      parseList(text, db[name]);
      fs.writeFileSync(cachePath(name), text);
      console.log(`[blocklist] ${name}: ${db[name].exact.size} IPs + ${db[name].cidrs.length} CIDRs`);
    } catch (e) {
      console.warn(`[blocklist] refresh ${name}:`, e.message);
    }
  }
}

/**
 * Initialise: load disk cache immediately, then refresh in background
 * and every 2 h thereafter.
 * @param {string} dir  writable directory (app.getPath('userData'))
 */
function init(dir) {
  cacheDir = dir;
  loadFromCache();
  refresh();
  setInterval(refresh, REFRESH_MS).unref?.();
}

// ── Lookup ────────────────────────────────────────────────────────────────────

function inList(name, ip, ipInt) {
  const { exact, cidrs } = db[name];
  if (exact.has(ip)) return true;
  // binary search sorted, non-overlapping-ish ranges
  let lo = 0, hi = cidrs.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [start, end] = cidrs[mid];
    if (ipInt < start) hi = mid - 1;
    else if (ipInt > end) lo = mid + 1;
    else return true;
  }
  return false;
}

/**
 * Check an IPv4 address against the blocklists.
 * @param {string} ip
 * @returns {{ listed: boolean, lists: string[] }}
 */
function check(ip) {
  const ipInt = ipToInt(ip);
  if (ipInt === null) return { listed: false, lists: [] };
  const lists = [];
  if (inList('outbound', ip, ipInt)) lists.push('outbound');
  if (inList('inbound', ip, ipInt)) lists.push('inbound');
  return { listed: lists.length > 0, lists };
}

function stats() {
  return Object.fromEntries(Object.entries(db).map(([k, v]) => [
    k, { ips: v.exact.size, cidrs: v.cidrs.length, updated: v.updated },
  ]));
}

/**
 * Merge external IP/CIDR text into a named list without replacing it.
 * Called by feed-ingester after fetching AbuseIPDB / Emerging Threats.
 * @param {string} listName  'inbound' or 'outbound'
 * @param {string} text      newline-separated IPs/CIDRs (comments with # ignored)
 */
function inject(listName, text) {
  if (!db[listName]) db[listName] = { exact: new Set(), cidrs: [], updated: 0 };
  const tmp = { exact: new Set(), cidrs: [], updated: 0 };
  parseList(text, tmp);
  for (const ip of tmp.exact) db[listName].exact.add(ip);
  for (const c of tmp.cidrs) db[listName].cidrs.push(c);
  db[listName].cidrs.sort((a, b) => a[0] - b[0]);
  db[listName].updated = Date.now();
}

module.exports = { init, refresh, check, stats, inject };
