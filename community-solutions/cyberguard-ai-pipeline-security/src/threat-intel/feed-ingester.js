'use strict';

/**
 * feed-ingester.js — curl-impersonate threat-intel feed ingestor
 *
 * Fetches from two sources using Chrome-fingerprint impersonation to avoid
 * bot-detection without a paid scraping proxy:
 *   • AbuseIPDB bulk blacklist    (requires ABUSEIPDB key; stored via store.js)
 *   • Emerging Threats compromised-ips.txt  (keyless, plaintext)
 *
 * Results are merged into the existing blocklist store via blocklist.inject()
 * and persisted to supplemental cache files so they survive restarts.
 *
 * curl-impersonate: https://github.com/lwthiker/curl-impersonate
 *
 * Standalone usage:
 *   node src/threat-intel/feed-ingester.js [--source abuseipdb|emerging-threats]
 *                                          [--cache-dir /path/to/dir]
 *   Set ABUSEIPDB_KEY env var for AbuseIPDB when running outside Electron.
 */

const { execFile, execSync } = require('child_process');
const fs   = require('fs');
const os   = require('os');
const path = require('path');

// ── curl-impersonate binary detection ─────────────────────────────────────────

const CURL_CANDIDATES = ['curl-impersonate-chrome', 'curl_chrome110'];
const CURL_EXTRA_PATHS = [
  '/usr/local/bin/curl-impersonate-chrome',
  '/opt/homebrew/bin/curl-impersonate-chrome',
  '/usr/bin/curl-impersonate-chrome',
  '/usr/local/bin/curl_chrome110',
  '/opt/homebrew/bin/curl_chrome110',
];

let curlBin = null;

function findCurlImpersonate() {
  for (const name of CURL_CANDIDATES) {
    try {
      const p = execSync(`which ${name} 2>/dev/null`, { timeout: 3000 }).toString().trim();
      if (p) return p;
    } catch { /* try next */ }
  }
  for (const p of CURL_EXTRA_PATHS) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function checkBinary() {
  curlBin = findCurlImpersonate();
  if (!curlBin) {
    console.warn(
      '[feed-ingester] curl-impersonate binary not found — feed ingestion disabled.\n' +
      '  Install from: https://github.com/lwthiker/curl-impersonate'
    );
  } else {
    console.log(`[feed-ingester] Using ${curlBin}`);
  }
  return curlBin !== null;
}

// ── curl-impersonate fetch ────────────────────────────────────────────────────

function curlFetch(url, headers = {}, timeoutSec = 30) {
  return new Promise((resolve, reject) => {
    if (!curlBin) return reject(new Error('curl-impersonate not available'));
    const args = [
      '--silent',
      '--compressed',        // accept gzip
      '--max-time', String(timeoutSec),
      '--location',          // follow redirects
    ];
    for (const [k, v] of Object.entries(headers)) args.push('-H', `${k}: ${v}`);
    args.push(url);

    execFile(
      curlBin, args,
      { maxBuffer: 20 * 1024 * 1024, timeout: (timeoutSec + 5) * 1000 },
      (err, stdout) => { if (err) return reject(err); resolve(stdout); }
    );
  });
}

// ── AbuseIPDB bulk blacklist ──────────────────────────────────────────────────
// Endpoint returns plaintext (one IP per line) when ?plaintext is appended.
// Requires a paid/subscribed API key; free keys get HTTP 422.

const ABUSEIPDB_URL =
  'https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&plaintext';

async function fetchAbuseIPDB(apiKey) {
  if (!apiKey) {
    console.warn('[feed-ingester] AbuseIPDB: no API key configured — skipping');
    return null;
  }
  console.log('[feed-ingester] Fetching AbuseIPDB blacklist…');
  const text = await curlFetch(ABUSEIPDB_URL, { Key: apiKey, Accept: 'text/plain' });

  // Detect JSON error responses (e.g. subscription required → 422)
  if (text.trimStart().startsWith('{')) {
    try {
      const body = JSON.parse(text);
      const detail = body.errors?.[0]?.detail || body.message || JSON.stringify(body);
      console.warn('[feed-ingester] AbuseIPDB error:', detail);
      return null;
    } catch { /* not valid JSON after all — fall through */ }
  }

  const lines = text.trim().split('\n').filter(l => l && !l.startsWith('#'));
  console.log(`[feed-ingester] AbuseIPDB: ${lines.length} IPs received`);
  return text;
}

// ── Emerging Threats compromised IPs ─────────────────────────────────────────

const EMERGING_THREATS_URL =
  'https://rules.emergingthreats.net/blockrules/compromised-ips.txt';

async function fetchEmergingThreats() {
  console.log('[feed-ingester] Fetching Emerging Threats compromised IPs…');
  const text = await curlFetch(EMERGING_THREATS_URL);
  const lines = text.trim().split('\n').filter(l => l && !l.startsWith('#'));
  console.log(`[feed-ingester] Emerging Threats: ${lines.length} IPs received`);
  return text;
}

// ── Supplemental cache (survives restarts) ────────────────────────────────────

let cacheDir = null;

function supplementalPath(feedName) {
  return path.join(cacheDir, `blocklist-${feedName}-ingested.txt`);
}

function saveSupplemental(feedName, text) {
  try {
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(supplementalPath(feedName), text);
  } catch (e) {
    console.warn(`[feed-ingester] cache write failed (${feedName}):`, e.message);
  }
}

function loadSupplemental(feedName) {
  try {
    const p = supplementalPath(feedName);
    if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8');
  } catch { /* ignore */ }
  return null;
}

// ── Core ingest routine ───────────────────────────────────────────────────────

// Maps feed name → which blocklist list it populates
const FEED_LIST_MAP = { 'abuseipdb': 'inbound', 'emerging-threats': 'outbound' };

async function ingest(blocklist, apiKey, sources) {
  const feeds = sources || ['abuseipdb', 'emerging-threats'];

  if (feeds.includes('abuseipdb')) {
    try {
      const text = await fetchAbuseIPDB(apiKey);
      if (text) {
        blocklist.inject('inbound', text);
        saveSupplemental('abuseipdb', text);
      }
    } catch (e) {
      console.warn('[feed-ingester] AbuseIPDB fetch error:', e.message);
    }
  }

  if (feeds.includes('emerging-threats')) {
    try {
      const text = await fetchEmergingThreats();
      blocklist.inject('outbound', text);
      saveSupplemental('emerging-threats', text);
    } catch (e) {
      console.warn('[feed-ingester] Emerging Threats fetch error:', e.message);
    }
  }
}

// ── Module API (used by main.js) ──────────────────────────────────────────────

let _blocklist = null;
let _apiKeyFn  = null;
let _interval  = null;

/**
 * Initialise the ingester. Call once from app.whenReady() after blocklist.init().
 * @param {string} dir       writable directory — app.getPath('userData')
 * @param {object} store     credential store instance (store.get('abuseipdb'))
 * @param {object} blocklist blocklist module (must export inject())
 */
function init(dir, store, blocklist) {
  cacheDir   = dir;
  _blocklist = blocklist;
  _apiKeyFn  = () => store.get('abuseipdb');

  checkBinary();

  // Load persisted supplemental data immediately so lookups work even offline
  for (const [feedName, listName] of Object.entries(FEED_LIST_MAP)) {
    const cached = loadSupplemental(feedName);
    if (cached) {
      blocklist.inject(listName, cached);
      console.log(`[feed-ingester] Loaded cached ${feedName} data`);
    }
  }

  if (!curlBin) return; // binary missing — warn was already printed

  // Fresh fetch on startup (non-blocking)
  ingest(_blocklist, _apiKeyFn(), null).catch(() => {});

  // Daily refresh — reuses the same setInterval pattern as the rest of main.js
  _interval = setInterval(
    () => ingest(_blocklist, _apiKeyFn(), null).catch(() => {}),
    24 * 60 * 60 * 1000
  );
  _interval.unref?.();
}

module.exports = { init, ingest, checkBinary };

// ── Standalone CLI ────────────────────────────────────────────────────────────

if (require.main === module) {
  const args    = process.argv.slice(2);
  const srcIdx  = args.indexOf('--source');
  const dirIdx  = args.indexOf('--cache-dir');
  const sources = srcIdx !== -1 ? [args[srcIdx + 1]] : null;
  cacheDir      = dirIdx !== -1 ? args[dirIdx + 1]
                : (process.env.CACHE_DIR || path.join(os.homedir(), '.cyberguard-cache'));

  if (!checkBinary()) {
    console.error('[feed-ingester] Cannot run without curl-impersonate.');
    process.exit(1);
  }

  // Use the real blocklist module so inject() parsing is fully exercised
  const blocklist = require('../blocklist');
  blocklist.init(cacheDir);

  const apiKey = process.env.ABUSEIPDB_KEY || null;

  ingest(blocklist, apiKey, sources)
    .then(() => {
      const s = blocklist.stats();
      console.log('[feed-ingester] Blocklist stats after ingest:');
      for (const [k, v] of Object.entries(s)) {
        console.log(`  ${k}: ${v.ips} IPs, ${v.cidrs} CIDRs`);
      }
      console.log('[feed-ingester] Done.');
    })
    .catch(e => {
      console.error('[feed-ingester] Fatal:', e.message);
      process.exit(1);
    });
}
