/**
 * Real threat-intelligence feeds.
 *
 * Sources:
 *   • CISA Alerts   — https://www.cisa.gov/uscert/ncas/alerts.xml  (US-CERT, free, no key)
 *   • CyberNews     — https://cybernews.com/feed/                   (RSS, free, no key)
 *   • NVD CVEs      — https://services.nvd.nist.gov/rest/json/cves/2.0 (free, no key)
 *
 * All fetching happens in the main process so there are no CORS restrictions.
 */

const https = require('https');
const http  = require('http');

// ── HTTP helper ───────────────────────────────────────────────────────────────

function get(url, timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { headers: { 'User-Agent': 'CyberGuard/1.0' } }, res => {
      // follow one redirect
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return get(res.headers.location, timeoutMs).then(resolve).catch(reject);
      }
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => resolve(data));
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

// ── RSS parser (no dependencies) ─────────────────────────────────────────────

function tag(xml, t) {
  const cdata = xml.match(new RegExp(`<${t}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${t}>`, 'i'));
  if (cdata) return cdata[1].trim();
  const plain = xml.match(new RegExp(`<${t}[^>]*>([\\s\\S]*?)<\\/${t}>`, 'i'));
  return plain ? plain[1].replace(/<[^>]+>/g, '').trim() : '';
}

function parseRSS(xml) {
  return (xml.match(/<item[^>]*>[\s\S]*?<\/item>/gi) || [])
    .slice(0, 20)
    .map(block => ({
      title:   tag(block, 'title'),
      link:    tag(block, 'link') || tag(block, 'guid'),
      date:    tag(block, 'pubDate') || tag(block, 'dc:date') || new Date().toUTCString(),
      summary: tag(block, 'description').slice(0, 240),
    }))
    .filter(i => i.title);
}

// ── Individual feed fetchers ──────────────────────────────────────────────────

async function fetchCISA() {
  try {
    const xml = await get('https://www.cisa.gov/uscert/ncas/alerts.xml');
    return parseRSS(xml).map(i => ({
      id:       i.link || i.title,
      source:   'CISA',
      severity: 'High',
      title:    i.title,
      summary:  i.summary,
      link:     i.link,
      date:     safeDate(i.date),
    }));
  } catch (e) {
    console.warn('[feeds] CISA:', e.message);
    return [];
  }
}

async function fetchCyberNews() {
  try {
    const xml = await get('https://cybernews.com/feed/');
    return parseRSS(xml).map(i => ({
      id:       i.link || i.title,
      source:   'CyberNews',
      severity: guessSeverity(i.title + ' ' + i.summary),
      title:    i.title,
      summary:  i.summary,
      link:     i.link,
      date:     safeDate(i.date),
    }));
  } catch (e) {
    console.warn('[feeds] CyberNews:', e.message);
    return [];
  }
}

async function fetchNVD() {
  try {
    const raw = await get(
      'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15&cvssV3Severity=CRITICAL'
    );
    const json = JSON.parse(raw);
    return (json.vulnerabilities || []).map(v => {
      const cve  = v.cve;
      const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore
                 || cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore
                 || 0;
      return {
        id:       cve.id,
        source:   'NVD',
        severity: score >= 9 ? 'Critical' : score >= 7 ? 'High' : 'Medium',
        title:    `${cve.id} — ${desc.slice(0, 120)}${desc.length > 120 ? '…' : ''}`,
        summary:  desc.slice(0, 300),
        link:     `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        score,
        date:     safeDate(cve.published),
      };
    });
  } catch (e) {
    console.warn('[feeds] NVD:', e.message);
    return [];
  }
}

// ── All feeds combined ────────────────────────────────────────────────────────

async function fetchAll() {
  const [cisa, cn, nvd] = await Promise.allSettled([
    fetchCISA(),
    fetchCyberNews(),
    fetchNVD(),
  ]);

  const items = [
    ...(cisa.status === 'fulfilled' ? cisa.value : []),
    ...(cn.status   === 'fulfilled' ? cn.value   : []),
    ...(nvd.status  === 'fulfilled' ? nvd.value  : []),
  ];

  // Sort newest first
  items.sort((a, b) => new Date(b.date) - new Date(a.date));
  return items;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function safeDate(raw) {
  try {
    const d = new Date(raw);
    return isNaN(d) ? new Date().toISOString() : d.toISOString();
  } catch { return new Date().toISOString(); }
}

const CRITICAL_WORDS = /ransomware|zero.?day|critical|exploit|breach|attack|hack|malware|backdoor|worm|trojan/i;
const HIGH_WORDS     = /vulnerability|cve|patch|update|warning|alert|risk/i;

function guessSeverity(text) {
  if (CRITICAL_WORDS.test(text)) return 'Critical';
  if (HIGH_WORDS.test(text))     return 'High';
  return 'Medium';
}

module.exports = { fetchAll, fetchCISA, fetchCyberNews, fetchNVD };
