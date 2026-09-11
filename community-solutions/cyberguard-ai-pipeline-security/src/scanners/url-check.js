/**
 * url-check.js — Real URL / domain reputation checker
 *
 * Checks a URL or domain against:
 *   1. VirusTotal URL analysis (API key required)
 *   2. Google Safe Browsing (API key required — free)
 *   3. URLhaus (abuse.ch) — FREE, no key, updated hourly
 *
 * All requests run in the Electron main process (no CORS).
 */

'use strict';

const https = require('https');
const http  = require('http');

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function request(options, body = null) {
  return new Promise((resolve, reject) => {
    const mod = (options.hostname || '').startsWith('http:') ? http : https;
    const req = (mod).request(options, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, json: JSON.parse(data), raw: data }); }
        catch { resolve({ status: res.statusCode, json: null, raw: data }); }
      });
    });
    req.setTimeout(12000, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ── VirusTotal URL check ──────────────────────────────────────────────────────

async function checkVirusTotalURL(url, apiKey) {
  if (!apiKey) return null;
  try {
    // Submit URL for analysis
    const encoded = Buffer.from(url).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const res = await request({
      hostname: 'www.virustotal.com',
      path:     `/api/v3/urls/${encoded}`,
      method:   'GET',
      headers:  { 'x-apikey': apiKey },
    });

    if (res.status === 404) {
      // URL not previously scanned — submit it
      const submitRes = await request({
        hostname: 'www.virustotal.com',
        path:     '/api/v3/urls',
        method:   'POST',
        headers:  { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
      }, `url=${encodeURIComponent(url)}`);

      if (submitRes.status !== 200) return null;
      return {
        source:  'VirusTotal',
        verdict: 'pending',
        summary: 'URL submitted to VirusTotal for analysis. Check again in 1–2 minutes.',
      };
    }

    if (res.status !== 200 || !res.json?.data) return null;

    const attrs   = res.json.data.attributes || {};
    const stats   = attrs.last_analysis_stats || {};
    const malicious  = stats.malicious  || 0;
    const suspicious = stats.suspicious || 0;
    const total   = Object.values(stats).reduce((a, b) => a + b, 0);

    return {
      source:      'VirusTotal',
      url,
      malicious,
      suspicious,
      harmless:    stats.harmless || 0,
      total,
      finalUrl:    attrs.last_final_url || url,
      title:       attrs.title,
      verdict:     malicious >= 3  ? 'malicious'
                 : malicious >= 1 || suspicious >= 3 ? 'suspicious'
                 : 'clean',
    };
  } catch { return null; }
}

// ── Google Safe Browsing ──────────────────────────────────────────────────────

async function checkSafeBrowsing(url, apiKey) {
  if (!apiKey) return null;
  try {
    const body = JSON.stringify({
      client:    { clientId: 'cyberguard', clientVersion: '2.0' },
      threatInfo: {
        threatTypes:      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes:    ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries:    [{ url }],
      },
    });

    const res = await request({
      hostname: 'safebrowsing.googleapis.com',
      path:     `/v4/threatMatches:find?key=${apiKey}`,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, body);

    if (res.status !== 200) return null;

    const matches = res.json?.matches || [];
    const verdict = matches.length > 0 ? 'malicious' : 'clean';
    const threatTypes = matches.map(m => m.threatType);

    return {
      source:     'Google Safe Browsing',
      url,
      verdict,
      threats:    threatTypes,
      summary:    matches.length > 0
        ? `UNSAFE — Google flags this URL as: ${threatTypes.join(', ')}`
        : 'Clean according to Google Safe Browsing.',
    };
  } catch { return null; }
}

// ── URLhaus (free, no key) ────────────────────────────────────────────────────

async function checkURLhaus(url) {
  try {
    const body = `url=${encodeURIComponent(url)}`;
    const res = await request({
      hostname: 'urlhaus-api.abuse.ch',
      path:     '/v1/url/',
      method:   'POST',
      headers:  {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    }, body);

    if (res.status !== 200 || !res.json) return null;
    const d = res.json;
    if (d.query_status === 'no_results') {
      return { source: 'URLhaus', url, verdict: 'clean', summary: 'Not found in URLhaus database.' };
    }

    return {
      source:      'URLhaus',
      url,
      verdict:     d.url_status === 'online' ? 'malicious' : 'suspicious',
      threat:      d.threat,
      tags:        d.tags || [],
      dateAdded:   d.date_added,
      urlStatus:   d.url_status,
      summary:     `URLhaus: ${d.threat || 'malware'} — status: ${d.url_status}`,
    };
  } catch { return null; }
}

// ── Combined check ────────────────────────────────────────────────────────────

/**
 * @param {string} url
 * @param {{ virustotal?: string, safebrowsing?: string }} keys
 * @returns {Promise<{ url, verdict, results, summary }>}
 */
async function checkURL(url, keys = {}) {
  // Normalise — add https:// if missing
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  const [vt, gsb, urlhaus] = await Promise.all([
    checkVirusTotalURL(url, keys.virustotal),
    checkSafeBrowsing(url, keys.safebrowsing),
    checkURLhaus(url),
  ]);

  const results = [vt, gsb, urlhaus].filter(Boolean);
  const verdicts = results.map(r => r.verdict);
  const verdict  = verdicts.includes('malicious')  ? 'malicious'
                 : verdicts.includes('suspicious') ? 'suspicious'
                 : results.length > 0              ? 'clean'
                 : 'unknown';

  let summary = '';
  if (!results.length) {
    summary = 'No reputation data available. Configure API keys in Settings.';
  } else if (verdict === 'malicious') {
    summary = `MALICIOUS URL detected by ${results.filter(r => r.verdict === 'malicious').map(r => r.source).join(' & ')}.`;
  } else if (verdict === 'suspicious') {
    summary = 'URL has suspicious indicators. Proceed with caution.';
  } else {
    summary = `URL appears clean across ${results.length} source(s).`;
  }

  return { url, verdict, results, summary };
}

module.exports = { checkURL };
