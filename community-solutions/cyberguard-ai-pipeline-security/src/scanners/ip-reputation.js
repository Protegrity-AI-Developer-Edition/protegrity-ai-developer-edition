/**
 * ip-reputation.js — Real IP reputation lookup
 *
 * Checks an IP address against:
 *   1. AbuseIPDB  (requires API key — free tier: 1 000 checks/day)
 *   2. VirusTotal (requires API key — free tier: 4 lookups/min)
 *
 * Both requests run in the Electron main process to avoid CORS.
 * Falls back gracefully when keys are not configured.
 */

'use strict';

const https = require('https');

// ── HTTP helper ───────────────────────────────────────────────────────────────

function request(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, json: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, json: null, raw: data }); }
      });
    });
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────

async function checkAbuseIPDB(ip, apiKey) {
  if (!apiKey) return null;
  try {
    const res = await request({
      hostname: 'api.abuseipdb.com',
      path:     `/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
      method:   'GET',
      headers:  { 'Key': apiKey, 'Accept': 'application/json' },
    });
    if (res.status !== 200 || !res.json?.data) return null;
    const d = res.json.data;
    return {
      source:           'AbuseIPDB',
      ip,
      abuseScore:       d.abuseConfidenceScore,    // 0–100
      totalReports:     d.totalReports,
      lastReported:     d.lastReportedAt,
      countryCode:      d.countryCode,
      isp:              d.isp,
      usageType:        d.usageType,
      isTor:            d.isTor,
      isPublic:         d.isPublic,
      verdict:          d.abuseConfidenceScore >= 50 ? 'malicious'
                      : d.abuseConfidenceScore >= 10 ? 'suspicious'
                      : 'clean',
    };
  } catch { return null; }
}

// ── VirusTotal ────────────────────────────────────────────────────────────────

async function checkVirusTotalIP(ip, apiKey) {
  if (!apiKey) return null;
  try {
    const res = await request({
      hostname: 'www.virustotal.com',
      path:     `/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
      method:   'GET',
      headers:  { 'x-apikey': apiKey },
    });
    if (res.status !== 200 || !res.json?.data) return null;
    const stats = res.json.data.attributes?.last_analysis_stats || {};
    const malicious  = stats.malicious  || 0;
    const suspicious = stats.suspicious || 0;
    const total      = Object.values(stats).reduce((a, b) => a + b, 0);
    return {
      source:      'VirusTotal',
      ip,
      malicious,
      suspicious,
      harmless:    stats.harmless || 0,
      total,
      country:     res.json.data.attributes?.country,
      asOwner:     res.json.data.attributes?.as_owner,
      verdict:     malicious >= 3  ? 'malicious'
                 : malicious >= 1 || suspicious >= 3 ? 'suspicious'
                 : 'clean',
    };
  } catch { return null; }
}

// ── Combined lookup ───────────────────────────────────────────────────────────

/**
 * Check an IP against available reputation services.
 * @param {string} ip
 * @param {{ abuseipdb?: string, virustotal?: string }} keys
 * @returns {Promise<{ ip, verdict, results: Array, summary: string }>}
 */
async function checkIP(ip, keys = {}) {
  const [abuse, vt] = await Promise.all([
    checkAbuseIPDB(ip, keys.abuseipdb),
    checkVirusTotalIP(ip, keys.virustotal),
  ]);

  const results = [abuse, vt].filter(Boolean);

  // Overall verdict: worst of the two
  const verdicts = results.map(r => r.verdict);
  const verdict  = verdicts.includes('malicious')  ? 'malicious'
                 : verdicts.includes('suspicious') ? 'suspicious'
                 : results.length > 0              ? 'clean'
                 : 'unknown';

  let summary = '';
  if (!results.length) {
    summary = 'No API keys configured. Add AbuseIPDB or VirusTotal keys in Settings.';
  } else if (verdict === 'malicious') {
    summary = `${ip} is flagged as MALICIOUS by ${results.filter(r => r.verdict === 'malicious').map(r => r.source).join(' & ')}.`;
  } else if (verdict === 'suspicious') {
    summary = `${ip} has suspicious activity reports.`;
  } else {
    summary = `${ip} appears clean across ${results.length} source(s).`;
  }

  return { ip, verdict, results, summary };
}

module.exports = { checkIP };
