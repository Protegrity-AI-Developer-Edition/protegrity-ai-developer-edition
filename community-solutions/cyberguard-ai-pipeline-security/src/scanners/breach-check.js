/**
 * breach-check.js — Real email breach checker via Have I Been Pwned (HIBP)
 *
 * Uses the HIBP v3 API:
 *   GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
 *
 * Requires a paid HIBP API key (~$3.50/mo for individuals).
 * Also checks the Pwned Passwords API (SHA-1 k-anonymity, FREE, no key needed)
 * to test whether a given plaintext password appears in breach data.
 *
 * Password hashes NEVER leave this machine in full — the k-anonymity model
 * sends only the first 5 hex characters of the SHA-1 hash.
 */

'use strict';

const https  = require('https');
const crypto = require('crypto');

// ── HTTP helper ───────────────────────────────────────────────────────────────

function get(hostname, path_, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname, path: path_, method: 'GET', headers }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.setTimeout(12000, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.end();
  });
}

// ── Email breach lookup ───────────────────────────────────────────────────────

/**
 * Check if an email address appears in any known data breach.
 *
 * @param {string} email
 * @param {string} apiKey   HIBP API key
 * @returns {Promise<BreachResult>}
 *
 * BreachResult:
 * {
 *   email,
 *   breached: boolean,
 *   breachCount: number,
 *   breaches: Array<{ name, domain, breachDate, dataClasses, description }>,
 *   pasteCount: number,
 *   summary: string,
 * }
 */
async function checkEmail(email, apiKey) {
  if (!apiKey) {
    return { error: 'No HIBP API key configured. Add it in Settings.' };
  }

  try {
    const res = await get(
      'haveibeenpwned.com',
      `/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      {
        'hibp-api-key':  apiKey,
        'User-Agent':    'CyberGuard/2.0',
        'Accept':        'application/json',
      }
    );

    if (res.status === 404) {
      return {
        email, breached: false, breachCount: 0,
        breaches: [], pasteCount: 0,
        summary: `Good news — ${email} was not found in any known data breaches.`,
      };
    }

    if (res.status === 401) return { error: 'Invalid HIBP API key.' };
    if (res.status === 429) return { error: 'Rate limited by HIBP. Wait 1 minute and try again.' };
    if (res.status !== 200) return { error: `HIBP returned HTTP ${res.status}` };

    let breaches = [];
    try { breaches = JSON.parse(res.body); } catch { return { error: 'Failed to parse HIBP response.' }; }

    const formatted = breaches.map(b => ({
      name:        b.Name,
      domain:      b.Domain,
      breachDate:  b.BreachDate,
      dataClasses: b.DataClasses || [],
      description: (b.Description || '').replace(/<[^>]+>/g, '').slice(0, 300),
      isVerified:  b.IsVerified,
      isSensitive: b.IsSensitive,
    }));

    // Sort newest first
    formatted.sort((a, b) => new Date(b.breachDate) - new Date(a.breachDate));

    const sensitiveClasses = ['Passwords', 'Credit cards', 'Bank account numbers', 'Social security numbers'];
    const hasSensitive = formatted.some(b =>
      b.dataClasses.some(dc => sensitiveClasses.includes(dc))
    );

    const summary = `${email} found in ${formatted.length} breach${formatted.length !== 1 ? 'es' : ''}.`
      + (hasSensitive ? ' SENSITIVE data exposed (passwords or financial info).' : '');

    return {
      email,
      breached:    true,
      breachCount: formatted.length,
      breaches:    formatted,
      pasteCount:  0, // Paste API requires separate call
      summary,
    };
  } catch (e) {
    return { error: `Network error: ${e.message}` };
  }
}

// ── Password breach check (k-anonymity, no key needed) ───────────────────────

/**
 * Check if a plaintext password appears in HIBP's Pwned Passwords list.
 * Uses k-anonymity — only the first 5 chars of the SHA-1 hash are sent.
 *
 * @param {string} password  Plaintext password to check
 * @returns {Promise<{ pwned: boolean, count: number, summary: string }>}
 */
async function checkPassword(password) {
  const sha1  = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  try {
    const res = await get(
      'api.pwnedpasswords.com',
      `/range/${prefix}`,
      { 'User-Agent': 'CyberGuard/2.0', 'Add-Padding': 'true' }
    );

    if (res.status !== 200) {
      return { error: `Pwned Passwords API returned HTTP ${res.status}` };
    }

    let count = 0;
    for (const line of res.body.split('\n')) {
      const [hash, cnt] = line.trim().split(':');
      if (hash === suffix) { count = parseInt(cnt, 10) || 1; break; }
    }

    return {
      pwned:   count > 0,
      count,
      summary: count > 0
        ? `This password has appeared ${count.toLocaleString()} times in data breaches. Do NOT use it.`
        : 'This password has not been seen in any known breach database.',
    };
  } catch (e) {
    return { error: `Network error: ${e.message}` };
  }
}

module.exports = { checkEmail, checkPassword };
