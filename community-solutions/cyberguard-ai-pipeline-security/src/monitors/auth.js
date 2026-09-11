/**
 * auth.js — Real authentication failure monitor
 *
 * macOS  : reads the Unified Log via `log show` (no root required for SSH events)
 * Linux  : reads /var/log/auth.log or /var/log/secure
 * Windows: reads the Security event log via PowerShell Get-WinEvent (ID 4625)
 *
 * Returns recent auth failure events so the main process can decide
 * whether to emit a threat (e.g. brute-force threshold crossed).
 */

'use strict';

const { execSync } = require('child_process');
const fs  = require('fs');
const os  = require('os');

// How far back to look (minutes)
const LOOKBACK_MINUTES = 10;
// How many failures from a single IP before it's flagged as brute-force
const BRUTE_FORCE_THRESHOLD = 5;

// ── macOS ─────────────────────────────────────────────────────────────────────

function fetchMac() {
  try {
    // SSH daemon failures — no special permissions needed for user-space log
    const raw = execSync(
      `log show --predicate 'process == "sshd" AND (eventMessage CONTAINS "Failed" OR eventMessage CONTAINS "Invalid user" OR eventMessage CONTAINS "authentication failure")' --last ${LOOKBACK_MINUTES}m --style syslog 2>/dev/null`,
      { timeout: 12000 }
    ).toString();

    return parseUnixAuthLog(raw, 'macOS-sshd');
  } catch {
    return [];
  }
}

// ── Linux ─────────────────────────────────────────────────────────────────────

function fetchLinux() {
  const candidates = ['/var/log/auth.log', '/var/log/secure', '/var/log/messages'];
  for (const f of candidates) {
    if (!fs.existsSync(f)) continue;
    try {
      // Read last 500 lines (avoids huge log reads)
      const raw = execSync(`tail -500 "${f}" 2>/dev/null`, { timeout: 5000 }).toString();
      return parseUnixAuthLog(raw, 'syslog');
    } catch { /* try next */ }
  }
  return [];
}

// ── Windows ───────────────────────────────────────────────────────────────────

function fetchWindows() {
  try {
    const ps = `
      $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-${LOOKBACK_MINUTES})} -ErrorAction SilentlyContinue | Select-Object -First 50;
      $events | ForEach-Object {
        $xml = [xml]$_.ToXml();
        $data = $xml.Event.EventData.Data;
        $ip   = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text';
        $user = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text';
        "$($_.TimeCreated)|$ip|$user"
      }
    `.trim();

    const raw = execSync(`powershell -NoProfile -Command "${ps}"`, { timeout: 15000 }).toString();
    const failures = [];
    for (const line of raw.split('\n')) {
      const parts = line.trim().split('|');
      if (parts.length < 2) continue;
      failures.push({ time: parts[0], ip: parts[1] || 'unknown', user: parts[2] || 'unknown', source: 'Windows-EventLog' });
    }
    return failures;
  } catch {
    return [];
  }
}

// ── Shared log parser ─────────────────────────────────────────────────────────

const FAIL_RE = /Failed password.*?from\s+([\d.a-fA-F:]+)/;
const INV_RE  = /Invalid user\s+(\S+)\s+from\s+([\d.a-fA-F:]+)/;
const AUTH_RE = /authentication failure.*?rhost=([\d.a-fA-F:]+)/;

function parseUnixAuthLog(raw, source) {
  const failures = [];
  for (const line of raw.split('\n')) {
    let ip = null, user = null;
    let m;
    if ((m = FAIL_RE.exec(line)))    { ip = m[1]; }
    else if ((m = INV_RE.exec(line))){ ip = m[2]; user = m[1]; }
    else if ((m = AUTH_RE.exec(line))){ ip = m[1]; }
    if (ip) failures.push({ ip, user: user || 'unknown', time: new Date().toISOString(), source });
  }
  return failures;
}

// ── Threat aggregation ────────────────────────────────────────────────────────

function buildThreats(failures) {
  if (!failures.length) return [];
  // Count per source IP
  const counts = {};
  for (const f of failures) {
    counts[f.ip] = (counts[f.ip] || 0) + 1;
  }
  const threats = [];
  for (const [ip, count] of Object.entries(counts)) {
    if (ip === 'unknown' || ip === '-') continue;
    if (count >= BRUTE_FORCE_THRESHOLD) {
      threats.push({
        type:     'Brute Force Attempt',
        severity: count >= 20 ? 'Critical' : 'High',
        source:   ip,
        detail:   `${count} failed auth attempts from ${ip} in the last ${LOOKBACK_MINUTES} minutes`,
      });
    } else if (count >= 2) {
      threats.push({
        type:     'Repeated Auth Failure',
        severity: 'Medium',
        source:   ip,
        detail:   `${count} failed login attempts from ${ip}`,
      });
    }
  }
  return threats;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * @returns {{ failures: Array, threats: Array }}
 */
function snapshot() {
  let failures = [];
  if (process.platform === 'darwin') {
    failures = fetchMac();
  } else if (process.platform === 'win32') {
    failures = fetchWindows();
  } else {
    failures = fetchLinux();
  }
  return {
    failures: failures.slice(0, 50),
    threats:  buildThreats(failures),
  };
}

module.exports = { snapshot };
