/**
 * ports.js — Real listening-port scanner
 *
 * Uses lsof (macOS/Linux) or netstat (Windows) to enumerate all
 * ports currently bound and listening on the machine.
 *
 * Flags ports that:
 *   • Are in a known-suspicious list (common backdoor / RAT ports)
 *   • Are listening on 0.0.0.0 or :: (publicly reachable on the LAN)
 *     and are NOT in a typical-service allow-list
 */

'use strict';

const { execSync } = require('child_process');

// ── Port categorisation ───────────────────────────────────────────────────────

// Normal services – don't warn about these even if public-facing
const COMMON_SAFE = new Set([
  22, 80, 443, 8080, 8443,   // SSH, HTTP, HTTPS
  53, 5353,                   // DNS, mDNS
  67, 68,                     // DHCP
  631,                        // CUPS printing
  3306, 5432, 27017, 6379,   // DB (warn if public, but common in dev)
  3000, 4200, 5173, 8000,    // dev servers
]);

// Known malware / RAT / C2 ports — always alert
const ALWAYS_SUSPICIOUS = new Set([
  31337, 1337, 4444, 4445, 5555, 6666, 6667, 6668, 6669,
  9001, 9030, 1080, 2323, 7547,
]);

// ── Parsers ───────────────────────────────────────────────────────────────────

function parseLsofListening(raw) {
  const ports = [];
  for (const line of raw.split('\n').slice(1)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 9) continue;
    const name = parts[8] || '';
    if (!name.includes(':')) continue;
    const colonIdx = name.lastIndexOf(':');
    const addr = name.slice(0, colonIdx);
    const port = parseInt(name.slice(colonIdx + 1), 10);
    if (isNaN(port)) continue;
    ports.push({
      pid:     parseInt(parts[1], 10) || 0,
      process: parts[0],
      proto:   parts[7]?.includes('6') ? 'TCP6' : 'TCP',
      addr,
      port,
    });
  }
  return ports;
}

function parseNetstatListening(raw) {
  const ports = [];
  for (const line of raw.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (!['TCP', 'UDP'].includes(parts[0])) continue;
    if (parts[3] !== 'LISTENING' && parts[0] === 'TCP') {
      if (parts[3] !== 'LISTENING') continue;
    }
    const local = parts[1] || '';
    const colonIdx = local.lastIndexOf(':');
    const addr = local.slice(0, colonIdx);
    const port = parseInt(local.slice(colonIdx + 1), 10);
    if (isNaN(port)) continue;
    const pid = parseInt(parts[4] || parts[3], 10) || 0;
    ports.push({ pid, process: `PID:${pid}`, proto: parts[0], addr, port });
  }
  return ports;
}

// ── Fetch ─────────────────────────────────────────────────────────────────────

function getListeningPorts() {
  try {
    if (process.platform === 'win32') {
      const raw = execSync('netstat -ano 2>nul', { timeout: 8000 }).toString();
      return parseNetstatListening(raw);
    } else {
      const raw = execSync('lsof -i -n -P -sTCP:LISTEN 2>/dev/null', { timeout: 8000 }).toString();
      return parseLsofListening(raw);
    }
  } catch {
    return [];
  }
}

// ── Analysis ──────────────────────────────────────────────────────────────────

function isPublicFacing(addr) {
  return addr === '0.0.0.0' || addr === '*' || addr === '::' || addr === '[::]';
}

function analyse(ports) {
  const threats = [];
  for (const p of ports) {
    if (ALWAYS_SUSPICIOUS.has(p.port)) {
      threats.push({
        type:     'Suspicious Listening Port',
        severity: 'High',
        source:   `localhost:${p.port}`,
        detail:   `${p.process} is listening on port ${p.port} — associated with malware/RAT activity`,
        process:  p.process,
        port:     p.port,
      });
      continue;
    }
    if (isPublicFacing(p.addr) && !COMMON_SAFE.has(p.port) && p.port > 1024) {
      threats.push({
        type:     'Unexpected Open Port',
        severity: 'Low',
        source:   `0.0.0.0:${p.port}`,
        detail:   `${p.process} (PID ${p.pid}) is publicly reachable on port ${p.port}`,
        process:  p.process,
        port:     p.port,
      });
    }
  }
  return threats;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * @returns {{ ports: Array, threats: Array }}
 */
function snapshot() {
  const ports = getListeningPorts();
  return {
    ports:   ports,
    threats: analyse(ports),
  };
}

module.exports = { snapshot };
