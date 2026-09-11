/**
 * connections.js — Real network connection monitor
 *
 * Uses lsof (macOS/Linux) or netstat (Windows) to read the OS connection
 * table every poll interval and emit threats for:
 *   • Connections to ports associated with known C2 / malware activity
 *   • Unusually high connection counts to a single external host
 *   • Connections to private RFC-1918 addresses on suspicious ports
 *
 * No third-party npm dependencies — only Node built-ins + child_process.
 */

'use strict';

const { execSync } = require('child_process');
const os = require('os');

// ── Known-suspicious destination ports ───────────────────────────────────────
// Common malware / C2 / RAT ports that are not normally used by everyday apps.
const SUSPICIOUS_PORTS = new Set([
  31337, 1337, 4444, 4445, 5555, 6666, 6667, 6668, 6669, // IRC / common RAT
  9001, 9030,                                              // Tor defaults
  1080,                                                    // SOCKS proxy
  3128, 8080, 8888,                                        // alt-HTTP often abused
  23,                                                      // Telnet (plaintext)
  2323,                                                    // Telnet alt
  7547,                                                    // Mirai botnet
]);

// Ports that are legitimately busy — skip noisy false-positives
const ALLOW_PORTS = new Set([80, 443, 53, 22, 587, 465, 993, 995, 5353]);

// ── Parse helpers ─────────────────────────────────────────────────────────────

/** Parse `lsof -i -n -P` output into connection objects */
function parseLsof(raw) {
  const conns = [];
  for (const line of raw.split('\n').slice(1)) {
    // COMMAND  PID  USER  FD  TYPE  DEVICE  SIZE  NODE  NAME
    // NAME format:  src_ip:port->dst_ip:port (TCP)
    const parts = line.trim().split(/\s+/);
    if (parts.length < 9) continue;
    const name = parts[8] || '';
    if (!name.includes('->')) continue;
    const [src, dst] = name.split('->');
    const srcParts = src.split(':');
    const dstParts = dst.split(':');
    if (srcParts.length < 2 || dstParts.length < 2) continue;
    conns.push({
      pid:     parseInt(parts[1], 10) || 0,
      process: parts[0],
      state:   parts[9] || '',
      srcIp:   srcParts.slice(0, -1).join(':'),
      srcPort: parseInt(srcParts[srcParts.length - 1], 10) || 0,
      dstIp:   dstParts.slice(0, -1).join(':'),
      dstPort: parseInt(dstParts[dstParts.length - 1], 10) || 0,
    });
  }
  return conns;
}

/** Parse `netstat -ano` (Windows) output */
function parseNetstat(raw) {
  const conns = [];
  for (const line of raw.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts[0] !== 'TCP' && parts[0] !== 'UDP') continue;
    // TCP  0.0.0.0:135  0.0.0.0:0  LISTENING  1234
    const proto = parts[0];
    const local = parts[1] || '';
    const remote = parts[2] || '';
    const state = proto === 'TCP' ? (parts[3] || '') : 'STATELESS';
    const pid = parseInt(proto === 'TCP' ? parts[4] : parts[3], 10) || 0;
    if (remote === '0.0.0.0:0' || remote === '*:*' || remote === '[::]' ) continue;
    const remParts = remote.split(':');
    conns.push({
      pid,
      process: `PID:${pid}`,
      state,
      srcIp:   local.split(':').slice(0, -1).join(':'),
      srcPort: parseInt(local.split(':').pop(), 10) || 0,
      dstIp:   remParts.slice(0, -1).join(':'),
      dstPort: parseInt(remParts[remParts.length - 1], 10) || 0,
    });
  }
  return conns;
}

// ── Private IP check ──────────────────────────────────────────────────────────

function isPrivateIp(ip) {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fe80:)/i.test(ip);
}

function isLoopback(ip) {
  return ip === '127.0.0.1' || ip === '::1' || ip === 'localhost';
}

// ── Main snapshot ─────────────────────────────────────────────────────────────

function getConnections() {
  try {
    let raw = '';
    if (process.platform === 'win32') {
      raw = execSync('netstat -ano', { timeout: 8000 }).toString();
      return parseNetstat(raw);
    } else {
      // macOS / Linux: lsof gives process names which is more useful
      raw = execSync('lsof -i -n -P -sTCP:ESTABLISHED 2>/dev/null', { timeout: 8000 }).toString();
      return parseLsof(raw);
    }
  } catch {
    return [];
  }
}

// ── Threat analysis ───────────────────────────────────────────────────────────

/**
 * Analyse a snapshot of connections and return threat events.
 * @param {ReturnType<typeof getConnections>} conns
 * @returns {Array<{type,severity,source,detail,process,port}>}
 */
function analyse(conns) {
  const threats = [];
  const externalCounts = {}; // dstIp → count

  for (const c of conns) {
    if (isLoopback(c.dstIp)) continue;

    // Count external host occurrences
    if (!isPrivateIp(c.dstIp)) {
      externalCounts[c.dstIp] = (externalCounts[c.dstIp] || 0) + 1;
    }

    // Check suspicious destination port
    if (SUSPICIOUS_PORTS.has(c.dstPort) && !ALLOW_PORTS.has(c.dstPort)) {
      threats.push({
        type:     'Suspicious Outbound Connection',
        severity: c.dstPort === 9001 || c.dstPort === 9030 ? 'High' : 'Medium',
        source:   c.dstIp,
        detail:   `${c.process} (PID ${c.pid}) → ${c.dstIp}:${c.dstPort}`,
        process:  c.process,
        port:     c.dstPort,
      });
    }
  }

  // High connection count to a single external host (potential beaconing/exfil)
  for (const [ip, count] of Object.entries(externalCounts)) {
    if (count >= 8) {
      threats.push({
        type:     'High Connection Count',
        severity: count >= 20 ? 'High' : 'Medium',
        source:   ip,
        detail:   `${count} simultaneous connections to ${ip}`,
        process:  '(multiple)',
        port:     0,
      });
    }
  }

  return threats;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Returns { connections, threats }
 * connections → raw list for the "Live Connections" table
 * threats     → detected anomalies to emit as threat events
 */
function snapshot() {
  const conns = getConnections();
  return {
    connections: conns.slice(0, 100), // cap UI list
    threats:     analyse(conns),
  };
}

module.exports = { snapshot };
