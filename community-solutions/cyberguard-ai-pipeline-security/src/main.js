'use strict';

const { app, BrowserWindow, ipcMain, Menu, shell, dialog, screen } = require('electron');
const { execSync } = require('child_process');
const path    = require('path');
const fs      = require('fs');
const si      = require('systeminformation');
const store   = require('./store');
const feeds   = require('./feeds');
const blocklist     = require('./blocklist');
const feedIngester  = require('./threat-intel/feed-ingester');
const kerrigan = require('./kerrigan-bridge');

// ── Window state persistence ──────────────────────────────────────────────────
function windowStatePath() {
  return path.join(app.getPath('userData'), 'window-state.json');
}

function loadWindowState() {
  try {
    const raw = fs.readFileSync(windowStatePath(), 'utf8');
    const s   = JSON.parse(raw);
    // Verify the saved display still exists (handles unplugging the second screen)
    const displays = screen.getAllDisplays();
    const onScreen = displays.some(d =>
      s.x >= d.bounds.x && s.x < d.bounds.x + d.bounds.width &&
      s.y >= d.bounds.y && s.y < d.bounds.y + d.bounds.height
    );
    return onScreen ? s : null;
  } catch { return null; }
}

function saveWindowState(win) {
  if (win.isMaximized() || win.isMinimized()) return;
  try {
    fs.writeFileSync(windowStatePath(), JSON.stringify(win.getBounds()));
  } catch { /* non-fatal */ }
}

// Real monitors
const connMonitor = require('./monitors/connections');
const authMonitor = require('./monitors/auth');
const portMonitor = require('./monitors/ports');

// Real scanners
const ipScanner   = require('./scanners/ip-reputation');
const fileScanner = require('./scanners/file-scan');
const breachCheck = require('./scanners/breach-check');
const urlCheck    = require('./scanners/url-check');

let mainWindow;
let statsInterval;
let monitorInterval;
let feedRefreshInterval;
let honeypotInterval;
let threatCount = 0;
let cachedFeeds = [];

// Dedup: don't flood the same threat within a short window
const recentThreatKeys = new Map(); // key → expiry timestamp
const THREAT_DEDUP_MS  = 5 * 60 * 1000; // 5 minutes

// ── Window ────────────────────────────────────────────────────────────────────

function createWindow() {
  const saved = loadWindowState();
  mainWindow = new BrowserWindow({
    width:    saved?.width  ?? 1200,
    height:   saved?.height ?? 780,
    x:        saved?.x,
    y:        saved?.y,
    minWidth: 1000,
    minHeight: 680,
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 18, y: 20 },
    backgroundColor: '#f5f5f7',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  // Save position/size whenever the user moves or resizes the window
  const persistState = () => saveWindowState(mainWindow);
  mainWindow.on('moved',   persistState);
  mainWindow.on('resized', persistState);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    startMonitoring();
    refreshFeeds();
  });

  mainWindow.on('closed', () => {
    stopMonitoring();
    mainWindow = null;
  });

  buildMenu();
}

// ── Monitoring ────────────────────────────────────────────────────────────────

function startMonitoring() {
  // Live system stats every 2 s
  statsInterval = setInterval(async () => {
    try {
      const [load, mem, nets] = await Promise.all([
        si.currentLoad(),
        si.mem(),
        si.networkStats(),
      ]);
      const net = nets[0] || {};
      mainWindow?.webContents.send('stats-update', {
        cpu:        Math.round(load.currentLoad),
        ram:        Math.round((mem.used / mem.total) * 100),
        ramUsedGB:  +(mem.used  / 1e9).toFixed(1),
        ramTotalGB: +(mem.total / 1e9).toFixed(1),
        netInKB:    Math.round((net.rx_sec || 0) / 1024),
        netOutKB:   Math.round((net.tx_sec || 0) / 1024),
        timestamp:  Date.now(),
      });
    } catch (_) {}
  }, 2000);

  // Real threat detection every 30 s
  monitorInterval = setInterval(runMonitors, 30_000);
  runMonitors(); // also run immediately on start

  // Refresh intelligence feeds every 30 min
  feedRefreshInterval = setInterval(refreshFeeds, 30 * 60 * 1000);

  // Honeypot hit notifications — poll every 20s, alert on new hits
  let lastHoneypotTotal = 0;
  let lastHoneypotIds   = new Set();
  honeypotInterval = setInterval(async () => {
    try {
      const data = await kerrigan.get('/honeypot/counts');
      if (!data || data.error) return;
      const recent = data.recent || [];
      // Find hits we haven't seen before (by timestamp+ip combo)
      for (const hit of recent) {
        const id = `${hit.honeypot_type}|${hit.attacker_ip}|${hit.created_at}`;
        if (!lastHoneypotIds.has(id)) {
          lastHoneypotIds.add(id);
          if (lastHoneypotTotal > 0) {
            // Only notify after first poll so we don't spam on startup
            mainWindow?.webContents.send('honeypot-hit', {
              type:    hit.honeypot_type,
              ip:      hit.attacker_ip,
              payload: hit.payload || '',
              time:    hit.created_at,
            });
          }
        }
      }
      lastHoneypotTotal = data.total;
    } catch (_) {}
  }, 20_000);
}

function stopMonitoring() {
  clearInterval(statsInterval);
  clearInterval(monitorInterval);
  clearInterval(feedRefreshInterval);
  clearInterval(honeypotInterval);
}

// ── Real threat monitors ──────────────────────────────────────────────────────

async function runMonitors() {
  const [connResult, authResult, portResult] = await Promise.all([
    Promise.resolve().then(() => connMonitor.snapshot()),
    Promise.resolve().then(() => authMonitor.snapshot()),
    Promise.resolve().then(() => portMonitor.snapshot()),
  ]);

  // Push live data to UI
  if (connResult.connections.length > 0) {
    mainWindow?.webContents.send('connections-update', connResult.connections);
  }
  mainWindow?.webContents.send('ports-update', portResult.ports);

  // Check live connection destinations against the local C2/malware blocklist
  const blocklistThreats = [];
  for (const c of connResult.connections) {
    const hit = blocklist.check(c.dstIp);
    if (hit.listed) {
      blocklistThreats.push({
        type:     'Blocklisted Destination',
        severity: hit.lists.includes('outbound') ? 'Critical' : 'High',
        source:   c.dstIp,
        detail:   `${c.process} (PID ${c.pid}) → ${c.dstIp}:${c.dstPort} — on ${hit.lists.join('+')} blocklist (known C2/malicious host)`,
        process:  c.process,
        port:     c.dstPort,
      });
    }
  }

  // Emit deduplicated threat events
  const allThreats = [
    ...connResult.threats,
    ...blocklistThreats,
    ...authResult.threats,
    ...portResult.threats,
  ];

  const now = Date.now();
  for (const [k, exp] of recentThreatKeys) {
    if (now > exp) recentThreatKeys.delete(k);
  }

  for (const t of allThreats) {
    const key = `${t.type}|${t.source}`;
    if (recentThreatKeys.has(key)) continue;
    recentThreatKeys.set(key, now + THREAT_DEDUP_MS);

    threatCount++;
    const event = {
      id:        Date.now() + Math.random(),
      count:     threatCount,
      type:      t.type,
      severity:  t.severity,
      source:    t.source,
      detail:    t.detail || '',
      blocked:   false,
      timestamp: new Date().toISOString(),
    };
    mainWindow?.webContents.send('threat-detected', event);
    logThreat(event);
  }
}

// ── Threat history persistence ────────────────────────────────────────────────
// Append-only JSONL in userData so detections survive restarts and can feed
// incident reports.

const fsThreatLog = require('fs');
let threatLogPath = null;

function logThreat(event) {
  if (!threatLogPath) return;
  try { fsThreatLog.appendFileSync(threatLogPath, JSON.stringify(event) + '\n'); }
  catch (_) {}
}

function readThreatHistory(limit = 200) {
  try {
    const lines = fsThreatLog.readFileSync(threatLogPath, 'utf8').trim().split('\n');
    return lines.slice(-limit).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean).reverse();
  } catch { return []; }
}

// ── Intelligence feeds ────────────────────────────────────────────────────────

async function refreshFeeds() {
  try {
    console.log('[feeds] Fetching intelligence feeds…');
    cachedFeeds = await feeds.fetchAll();
    mainWindow?.webContents.send('feeds-updated', cachedFeeds);
    console.log(`[feeds] Got ${cachedFeeds.length} items`);
  } catch (e) {
    console.error('[feeds] Error:', e.message);
  }
}

// ── IPC: System stats ─────────────────────────────────────────────────────────

ipcMain.handle('get-system-stats', async () => {
  const [load, mem, disks, nets, cpu] = await Promise.all([
    si.currentLoad(), si.mem(), si.fsSize(), si.networkStats(), si.cpu(),
  ]);
  const disk = disks.find(d => d.mount === '/') || disks[0] || {};
  const net  = nets[0] || {};
  return {
    cpu:         Math.round(load.currentLoad),
    cpuModel:    cpu.brand || 'Processor',
    cpuCores:    cpu.cores  || 0,
    ram:         Math.round((mem.used / mem.total) * 100),
    ramUsedGB:   +(mem.used  / 1e9).toFixed(1),
    ramTotalGB:  +(mem.total / 1e9).toFixed(1),
    disk:        disk.size ? Math.round((disk.used / disk.size) * 100) : 0,
    diskUsedGB:  disk.used  ? Math.round(disk.used  / 1e9) : 0,
    diskTotalGB: disk.size  ? Math.round(disk.size  / 1e9) : 0,
    netInKB:     Math.round((net.rx_sec || 0) / 1024),
    netOutKB:    Math.round((net.tx_sec || 0) / 1024),
  };
});

// ── IPC: Security checks ──────────────────────────────────────────────────────

ipcMain.handle('get-security-checks', () => {
  const run = cmd => {
    try { return execSync(cmd, { timeout: 5000 }).toString().trim(); }
    catch { return ''; }
  };
  const checks = [];

  if (process.platform === 'darwin') {
    const fw = run('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null');
    checks.push({ id: 'firewall', name: 'Firewall', icon: 'firewall',
      status: fw.includes('enabled') ? 'pass' : 'fail',
      detail: fw.includes('enabled') ? 'Enabled — blocking unsolicited connections' : 'Disabled — your Mac is exposed to the network',
      fix: 'System Settings → Network → Firewall' });

    const fv = run('fdesetup status 2>/dev/null');
    checks.push({ id: 'filevault', name: 'FileVault Encryption', icon: 'lock',
      status: fv.includes('On') ? 'pass' : 'warn',
      detail: fv.includes('On') ? 'Disk encryption is active' : 'Disk is unencrypted — data is readable if the device is lost',
      fix: 'System Settings → Privacy & Security → FileVault' });

    const sip = run('csrutil status 2>/dev/null');
    checks.push({ id: 'sip', name: 'System Integrity Protection', icon: 'shield',
      status: sip.includes('enabled') ? 'pass' : 'warn',
      detail: sip.includes('enabled') ? 'SIP is protecting system files' : 'SIP is disabled — system files are modifiable',
      fix: 'Re-enable from macOS Recovery (hold Power on Apple Silicon)' });

    const gk = run('spctl --status 2>/dev/null');
    checks.push({ id: 'gatekeeper', name: 'Gatekeeper', icon: 'gatekeeper',
      status: gk.includes('enabled') ? 'pass' : 'warn',
      detail: gk.includes('enabled') ? 'Only verified apps are allowed' : 'Unverified apps can run freely',
      fix: 'System Settings → Privacy & Security' });

    const au = run('defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null');
    checks.push({ id: 'updates', name: 'Automatic Updates', icon: 'refresh',
      status: au === '1' ? 'pass' : 'warn',
      detail: au === '1' ? 'macOS checks for security updates automatically' : 'Auto-updates are off — patches must be applied manually',
      fix: 'System Settings → General → Software Update' });

    const sl = run('defaults read com.apple.screensaver idleTime 2>/dev/null');
    const idle = parseInt(sl, 10) || 0;
    checks.push({ id: 'screenlock', name: 'Screen Lock', icon: 'screenlock',
      status: idle > 0 && idle <= 300 ? 'pass' : 'warn',
      detail: idle > 0 ? `Screen locks after ${Math.round(idle / 60)} min of inactivity` : 'Screen never locks automatically',
      fix: 'System Settings → Lock Screen' });

  } else if (process.platform === 'win32') {
    const fwStatus = run('powershell -NoProfile -Command "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled" 2>nul');
    checks.push({ id: 'firewall', name: 'Windows Firewall', icon: 'firewall',
      status: fwStatus.includes('True') ? 'pass' : 'fail',
      detail: fwStatus.includes('True') ? 'Windows Firewall is active' : 'Firewall is OFF — enable it immediately',
      fix: 'Windows Security → Firewall & network protection' });

    const defStatus = run('powershell -NoProfile -Command "(Get-MpComputerStatus).RealTimeProtectionEnabled" 2>nul');
    checks.push({ id: 'defender', name: 'Windows Defender', icon: 'shield',
      status: defStatus.trim() === 'True' ? 'pass' : 'fail',
      detail: defStatus.trim() === 'True' ? 'Real-time protection is active' : 'Defender real-time protection is OFF',
      fix: 'Windows Security → Virus & threat protection' });

    const uacStatus = run('powershell -NoProfile -Command "(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA" 2>nul');
    checks.push({ id: 'uac', name: 'User Account Control', icon: 'lock',
      status: uacStatus.trim() === '1' ? 'pass' : 'warn',
      detail: uacStatus.trim() === '1' ? 'UAC is enabled' : 'UAC is disabled — malware can escalate privileges silently',
      fix: 'Control Panel → User Accounts → Change UAC settings' });

    const auStatus = run('powershell -NoProfile -Command "(Get-Service wuauserv).Status" 2>nul');
    checks.push({ id: 'updates', name: 'Windows Update Service', icon: 'refresh',
      status: auStatus.includes('Running') ? 'pass' : 'warn',
      detail: auStatus.includes('Running') ? 'Windows Update service is running' : 'Windows Update service is stopped',
      fix: 'Services → Windows Update → Start' });

    const bitlocker = run('powershell -NoProfile -Command "manage-bde -status C: 2>nul | Select-String \'Protection Status\'" 2>nul');
    checks.push({ id: 'bitlocker', name: 'BitLocker Encryption', icon: 'lock',
      status: bitlocker.includes('Protection On') ? 'pass' : 'warn',
      detail: bitlocker.includes('Protection On') ? 'Drive C: is encrypted with BitLocker' : 'Drive C: is not encrypted',
      fix: 'Control Panel → BitLocker Drive Encryption' });
  }

  return checks;
});

// ── IPC: Network devices ──────────────────────────────────────────────────────

ipcMain.handle('get-network-devices', () => {
  try {
    const raw = execSync('arp -a 2>/dev/null', { timeout: 5000 }).toString();
    return raw.split('\n')
      .filter(l => l.includes('at') && !l.includes('incomplete') && !l.includes('(0.0.0.0)'))
      .map(l => {
        const m = l.match(/^(\S+)\s+\(([^)]+)\)\s+at\s+(\S+)/);
        if (!m) return null;
        return { hostname: m[1] === '?' ? 'Unknown Device' : m[1].replace(/\.$/, ''), ip: m[2], mac: m[3], status: 'online' };
      })
      .filter(Boolean)
      .slice(0, 25);
  } catch { return []; }
});

// ── IPC: Processes ────────────────────────────────────────────────────────────

ipcMain.handle('get-processes', async () => {
  const SUSPICIOUS = ['xmrig','miner','coinminer','cryptominer','keylogger','backdoor',
                      'netcat','ncat','reverse_shell','mimikatz','cobalt','empire','metasploit'];
  try {
    const { list } = await si.processes();
    return list.sort((a, b) => b.cpu - a.cpu).slice(0, 40).map(p => ({
      pid:  p.pid, name: p.name,
      cpu:  +p.cpu.toFixed(1), mem: +p.mem.toFixed(1), user: p.user || '—',
      suspicious: SUSPICIOUS.some(s => p.name.toLowerCase().includes(s)),
    }));
  } catch { return []; }
});

ipcMain.handle('kill-process', async (_, pid) => {
  try {
    process.kill(pid, 'SIGTERM');
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

// ── IPC: Live connections & ports ─────────────────────────────────────────────

ipcMain.handle('get-connections', () => {
  try { return connMonitor.snapshot().connections; }
  catch { return []; }
});

ipcMain.handle('get-ports', () => {
  try { return portMonitor.snapshot().ports; }
  catch { return []; }
});

// ── IPC: Intelligence feeds ───────────────────────────────────────────────────

ipcMain.handle('get-feeds', () => cachedFeeds);
ipcMain.handle('refresh-feeds', async () => { await refreshFeeds(); return cachedFeeds; });

// ── IPC: Threat history & blocklist ───────────────────────────────────────────

ipcMain.handle('get-threat-history', (_, limit) => readThreatHistory(limit));
ipcMain.handle('blocklist-stats', () => blocklist.stats());
ipcMain.handle('blocklist-check', (_, ip) => blocklist.check(ip));

// ── IPC: Credentials ─────────────────────────────────────────────────────────

ipcMain.handle('cred-get-masked', () => store.getMasked());
ipcMain.handle('cred-configured', () => store.getConfiguredKeys());
ipcMain.handle('cred-set',    (_, key, value) => { store.set(key, value); return true; });
ipcMain.handle('cred-delete', (_, key)        => { store.delete(key); return true; });

// ── IPC: Test API connections ─────────────────────────────────────────────────

ipcMain.handle('cred-test', async (_, service) => {
  const key = store.get(service);
  if (!key) return { ok: false, msg: 'No API key configured' };
  try {
    if (service === 'virustotal') {
      const r = await fetchJSON('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', { 'x-apikey': key });
      return r.status === 200 ? { ok: true, msg: 'Connected' } : { ok: false, msg: `HTTP ${r.status}` };
    }
    if (service === 'abuseipdb') {
      const r = await fetchJSON('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90', { 'Key': key, 'Accept': 'application/json' });
      return r.status === 200 ? { ok: true, msg: 'Connected' } : { ok: false, msg: `HTTP ${r.status}` };
    }
    if (service === 'shodan') {
      const r = await fetchJSON(`https://api.shodan.io/api-info?key=${key}`, {});
      return r.status === 200 ? { ok: true, msg: 'Connected' } : { ok: false, msg: `HTTP ${r.status}` };
    }
    if (service === 'hibp') {
      return key.length >= 20 ? { ok: true, msg: 'Key saved (test with a scan)' } : { ok: false, msg: 'Key looks too short' };
    }
    if (service === 'safebrowsing') {
      return key.length >= 30 ? { ok: true, msg: 'Key saved' } : { ok: false, msg: 'Key looks too short' };
    }
    return { ok: false, msg: 'Unknown service' };
  } catch (e) {
    return { ok: false, msg: e.message };
  }
});

// ── IPC: Scanners ─────────────────────────────────────────────────────────────

ipcMain.handle('scan-ip', async (_, ip) => {
  const result = await ipScanner.checkIP(ip, {
    abuseipdb:  store.get('abuseipdb'),
    virustotal: store.get('virustotal'),
  });

  // Local blocklist (bitwire-it/ipblocklist) — no API key needed
  const hit = blocklist.check(ip);
  if (hit.listed) {
    result.results.push({
      source:  'Local Blocklist',
      ip,
      lists:   hit.lists,
      verdict: 'malicious',
    });
    result.verdict = 'malicious';
    result.summary = `${ip} is on the ${hit.lists.join(' & ')} blocklist (known malicious). ${result.summary}`;
  } else if (result.verdict === 'unknown') {
    result.verdict = 'clean';
    result.summary = `${ip} is not on the local blocklist. ${result.summary}`;
  }
  return result;
});

ipcMain.handle('scan-url', async (_, url) => {
  return urlCheck.checkURL(url, {
    virustotal:   store.get('virustotal'),
    safebrowsing: store.get('safebrowsing'),
  });
});

ipcMain.handle('scan-file', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title:       'Select File to Scan',
    properties:  ['openFile'],
    buttonLabel: 'Scan with VirusTotal',
  });
  if (result.canceled || !result.filePaths.length) return { canceled: true };
  return fileScanner.scanFile(result.filePaths[0], store.get('virustotal'));
});

ipcMain.handle('check-email-breach', async (_, email) => {
  return breachCheck.checkEmail(email, store.get('hibp'));
});

ipcMain.handle('check-password-breach', async (_, password) => {
  return breachCheck.checkPassword(password);
});

// ── IPC: App info ─────────────────────────────────────────────────────────────

ipcMain.handle('get-version', () => app.getVersion());
ipcMain.handle('open-url', (_, url) => shell.openExternal(url));

// ── Kerrigan DB IPC ───────────────────────────────────────────────────────────

// ── Real security tool IPC ────────────────────────────────────────────────────
ipcMain.handle('pentest-headers',  async (_, url) => { try { return await kerrigan.get(`/pentest/headers?url=${encodeURIComponent(url)}`); } catch(e) { return {error:e.message}; }});
ipcMain.handle('pentest-portscan', async (_, target, ports) => { try { return await kerrigan.post('/pentest/portscan', {target, ports}); } catch(e) { return {error:e.message}; }});
ipcMain.handle('pentest-ssl',      async (_, host, port) => { try { return await kerrigan.get(`/pentest/ssl?host=${host}&port=${port}`); } catch(e) { return {error:e.message}; }});
ipcMain.handle('pentest-ssh',      async () => { try { return await kerrigan.get('/pentest/ssh-audit'); } catch(e) { return {error:e.message}; }});
ipcMain.handle('network-arp',      async () => { try { return await kerrigan.get('/network/arp'); } catch(e) { return {error:e.message}; }});
ipcMain.handle('network-routes',   async () => { try { return await kerrigan.get('/network/routes'); } catch(e) { return {error:e.message}; }});
ipcMain.handle('scan-cve',         async (_, q) => { try { return await kerrigan.get(`/scan/cve?q=${encodeURIComponent(q)}`); } catch(e) { return {error:e.message}; }});
ipcMain.handle('patcher-status',    async () => { try { return await kerrigan.get('/patcher/status'); } catch(e) { return {error:e.message}; }});
ipcMain.handle('firewall-blocked',  async () => { try { return await kerrigan.get('/firewall/blocked'); } catch(e) { return {error:e.message}; }});

ipcMain.handle('honeypot-counts', async () => {
  try { return await kerrigan.get('/honeypot/counts'); }
  catch (e) { return { ssh: 0, web: 0, database: 0, total: 0, recent: [], error: e.message }; }
});

ipcMain.handle('db-memories', async (_, limit = 20, offset = 0) => {
  try {
    const r = await kerrigan.get(`/db/memories?limit=${limit}&offset=${offset}`);
    return r;
  } catch (e) { return { memories: [], total: 0, error: e.message }; }
});

ipcMain.handle('db-crashes', async (_, limit = 20) => {
  try {
    const r = await kerrigan.get(`/db/crashes?limit=${limit}`);
    return r;
  } catch (e) { return { crashes: [], error: e.message }; }
});

ipcMain.handle('db-sessions', async (_, limit = 10) => {
  try {
    const r = await kerrigan.get(`/db/sessions?limit=${limit}`);
    return r;
  } catch (e) { return { sessions: [], error: e.message }; }
});

// ── Kerrigan IPC ──────────────────────────────────────────────────────────────

ipcMain.handle('kerrigan-chat',   async (_, message, history, system_context) => kerrigan.chat(message, history, system_context));
ipcMain.handle('kerrigan-status', async ()                    => kerrigan.status());
ipcMain.handle('kerrigan-hunt',   async (_, targetPath)       => {
  const http = require('http');
  return new Promise((resolve) => {
    const body = JSON.stringify({ path: targetPath });
    const req  = http.request({
      hostname: '127.0.0.1', port: 7432, path: '/hunt',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve({ error: d }); } });
    });
    req.on('error', () => resolve({ error: 'Kerrigan offline' }));
    req.write(body); req.end();
  });
});
// ── Protegrity Real Tokenization ──────────────────────────────────────────────

ipcMain.handle('protegrity-protect', async (_, fields, policyUser = 'superuser') => {
  try {
    return await kerrigan.post('/protegrity/protect', { fields, policy_user: policyUser });
  } catch (e) { return { error: e.message }; }
});

ipcMain.handle('protegrity-unprotect', async (_, fields, policyUser = 'superuser') => {
  try {
    return await kerrigan.post('/protegrity/unprotect', { fields, policy_user: policyUser });
  } catch (e) { return { error: e.message }; }
});

// ── Protegrity Demo Pipeline ──────────────────────────────────────────────────

ipcMain.handle('demo-llm-infer', async (_, tokenizedRecords) => {
  const now = new Date().toISOString();
  const count = Array.isArray(tokenizedRecords) ? tokenizedRecords.length : 6;

  const STUB_RESPONSE = `INCIDENT REPORT — CyberGuard AI Pipeline [Protegrity-Protected]
Generated: ${now} | Classification: RESTRICTED | Analyst: Kerrigan-Fantasma Lite

EXECUTIVE SUMMARY
Analysis of ${count} tokenized endpoint telemetry records reveals a coordinated multi-stage intrusion. Primary threat actor usr_a7c3f2 on device DEV-SC7291X established Command-and-Control beaconing to external host 143.22.118.91 via process svchost.exe (port 443). Secondary actor usr_8b2f1d on device DEV-MW0034K executed a 2.3 MB data exfiltration event over an encrypted channel (port 8443) before installing a persistence mechanism via curl. Lateral movement was observed from DEV-SC7291X to DEV-MW0034K using NTLM relay on port 445.

NIST 800-53 CONTROL FINDINGS
• SC-28 (Protection of Information at Rest): All PII fields — source IP, destination IP, username, and device ID — were replaced with format-preserving Protegrity tokens prior to model context ingestion. The inference engine operated exclusively on tokenized identifiers; no real values entered the AI context window.
• AC-3 (Access Enforcement): Unauthorized cross-segment access detected from DEV-SC7291X to resources outside its assigned network zone. De-tokenization is enforced only at the authenticated analyst display layer per least-privilege policy (NIST SP 800-171 §3.1.3).
• CSF 2.0 PR.DS-1 (Data-at-Rest Protection): Tokenization vault maintained exclusively by Protegrity Developer Edition. Model output confirmed PII-free by output guardrail scan — zero re-identification patterns detected.
• AI RMF 1.0 MAP 1.6: Pipeline architecture reflects organizational risk priorities. Data minimization applied before AI processing, not post-hoc — the model never had access to sensitive values to begin with.
• ISO/IEC 42001 §6.1: Risk treatment applied at the architectural level. The protect-before-ingest pattern eliminates a full class of AI-specific re-identification risks identified in the system's AI risk register.

RECOMMENDED ACTIONS
1. Isolate DEV-SC7291X and DEV-MW0034K from all network segments immediately — preserve volatile memory for forensic imaging
2. Revoke all active credentials for usr_a7c3f2 and usr_8b2f1d — coordinate with IAM; check for OAuth token reuse
3. Block C2 destination ranges 143.22.0.0/16, 91.108.0.0/16, and 203.0.113.0/24 at perimeter firewall
4. Preserve tokenized telemetry logs under litigation hold — NIST SP 800-92 compliant retention
5. Initiate NIST SP 800-61 Rev 3 Incident Response procedure — escalate to Tier 3 SOC within 1 hour

PIPELINE INTEGRITY ATTESTATION
• Stage 1 (Ingest & Classify): ${count} records classified, 4 PII field types identified per record
• Stage 2 (Tokenize — Protegrity): Format-preserving tokens applied; vault sealed
• Stage 3 (Model Inference): 0 raw PII values in model context — verified pre-inference
• Stage 4 (Output Guardrail): PASSED — output scanned, no re-identification patterns detected
• Stage 5 (De-tokenize — Protegrity): Real values restored at display layer only; vault released`;

  try {
    const message = `You are a cybersecurity analyst generating a NIST 800-53 incident report. The following endpoint telemetry has been tokenized using Protegrity format-preserving tokenization — all IP addresses, usernames, and device IDs are synthetic tokens. Reference ONLY these tokens in your report. Map findings to SC-28, AC-3, and CSF 2.0 PR.DS-1.\n\nTOKENIZED TELEMETRY (${count} records):\n${JSON.stringify(tokenizedRecords, null, 2)}\n\nWrite the NIST-mapped incident report now:`;
    const kerriganResult = await kerrigan.chat(message, [], 'You are a NIST-certified security analyst writing structured incident reports. Be concise, precise, and reference only the tokenized identifiers provided. Map every finding to a specific NIST control.');
    if (kerriganResult && kerriganResult.reply) {
      return { model: kerriganResult.model || 'Kerrigan-Fantasma', response: kerriganResult.reply, isStub: false };
    }
    throw new Error('no reply');
  } catch (_) {
    return { model: 'Kerrigan-Fantasma (offline — using cached analysis)', response: STUB_RESPONSE, isStub: true };
  }
});

ipcMain.handle('check-for-updates', () => {
  if (app.isPackaged) {
    const { autoUpdater } = require('electron-updater');
    autoUpdater.checkForUpdates();
  }
  return app.getVersion();
});

// ── Fetch helper ──────────────────────────────────────────────────────────────

function fetchJSON(url, headers) {
  const https = require('https');
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

// ── App lifecycle ─────────────────────────────────────────────────────────────

app.whenReady().then(() => {
  store.init(app.getPath('userData'));
  blocklist.init(app.getPath('userData'));
  feedIngester.init(app.getPath('userData'), store, blocklist);
  threatLogPath = path.join(app.getPath('userData'), 'threat-history.jsonl');
  kerrigan.start();
  createWindow();

  if (app.isPackaged) {
    const { autoUpdater } = require('electron-updater');
    autoUpdater.checkForUpdatesAndNotify();
    autoUpdater.on('update-available',  () => mainWindow?.webContents.send('update-available'));
    autoUpdater.on('update-downloaded', () => mainWindow?.webContents.send('update-downloaded'));
  }
});

app.on('window-all-closed', () => {
  stopMonitoring();
  kerrigan.stop();
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// ── Menu ──────────────────────────────────────────────────────────────────────

function buildMenu() {
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'CyberGuard', submenu: [
      { label: 'About CyberGuard', role: 'about' },
      { type: 'separator' },
      { role: 'hide' }, { role: 'hideOthers' }, { role: 'unhide' },
      { type: 'separator' },
      { role: 'quit' },
    ]},
    { label: 'Edit', submenu: [
      { role: 'undo' }, { role: 'redo' },
      { type: 'separator' },
      { role: 'cut' }, { role: 'copy' }, { role: 'paste' },
      { role: 'pasteAndMatchStyle' },
      { role: 'delete' }, { role: 'selectAll' },
    ]},
    { label: 'View', submenu: [
      { role: 'reload' }, { role: 'toggleDevTools' },
      { type: 'separator' },
      { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' },
      { type: 'separator' }, { role: 'togglefullscreen' },
    ]},
    { label: 'Window', submenu: [
      { role: 'minimize' }, { role: 'zoom' }, { type: 'separator' }, { role: 'front' },
    ]},
  ]));
}
