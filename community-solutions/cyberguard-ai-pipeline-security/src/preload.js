const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cyberguard', {
  // System
  getSystemStats:    () => ipcRenderer.invoke('get-system-stats'),
  getSecurityChecks: () => ipcRenderer.invoke('get-security-checks'),
  getNetworkDevices: () => ipcRenderer.invoke('get-network-devices'),
  getProcesses:      () => ipcRenderer.invoke('get-processes'),
  killProcess:       (pid) => ipcRenderer.invoke('kill-process', pid),
  honeypotCounts:    () => ipcRenderer.invoke('honeypot-counts'),
  pentestHeaders:    (url) => ipcRenderer.invoke('pentest-headers', url),
  pentestPortscan:   (target, ports) => ipcRenderer.invoke('pentest-portscan', target, ports),
  pentestSsl:        (host, port) => ipcRenderer.invoke('pentest-ssl', host, port),
  pentestSsh:        () => ipcRenderer.invoke('pentest-ssh'),
  networkArp:        () => ipcRenderer.invoke('network-arp'),
  networkRoutes:     () => ipcRenderer.invoke('network-routes'),
  scanCve:           (q) => ipcRenderer.invoke('scan-cve', q),
  patcherStatus:     () => ipcRenderer.invoke('patcher-status'),
  dbMemories:        (limit, offset) => ipcRenderer.invoke('db-memories', limit, offset),
  dbCrashes:         (limit) => ipcRenderer.invoke('db-crashes', limit),
  dbSessions:        (limit) => ipcRenderer.invoke('db-sessions', limit),
  getVersion:        () => ipcRenderer.invoke('get-version'),
  checkForUpdates:   () => ipcRenderer.invoke('check-for-updates'),
  openUrl:           (url) => ipcRenderer.invoke('open-url', url),

  // Live monitoring data
  getConnections: () => ipcRenderer.invoke('get-connections'),
  getPorts:       () => ipcRenderer.invoke('get-ports'),

  // Intelligence feeds
  getFeeds:     () => ipcRenderer.invoke('get-feeds'),
  refreshFeeds: () => ipcRenderer.invoke('refresh-feeds'),
  getThreatHistory: (limit) => ipcRenderer.invoke('get-threat-history', limit),
  blocklistStats:   ()      => ipcRenderer.invoke('blocklist-stats'),
  blocklistCheck:   (ip)    => ipcRenderer.invoke('blocklist-check', ip),

  // Credentials (encrypted, local only)
  credGetMasked:  ()         => ipcRenderer.invoke('cred-get-masked'),
  credConfigured: ()         => ipcRenderer.invoke('cred-configured'),
  credSet:        (key, val) => ipcRenderer.invoke('cred-set', key, val),
  credDelete:     (key)      => ipcRenderer.invoke('cred-delete', key),
  credTest:       (service)  => ipcRenderer.invoke('cred-test', service),

  // Scanners (real — results from actual APIs)
  scanIP:             (ip)       => ipcRenderer.invoke('scan-ip', ip),
  scanURL:            (url)      => ipcRenderer.invoke('scan-url', url),
  scanFile:           ()         => ipcRenderer.invoke('scan-file'),
  checkEmailBreach:   (email)    => ipcRenderer.invoke('check-email-breach', email),
  checkPasswordBreach:(password) => ipcRenderer.invoke('check-password-breach', password),

  // Real-time push events from main process
  onStatsUpdate:       (cb) => ipcRenderer.on('stats-update',        (_, d) => cb(d)),
  onThreatDetected:    (cb) => ipcRenderer.on('threat-detected',     (_, d) => cb(d)),
  onFeedsUpdated:      (cb) => ipcRenderer.on('feeds-updated',       (_, d) => cb(d)),
  onConnectionsUpdate: (cb) => ipcRenderer.on('connections-update',  (_, d) => cb(d)),
  onPortsUpdate:       (cb) => ipcRenderer.on('ports-update',        (_, d) => cb(d)),
  onUpdateAvailable:   (cb) => ipcRenderer.on('update-available',    ()     => cb()),
  onUpdateDownloaded:  (cb) => ipcRenderer.on('update-downloaded',   ()     => cb()),
  onHoneypotHit:       (cb) => ipcRenderer.on('honeypot-hit',        (_, d) => cb(d)),

  off: (channel) => ipcRenderer.removeAllListeners(channel),

  // Protegrity Real Tokenization
  protegrityProtect:   (fields, policyUser) => ipcRenderer.invoke('protegrity-protect', fields, policyUser),
  protegrityUnprotect: (fields, policyUser) => ipcRenderer.invoke('protegrity-unprotect', fields, policyUser),

  // Protegrity Demo Pipeline
  demoLlmInfer: (tokenizedRecords) => ipcRenderer.invoke('demo-llm-infer', tokenizedRecords),

  // Kerrigan AI
  kerriganChat:   (msg, history, ctx) => ipcRenderer.invoke('kerrigan-chat', msg, history, ctx),
  kerriganStatus: ()             => ipcRenderer.invoke('kerrigan-status'),
  kerriganHunt:   (path)         => ipcRenderer.invoke('kerrigan-hunt', path),
  firewallBlocked: ()            => ipcRenderer.invoke('firewall-blocked'),
});
