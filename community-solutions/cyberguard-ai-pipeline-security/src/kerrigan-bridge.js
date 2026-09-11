'use strict';
/**
 * Kerrigan bridge — spawns a Python FastAPI server wrapping kerrigan.py,
 * proxies chat requests to it from the Electron main process.
 *
 * The server runs on localhost:7432 and is killed when the app closes.
 * Falls back to "offline" mode if kerrigan-fantasma path isn't configured.
 */

const { spawn } = require('child_process');
const http       = require('http');
const path       = require('path');
const fs         = require('fs');

// ── Config ────────────────────────────────────────────────────────────────────

const PORT         = 7432;
const HOME         = require('os').homedir();
const KERRIGAN_DIR = process.env.KERRIGAN_PATH ||
                     path.join(HOME, 'kerrigan-fantasma');
const ANTHOS_DIR   = process.env.ANTHOS_PATH   ||
                     path.join(HOME, 'Desktop', 'anthos-repo');
const SERVER_SCRIPT = path.join(__dirname, 'kerrigan_server.py');

let serverProcess = null;
let _ready        = false;

// ── Ollama startup ────────────────────────────────────────────────────────────

const OLLAMA_MODEL = process.env.KERRIGAN_MODEL || 'kerrigan-fantasma:latest';

function ollamaRunning() {
  return new Promise((resolve) => {
    http.get({ hostname: '127.0.0.1', port: 11434, path: '/api/tags' }, (res) => {
      resolve(res.statusCode === 200);
    }).on('error', () => resolve(false));
  });
}

async function ensureOllama() {
  const running = await ollamaRunning();
  if (!running) {
    console.log('[Ollama] not running — starting ollama serve…');
    spawn('ollama', ['serve'], { stdio: 'ignore', detached: true }).unref();
    // Wait up to 8s for Ollama to come up
    for (let i = 0; i < 16; i++) {
      await new Promise(r => setTimeout(r, 500));
      if (await ollamaRunning()) { console.log('[Ollama] ready'); break; }
    }
  }
  // Warm the model with a no-op so first real request isn't slow
  console.log(`[Ollama] warming model ${OLLAMA_MODEL}…`);
  const { execSync } = require('child_process');
  try {
    execSync(`ollama run ${OLLAMA_MODEL} ""`, { timeout: 30000, stdio: 'ignore' });
    console.log('[Ollama] model warm');
  } catch (_) {
    // Non-fatal — model will load on first chat request instead
    console.warn('[Ollama] warm-up skipped (model will load on first request)');
  }
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

async function start() {
  if (serverProcess) return;
  if (!fs.existsSync(KERRIGAN_DIR)) {
    console.warn('[Kerrigan] kerrigan-fantasma not found at', KERRIGAN_DIR);
    return;
  }

  await ensureOllama();

  // Kill any stale process holding our port
  try { require('child_process').execSync(`lsof -ti:${PORT} | xargs kill -9 2>/dev/null || true`); } catch (_) {}

  const existingPythonPath = process.env.PYTHONPATH || '';
  const pythonPath = [KERRIGAN_DIR, ANTHOS_DIR, path.join(__dirname), existingPythonPath]
    .filter(Boolean).join(':');

  serverProcess = spawn('python3', [SERVER_SCRIPT], {
    cwd:  KERRIGAN_DIR,
    env:  {
      ...process.env,
      KERRIGAN_PATH:  KERRIGAN_DIR,
      KERRIGAN_MODEL: OLLAMA_MODEL,
      PYTHONPATH:     pythonPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  serverProcess.stdout.on('data', (d) => {
    const line = d.toString().trim();
    if (line.includes('CyberGuard AI server ready')) _ready = true;
    console.log('[Kerrigan]', line);
  });
  serverProcess.stderr.on('data', (d) => console.error('[Kerrigan]', d.toString().trim()));
  serverProcess.on('exit', (code) => {
    console.log('[Kerrigan] server exited', code);
    serverProcess = null;
    _ready = false;
  });
}

function stop() {
  if (serverProcess) { serverProcess.kill(); serverProcess = null; }
  _ready = false;
}

function isReady() { return _ready; }

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function post(endpoint, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req  = http.request({
      hostname: '127.0.0.1',
      port:     PORT,
      path:     endpoint,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      let raw = '';
      res.on('data', (c) => raw += c);
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); }
        catch { resolve({ error: raw }); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function get(endpoint) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port: PORT, path: endpoint }, (res) => {
      let raw = '';
      res.on('data', (c) => raw += c);
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); }
        catch { resolve({ error: raw }); }
      });
    }).on('error', reject);
  });
}

// ── Public API (called by ipcMain handlers) ───────────────────────────────────

async function chat(message, history = [], system_context = '') {
  if (!_ready) {
    return { reply: '[Kerrigan offline — server not running. Check KERRIGAN_PATH.]', blocked: false };
  }
  try {
    return await post('/chat', { message, history, system_context });
  } catch (e) {
    return { reply: `[Kerrigan error: ${e.message}]`, blocked: false };
  }
}

async function status() {
  try {
    const s = await get('/status');
    return { online: true, ...s };
  } catch {
    return { online: false };
  }
}

module.exports = { start, stop, isReady, chat, status, get, post };
