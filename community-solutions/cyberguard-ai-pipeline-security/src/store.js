/**
 * Encrypted credential store.
 * Uses AES-256-GCM keyed from the machine's hardware UUID.
 * Credentials are stored in ~/.config/CyberGuard/credentials.enc
 * They never leave the local machine.
 */

const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');
const { execSync } = require('child_process');

const ALGO = 'aes-256-gcm';

// ── Machine-unique key ────────────────────────────────────────────────────────

function getMachineId() {
  try {
    if (process.platform === 'darwin') {
      return execSync(
        "ioreg -d2 -c IOPlatformExpertDevice | awk -F'\"' '/IOPlatformUUID/{print $(NF-1)}'",
        { timeout: 3000 }
      ).toString().trim();
    }
    if (process.platform === 'win32') {
      const out = execSync('wmic csproduct get uuid', { timeout: 3000 }).toString();
      return out.match(/[0-9A-F-]{36}/i)?.[0] || 'fallback';
    }
    // Linux
    return fs.readFileSync('/etc/machine-id', 'utf8').trim();
  } catch {
    return 'cyberguard-fallback-machine-id';
  }
}

function deriveKey() {
  return crypto.createHash('sha256')
    .update(getMachineId() + ':cyberguard-v1')
    .digest();                               // 32 bytes → AES-256
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

function encrypt(plaintext) {
  const iv  = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, deriveKey(), iv);
  const body   = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return JSON.stringify({
    v:    1,
    iv:   iv.toString('hex'),
    tag:  tag.toString('hex'),
    data: body.toString('hex'),
  });
}

function decrypt(json) {
  const { iv, tag, data } = JSON.parse(json);
  const decipher = crypto.createDecipheriv(ALGO, deriveKey(), Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return decipher.update(Buffer.from(data, 'hex')) + decipher.final('utf8');
}

// ── Store class ───────────────────────────────────────────────────────────────

class CredentialStore {
  constructor() {
    this._path = null;
    this._data = {};
  }

  /** Call once after app.getPath('userData') is available */
  init(userDataPath) {
    this._path = path.join(userDataPath, 'credentials.enc');
    this._load();
  }

  _load() {
    try {
      if (fs.existsSync(this._path)) {
        this._data = JSON.parse(decrypt(fs.readFileSync(this._path, 'utf8')));
      }
    } catch (e) {
      console.warn('[store] Could not decrypt credentials (first run or key change):', e.message);
      this._data = {};
    }
  }

  _save() {
    try {
      fs.writeFileSync(this._path, encrypt(JSON.stringify(this._data)));
    } catch (e) {
      console.error('[store] Save error:', e.message);
    }
  }

  /** Get raw value (only used inside main process for API calls) */
  get(key) { return this._data[key] || null; }

  /** Set and persist */
  set(key, value) { this._data[key] = value; this._save(); }

  /** Delete one key */
  delete(key) { delete this._data[key]; this._save(); }

  /** Return masked map safe to send to renderer */
  getMasked() {
    const out = {};
    for (const [k, v] of Object.entries(this._data)) {
      out[k] = v ? ('•'.repeat(Math.max(0, v.length - 4)) + v.slice(-4)) : '';
    }
    return out;
  }

  /** Which keys have values set */
  getConfiguredKeys() {
    return Object.keys(this._data).filter(k => !!this._data[k]);
  }
}

module.exports = new CredentialStore();
