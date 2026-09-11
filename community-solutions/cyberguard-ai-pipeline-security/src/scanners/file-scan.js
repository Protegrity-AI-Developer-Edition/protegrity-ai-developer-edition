/**
 * file-scan.js — Real file hash scanner via VirusTotal
 *
 * Computes the SHA-256 hash of a file locally (no file data leaves the machine),
 * then queries the VirusTotal v3 API for a prior analysis of that hash.
 *
 * Free tier: 4 requests/min, 500/day.
 * Returns null for unknown hashes (file has never been submitted to VT).
 */

'use strict';

const crypto = require('crypto');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');

// ── SHA-256 helper ────────────────────────────────────────────────────────────

function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash   = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data',  chunk => hash.update(chunk));
    stream.on('end',   () => resolve(hash.digest('hex')));
  });
}

// ── VirusTotal lookup ─────────────────────────────────────────────────────────

function vtRequest(path_, apiKey) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'www.virustotal.com',
      path:     path_,
      method:   'GET',
      headers:  { 'x-apikey': apiKey },
    }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, json: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, json: null }); }
      });
    });
    req.setTimeout(12000, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.end();
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Scan a file by its hash via VirusTotal.
 *
 * @param {string} filePath   Absolute path to the file on disk
 * @param {string} apiKey     VirusTotal API key
 * @returns {Promise<ScanResult>}
 *
 * ScanResult shape:
 * {
 *   filePath, fileName, sha256, fileSize,
 *   verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown',
 *   malicious, suspicious, harmless, undetected, total,
 *   names: string[],      // names AV vendors gave the file
 *   firstSeen, lastSeen,
 *   summary: string,
 * }
 */
async function scanFile(filePath, apiKey) {
  if (!apiKey) {
    return { error: 'No VirusTotal API key configured. Add it in Settings.' };
  }

  // Stat the file first
  let stat;
  try { stat = fs.statSync(filePath); }
  catch { return { error: `Cannot read file: ${filePath}` }; }

  if (!stat.isFile()) return { error: 'Path is not a regular file.' };
  if (stat.size > 650 * 1024 * 1024) return { error: 'File too large (> 650 MB).' };

  // Hash locally
  let sha256;
  try { sha256 = await hashFile(filePath); }
  catch (e) { return { error: `Hash error: ${e.message}` }; }

  // Query VT
  let res;
  try { res = await vtRequest(`/api/v3/files/${sha256}`, apiKey); }
  catch (e) { return { error: `Network error: ${e.message}` }; }

  if (res.status === 404) {
    return {
      filePath, fileName: path.basename(filePath), sha256,
      fileSize: stat.size,
      verdict: 'unknown',
      summary: 'File hash not found in VirusTotal database. It may be safe or simply not yet submitted.',
    };
  }

  if (res.status !== 200 || !res.json?.data) {
    return { error: `VirusTotal returned HTTP ${res.status}` };
  }

  const attrs = res.json.data.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const malicious  = stats.malicious  || 0;
  const suspicious = stats.suspicious || 0;
  const harmless   = stats.harmless   || 0;
  const undetected = stats.undetected || 0;
  const total      = malicious + suspicious + harmless + undetected;

  // Collect AV engine names that flagged it
  const names = [];
  for (const [engine, result] of Object.entries(attrs.last_analysis_results || {})) {
    if (result.category === 'malicious' || result.category === 'suspicious') {
      names.push(`${engine}: ${result.result || result.category}`);
    }
  }

  const verdict = malicious >= 3  ? 'malicious'
               : malicious >= 1 || suspicious >= 5 ? 'suspicious'
               : 'clean';

  const summary = verdict === 'malicious'
    ? `MALICIOUS — ${malicious}/${total} engines detected threats.`
    : verdict === 'suspicious'
    ? `Suspicious — ${malicious + suspicious}/${total} engines flagged this file.`
    : `Clean — 0/${total} detections.`;

  return {
    filePath,
    fileName:  path.basename(filePath),
    sha256,
    fileSize:  stat.size,
    verdict,
    malicious,
    suspicious,
    harmless,
    undetected,
    total,
    names:     names.slice(0, 20),
    firstSeen: attrs.first_submission_date
               ? new Date(attrs.first_submission_date * 1000).toISOString() : null,
    lastSeen:  attrs.last_analysis_date
               ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
    summary,
  };
}

module.exports = { scanFile, hashFile };
