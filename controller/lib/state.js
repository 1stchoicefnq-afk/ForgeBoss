'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ensureDir } = require('./logger');

function atomicWriteJson(file, obj) {
  ensureDir(path.dirname(file));
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(6).toString('hex')}`;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}
function readJson(file, fallback = null) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function sha256Text(text) { return crypto.createHash('sha256').update(text, 'utf8').digest('hex'); }
function nowIso() { return new Date().toISOString(); }

module.exports = { atomicWriteJson, readJson, sha256Text, nowIso };
