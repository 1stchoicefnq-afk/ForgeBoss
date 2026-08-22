'use strict';
const fs = require('fs');
const path = require('path');

function ensureDir(p) { fs.mkdirSync(p, { recursive: true }); }
function appendJsonl(file, event) {
  ensureDir(path.dirname(file));
  fs.appendFileSync(file, JSON.stringify(event) + '\n', 'utf8');
}
function createLogger(logFile, runId) {
  return function log(level, event, detail = {}) {
    const record = { at: new Date().toISOString(), level, run_id: runId || null, event, ...detail };
    appendJsonl(logFile, record);
    const prefix = `[${level.toUpperCase()}] ${event}`;
    const msg = detail.message ? `: ${detail.message}` : '';
    console.log(prefix + msg);
  };
}
module.exports = { createLogger, appendJsonl, ensureDir };
