'use strict';
const fs = require('fs');
const path = require('path');

function expandEnv(s) {
  if (typeof s !== 'string') return s;
  return s.replace(/%([^%]+)%/g, (_, name) => process.env[name] || `%${name}%`);
}
function deepExpand(value) {
  if (Array.isArray(value)) return value.map(deepExpand);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, deepExpand(v)]));
  }
  return expandEnv(value);
}
function loadConfig(root) {
  const file = path.join(root, 'controller', 'config.default.json');
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const cfg = deepExpand(raw);
  const errors = [];
  if (cfg.schema !== 1) errors.push('Unsupported config schema');
  if (!cfg.project) errors.push('project missing');
  if (!cfg.repository?.url) errors.push('repository.url missing');
  if (!cfg.repository?.expected_name) errors.push('repository.expected_name missing');
  if (!cfg.state?.root) errors.push('state.root missing');
  if (!(cfg.state?.lock_timeout_seconds > 0)) errors.push('state.lock_timeout_seconds invalid');
  if (!(cfg.state?.heartbeat_seconds > 0)) errors.push('state.heartbeat_seconds invalid');
  if (!(cfg.budgets?.max_model_calls_per_run >= 0)) errors.push('budget max_model_calls_per_run invalid');
  if (errors.length) {
    const e = new Error(`Configuration invalid: ${errors.join('; ')}`);
    e.code = 'CONFIG_INVALID';
    throw e;
  }
  return cfg;
}
module.exports = { loadConfig };
