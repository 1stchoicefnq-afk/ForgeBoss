'use strict';
const { spawnSync } = require('child_process');

function run(exe, args, opts = {}) {
  const live = opts.live === true;
  const result = spawnSync(exe, args, {
    cwd: opts.cwd,
    env: opts.env || process.env,
    encoding: 'utf8',
    windowsHide: true,
    timeout: opts.timeoutMs || 120000,
    shell: false,
    stdio: live ? 'inherit' : 'pipe',
  });
  return {
    exit_code: result.status === null ? 1 : result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error ? String(result.error.message || result.error) : '',
  };
}
module.exports = { run };
