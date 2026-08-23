'use strict';
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const command = process.platform === 'win32' ? 'opencode.cmd' : 'opencode';
const r = spawnSync(command, ['--version'], {
  encoding: 'utf8',
  shell: false,
  windowsHide: true,
  timeout: 30000,
});

const ok = !r.error && r.status === 0;
console.log(`[${ok ? 'PASS' : 'FAIL'}] OpenCode: ${(r.stdout || r.stderr || r.error?.message || '').trim()}`);
const dir = path.join(os.homedir(), '.forgeboss', 'runtime');
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, 'opencode-version.txt'), (r.stdout || r.stderr || '').trim());
process.exit(ok ? 0 : 2);
