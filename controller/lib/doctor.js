'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const { run } = require('./process');

function commandVersion(exe, args) {
  const r = run(exe, args, { timeoutMs: 15000 });
  return { ok: r.exit_code === 0, output: (r.stdout || r.stderr).trim(), error: r.error };
}
function diskCheck(targetPath) {
  try {
    fs.mkdirSync(targetPath, { recursive: true });
    const probe = path.join(targetPath, `.probe-${process.pid}`);
    fs.writeFileSync(probe, 'ok', 'utf8');
    fs.unlinkSync(probe);
    return { ok: true, message: 'state root writable' };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}
function doctor(root, cfg) {
  const checks = [];
  const add = (name, ok, detail) => checks.push({ name, ok: !!ok, detail: detail || '' });

  const node = commandVersion(process.execPath, ['--version']);
  add('runtime.node', node.ok, node.output);

  const git = commandVersion('git.exe', ['--version']);
  add('runtime.git', git.ok, git.output || git.error);

  const pwsh = commandVersion('pwsh.exe', ['-NoLogo','-NoProfile','-Command','$PSVersionTable.PSVersion.ToString()']);
  add('runtime.powershell', pwsh.ok, pwsh.output || pwsh.error);

  const docker = commandVersion('docker.exe', ['info','--format','{{json .ServerVersion}}']);
  add('runtime.docker', docker.ok, docker.output || docker.error);

  const write = diskCheck(cfg.state.root);
  add('state.writable', write.ok, write.message);
  if (cfg.features.control_read) {
    add('control.github_app_pem', fs.existsSync(cfg.control.github_app.pem_path), cfg.control.github_app.pem_path);
    add('control.github_reads_enabled', cfg.features.github_reads === true, String(cfg.features.github_reads));
  }

  for (const [key, rel] of Object.entries(cfg.adapters || {})) {
    const file = path.join(root, rel);
    add(`adapter.${key}`, fs.existsSync(file), file);
  }

  const publication = cfg.publication || {};
  add(
    'config.live_execution_guarded',
    cfg.features.live_execution === true && cfg.features.repair_pipeline === true,
    `live_execution=${cfg.features.live_execution}; repair_pipeline=${cfg.features.repair_pipeline}`
  );
  add(
    'config.github_writes_draft_guarded',
    cfg.features.github_writes === true &&
      publication.draft_child_pr_only === true &&
      publication.requires_env_gate === 'SITEBOSS_ALLOW_DRAFT_PUBLISH=YES' &&
      publication.merge === false &&
      publication.deploy === false &&
      publication.force_push === false,
    `github_writes=${cfg.features.github_writes}; draft_only=${publication.draft_child_pr_only}; gate=${publication.requires_env_gate || ''}`
  );
  add('config.model_calls_default_off', cfg.features.model_calls === false, String(cfg.features.model_calls));
  add('config.merge_off', cfg.features.merge === false, String(cfg.features.merge));
  add('config.deploy_off', cfg.features.deploy === false, String(cfg.features.deploy));

  return { schema:1, generated_at:new Date().toISOString(), host:os.hostname(),
    pass:checks.filter(x=>x.ok).length, fail:checks.filter(x=>!x.ok).length, checks };
}
module.exports = { doctor };
