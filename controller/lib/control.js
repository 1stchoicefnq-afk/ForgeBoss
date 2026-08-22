'use strict';
const path=require('path');
const {run}=require('./process');
const {readJson}=require('./state');

function readControl(root,cfg,stateRoot){
  const out=path.join(stateRoot,'control-latest.json');
  const a=cfg.control.github_app;
  const exe=process.platform==='win32'?'pwsh.exe':'pwsh';
  const args=[
    '-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',
    path.join(root,'controller','adapters','Read-GitHub-Control.ps1'),
    '-Owner',cfg.control.owner,
    '-Repo',cfg.control.repo,
    '-RootPr',String(cfg.control.root_pr),
    '-PreferredRepairPr',String(cfg.control.preferred_repair_pr||0),
    '-AppId',String(a.app_id),
    '-InstallationId',String(a.installation_id),
    '-PemPath',String(a.pem_path),
    '-Output',out
  ];
  const r=run(exe,args,{cwd:root,timeoutMs:90000});
  if(r.exit_code!==0){
    throw new Error(`Authoritative control read failed: ${(r.stderr||r.stdout||r.error).trim()}`);
  }
  const c=readJson(out,null);
  if(!c?.binding?.status)throw new Error('Authoritative control result is malformed');
  if(c.binding.status==='EXACT_REPAIR_CHILD_BOUND'){
    if(!c.repair_pr?.number || !c.binding.repair_base_equals_root_head){
      throw new Error('Authoritative exact repair binding is internally inconsistent');
    }
  }
  return c;
}


function selectRepairTarget(control){
  if(control?.binding?.status==='EXACT_REPAIR_CHILD_BOUND' && control.repair_pr){
    return {
      mode:'existing-child',
      root_pr:control.root_pr.number,
      repair_pr:control.repair_pr.number,
      target_sha:control.repair_pr.head_sha,
      base_sha:control.repair_pr.base_sha,
      target_ref:control.repair_pr.head_ref,
      base_ref:control.repair_pr.base_ref
    };
  }
  if(control?.binding?.status==='NO_CURRENT_EXACT_REPAIR_CHILD' && control.root_pr){
    return {
      mode:'parent-head-local',
      root_pr:control.root_pr.number,
      repair_pr:null,
      target_sha:control.root_pr.head_sha,
      base_sha:control.root_pr.base_sha,
      target_ref:control.root_pr.head_ref,
      base_ref:control.root_pr.base_ref
    };
  }
  throw new Error('Unable to derive repair target from control state');
}
module.exports={readControl,selectRepairTarget};

