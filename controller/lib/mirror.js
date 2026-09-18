'use strict';
const fs=require('fs');const path=require('path');const {spawnSync}=require('child_process');
const {run}=require('./process');const {ensureDir}=require('./logger');
function git(args,cwd,timeoutMs=180000){
 const exe=process.platform==='win32'?'git.exe':'git';
 const r=run(exe,args,{cwd,timeoutMs});
 if(r.exit_code!==0){const e=new Error(`git ${args[0]} failed: ${(r.stderr||r.stdout||r.error).trim()}`);e.git_exit=r.exit_code;throw e;}
 return r.stdout.trim();
}
function governedGit(args,cwd,timeoutMs=300000){
 const root=path.resolve(__dirname,'..','..');
 const cli=path.join(root,'forgeboss','github','github-gate-cli.js');
 const node=process.execPath;
 const p=spawnSync(node,[cli],{
  cwd:cwd||undefined,
  input:JSON.stringify({mode:'git-network',cwd:cwd||undefined,args}),
  encoding:'utf8',
  windowsHide:true,
  timeout:timeoutMs,
  maxBuffer:20*1024*1024
 });
 let j=null;try{j=JSON.parse(p.stdout||'{}')}catch{}
 if(p.status!==0||!j||!j.ok){
  const detail=(j&&j.stderr)||p.stderr||p.stdout||p.error?.message||'unknown failure';
  const e=new Error('governed git '+args[0]+' failed: '+String(detail).trim());e.git_exit=(j&&j.exitCode)||p.status||1;throw e;
 }
 return String(j.stdout||'').trim();
}
function ensureMirror(cfg,c,target){
 const mirror=cfg.repository.local_mirror;ensureDir(path.dirname(mirror));
 if(!target)throw new Error('Repair target missing');

 if(!fs.existsSync(mirror))governedGit(['clone','--mirror',cfg.repository.url,mirror],undefined,300000);
 git(['--git-dir',mirror,'remote','set-url','origin',cfg.repository.url]);
 const specs=[
  `+refs/pull/${c.root_pr.number}/head:refs/siteboss/root/${c.root_pr.number}`,
  `+refs/heads/${c.root_pr.base_ref}:refs/siteboss/base/${c.root_pr.base_ref}`
 ];
 if(target.mode==='existing-child'){
  specs.push(`+refs/pull/${target.repair_pr}/head:refs/siteboss/repair/${target.repair_pr}`);
 }
 governedGit(['--git-dir',mirror,'fetch','--prune','origin',...specs],undefined,300000);

 const root=git(['--git-dir',mirror,'rev-parse',`refs/siteboss/root/${c.root_pr.number}`]);
 if(root!==c.root_pr.head_sha)throw new Error(`Mirror root SHA mismatch: api=${c.root_pr.head_sha} mirror=${root}`);

 let repair=null;
 if(target.mode==='existing-child'){
  repair=git(['--git-dir',mirror,'rev-parse',`refs/siteboss/repair/${target.repair_pr}`]);
  if(repair!==target.target_sha)throw new Error(`Mirror repair SHA mismatch: target=${target.target_sha} mirror=${repair}`);
 }else if(target.target_sha!==root){
  throw new Error(`Parent-head local target mismatch: target=${target.target_sha} root=${root}`);
 }

 return {mirror,root_sha:root,repair_sha:repair,target_sha:target.target_sha,target_mode:target.mode};
}
module.exports={ensureMirror,git};
