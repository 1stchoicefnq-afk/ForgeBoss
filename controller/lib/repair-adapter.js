'use strict';
const fs=require('fs');
const path=require('path');
const {run}=require('./process');
const {readJson,atomicWriteJson}=require('./state');
const {routeSpecialists,composePrompt}=require('./specialists');

function newestJson(dir,prefix){
  if(!fs.existsSync(dir))return null;
  return fs.readdirSync(dir)
    .filter(x=>x.startsWith(prefix)&&x.endsWith('.json'))
    .map(x=>({p:path.join(dir,x),t:fs.statSync(path.join(dir,x)).mtimeMs}))
    .sort((a,b)=>b.t-a.t)[0]?.p||null;
}

function historicalRepairPr(cfg,control,target){
  return target.repair_pr || control.preferred_repair_pr?.number || cfg.control.preferred_repair_pr || 0;
}

function runRepair(root,cfg,control,target,scopePath,specialistPlanPath){
  if(process.env.SITEBOSS_ALLOW_PAID_REPAIR!=='YES'){
    throw new Error('Paid repair is locked. Use AUTOPILOT-REPAIR-PAID.cmd.');
  }
  const exe=process.platform==='win32'?'pwsh.exe':'pwsh';
  const args=[
    '-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',
    path.join(root,'SiteBoss-Repair-Rat.ps1'),
    '-RepairPullRequest',String(historicalRepairPr(cfg,control,target)),
    '-MaxAttempts','1',
    '-ScopeManifest',scopePath,
    '-SpecialistPlan',specialistPlanPath
  ];
  if(target.mode==='parent-head-local'){
    args.push('-RootPullRequest',String(control.root_pr.number),'-TargetSha',target.target_sha);
  }
  const r=run(exe,args,{cwd:root,timeoutMs:3600000,live:true});
  const rp=newestJson(path.join(root,'state','repair-rat'),'repair-rat-');
  return {exit_code:r.exit_code,stdout:r.stdout,stderr:r.stderr,report_path:rp,report:rp?readJson(rp,null):null};
}

function runReview(root,cfg,control,target,repairReportPath){
  const repairReport=readJson(repairReportPath,null);
  if(!repairReport)throw new Error('Cannot route review without Repair Rat report');
  const builderSpecialists=repairReport.builder_specialists||[];
  const changed=[...new Set((repairReport.attempts||[]).flatMap(a=>a.changed_paths||[]))];
  const reviewPacket={
    objective:'Independently review the exact SiteBoss repair candidate.',
    reason:'Independent review gate after clean acceptance.',
    task:'code review',
    changed_files:changed,
    findings:['transaction safety','idempotency','security','regression risk']
  };
  const routing=routeSpecialists(root,reviewPacket,{mode:'reviewer',builderSpecialists});
  const composition=composePrompt(root,reviewPacket,routing,{mode:'reviewer'});
  const planPath=path.join(cfg.state.root,'specialist-review-latest.json');
  atomicWriteJson(planPath,{routing,composition,builder_specialists:builderSpecialists});

  const exe=process.platform==='win32'?'pwsh.exe':'pwsh';
  const args=[
    '-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',
    path.join(root,'SiteBoss-Rat-Review.ps1'),
    '-RepairPullRequest',String(historicalRepairPr(cfg,control,target)),
    '-RepairRatReport',repairReportPath,
    '-SpecialistPlan',planPath
  ];
  if(process.env.SITEBOSS_ALLOW_DRAFT_PUBLISH!=='YES'){
    args.push('-NoPublish');
  }
  if(target.mode==='parent-head-local'){
    args.push('-RootPullRequest',String(control.root_pr.number),'-TargetSha',target.target_sha);
  }
  const r=run(exe,args,{cwd:root,timeoutMs:3600000,live:true});
  const rp=newestJson(path.join(root,'state','rat-review'),'rat-review-');
  return {exit_code:r.exit_code,stdout:r.stdout,stderr:r.stderr,report_path:rp,report:rp?readJson(rp,null):null};
}

module.exports={runRepair,runReview};
