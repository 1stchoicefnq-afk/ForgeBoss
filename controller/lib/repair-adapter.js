'use strict';
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');
const {run}=require('./process');
const {readJson,atomicWriteJson}=require('./state');
const {routeSpecialists,composePrompt}=require('./specialists');

function requireZeroExit(result,kind){if(!result||result.exit_code!==0){const e=new Error(`${kind} subprocess failed with exit ${result?.exit_code??'unknown'}; current report is not trusted.`);e.code='SUBPROCESS_FAILED';throw e;}}
function historicalRepairPr(cfg,control,target){return target.repair_pr||control.preferred_repair_pr?.number||cfg.control.preferred_repair_pr||0;}
function sameText(a,b){return String(a??'')===String(b??'');}
function requireBinding(ok,msg){if(!ok){const e=new Error(msg);e.code='REPORT_BINDING_MISMATCH';throw e;}}
function samePath(a,b){const x=path.resolve(a),y=path.resolve(b);return process.platform==='win32'?x.toLowerCase()===y.toLowerCase():x===y;}
function validInvocationId(id){return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(id||''));}

function replaceExactlyOnce(source,anchor,replacement,label){
 if((source.split(anchor).length-1)!==1)throw new Error(`${label} anchor missing/ambiguous`);
 return source.replace(anchor,()=>replacement);
}
function bindProducerSource(source,kind){
 let out=String(source).replace(/\r\n/g,'\n').replace(/\r/g,'\n');
 const paramAnchor="  [string]$SpecialistPlan = ''\n)";
 const paramBound="  [string]$SpecialistPlan = '',\n  [string]$InvocationId = '',\n  [string]$ForgeBossOwnershipPath = ''\n)";
 out=replaceExactlyOnce(out,paramAnchor,paramBound,`${kind} producer parameter`);
 const strictAnchor='Set-StrictMode -Version Latest';
 const validation=`${strictAnchor}\nif($InvocationId-notmatch'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'){throw 'Invalid ForgeBoss InvocationId'}\nif([string]::IsNullOrWhiteSpace($ForgeBossOwnershipPath)){throw 'Missing ForgeBoss ownership path'}`;
 out=replaceExactlyOnce(out,strictAnchor,validation,`${kind} producer strict-mode`);
 const pathOld=kind==='Repair Rat'?`$ReportPath=Join-Path $State \"repair-rat-$Stamp.json\"`:`$ReportPath=Join-Path $State \"rat-review-$Stamp.json\"`;
 const pathNew=kind==='Repair Rat'?`$ReportPath=Join-Path $State \"repair-rat-$Stamp-$InvocationId.json\"`:`$ReportPath=Join-Path $State \"rat-review-$Stamp-$InvocationId.json\"`;
 out=replaceExactlyOnce(out,pathOld,pathNew,`${kind} producer report-path`);
 const name=kind==='Repair Rat'?"name='SiteBoss Repair Rat'":"name='Repair Rat Review'";
 const bindAnchor=`${name}\n    generated_at=[DateTimeOffset]::UtcNow.ToString('o')`;
 out=replaceExactlyOnce(out,bindAnchor,`${bindAnchor}\n    invocation_id=$InvocationId`,`${kind} producer report-json`);
 const logAnchor=kind==='Repair Rat'?`Log \"Repair Rat report: $ReportPath\" 'Cyan'`:`Log \"Rat Review report: $ReportPath\" 'Cyan'`;
 out=replaceExactlyOnce(out,logAnchor,`[IO.File]::WriteAllText($ForgeBossOwnershipPath,$ReportPath,[Text.UTF8Encoding]::new($false))\n  ${logAnchor}`,`${kind} producer ownership`);
 return out;
}

function prepareBoundProducer(root,fileName,kind,invocationId){
 if(!validInvocationId(invocationId)){const e=new Error('Invalid invocation id');e.code='INVOCATION_ID_INVALID';throw e;}
 const sourcePath=path.join(root,fileName),source=fs.readFileSync(sourcePath,'utf8'),bound=bindProducerSource(source,kind);
 const tempPath=path.join(root,`.forgeboss-bound-${kind==='Repair Rat'?'repair':'review'}-${invocationId}.ps1`);
 const fd=fs.openSync(tempPath,'wx',0o600);try{fs.writeFileSync(fd,bound,'utf8');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 return tempPath;
}
function cleanupFile(p){try{fs.unlinkSync(p)}catch(e){if(e.code!=='ENOENT')throw e;}}
function readOwnedReportPath(ownershipPath,kind,dir,prefix,invocationId){
 let raw='';try{raw=fs.readFileSync(ownershipPath,'utf8').trim()}catch(e){if(e.code==='ENOENT'){const x=new Error(`${kind} subprocess produced no ownership marker.`);x.code='CURRENT_REPORT_MISSING';throw x}throw e}
 if(!raw){const e=new Error(`${kind} ownership marker is empty.`);e.code='CURRENT_REPORT_MISSING';throw e;}
 const reportPath=path.resolve(raw),reportDir=path.resolve(dir),name=path.basename(reportPath);
 if(!samePath(path.dirname(reportPath),reportDir)||!name.startsWith(prefix)||!name.endsWith(`-${invocationId}.json`)){const e=new Error(`${kind} reported an unsafe/unexpected report path: ${raw}`);e.code='CURRENT_REPORT_PATH_INVALID';throw e;}
 return reportPath;
}
function validateRepairReport(report,cfg,control,target,invocationId){
 requireBinding(report&&typeof report==='object','Repair Rat report is missing or invalid.');requireBinding(sameText(report.invocation_id,invocationId),'Repair Rat invocation mismatch.');
 const expectedPr=historicalRepairPr(cfg,control,target);requireBinding(sameText(report.repair_pr,expectedPr),`Repair Rat report PR mismatch: expected ${expectedPr}, got ${report.repair_pr}.`);requireBinding(sameText(report.exact_head,target.target_sha),`Repair Rat report head mismatch: expected ${target.target_sha}, got ${report.exact_head}.`);
 if(target.mode==='parent-head-local'){requireBinding(sameText(report.root_pr,control.root_pr.number),`Repair Rat report root PR mismatch: expected ${control.root_pr.number}, got ${report.root_pr}.`);requireBinding(report.target_mode==='parent-head-local',`Repair Rat report target mode mismatch: ${report.target_mode}.`);}else requireBinding(report.target_mode==='existing-child',`Repair Rat report target mode mismatch: ${report.target_mode}.`);return report;
}
function validateReviewReport(report,cfg,control,target,repairReport,invocationId){
 requireBinding(report&&typeof report==='object','Rat Review report is missing or invalid.');requireBinding(sameText(report.invocation_id,invocationId),'Rat Review invocation mismatch.');const expectedPr=historicalRepairPr(cfg,control,target);requireBinding(sameText(report.parent_repair_pr,expectedPr),`Rat Review parent PR mismatch: expected ${expectedPr}, got ${report.parent_repair_pr}.`);requireBinding(sameText(report.exact_parent_head,target.target_sha),`Rat Review head mismatch: expected ${target.target_sha}, got ${report.exact_parent_head}.`);requireBinding(sameText(report.local_commit,repairReport.local_commit),`Rat Review local commit mismatch: expected ${repairReport.local_commit}, got ${report.local_commit}.`);return report;
}
function currentReport(result,kind,ownershipPath,dir,prefix,invocationId,validate){requireZeroExit(result,kind);const reportPath=readOwnedReportPath(ownershipPath,kind,dir,prefix,invocationId),report=readJson(reportPath,null);if(!report){const e=new Error(`${kind} current report is unreadable.`);e.code='CURRENT_REPORT_INVALID';throw e;}validate(report);return{exit_code:result.exit_code,stdout:result.stdout||'',stderr:result.stderr||'',report_path:reportPath,report};}
function executeBound(root,fileName,kind,args){
 const invocationId=crypto.randomUUID(),ownershipPath=path.join(root,`.forgeboss-owned-${kind==='Repair Rat'?'repair':'review'}-${invocationId}.txt`),temp=prepareBoundProducer(root,fileName,kind,invocationId);
 let r;try{const exe=process.platform==='win32'?'pwsh.exe':'pwsh';r=run(exe,['-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',temp,'-InvocationId',invocationId,'-ForgeBossOwnershipPath',ownershipPath,...args],{cwd:root,timeoutMs:3600000,live:true});return{r,invocationId,ownershipPath};}finally{cleanupFile(temp)}
}

function runRepair(root,cfg,control,target,scopePath,specialistPlanPath){
 if(process.env.SITEBOSS_ALLOW_PAID_REPAIR!=='YES')throw new Error('Paid repair is locked. Use AUTOPILOT-REPAIR-PAID.cmd.');
 const reportDir=path.join(root,'state','repair-rat'),prefix='repair-rat-',args=['-RepairPullRequest',String(historicalRepairPr(cfg,control,target)),'-MaxAttempts','1','-ScopeManifest',scopePath,'-SpecialistPlan',specialistPlanPath];if(target.mode==='parent-head-local')args.push('-RootPullRequest',String(control.root_pr.number),'-TargetSha',target.target_sha);
 const {r,invocationId,ownershipPath}=executeBound(root,'SiteBoss-Repair-Rat.ps1','Repair Rat',args);try{return currentReport(r,'Repair Rat',ownershipPath,reportDir,prefix,invocationId,report=>validateRepairReport(report,cfg,control,target,invocationId));}finally{cleanupFile(ownershipPath)}
}
function runReview(root,cfg,control,target,repairReportPath){
 const repairReport=readJson(repairReportPath,null);if(!repairReport)throw new Error('Cannot route review without Repair Rat report');
 requireBinding(validInvocationId(repairReport.invocation_id),'Repair Rat report lacks a valid invocation identity.');validateRepairReport(repairReport,cfg,control,target,repairReport.invocation_id);
 const builderSpecialists=repairReport.builder_specialists||[],changed=[...new Set((repairReport.attempts||[]).flatMap(a=>a.changed_paths||[]))],reviewPacket={objective:'Independently review the exact SiteBoss repair candidate.',reason:'Independent review gate after clean acceptance.',task:'code review',changed_files:changed,findings:['transaction safety','idempotency','security','regression risk']};
 const routing=routeSpecialists(root,reviewPacket,{mode:'reviewer',builderSpecialists}),composition=composePrompt(root,reviewPacket,routing,{mode:'reviewer'}),planPath=path.join(cfg.state.root,'specialist-review-latest.json');atomicWriteJson(planPath,{routing,composition,builder_specialists:builderSpecialists});
 const args=['-RepairPullRequest',String(historicalRepairPr(cfg,control,target)),'-RepairRatReport',repairReportPath,'-SpecialistPlan',planPath];if(process.env.SITEBOSS_ALLOW_DRAFT_PUBLISH!=='YES')args.push('-NoPublish');if(target.mode==='parent-head-local')args.push('-RootPullRequest',String(control.root_pr.number),'-TargetSha',target.target_sha);
 const {r,invocationId,ownershipPath}=executeBound(root,'SiteBoss-Rat-Review.ps1','Rat Review',args),reportDir=path.join(root,'state','rat-review');try{return currentReport(r,'Rat Review',ownershipPath,reportDir,'rat-review-',invocationId,report=>validateReviewReport(report,cfg,control,target,repairReport,invocationId));}finally{cleanupFile(ownershipPath)}
}
module.exports={runRepair,runReview,_test:{validInvocationId,replaceExactlyOnce,bindProducerSource,readOwnedReportPath,validateRepairReport,validateReviewReport,currentReport}};
