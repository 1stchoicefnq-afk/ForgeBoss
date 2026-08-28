#!/usr/bin/env node
'use strict';
const fs=require('fs');const path=require('path');
const {loadConfig}=require('./lib/config');const {createLogger,ensureDir}=require('./lib/logger');
const {atomicWriteJson,readJson,nowIso}=require('./lib/state');const {ControllerLock}=require('./lib/lock');
const {doctor}=require('./lib/doctor');const {transition}=require('./lib/machine');
const {createRun,saveRun,latestRun,listRuns}=require('./lib/runs');
const {buildDryRunPlan}=require('./lib/planner');const {readControl,selectRepairTarget}=require('./lib/control');
const {ensureMirror}=require('./lib/mirror');const {buildScope}=require('./lib/scope');
const {buildPacket}=require('./lib/packet');const {routeSpecialists,composePrompt}=require('./lib/specialists');const {runRepair,runReview}=require('./lib/repair-adapter');
const ROOT=path.resolve(__dirname,'..');const command=(process.argv[2]||'help').toLowerCase();

function help(){console.log(`
SiteBoss Autopilot v1.4.3-fresh-evidence-cost-meter
  run       authoritative read -> exact mirror -> bounded scope -> packet -> stop
  control   verify live root/repair PR authority only
  plan      build and print bounded repair packet
  repair    explicit paid Repair Rat + independent review; optional draft publication
  autobuild one bounded live build cycle: GitHub workload -> repair -> review -> draft PR
  doctor    validate local environment and controller prerequisites
  dry-run   foundation zero-network plan
  status    show latest persisted run
  resume    reconcile interrupted controller run
  logs      show recent structured events
  costs     show recorded paid-call/write counters
  stop      request controller stop
  selftest  local controller self-tests
`);}
function paths(cfg){return{root:cfg.state.root,logs:path.join(cfg.state.root,'events.jsonl'),doctor:path.join(cfg.state.root,'doctor-latest.json'),
 plan:path.join(cfg.state.root,'dry-run-plan-latest.json'),control:path.join(cfg.state.root,'control-latest.json'),
 scope:path.join(cfg.state.root,'scope-latest.json'),packet:path.join(cfg.state.root,'packet-latest.json'),stop:path.join(cfg.state.root,'STOP')};}
function selftest(cfg){
 const out=[];const a=(n,o,d='')=>out.push({name:n,ok:!!o,detail:d});
 a('features.github_writes_draft_capable',cfg.features.github_writes===true);a('features.merge_off',cfg.features.merge===false);a('features.deploy_off',cfg.features.deploy===false);
 a('features.model_calls_off_default',cfg.features.model_calls===false);a('control.read_enabled',cfg.features.control_read===true);
 const temp=path.join(cfg.state.root,'selftest-v09');ensureDir(temp);const f=path.join(temp,'a.json');atomicWriteJson(f,{x:1});a('state.atomic',readJson(f)?.x===1);
 let bad=false;try{transition({state:'BOOT',history:[],updated_at:nowIso()},'PUBLISH','illegal');}catch{bad=true;}a('machine.invalid_transition_rejected',bad);
 const l1=new ControllerLock(temp,60),l2=new ControllerLock(temp,60);try{l1.acquire('a');let blocked=false;try{l2.acquire('b');}catch{blocked=true;}a('lock.duplicate_blocked',blocked);}finally{l1.release();l2.release();}
 try{fs.rmSync(temp,{recursive:true,force:true});}catch{}
 const fail=out.filter(x=>!x.ok).length;console.log(JSON.stringify({pass:out.length-fail,fail,results:out},null,2));return fail?2:0;
}
function withLock(cfg,name,fn){
 const p=paths(cfg);ensureDir(p.root);const run=createRun(p.root,name),log=createLogger(p.logs,run.run_id),lock=new ControllerLock(p.root,cfg.state.lock_timeout_seconds);let hb;
 try{
  const prev=lock.acquire(run.run_id);if(prev)log('warn','lock.recovered',{message:`recovered ${prev.run_id||'unknown'}`});
  hb=setInterval(()=>{
   try{lock.heartbeat(run.run_id);}
   catch(e){
    // lock.heartbeat() throws when ownership was lost (lock file deleted/stolen/
    // rewritten by another process). That throw happens on the timer's own call
    // stack, outside this function's try/catch, so previously it was an uncaught
    // exception that killed the whole controller process mid-run without ever
    // reaching the finally block below (no clearInterval, no lock.release(),
    // no SAFE_STOP transition). Catch it here, log it, and stop heartbeating
    // instead of crashing; fn() will still run to completion, but the run's
    // own state/lock bookkeeping stays intact.
    try{log('error','lock.heartbeat_failed',{message:e.message});}catch{}
    if(hb){clearInterval(hb);hb=null;}
   }
  },cfg.state.heartbeat_seconds*1000);if(hb.unref)hb.unref();
  transition(run,'PREFLIGHT','controller lock acquired');saveRun(p.root,run);log('info','run.started',{message:name});
  return fn({run,log,p})??0;
 }catch(e){
  try{run.owner_action={what_failed:e.message,anything_changed:!!run.changes_made,safe:true};if(!['SAFE_STOP','COMPLETE'].includes(run.state))try{transition(run,'SAFE_STOP',e.code||'error');}catch{};run.finished_at=nowIso();saveRun(p.root,run);}catch{}
  console.error(`[FAIL] ${e.message}`);return 2;
 }finally{if(hb)clearInterval(hb);lock.release();}
}
function preflight(cfg,p){
 const d=doctor(ROOT,cfg);
 atomicWriteJson(p.doctor,d);
 if(d.fail){
   const failed=d.checks.filter(x=>!x.ok);
   for(const c of failed)console.error(`[PREFLIGHT FAIL] ${c.name}${c.detail?`: ${c.detail}`:''}`);
   throw new Error(`Preflight failed: ${d.fail} doctor check(s) failed: ${failed.map(x=>x.name).join(', ')}`);
 }
 return d;
}
function build(cfg,run,log,p){
 transition(run,'SYNC','authoritative GitHub read-only sync');saveRun(p.root,run);
 const c=readControl(ROOT,cfg,p.root);
 const target=selectRepairTarget(c);

 if(target.mode==='existing-child'){
  transition(run,'READ_CONTROL',`root #${c.root_pr.number} -> repair #${target.repair_pr} (${c.binding.selection_reason})`);
 }else{
  transition(run,'READ_CONTROL',`root #${c.root_pr.number} -> LOCAL candidate from parent head ${target.target_sha}`);
  log('warn','repair.child.absent',{message:`No exact repair child exists. Planning fresh local candidate from root PR #${c.root_pr.number} head.`});
 }
 saveRun(p.root,run);

 const m=ensureMirror(cfg,c,target);
 transition(run,'INSPECT',`${target.mode} target ${target.target_sha}`);
 saveRun(p.root,run);

 const s=buildScope(cfg,c,m,target);
 atomicWriteJson(p.scope,s);
 transition(run,'PLAN',`scope ${s.source_paths.length}/${s.write_allowlist.length}`);
 saveRun(p.root,run);

 const packet=buildPacket(cfg,c,s,target);
 const specialistRouting=routeSpecialists(ROOT,packet,{mode:'builder'});
 const specialistComposition=composePrompt(ROOT,packet,specialistRouting,{mode:'builder'});
 packet.specialist_plan={
  mode:'builder',
  specialists:specialistRouting.specialists,
  selection:specialistRouting.selection,
  governance_precedence:true
 };
 const specialistPath=path.join(p.root,'specialist-builder-latest.json');
 atomicWriteJson(specialistPath,{routing:specialistRouting,composition:specialistComposition});
 atomicWriteJson(p.packet,packet);
 transition(run,'QUEUE',packet.packet_id);
 saveRun(p.root,run);

 log('info','packet.ready',{message:`${packet.packet_id}; mode=${target.mode}; source=${s.source_paths.length}; writable=${s.write_allowlist.length}`});
 return{control:c,target,mirror:m,scope:s,packet,specialistPath};
}
function cmdDoctor(cfg){const p=paths(cfg),d=doctor(ROOT,cfg);atomicWriteJson(p.doctor,d);for(const c of d.checks)console.log(`[${c.ok?'OK':'FAIL'}] ${c.name}${c.detail?`: ${c.detail}`:''}`);console.log(`Doctor: PASS=${d.pass} FAIL=${d.fail}`);return d.fail?2:0;}
function cmdDry(cfg){return withLock(cfg,'dry-run',({run,log,p})=>{const d=preflight(cfg,p);transition(run,'SYNC','foundation dry-run');transition(run,'READ_CONTROL','live control intentionally skipped');transition(run,'INSPECT','local only');transition(run,'PLAN','foundation plan');const plan=buildDryRunPlan(ROOT,cfg,d);atomicWriteJson(p.plan,plan);transition(run,'QUEUE','dry packet');transition(run,'COMPLETE','dry run complete');run.finished_at=nowIso();saveRun(p.root,run);console.log(JSON.stringify(plan,null,2));return 0;});}
function cmdControl(cfg){return withLock(cfg,'control',({run,log,p})=>{preflight(cfg,p);const b=build(cfg,run,log,p);transition(run,'COMPLETE','control verified');run.finished_at=nowIso();saveRun(p.root,run);console.log(JSON.stringify(b.control,null,2));return 0;});}
function cmdPlan(cfg){return withLock(cfg,'plan',({run,log,p})=>{preflight(cfg,p);const b=build(cfg,run,log,p);transition(run,'COMPLETE','bounded packet ready; no model call');run.finished_at=nowIso();saveRun(p.root,run);console.log(JSON.stringify(b.packet,null,2));return 0;});}
function cmdRun(cfg){return withLock(cfg,'run',({run,log,p})=>{preflight(cfg,p);const b=build(cfg,run,log,p);run.owner_action={anything_changed:false,safe:true,automatic_repair_available:true,message:`Packet ${b.packet.packet_id} ready. Paid execution remains explicit.`};transition(run,'COMPLETE','read/plan checkpoint complete');run.finished_at=nowIso();saveRun(p.root,run);console.log(`[DONE] ${run.owner_action.message}`);return 0;});}
function cmdRepair(cfg){return withLock(cfg,'repair',({run,log,p})=>{
 preflight(cfg,p);const b=build(cfg,run,log,p);
 if(process.env.SITEBOSS_ALLOW_PAID_REPAIR!=='YES'){transition(run,'NEEDS_OWNER','explicit paid launcher required');saveRun(p.root,run);throw new Error('Paid repair locked. Use AUTOPILOT-REPAIR-PAID.cmd.');}
 transition(run,'EXECUTE','controller-dispatched Repair Rat');saveRun(p.root,run);
 const rr=runRepair(ROOT,cfg,b.control,b.target,p.scope,b.specialistPath);run.model_calls+=Number(rr.report?.api_calls||0);saveRun(p.root,run);if(rr.stdout)console.log(rr.stdout);if(rr.stderr)console.error(rr.stderr);
 if(!rr.report_path)throw new Error('Repair Rat produced no report');
 if(!rr.report?.passed){transition(run,'NEEDS_OWNER','Repair Rat not green');run.finished_at=nowIso();run.owner_action={what_failed:rr.report?.fatal_failure?.reason||'acceptance failed',anything_changed:false,safe:true};saveRun(p.root,run);console.log('[SAFE STOP] Repair not green; no review publication attempted.');return 2;}
 transition(run,'VALIDATE','Repair Rat clean acceptance PASS');transition(run,'REVIEW','independent review-only gate');saveRun(p.root,run);
 const rv=runReview(ROOT,cfg,b.control,b.target,rr.report_path);run.model_calls+=Number(rv.report?.api_calls||0);saveRun(p.root,run);if(rv.stdout)console.log(rv.stdout);if(rv.stderr)console.error(rv.stderr);
 if(!rv.report_path)throw new Error('Independent reviewer produced no report');
 if(!rv.report?.passed){transition(run,'NEEDS_OWNER','independent review rejected candidate');run.finished_at=nowIso();run.owner_action={what_failed:rv.report?.review?.summary||'review failed',anything_changed:false,safe:true};saveRun(p.root,run);console.log('[SAFE STOP] Review rejected candidate. Nothing published.');return 2;}
 const published=Number(rv.report?.published_draft_pr||0);
 if(published){
   transition(run,'COMMIT','reviewed local commit verified');transition(run,'PUBLISH',`draft child PR #${published}`);run.github_writes+=Number(rv.report?.github_writes||0);
   transition(run,'UPDATE_CONTROL','draft child published; merge/deploy remain forbidden');transition(run,'CHECK_NEXT_WORK','one bounded cycle complete');
   transition(run,'COMPLETE',`review PASS + draft child PR #${published}`);run.finished_at=nowIso();saveRun(p.root,run);
   console.log(`[DONE] Reviewed candidate published as DRAFT child PR #${published}. NO merge. NO deploy.`);return 0;
 }
 transition(run,'COMPLETE','repair + clean acceptance + review PASS; review-only mode');run.finished_at=nowIso();saveRun(p.root,run);console.log('[DONE] Candidate passed review. No publication requested.');return 0;
 });}

function cmdAutobuild(cfg){
 if(process.env.SITEBOSS_ALLOW_PAID_REPAIR!=='YES')throw new Error('Autobuild requires SITEBOSS_ALLOW_PAID_REPAIR=YES');
 if(process.env.SITEBOSS_ALLOW_DRAFT_PUBLISH!=='YES')throw new Error('Autobuild requires SITEBOSS_ALLOW_DRAFT_PUBLISH=YES');
 return cmdRepair(cfg);
}
function cmdStatus(cfg){const r=latestRun(cfg.state.root);console.log(r?JSON.stringify(r,null,2):'No persisted SiteBoss run.');return 0;}
function cmdResume(cfg){const r=latestRun(cfg.state.root);if(!r||['COMPLETE','SAFE_STOP'].includes(r.state))return cmdRun(cfg);console.log(`Reconciling interrupted ${r.run_id} from ${r.state}; starting fresh read/plan checkpoint.`);return cmdRun(cfg);}
function cmdLogs(cfg){const f=paths(cfg).logs;if(!fs.existsSync(f)){console.log('No logs found.');return 0;}for(const l of fs.readFileSync(f,'utf8').trim().split(/\r?\n/).filter(Boolean).slice(-100))console.log(l);return 0;}
function cmdCosts(cfg){const rs=listRuns(cfg.state.root);console.log(JSON.stringify({runs:rs.length,model_calls_recorded:rs.reduce((n,r)=>n+Number(r.model_calls||0),0),github_writes_recorded:rs.reduce((n,r)=>n+Number(r.github_writes||0),0)},null,2));return 0;}
function cmdStop(cfg){const p=paths(cfg);ensureDir(p.root);fs.writeFileSync(p.stop,new Date().toISOString());console.log(`Stop requested: ${p.stop}`);return 0;}

let cfg;try{cfg=loadConfig(ROOT);}catch(e){console.error(`[CONFIG FAIL] ${e.message}`);process.exit(2);}
let code=0;switch(command){
 case'doctor':code=cmdDoctor(cfg);break;case'dry-run':code=cmdDry(cfg);break;case'control':code=cmdControl(cfg);break;case'plan':code=cmdPlan(cfg);break;
 case'run':code=cmdRun(cfg);break;case'repair':code=cmdRepair(cfg);break;case'autobuild':code=cmdAutobuild(cfg);break;case'status':code=cmdStatus(cfg);break;case'resume':code=cmdResume(cfg);break;
 case'logs':code=cmdLogs(cfg);break;case'costs':code=cmdCosts(cfg);break;case'stop':code=cmdStop(cfg);break;case'selftest':code=selftest(cfg);break;case'help':help();break;default:help();code=2;
}process.exit(code);
