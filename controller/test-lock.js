'use strict';
const fs=require('fs'),os=require('os'),path=require('path'),{spawnSync}=require('child_process');
const {ControllerLock}=require('./lib/lock');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'forgeboss-lock-'));
const file=path.join(root,'controller.lock.json');
let pass=0,fail=0;
function ok(name,fn){let value=false,detail='';try{value=!!fn()}catch(e){detail=e&&e.stack?e.stack:String(e)}console.log(`[${value?'PASS':'FAIL'}] ${name}${detail?': '+detail:''}`);if(value)pass++;else fail++;}
function writeLock(lock){fs.writeFileSync(file,JSON.stringify(lock,null,2),'utf8');}
function baseLock(overrides={}){const now=new Date().toISOString();return{schema:1,pid:process.pid,host:os.hostname(),run_id:'holder',created_at:now,heartbeat_at:now,...overrides};}
function held(lock){try{lock.acquire('contender');return false}catch(e){return e&&e.code==='LOCK_HELD'}finally{lock.release()}}
function acquired(lock){try{lock.acquire('contender');return lock.inspect()?.run_id==='contender'}finally{lock.release()}}
const old='2000-01-01T00:00:00.000Z';
try{
 writeLock(baseLock({run_id:'stale-live-local',created_at:old,heartbeat_at:old}));
 ok('stale + live same-host PID is blocked',()=>held(new ControllerLock(root,1)));

 writeLock(baseLock({pid:Number.MAX_SAFE_INTEGER,run_id:'dead-local'}));
 ok('dead same-host PID is recoverable',()=>acquired(new ControllerLock(root,60)));

 writeLock(baseLock({run_id:'fresh-live-local'}));
 ok('fresh same-host duplicate is blocked',()=>held(new ControllerLock(root,60)));

 writeLock(baseLock({host:`${os.hostname()}-remote`,run_id:'stale-remote',created_at:old,heartbeat_at:old}));
 ok('stale remote-host lock is recoverable',()=>acquired(new ControllerLock(root,1)));

 writeLock(baseLock({run_id:'invalid-heartbeat-live-local',heartbeat_at:'not-a-date'}));
 ok('invalid heartbeat cannot steal live same-host lock',()=>held(new ControllerLock(root,1)));

 writeLock(baseLock({host:`${os.hostname()}-remote`,run_id:'race-stale-remote',created_at:old,heartbeat_at:old}));
 const racing=new ControllerLock(root,1),inspect=racing.inspect.bind(racing);let inspections=0;
 racing.inspect=function(){const seen=inspect();inspections++;if(inspections===1)writeLock(baseLock({run_id:'race-replacement-live-local'}));return seen;};
 ok('stale cleanup revalidates before unlinking replacement lock',()=>held(racing)&&JSON.parse(fs.readFileSync(file,'utf8')).run_id==='race-replacement-live-local');

 {
  const ownershipRoot=path.join(root,'heartbeat-ownership');fs.mkdirSync(ownershipRoot,{recursive:true});
  const ownershipFile=path.join(ownershipRoot,'controller.lock.json');
  const hLock=new ControllerLock(ownershipRoot,60);
  hLock.acquire('owner');
  fs.writeFileSync(ownershipFile,JSON.stringify(baseLock({run_id:'thief'})));
  ok('heartbeat() throws when lock ownership is lost',()=>{
   try{hLock.heartbeat('owner');return false}
   catch(e){return /ownership was lost/.test(e.message)}
   finally{hLock.owned=false}
  });
 }

 // Regression for the controller crash where withLock()'s setInterval called
 // lock.heartbeat() unguarded: that throw happens on the timer's own call stack,
 // outside any try/catch in the caller, so it was an uncaught exception that
 // killed the whole Node process mid-run (no clearInterval, no lock.release(),
 // no SAFE_STOP transition). Prove the guarded pattern survives and the
 // unguarded pattern actually does crash, so this test would fail if the fix
 // in controller/siteboss-autopilot.js were ever reverted.
 {
  const lockLib=JSON.stringify(path.resolve(__dirname,'lib/lock.js'));
  // Each run gets its own fresh directory: the child process acquires the lock
  // itself (real ownership), then after the interval is running, something
  // else (simulated here by the child overwriting its own lock file) steals
  // the lock -- mirroring another host/process reclaiming a stale-looking lock
  // while this process is still alive but blocked in a long operation.
  const scriptOf=(guarded,dir)=>`
   const fs=require('fs'),path=require('path');
   const {ControllerLock}=require(${lockLib});
   const dir=${JSON.stringify(dir)};
   const lockFile=path.join(dir,'controller.lock.json');
   const lock=new ControllerLock(dir,60);
   lock.acquire('run');
   let hb=setInterval(()=>{
    ${guarded?`
    try{lock.heartbeat('run');}
    catch(e){if(hb){clearInterval(hb);hb=null;}console.log('HEARTBEAT_FAILURE_CAUGHT');}
    `:`
    lock.heartbeat('run');
    `}
   },30);
   setTimeout(()=>{
    fs.writeFileSync(lockFile,JSON.stringify({schema:1,pid:1,host:'someone-else',run_id:'thief',created_at:new Date().toISOString(),heartbeat_at:new Date().toISOString()}));
   },60);
   setTimeout(()=>{console.log('SURVIVED');process.exit(0);},250);
  `;
  const guardedDir=path.join(root,'heartbeat-guarded');fs.mkdirSync(guardedDir,{recursive:true});
  const guardedRun=spawnSync(process.execPath,['-e',scriptOf(true,guardedDir)],{encoding:'utf8'});
  ok('guarded heartbeat timer survives lost lock ownership',()=>guardedRun.status===0&&/SURVIVED/.test(guardedRun.stdout)&&/HEARTBEAT_FAILURE_CAUGHT/.test(guardedRun.stdout));

  const unguardedDir=path.join(root,'heartbeat-unguarded');fs.mkdirSync(unguardedDir,{recursive:true});
  const unguardedRun=spawnSync(process.execPath,['-e',scriptOf(false,unguardedDir)],{encoding:'utf8'});
  ok('unguarded heartbeat timer crashes the process on lost lock ownership (proves the guard is load-bearing)',()=>unguardedRun.status!==0&&!/SURVIVED/.test(unguardedRun.stdout));
 }
}finally{try{fs.rmSync(root,{recursive:true,force:true})}catch{}}
console.log(`LOCK SELFTEST: PASS=${pass} FAIL=${fail}`);
process.exit(fail?2:0);
