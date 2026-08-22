'use strict';
const fs=require('fs'),os=require('os'),path=require('path');
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
}finally{try{fs.rmSync(root,{recursive:true,force:true})}catch{}}
console.log(`LOCK SELFTEST: PASS=${pass} FAIL=${fail}`);
process.exit(fail?2:0);
