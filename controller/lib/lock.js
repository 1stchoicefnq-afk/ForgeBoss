'use strict';
const fs=require('fs'),path=require('path'),os=require('os');
const {atomicWriteJson,readJson,nowIso}=require('./state');
const {ensureDir}=require('./logger');
function pidAlive(pid){if(!Number.isInteger(pid)||pid<=0)return false;try{process.kill(pid,0);return true}catch{return false}}
function lockAgeSeconds(lock){const t=Date.parse(lock?.heartbeat_at||lock?.created_at||'');if(!Number.isFinite(t))return Infinity;return Math.max(0,(Date.now()-t)/1000)}
class ControllerLock{
 constructor(stateRoot,timeoutSeconds){this.file=path.join(stateRoot,'controller.lock.json');this.timeoutSeconds=timeoutSeconds;this.owned=false;this.runId=null}
 inspect(){return readJson(this.file,null)}
 _createExclusive(lock){const fd=fs.openSync(this.file,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify(lock,null,2),'utf8');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}}
 acquire(runId){ensureDir(path.dirname(this.file));for(let attempt=0;attempt<3;attempt++){const lock={schema:1,pid:process.pid,host:os.hostname(),run_id:runId,created_at:nowIso(),heartbeat_at:nowIso()};try{this._createExclusive(lock);this.owned=true;this.runId=runId;return null}catch(e){if(e.code!=='EEXIST')throw e;const existing=this.inspect();if(!existing)continue;const sameHost=existing.host===os.hostname(),alive=sameHost&&pidAlive(existing.pid),stale=lockAgeSeconds(existing)>this.timeoutSeconds;if((sameHost&&alive&&!stale)||(!sameHost&&!stale)){const err=new Error(`Another SiteBoss controller is running (host ${existing.host}, PID ${existing.pid}, run ${existing.run_id}).`);err.code='LOCK_HELD';throw err}try{fs.unlinkSync(this.file)}catch(x){if(x.code!=='ENOENT')throw x}}}const err=new Error('Could not acquire SiteBoss controller lock after stale-lock recovery.');err.code='LOCK_BUSY';throw err}
 heartbeat(runId){if(!this.owned||runId!==this.runId)return;const cur=this.inspect();if(!cur||cur.pid!==process.pid||cur.host!==os.hostname()||cur.run_id!==this.runId){this.owned=false;throw new Error('SiteBoss controller lock ownership was lost.')}atomicWriteJson(this.file,{...cur,heartbeat_at:nowIso()})}
 release(){if(!this.owned)return;try{const cur=this.inspect();if(cur&&cur.pid===process.pid&&cur.host===os.hostname()&&cur.run_id===this.runId)fs.unlinkSync(this.file)}catch{}this.owned=false;this.runId=null}
}
module.exports={ControllerLock,pidAlive,lockAgeSeconds};
