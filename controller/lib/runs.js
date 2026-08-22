'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { atomicWriteJson, readJson, nowIso } = require('./state');
const { ensureDir } = require('./logger');

function newRunId(){return `${new Date().toISOString().replace(/[:.]/g,'-')}-${crypto.randomBytes(4).toString('hex')}`;}
function runFile(stateRoot,runId){return path.join(stateRoot,'runs',`${runId}.json`);}
function createRun(stateRoot,command){
  const runId=newRunId();
  const run={schema:1,run_id:runId,command,state:'BOOT',created_at:nowIso(),updated_at:nowIso(),
    finished_at:null,owner_action:null,changes_made:false,model_calls:0,github_writes:0,history:[]};
  ensureDir(path.join(stateRoot,'runs'));
  atomicWriteJson(runFile(stateRoot,runId),run);
  atomicWriteJson(path.join(stateRoot,'latest-run.json'),{run_id:runId});
  return run;
}
function saveRun(stateRoot,run){
  atomicWriteJson(runFile(stateRoot,run.run_id),run);
  atomicWriteJson(path.join(stateRoot,'latest-run.json'),{run_id:run.run_id});
}
function latestRun(stateRoot){
  const latest=readJson(path.join(stateRoot,'latest-run.json'),null);
  if(!latest?.run_id)return null;
  return readJson(runFile(stateRoot,latest.run_id),null);
}
function listRuns(stateRoot){
  const dir=path.join(stateRoot,'runs');
  if(!fs.existsSync(dir))return [];
  return fs.readdirSync(dir).filter(x=>x.endsWith('.json')).map(x=>readJson(path.join(dir,x),null)).filter(Boolean)
    .sort((a,b)=>String(b.created_at).localeCompare(String(a.created_at)));
}
module.exports={createRun,saveRun,latestRun,listRuns};
