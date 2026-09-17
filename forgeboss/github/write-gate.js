'use strict';
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const ROOT=path.resolve(__dirname,'..','..');
const STATE=path.join(ROOT,'.forgeboss-github-write-state');
const LOCK=STATE+'.lock';
const METRICS=STATE+'.jsonl';
const RECENT=STATE+'.recent.json';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
function log(event,extra={}){try{fs.appendFileSync(METRICS,JSON.stringify({ts:new Date().toISOString(),event,...extra})+'\n')}catch{}}
async function lock(){for(let n=0;n<120;n++){try{fs.mkdirSync(LOCK);fs.writeFileSync(path.join(LOCK,'owner'),JSON.stringify({pid:process.pid,ts:Date.now()}));return}catch(e){if(e.code!=='EEXIST')throw e;try{const s=fs.statSync(LOCK);if(Date.now()-s.mtimeMs>120000)fs.rmSync(LOCK,{recursive:true,force:true})}catch{}await sleep(250+Math.floor(Math.random()*250))}throw new Error('GitHub write gate busy')}
function unlock(){try{fs.rmSync(LOCK,{recursive:true,force:true})}catch{}}
function recent(){try{return JSON.parse(fs.readFileSync(RECENT,'utf8'))}catch{return {lastWrite:0,writes:[],keys:{}}}}
function save(s){const t=RECENT+'.tmp';fs.writeFileSync(t,JSON.stringify(s));fs.renameSync(t,RECENT)}
function retryDelay(r,attempt){const ra=r.headers.get('retry-after');if(ra){const n=Number(ra);if(Number.isFinite(n))return n*1000;const d=Date.parse(ra);if(Number.isFinite(d))return Math.max(0,d-Date.now())}const reset=Number(r.headers.get('x-ratelimit-reset'));if(reset&&Number(r.headers.get('x-ratelimit-remaining'))===0)return Math.max(1000,reset*1000-Date.now());return Math.min(60000,1000*(2**attempt))+Math.floor(Math.random()*1000)}
async function githubWrite(url,options={},key=''){
 await lock();try{
  const s=recent(),now=Date.now();s.writes=(s.writes||[]).filter(x=>now-x<60000);s.keys=s.keys||{};
  if(key&&s.keys[key]&&now-s.keys[key]<300000){log('deduplicated',{key});return {deduplicated:true}}
  if(s.writes.length>=30){const wait=60000-(now-s.writes[0])+250;log('throttle',{wait});await sleep(wait)}
  const gap=Math.max(0,2000-(Date.now()-(s.lastWrite||0)));if(gap)await sleep(gap);
  for(let attempt=0;attempt<6;attempt++){
   const r=await fetch(url,options);log('response',{status:r.status,url:new URL(url).pathname,attempt,remaining:r.headers.get('x-ratelimit-remaining')});
   if(r.ok){const t=Date.now();s.lastWrite=t;s.writes.push(t);if(key)s.keys[key]=t;save(s);return r}
   if(!([403,429,500,502,503,504].includes(r.status)))return r;
   const wait=retryDelay(r,attempt);log('backoff',{status:r.status,wait,attempt});await sleep(wait)
  }
  throw new Error('GitHub write retry budget exhausted');
 }finally{unlock()}
}
module.exports={githubWrite};
