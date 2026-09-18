'use strict';

const fs=require('fs'),os=require('os'),path=require('path'),crypto=require('crypto');
const {spawnSync}=require('child_process');
const sleep=ms=>new Promise(r=>setTimeout(r,Math.max(0,ms)));
const sha=v=>crypto.createHash('sha256').update(String(v)).digest('hex');

class GitHubCircuitOpenError extends Error{
 constructor(until,reason){super('GitHub governor circuit open until '+new Date(until).toISOString()+': '+(reason||'rate-limit protection'));this.name='GitHubCircuitOpenError';this.until=until;this.reason=reason||'rate-limit protection'}
}
function root(){return path.resolve(process.env.SITEBOSS_GITHUB_GOVERNOR_DIR||path.join(os.homedir(),'.siteboss','github-governor'))}
function cfg(o={}){
 const n=(k,d)=>{const v=Number(process.env[k]);return Number.isFinite(v)&&v>=0?v:d};
 return{maxRequestsPerMinute:n('SITEBOSS_GITHUB_MAX_REQUESTS_PER_MINUTE',30),maxMutationsPerMinute:n('SITEBOSS_GITHUB_MAX_MUTATIONS_PER_MINUTE',6),maxMutationsPerHour:n('SITEBOSS_GITHUB_MAX_MUTATIONS_PER_HOUR',60),minRequestGapMs:n('SITEBOSS_GITHUB_MIN_REQUEST_GAP_MS',500),minMutationGapMs:n('SITEBOSS_GITHUB_MIN_MUTATION_GAP_MS',2500),cacheTtlMs:n('SITEBOSS_GITHUB_CACHE_TTL_MS',15000),notFoundTtlMs:n('SITEBOSS_GITHUB_NOT_FOUND_TTL_MS',300000),mutationDedupeMs:n('SITEBOSS_GITHUB_MUTATION_DEDUPE_MS',300000),staleLockMs:n('SITEBOSS_GITHUB_STALE_LOCK_MS',300000),lockTimeoutMs:n('SITEBOSS_GITHUB_LOCK_TIMEOUT_MS',180000),maxCacheBodyBytes:n('SITEBOSS_GITHUB_MAX_CACHE_BODY_BYTES',1048576),...o}
}
function paths(r=root()){return{root:r,lock:path.join(r,'request.lock'),state:path.join(r,'state.json'),metrics:path.join(r,'metrics.jsonl'),cache:path.join(r,'cache')}}
function ensure(p){fs.mkdirSync(p.root,{recursive:true});fs.mkdirSync(p.cache,{recursive:true})}
function readJson(f,d){try{return JSON.parse(fs.readFileSync(f,'utf8'))}catch{return d}}
function atomic(f,v){const t=f+'.'+process.pid+'.'+Date.now()+'.tmp';fs.writeFileSync(t,JSON.stringify(v));fs.renameSync(t,f)}
function blank(){return{schema:1,lastRequestAt:0,lastMutationAt:0,requests:[],mutations:[],dedupe:{},notFound:{},circuitUntil:0,circuitReason:'',secondaryLimitStrikes:0,updatedAt:0}}
function load(p){const s={...blank(),...readJson(p.state,{})};s.requests=Array.isArray(s.requests)?s.requests:[];s.mutations=Array.isArray(s.mutations)?s.mutations:[];s.dedupe=s.dedupe&&typeof s.dedupe==='object'?s.dedupe:{};s.notFound=s.notFound&&typeof s.notFound==='object'?s.notFound:{};return s}
function save(p,s){s.updatedAt=Date.now();atomic(p.state,s)}
function metric(p,event,x={}){try{ensure(p);fs.appendFileSync(p.metrics,JSON.stringify({ts:new Date().toISOString(),event,...x})+'\n')}catch{}}
async function lock(p,c){
 ensure(p);const start=Date.now();
 while(Date.now()-start<=c.lockTimeoutMs){
  try{fs.mkdirSync(p.lock);fs.writeFileSync(path.join(p.lock,'owner.json'),JSON.stringify({pid:process.pid,at:Date.now()}));return}
  catch(e){if(e.code!=='EEXIST')throw e;try{const st=fs.statSync(p.lock);if(Date.now()-st.mtimeMs>c.staleLockMs){fs.rmSync(p.lock,{recursive:true,force:true});continue}}catch{}await sleep(150+Math.floor(Math.random()*250))}
 }
 throw new Error('GitHub governor lock timeout');
}
function unlock(p){try{fs.rmSync(p.lock,{recursive:true,force:true})}catch{}}
async function guarded(fn,o={}){const c=cfg(o.config||{}),p=paths(o.root||root());await lock(p,c);try{return await fn({p,c})}finally{unlock(p)}}
function prune(s,now){s.requests=s.requests.filter(t=>now-t<60000);s.mutations=s.mutations.filter(t=>now-t<3600000);for(const[k,t]of Object.entries(s.dedupe))if(now-t>3600000)delete s.dedupe[k];for(const[k,v]of Object.entries(s.notFound))if(!v||Number(v.until||0)<=now)delete s.notFound[k]}
const mutation=m=>!['GET','HEAD','OPTIONS'].includes(String(m||'GET').toUpperCase());
async function budget(s,c,isMutation,p){
 for(;;){
  const now=Date.now();prune(s,now);let wait=0;
  if(c.maxRequestsPerMinute>0&&s.requests.length>=c.maxRequestsPerMinute)wait=Math.max(wait,60000-(now-s.requests[0])+100);
  if(isMutation&&c.maxMutationsPerMinute>0){const a=s.mutations.filter(t=>now-t<60000);if(a.length>=c.maxMutationsPerMinute)wait=Math.max(wait,60000-(now-a[0])+100)}
  if(isMutation&&c.maxMutationsPerHour>0&&s.mutations.length>=c.maxMutationsPerHour)wait=Math.max(wait,3600000-(now-s.mutations[0])+100);
  const gap=isMutation?Math.max(c.minRequestGapMs,c.minMutationGapMs):c.minRequestGapMs,last=isMutation?Math.max(s.lastRequestAt||0,s.lastMutationAt||0):(s.lastRequestAt||0);
  wait=Math.max(wait,gap-(now-last));if(wait<=0)return;metric(p,'local_throttle',{wait_ms:wait,mutation:isMutation});await sleep(wait);
 }
}
function hobj(h){const o={};if(!h)return o;if(typeof h.forEach==='function')h.forEach((v,k)=>o[String(k).toLowerCase()]=String(v));else for(const[k,v]of Object.entries(h))o[String(k).toLowerCase()]=String(v);return o}
function cleanUrl(u){try{const x=new URL(u);return x.origin+x.pathname}catch{return String(u).split('?')[0]}}
function looksLimited(b){const s=String(b||'').toLowerCase();return s.includes('secondary rate limit')||s.includes('rate limit exceeded')||s.includes('abuse detection')||s.includes('temporarily blocked')}
function limitInfo(status,headers,body,s){
 const h=hobj(headers),limited=Number(status)===429||(Number(status)===403&&(h['retry-after']||String(h['x-ratelimit-remaining'])==='0'||looksLimited(body)));if(!limited)return null;
 const now=Date.now();let wait=0;if(h['retry-after']){const n=Number(h['retry-after']);if(Number.isFinite(n))wait=Math.max(wait,n*1000);else{const d=Date.parse(h['retry-after']);if(Number.isFinite(d))wait=Math.max(wait,d-now)}}
 if(String(h['x-ratelimit-remaining'])==='0'){const r=Number(h['x-ratelimit-reset']);if(Number.isFinite(r)&&r>0)wait=Math.max(wait,r*1000-now)}
 const strikes=Math.max(1,Number(s.secondaryLimitStrikes||0)+1);if(wait<=0)wait=Math.min(3600000,60000*(2**Math.min(5,strikes-1)));return{waitMs:Math.max(60000,wait+Math.floor(Math.random()*1000)),strikes};
}
function ckey(method,url,accept=''){return sha(String(method).toUpperCase()+'\n'+url+'\n'+accept)}
function cpath(p,k){return path.join(p.cache,k+'.json')}
function cacheGet(p,k){return readJson(cpath(p,k),null)}
function cachePut(p,k,v){try{atomic(cpath(p,k),v)}catch{}}
function result(status,headers={},body='',x={}){const h=hobj(headers);return{status:Number(status),ok:Number(status)>=200&&Number(status)<300,headers:h,body:String(body||''),cached:!!x.cached,deduplicated:!!x.deduplicated,rateLimited:!!x.rateLimited,async text(){return String(body||'')},async json(){return body?JSON.parse(String(body)):null}}}
async function githubRequest(url,options={},g={}){
 const method=String(options.method||'GET').toUpperCase(),isMutation=mutation(method),fetchImpl=g.fetchImpl||global.fetch;if(typeof fetchImpl!=='function')throw new Error('fetch is unavailable');
 return guarded(async({p,c})=>{
  const s=load(p),now=Date.now();prune(s,now);if(Number(s.circuitUntil||0)>now){metric(p,'circuit_block',{until:s.circuitUntil,reason:s.circuitReason||''});throw new GitHubCircuitOpenError(Number(s.circuitUntil),s.circuitReason||'rate-limit protection')}
  const dk=g.dedupeKey||'';if(isMutation&&dk&&s.dedupe[dk]&&now-s.dedupe[dk]<c.mutationDedupeMs){metric(p,'mutation_deduplicated',{key_hash:sha(dk).slice(0,16)});return result(208,{},'',{deduplicated:true})}
  const accept=options.headers&&(options.headers.Accept||options.headers.accept)||'',key=ckey(method,url,accept),cached=!isMutation?cacheGet(p,key):null;
  if(!isMutation&&s.notFound[key]&&Number(s.notFound[key].until||0)>now){metric(p,'not_found_suppressed',{path:cleanUrl(url)});return result(404,{},s.notFound[key].body||'',{cached:true})}
  const ttl=g.cacheTtlMs===undefined?c.cacheTtlMs:Number(g.cacheTtlMs);if(!isMutation&&cached&&ttl>0&&now-Number(cached.savedAt||0)<ttl&&cached.body!==undefined){metric(p,'cache_hit',{path:cleanUrl(url)});return result(cached.status||200,cached.headers||{},cached.body||'',{cached:true})}
  await budget(s,c,isMutation,p);const headers={...(options.headers||{})};if(!isMutation&&cached&&cached.etag&&!headers['If-None-Match']&&!headers['if-none-match'])headers['If-None-Match']=cached.etag;if(!isMutation&&cached&&cached.lastModified&&!headers['If-Modified-Since']&&!headers['if-modified-since'])headers['If-Modified-Since']=cached.lastModified;
  const started=Date.now();let r;try{r=await fetchImpl(url,{...options,method,headers})}catch(e){metric(p,'network_error',{method,path:cleanUrl(url),duration_ms:Date.now()-started,error:e.name||'Error'});throw e}
  const hs=hobj(r.headers);let body='';if(Number(r.status)!==304)body=await r.text();const done=Date.now();s.lastRequestAt=done;s.requests.push(done);if(isMutation){s.lastMutationAt=done;s.mutations.push(done)}
  if(Number(r.status)===304&&cached){cached.savedAt=done;cachePut(p,key,cached);s.secondaryLimitStrikes=0;save(p,s);metric(p,'response',{method,path:cleanUrl(url),status:304,cached:true,duration_ms:done-started,remaining:hs['x-ratelimit-remaining']||null});return result(cached.status||200,cached.headers||{},cached.body||'',{cached:true})}
  const li=limitInfo(r.status,hs,body,s);if(li){s.secondaryLimitStrikes=li.strikes;s.circuitUntil=done+li.waitMs;s.circuitReason='GitHub HTTP '+r.status+' rate-limit signal';save(p,s);metric(p,'rate_limit_circuit_open',{method,path:cleanUrl(url),status:Number(r.status),wait_ms:li.waitMs,strikes:li.strikes,remaining:hs['x-ratelimit-remaining']||null});return result(r.status,hs,body,{rateLimited:true})}
  if(Number(r.status)===403){save(p,s);metric(p,'permission_or_auth_403',{method,path:cleanUrl(url),status:403});return result(403,hs,body)}
  if(Number(r.status)===404&&!isMutation)s.notFound[key]={until:done+c.notFoundTtlMs,body:body.slice(0,65536)};
  if(r.ok){s.secondaryLimitStrikes=0;if(isMutation&&dk)s.dedupe[dk]=done;if(!isMutation&&Buffer.byteLength(body,'utf8')<=c.maxCacheBodyBytes)cachePut(p,key,{savedAt:done,status:Number(r.status),headers:hs,etag:hs.etag||'',lastModified:hs['last-modified']||'',body})}
  save(p,s);metric(p,'response',{method,path:cleanUrl(url),status:Number(r.status),mutation:isMutation,duration_ms:done-started,remaining:hs['x-ratelimit-remaining']||null});return result(r.status,hs,body);
 },g);
}
async function governedGitNetwork({cwd,args=[]},g={}){
 if(!Array.isArray(args)||args.length<1)throw new Error('git network args are required');
 const joined=args.join(' '),allowed=args[0]==='clone'||args[0]==='ls-remote'||args.includes('fetch')||(args.includes('remote')&&args.includes('update'));
 if(!allowed)throw new Error('refusing non-network git command through GitHub governor: '+joined);
 return guarded(async({p,c})=>{
  const s=load(p),now=Date.now();prune(s,now);if(Number(s.circuitUntil||0)>now)throw new GitHubCircuitOpenError(Number(s.circuitUntil),s.circuitReason||'rate-limit protection');
  await budget(s,c,false,p);const started=Date.now(),spawn=g.spawnImpl||spawnSync,gitExe=process.platform==='win32'?'git.exe':'git',r=spawn(gitExe,args,{cwd:cwd||undefined,env:process.env,encoding:'utf8',windowsHide:true,maxBuffer:20*1024*1024}),done=Date.now(),stderr=String(r.stderr||'');
  s.lastRequestAt=done;s.requests.push(done);
  if(r.status!==0&&/(rate limit|too many requests|abuse detection|secondary rate|temporarily blocked)/i.test(stderr)){const strikes=Math.max(1,Number(s.secondaryLimitStrikes||0)+1),wait=Math.min(3600000,60000*(2**Math.min(5,strikes-1)))+Math.floor(Math.random()*1000);s.secondaryLimitStrikes=strikes;s.circuitUntil=done+wait;s.circuitReason='git network rate-limit/abuse signal'}else if(r.status===0)s.secondaryLimitStrikes=0;
  save(p,s);metric(p,'git_network',{operation:String(args.find(x=>['clone','fetch','ls-remote','remote'].includes(x))||args[0]),status:Number.isInteger(r.status)?r.status:-1,duration_ms:done-started});
  return{exitCode:Number.isInteger(r.status)?r.status:-1,stdout:String(r.stdout||''),stderr};
 },g);
}
async function governedGitPush({cwd,remote='origin',refspec,extraArgs=[]},g={}){
 if(!cwd||!refspec)throw new Error('cwd and refspec are required for governed git push');
 return guarded(async({p,c})=>{
  const s=load(p),now=Date.now();prune(s,now);if(Number(s.circuitUntil||0)>now)throw new GitHubCircuitOpenError(Number(s.circuitUntil),s.circuitReason||'rate-limit protection');await budget(s,c,true,p);
  const started=Date.now(),spawn=g.spawnImpl||spawnSync,gitExe=process.platform==='win32'?'git.exe':'git',r=spawn(gitExe,['push',...extraArgs,remote,refspec],{cwd,env:process.env,encoding:'utf8',windowsHide:true,maxBuffer:10*1024*1024}),done=Date.now(),stderr=String(r.stderr||'');
  s.lastRequestAt=done;s.lastMutationAt=done;s.requests.push(done);s.mutations.push(done);
  if(r.status!==0&&/(rate limit|too many requests|abuse detection|secondary rate)/i.test(stderr)){const strikes=Math.max(1,Number(s.secondaryLimitStrikes||0)+1),wait=Math.min(3600000,60000*(2**Math.min(5,strikes-1)))+Math.floor(Math.random()*1000);s.secondaryLimitStrikes=strikes;s.circuitUntil=done+wait;s.circuitReason='git push rate-limit/abuse signal'}else if(r.status===0)s.secondaryLimitStrikes=0;
  save(p,s);metric(p,'git_push',{status:Number.isInteger(r.status)?r.status:-1,duration_ms:done-started});return{exitCode:Number.isInteger(r.status)?r.status:-1,stdout:String(r.stdout||''),stderr};
 },g);
}
function status(o={}){const p=paths(o.root||root());ensure(p);const s=load(p);prune(s,Date.now());return{root:p.root,...s}}
module.exports={GitHubCircuitOpenError,githubRequest,governedGitNetwork,governedGitPush,governorStatus:status,getConfig:cfg,stateRoot:root,_internal:{pathsFor:paths,loadState:load,saveState:save,limitInfo}};
