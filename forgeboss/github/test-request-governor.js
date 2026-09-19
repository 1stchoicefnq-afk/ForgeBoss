#!/usr/bin/env node
'use strict';
const assert=require('assert'),fs=require('fs'),os=require('os'),path=require('path'),{spawnSync}=require('child_process');

const realUserInfo=os.userInfo.bind(os);
const base=fs.mkdtempSync(path.join(os.tmpdir(),'fb-gh-gov-'));
let activeHome=path.join(base,'home');
fs.mkdirSync(activeHome,{recursive:true});
os.userInfo=()=>({...realUserInfo(),homedir:activeHome});

const gov=require('./request-governor');
const {githubRequest,governedGitNetwork,governedGitPush,governorStatus,stateRoot,getConfig}=gov;
const resp=(status,body='',headers={})=>({status,ok:status>=200&&status<300,headers:new Headers(headers),async text(){return body}});
const c={minRequestGapMs:0,minMutationGapMs:0,maxRequestsPerMinute:1000,maxMutationsPerMinute:1000,maxMutationsPerHour:1000,cacheTtlMs:0,notFoundTtlMs:60000};
let pass=0,selected=0;
const FILTER=process.env.FB_GOV_TEST_FILTER||'';

function useHome(name){
 activeHome=path.join(base,name);
 fs.mkdirSync(activeHome,{recursive:true});
 return path.join(activeHome,'.siteboss','github-governor');
}
function auditFixture(files){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'fb-gh-audit-'));
 files={'safe.js':"console.log('safe')\n",...files};
 for(const [rel,body] of Object.entries(files)){
  const p=path.join(root,rel);fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,body);
 }
 return spawnSync(process.execPath,[path.join(__dirname,'audit-governor-bypasses.js'),root],{encoding:'utf8'});
}
async function t(n,f){
 if(FILTER&&!n.includes(FILTER))return;
 selected++;
 try{await f();console.log('PASS '+n);pass++}
 catch(e){console.error('FAIL '+n+'\n'+(e.stack||e));process.exitCode=1}
}

(async()=>{
 await t('serializes concurrent requests',async()=>{
  useHome('serial');let a=0,m=0;
  const f=async()=>{a++;m=Math.max(m,a);await new Promise(r=>setTimeout(r,40));a--;return resp(200,'{}')};
  await Promise.all([githubRequest('https://api.github.com/x/a',{}, {config:c,fetchImpl:f}),githubRequest('https://api.github.com/x/b',{}, {config:c,fetchImpl:f})]);
  assert.equal(m,1);
 });

 await t('deduplicates mutation key',async()=>{
  useHome('dedupe');let n=0;const f=async()=>{n++;return resp(201,'{}')};
  await githubRequest('https://api.github.com/x/m',{method:'POST',body:'{}'},{config:c,fetchImpl:f,dedupeKey:'same'});
  const b=await githubRequest('https://api.github.com/x/m',{method:'POST',body:'{}'},{config:c,fetchImpl:f,dedupeKey:'same'});
  assert.equal(b.deduplicated,true);assert.equal(n,1);
 });

 await t('ETag 304 reuses stale cached body',async()=>{
  const r=useHome('etag');let n=0,seen='';
  const f=async(_u,o)=>{n++;if(n===1)return resp(200,'{"v":1}',{etag:'"abc"'});seen=o.headers['If-None-Match']||'';return resp(304,'',{etag:'"abc"'})};
  const a=await githubRequest('https://api.github.com/x/e',{}, {config:c,fetchImpl:f,cacheTtlMs:0});
  const cacheDir=path.join(r,'cache'),files=fs.readdirSync(cacheDir);assert.equal(files.length,1);
  const cp=path.join(cacheDir,files[0]),cv=JSON.parse(fs.readFileSync(cp,'utf8'));cv.savedAt=0;fs.writeFileSync(cp,JSON.stringify(cv));
  const b=await githubRequest('https://api.github.com/x/e',{}, {config:c,fetchImpl:f,cacheTtlMs:0});
  assert.equal(a.body,'{"v":1}');assert.equal(b.body,'{"v":1}');assert.equal(seen,'"abc"');assert.equal(b.cached,true);
 });

 await t('429 opens circuit before next request',async()=>{
  useHome('rate');let n=0;const f=async()=>{n++;return resp(429,'secondary rate limit',{'retry-after':'60'})};
  assert.equal((await githubRequest('https://api.github.com/x/r',{}, {config:c,fetchImpl:f})).rateLimited,true);
  let blocked=false;try{await githubRequest('https://api.github.com/x/r2',{}, {config:c,fetchImpl:f})}catch(e){blocked=e.name==='GitHubCircuitOpenError'}
  assert.equal(blocked,true);assert.equal(n,1);
 });

 await t('permission 403 does not open rate circuit',async()=>{
  useHome('perm');let n=0;const f=async()=>{n++;return n===1?resp(403,'Resource not accessible by integration'):resp(200,'{}')};
  assert.equal((await githubRequest('https://api.github.com/x/p',{}, {config:c,fetchImpl:f})).status,403);
  assert.equal((await githubRequest('https://api.github.com/x/p2',{}, {config:c,fetchImpl:f})).status,200);assert.equal(n,2);
 });

 await t('repeated 404 is suppressed',async()=>{
  useHome('nf');let n=0;const f=async()=>{n++;return resp(404,'missing')};
  await githubRequest('https://api.github.com/x/n',{}, {config:c,fetchImpl:f});
  assert.equal((await githubRequest('https://api.github.com/x/n',{}, {config:c,fetchImpl:f})).cached,true);assert.equal(n,1);
 });

 await t('mutation spacing enforced',async()=>{
  useHome('gap');const times=[];const f=async()=>{times.push(Date.now());return resp(201,'{}')};
  await githubRequest('https://api.github.com/x/g1',{method:'POST',body:'{}'},{config:c,fetchImpl:f,dedupeKey:'1'});
  await githubRequest('https://api.github.com/x/g2',{method:'POST',body:'{}'},{config:c,fetchImpl:f,dedupeKey:'2'});
  assert(times[1]-times[0]>=2400);
 });

 await t('metrics redact auth and query',async()=>{
  const r=useHome('metrics');
  await githubRequest('https://api.github.com/repos/o/r/issues?secret=query',{headers:{Authorization:'Bearer SUPERSECRET'}},{config:c,fetchImpl:async()=>resp(200,'{}')});
  const x=fs.readFileSync(path.join(r,'metrics.jsonl'),'utf8');assert(!x.includes('SUPERSECRET'));assert(!x.includes('secret=query'));
 });

 await t('governed git network uses shared request budget',async()=>{
  useHome('gitnet');let called=0;
  const spawnImpl=(exe,args)=>{called++;assert(/git(?:\.exe)?$/.test(exe));assert.equal(args[0],'clone');return{status:0,stdout:'ok',stderr:''}};
  const x=await governedGitNetwork({args:['clone','https://example.invalid/repo.git','x']},{config:c,spawnImpl});
  assert.equal(x.exitCode,0);assert.equal(called,1);assert.equal(governorStatus().requests.length,1);
 });

 await t('governed git push consumes mutation budget',async()=>{
  const r=useHome('gitpush');let argsSeen=[];
  const spawnImpl=(_exe,args)=>{argsSeen=args;return{status:0,stdout:'ok',stderr:''}};
  const x=await governedGitPush({cwd:r,refspec:'HEAD:refs/heads/test'},{config:c,spawnImpl});
  assert.equal(x.exitCode,0);assert.equal(argsSeen[0],'push');assert.equal(governorStatus().mutations.length,1);
 });

 await t('governed git rejects local non-network commands',async()=>{
  useHome('badgit');let rejected=false;
  try{await governedGitNetwork({args:['status']},{config:c,spawnImpl:()=>({status:0,stdout:'',stderr:''})})}catch(e){rejected=/refusing non-network/.test(e.message)}
  assert.equal(rejected,true);
 });

 await t('long local mutation budget opens circuit instead of sleeping under lock',async()=>{
  const r=useHome('localbudget');fs.mkdirSync(r,{recursive:true});const now=Date.now();
  fs.writeFileSync(path.join(r,'state.json'),JSON.stringify({schema:1,lastRequestAt:now,lastMutationAt:now,requests:[now],mutations:[now],dedupe:{},notFound:{},circuitUntil:0,circuitReason:'',secondaryLimitStrikes:0,updatedAt:now}));
  let blocked=false;try{await githubRequest('https://api.github.com/x/hour',{method:'POST',body:'{}'},{config:{...c,maxMutationsPerHour:1},fetchImpl:async()=>resp(201,'{}')})}catch(e){blocked=e.name==='GitHubCircuitOpenError'&&/local GitHub governor budget/.test(e.reason)}
  assert.equal(blocked,true);assert(governorStatus().circuitUntil>Date.now());
 });

 await t('stale lock configuration is clamped safely',async()=>{
  const old=process.env.SITEBOSS_GITHUB_STALE_LOCK_MS;
  try{
   for(const [v,min,max] of [['5000',300000,300000],['0',300000,300000],['1',300000,300000],['999999999999',3600000,3600000],['nonsense',300000,300000]]){
    process.env.SITEBOSS_GITHUB_STALE_LOCK_MS=v;const x=getConfig();assert(x.staleLockMs>=min&&x.staleLockMs<=max,v+' -> '+x.staleLockMs);
   }
  }finally{if(old===undefined)delete process.env.SITEBOSS_GITHUB_STALE_LOCK_MS;else process.env.SITEBOSS_GITHUB_STALE_LOCK_MS=old}
 });

 await t('stale mtime cannot steal lock from live owner',async()=>{
  const r=useHome('stale-live');fs.mkdirSync(r,{recursive:true});const lock=path.join(r,'request.lock');fs.mkdirSync(lock);
  fs.writeFileSync(path.join(lock,'owner.json'),JSON.stringify({pid:process.pid,host:os.hostname(),token:'live-owner',at:Date.now()}));
  const old=new Date(Date.now()-7200000);fs.utimesSync(lock,old,old);
  let called=0,blocked=false;
  try{await githubRequest('https://api.github.com/x/stale',{}, {config:{...c,lockTimeoutMs:5000},fetchImpl:async()=>{called++;return resp(200,'{}')}})}catch(e){blocked=/lock timeout/.test(e.message)}
  assert.equal(blocked,true);assert.equal(called,0);
 });

 await t('competing writer cannot overlap after stale mtime attack',async()=>{
  const r=useHome('stale-race');let active=0,maxActive=0,started=false;
  const slow=async()=>{started=true;active++;maxActive=Math.max(maxActive,active);await new Promise(x=>setTimeout(x,700));active--;return resp(200,'{}')};
  const fast=async()=>{active++;maxActive=Math.max(maxActive,active);active--;return resp(200,'{}')};
  const a=githubRequest('https://api.github.com/x/one',{}, {config:c,fetchImpl:slow});
  while(!started)await new Promise(x=>setTimeout(x,10));
  const lock=path.join(r,'request.lock'),old=new Date(Date.now()-7200000);fs.utimesSync(lock,old,old);
  const b=githubRequest('https://api.github.com/x/two',{}, {config:c,fetchImpl:fast});
  await Promise.all([a,b]);assert.equal(maxActive,1);
 });

 await t('hard compliance limits cannot be weakened by config',async()=>{
  const x=getConfig({maxRequestsPerMinute:999,maxMutationsPerMinute:999,maxMutationsPerHour:999,minRequestGapMs:0,minMutationGapMs:0});
  assert.equal(x.maxRequestsPerMinute,30);assert.equal(x.maxMutationsPerMinute,6);assert.equal(x.maxMutationsPerHour,60);assert(x.minRequestGapMs>=500);assert(x.minMutationGapMs>=2500);
 });

 await t('hard compliance limits cannot be disabled by zero env',async()=>{
  const keys=['SITEBOSS_GITHUB_MAX_REQUESTS_PER_MINUTE','SITEBOSS_GITHUB_MAX_MUTATIONS_PER_MINUTE','SITEBOSS_GITHUB_MAX_MUTATIONS_PER_HOUR','SITEBOSS_GITHUB_MIN_REQUEST_GAP_MS','SITEBOSS_GITHUB_MIN_MUTATION_GAP_MS'],old=Object.fromEntries(keys.map(k=>[k,process.env[k]]));
  try{for(const k of keys)process.env[k]='0';const x=getConfig();assert(x.maxRequestsPerMinute>=1&&x.maxRequestsPerMinute<=30);assert(x.maxMutationsPerMinute>=1&&x.maxMutationsPerMinute<=6);assert(x.maxMutationsPerHour>=1&&x.maxMutationsPerHour<=60);assert(x.minRequestGapMs>=500);assert(x.minMutationGapMs>=2500)}
  finally{for(const k of keys){if(old[k]===undefined)delete process.env[k];else process.env[k]=old[k]}}
 });

 await t('cache TTL has safe floor and ceiling',async()=>{
  const old=process.env.SITEBOSS_GITHUB_CACHE_TTL_MS;
  try{
   for(const [v,expected] of [['0',5000],['-1',5000],['bad',15000],['2',5000],['15000',15000],['999999999',300000]]){
    process.env.SITEBOSS_GITHUB_CACHE_TTL_MS=v;assert.equal(getConfig().cacheTtlMs,expected,v);
   }
  }finally{if(old===undefined)delete process.env.SITEBOSS_GITHUB_CACHE_TTL_MS;else process.env.SITEBOSS_GITHUB_CACHE_TTL_MS=old}
 });

 await t('call-scoped cache TTL cannot disable cache',async()=>{
  useHome('cache-floor-call');let n=0;const f=async()=>{n++;return resp(200,'{"ok":1}')};
  await githubRequest('https://api.github.com/x/cache',{}, {config:c,cacheTtlMs:0,fetchImpl:f});
  const b=await githubRequest('https://api.github.com/x/cache',{}, {config:c,cacheTtlMs:0,fetchImpl:f});
  assert.equal(b.cached,true);assert.equal(n,1);
 });

 await t('production root ignores env and argv spoofing and rejects option override',async()=>{
  const evil=path.join(base,'evil-root');
  const script=[
   "process.env.NODE_ENV='test'",
   "process.env.SITEBOSS_GITHUB_GOVERNOR_DIR="+JSON.stringify(evil),
   "process.argv[1]='test-request-governor.js'",
   "const g=require("+JSON.stringify(path.join(__dirname,'request-governor.js'))+")",
   "if(g.stateRoot()===require('path').resolve("+JSON.stringify(evil)+"))process.exit(7)",
   "try{g.governorStatus({root:"+JSON.stringify(evil)+"});process.exit(8)}catch(e){if(!/not supported/.test(e.message))process.exit(9)}"
  ].join(';');
  const p=spawnSync(process.execPath,['-e',script],{encoding:'utf8'});assert.equal(p.status,0,(p.stderr||'')+(p.stdout||''));
 });

 await t('state deletion after protection history fails closed',async()=>{
  const r=useHome('state-delete');let n=0;const f=async()=>{n++;return resp(200,'{}')};
  await githubRequest('https://api.github.com/x/state',{}, {config:c,fetchImpl:f});assert(fs.existsSync(path.join(r,'state-authority.json')));
  fs.unlinkSync(path.join(r,'state.json'));
  let blocked=false;try{await githubRequest('https://api.github.com/x/state2',{}, {config:c,fetchImpl:f})}catch(e){blocked=e.name==='GitHubStateTamperError'}
  assert.equal(blocked,true);assert.equal(n,1);
 });

 await t('state reset/regression after protection history fails closed',async()=>{
  const r=useHome('state-reset');let n=0;const f=async()=>{n++;return resp(200,'{}')};
  await githubRequest('https://api.github.com/x/state',{}, {config:c,fetchImpl:f});
  fs.writeFileSync(path.join(r,'state.json'),JSON.stringify({schema:2,sequence:0,lastRequestAt:0,lastMutationAt:0,requests:[],mutations:[],dedupe:{},notFound:{},circuitUntil:0,circuitReason:'',secondaryLimitStrikes:0,updatedAt:0}));
  let blocked=false;try{await githubRequest('https://api.github.com/x/state2',{}, {config:c,fetchImpl:f})}catch(e){blocked=e.name==='GitHubStateTamperError'}
  assert.equal(blocked,true);assert.equal(n,1);
 });

 await t('whole governor state-root deletion after history fails closed',async()=>{
  const r=useHome('state-root-delete');let n=0;const f=async()=>{n++;return resp(200,'{}')};
  await githubRequest('https://api.github.com/x/root-state',{}, {config:c,fetchImpl:f});
  const authority=path.join(path.dirname(r),'github-governor-authority.json');
  assert(fs.existsSync(authority));fs.rmSync(r,{recursive:true,force:true});assert(fs.existsSync(authority));
  let blocked=false;try{await githubRequest('https://api.github.com/x/root-state2',{}, {config:c,fetchImpl:f})}catch(e){blocked=e.name==='GitHubStateTamperError'}
  assert.equal(blocked,true);assert.equal(n,1);
 });

 await t('forward clock jump remains fail-closed for local budget',async()=>{
  const r=useHome('future-clock');fs.mkdirSync(r,{recursive:true});const future=Date.now()+3600000;
  fs.writeFileSync(path.join(r,'state.json'),JSON.stringify({schema:1,lastRequestAt:future,lastMutationAt:future,requests:[future],mutations:[future],dedupe:{},notFound:{},circuitUntil:0,circuitReason:'',secondaryLimitStrikes:0,updatedAt:future}));
  let blocked=false;try{await githubRequest('https://api.github.com/x/future',{method:'POST',body:'{}'},{config:{...c,maxMutationsPerHour:1},fetchImpl:async()=>resp(201,'{}')})}catch(e){blocked=e.name==='GitHubCircuitOpenError'}
  assert.equal(blocked,true);
 });

 for(const [name,files] of [
  ['audit catches check-prs.js',{'check-prs.js':"require('child_process').execSync('gh api /user')\n"}],
  ['audit catches components/check-deploy.ps1',{'components/check-deploy.ps1':"gh api /user\n"}],
  ['audit catches break-glass.sh',{'break-glass.sh':"curl https://api.github.com/user\n"}],
  ['audit catches unmanaged psm1',{'modules/bad.psm1':"gh api /user\n"}],
  ['audit catches workflow gh api',{'.github/workflows/bad.yml':"jobs:\n  x:\n    steps:\n      - run: gh api /user\n"}],
  ['audit catches workflow curl',{'.github/workflows/bad.yaml':"jobs:\n  x:\n    steps:\n      - run: curl https://api.github.com/user\n"}],
  ['audit catches PowerShell module HTTP',{'modules/direct.psm1':"Invoke-RestMethod -Uri 'https://api.github.com/user'\n"}],
  ['governor awareness is call scoped',{'mixed.js':"const g=require('./request-governor');\nvoid g;\nfetch('https://api.github.com/user');\n"}],
  ['audit does not exempt test directory',{'test/live-worker.js':"fetch('https://api.github.com/user');\n"}],
  ['audit does not exempt fixtures directory',{'fixtures/runtime.js':"require('child_process').execSync('gh api /user');\n"}],
  ['audit does not exempt examples directory',{'examples/runner.ps1':"Invoke-RestMethod -Uri 'https://api.github.com/user'\n"}]
 ]){
  await t(name,async()=>{const p=auditFixture(files),out=(p.stderr||'')+(p.stdout||'');assert.notEqual(p.status,0,out);assert(/FAIL/.test(out),out)});
 }

 await t('audit reports multiple findings in one file',async()=>{
  const p=auditFixture({'multi.sh':"gh api /user\ncurl https://api.github.com/user\ngit push origin HEAD:main\n"}),out=(p.stderr||'')+(p.stdout||'');
  assert.notEqual(p.status,0);assert((out.match(/FAIL /g)||[]).length>=3,out);
 });

 await t('status has no credentials',async()=>{useHome('status');const s=governorStatus();assert.equal(typeof s.lastRequestAt,'number');assert(!JSON.stringify(s).includes('Authorization'))});

 const expected=FILTER?selected:37;
 console.log('\n'+pass+'/'+expected+' governor tests passed'+(FILTER?' (filtered)':''));
 if(pass!==expected)process.exitCode=1;
})().catch(e=>{console.error(e.stack||e);process.exit(2)});
