'use strict';
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');
const {run}=require('./process');

const CONTROL_MARKER='FORGEBOSS_CONTROL_RESULT_B64=';
const SHA=/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const HEX64=/^[0-9a-f]{64}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const REPAIR_RUNTIME_ENV_KEYS=[
 'SITEBOSS_ALLOW_PAID_REPAIR','SITEBOSS_ALLOW_DRAFT_PUBLISH','SITEBOSS_TEST_IMAGE','SITEBOSS_REPAIR_PROVIDER','SITEBOSS_RAT_REVIEW_PROVIDER','SITEBOSS_REVIEW_PROVIDER',
 'SITEBOSS_OPENAI_MODEL','SITEBOSS_ANTHROPIC_MODEL','SITEBOSS_FORGEBOSS_DEBUG_FUNNEL','SITEBOSS_FORGEBOSS_RETAINED_FOUNDATION',
 'SITEBOSS_OPENAI_INPUT_USD_PER_M','SITEBOSS_OPENAI_CACHED_INPUT_USD_PER_M','SITEBOSS_OPENAI_OUTPUT_USD_PER_M','SITEBOSS_OPENAI_REASONING_EFFORT','SITEBOSS_OPENAI_MAX_OUTPUT_TOKENS',
 'OPENAI_API_KEY','ANTHROPIC_API_KEY','DOCKER_HOST','DOCKER_CONTEXT','DOCKER_CONFIG'
];
function sha256(buf){return crypto.createHash('sha256').update(buf).digest('hex');}
function fail(msg,code='CONTROL_BINDING_MISMATCH'){const e=new Error(msg);e.code=code;throw e;}
function str(v,name){if(typeof v!=='string'||!v||/[\x00-\x1f\x7f]/.test(v))fail(`${name} invalid`);return v;}
function oid(v,name){v=str(v,name);if(!SHA.test(v))fail(`${name} invalid`);return v;}
function sameFsPath(a,b){const x=path.resolve(a),y=path.resolve(b);return process.platform==='win32'?x.toLowerCase()===y.toLowerCase():x===y;}
function decodeCanonicalBase64(text,maxBytes=2*1024*1024){
 if(typeof text!=='string'||text.length===0||text.length%4!==0||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text))fail('authoritative control producer base64 is non-canonical','CONTROL_RESULT_INVALID');
 let raw;try{raw=Buffer.from(text,'base64');}catch(e){fail(`authoritative control producer base64 invalid: ${e.message}`,'CONTROL_RESULT_INVALID');}
 if(raw.length>maxBytes||raw.toString('base64')!==text)fail('authoritative control producer base64 is non-canonical/oversized','CONTROL_RESULT_INVALID');
 return raw;
}
function parseControlResult(stdout,invocationId){
 if(!UUID.test(String(invocationId||'')))fail('control invocation id invalid','CONTROL_INVOCATION_INVALID');
 const lines=String(stdout||'').split(/\r?\n/).filter(x=>x.startsWith(CONTROL_MARKER));
 if(lines.length!==1)fail(`authoritative control producer returned ${lines.length} result markers`,'CONTROL_RESULT_MARKER_INVALID');
 let raw,obj;try{raw=decodeCanonicalBase64(lines[0].slice(CONTROL_MARKER.length));obj=JSON.parse(raw.toString('utf8'));}catch(e){if(e?.code)throw e;fail(`authoritative control producer result invalid: ${e.message}`,'CONTROL_RESULT_INVALID');}
 if(!obj||typeof obj!=='object'||Array.isArray(obj))fail('authoritative control producer result must be object','CONTROL_RESULT_INVALID');
 if(obj.invocation_id!==invocationId)fail('authoritative control invocation mismatch');
 return{raw,obj};
}
function validateControlResult(c,cfg,invocationId){
 if(c.schema!==3||c.invocation_id!==invocationId)fail('authoritative control schema/invocation mismatch');
 const owner=str(cfg.control.owner,'configured owner'),repo=str(cfg.control.repo,'configured repo'),rootPr=Number(cfg.control.root_pr);
 if(c.owner!==owner||c.repo!==repo)fail('authoritative control owner/repo mismatch');
 if(!Number.isInteger(rootPr)||rootPr<=0||c.root_pr?.number!==rootPr)fail('authoritative root PR mismatch');
 if(c.root_pr?.state!=='open')fail('authoritative root PR is not open');
 const expectedRootUrl=`https://api.github.com/repos/${owner}/${repo}/pulls/${rootPr}`;
 if(c.root_pr?.api_url!==expectedRootUrl||typeof c.root_pr?.node_id!=='string'||!c.root_pr.node_id)fail('authoritative root PR object identity mismatch');
 oid(c.root_pr.head_sha,'root head SHA');oid(c.root_pr.base_sha,'root base SHA');str(c.root_pr.head_ref,'root head ref');str(c.root_pr.base_ref,'root base ref');
 if(c.binding?.repository!==`${owner}/${repo}`)fail('authoritative binding repository mismatch');
 if(!['EXACT_REPAIR_CHILD_BOUND','NO_CURRENT_EXACT_REPAIR_CHILD'].includes(c.binding?.status))fail('authoritative binding status invalid');
 if(c.binding.status==='EXACT_REPAIR_CHILD_BOUND'){
  const r=c.repair_pr;if(!r||!Number.isInteger(r.number)||r.number<=0)fail('authoritative repair PR missing');
  if(r.repo!==`${owner}/${repo}`)fail('authoritative repair repository mismatch');
  if(r.api_url!==`https://api.github.com/repos/${owner}/${repo}/pulls/${r.number}`||typeof r.node_id!=='string'||!r.node_id)fail('authoritative repair PR object identity mismatch');
  oid(r.head_sha,'repair head SHA');oid(r.base_sha,'repair base SHA');str(r.head_ref,'repair head ref');str(r.base_ref,'repair base ref');
  if(r.base_sha!==c.root_pr.head_sha||r.base_ref!==c.root_pr.head_ref||c.binding.repair_base_equals_root_head!==true)fail('authoritative exact repair binding inconsistent');
 }else{
  if(c.repair_pr!==null||c.binding.repair_base_equals_root_head!==false)fail('authoritative no-child binding inconsistent');
 }
 return c;
}
function assertNoLinksAbsolute(target,code='CONTROL_ARTIFACT_LINK'){
 const full=path.resolve(target),parsed=path.parse(full);let cur=parsed.root;
 for(const part of full.slice(parsed.root.length).split(path.sep).filter(Boolean)){
  cur=path.join(cur,part);let st;try{st=fs.lstatSync(cur);}catch(e){fail(`artifact path unreadable: ${cur}: ${e.message}`,code);}
  if(st.isSymbolicLink())fail(`artifact path contains symlink/junction: ${cur}`,code);
 }
 return full;
}
function trustedPowerShell(spec){
 if(!spec||typeof spec!=='object'||Array.isArray(spec))fail('trusted PowerShell configuration missing','POWERSHELL_AUTHORITY_INVALID');
 const configured=str(spec.path,'PowerShell executable path');
 if(!path.isAbsolute(configured))fail('PowerShell executable path must be absolute','POWERSHELL_AUTHORITY_INVALID');
 const expected=str(spec.sha256,'PowerShell executable SHA256').toLowerCase();
 if(!HEX64.test(expected))fail('PowerShell executable SHA256 invalid','POWERSHELL_AUTHORITY_INVALID');
 const target=path.normalize(configured);
 assertNoLinksAbsolute(target,'POWERSHELL_EXECUTABLE_LINK');
 let st;try{st=fs.lstatSync(target);}catch(e){fail(`PowerShell executable unreadable: ${e.message}`,'POWERSHELL_EXECUTABLE_INVALID');}
 if(!st.isFile()||st.isSymbolicLink())fail('PowerShell executable is not a regular file','POWERSHELL_EXECUTABLE_INVALID');
 let real;try{real=fs.realpathSync.native?fs.realpathSync.native(target):fs.realpathSync(target);}catch(e){fail(`PowerShell executable cannot be resolved: ${e.message}`,'POWERSHELL_EXECUTABLE_INVALID');}
 if(!sameFsPath(real,target))fail('PowerShell executable resolves through an alias/link','POWERSHELL_EXECUTABLE_LINK');
 const actual=sha256(fs.readFileSync(target));
 if(actual!==expected)fail(`PowerShell executable identity drift: expected ${expected} got ${actual}`,'POWERSHELL_EXECUTABLE_DRIFT');
 return target;
}
function minimalPowerShellEnv(exe,boundArgsB64){
 const keys=process.platform==='win32'
  ? ['SystemRoot','WINDIR','ComSpec','TEMP','TMP','ProgramData','USERPROFILE','LOCALAPPDATA','APPDATA','PSModulePath']
  : ['HOME','TMPDIR','LANG','LC_ALL','PSModulePath'];
 if(boundArgsB64!==undefined)keys.push(...REPAIR_RUNTIME_ENV_KEYS);
 const env={};
 for(const k of keys){const v=process.env[k];if(typeof v==='string'&&v)env[k]=v;}
 const inherited=process.env.PATH||process.env.Path||process.env.path||'';
 env.PATH=path.dirname(path.resolve(exe))+(inherited?path.delimiter+inherited:'');
 if(boundArgsB64!==undefined){if(typeof boundArgsB64!=='string'||!boundArgsB64)fail('bound PowerShell argument record invalid','POWERSHELL_ENV_INVALID');env.FORGEBOSS_BOUND_ARGS_B64=boundArgsB64;}
 return env;
}
function readBoundArtifact(file,root){
 const base=assertNoLinksAbsolute(root),target=path.resolve(file),rel=path.relative(base,target);
 if(rel.startsWith('..')||path.isAbsolute(rel))fail('control artifact escapes protected root','CONTROL_ARTIFACT_PATH_INVALID');
 assertNoLinksAbsolute(target);
 const before=fs.lstatSync(target);if(!before.isFile()||before.isSymbolicLink())fail('control artifact is not regular file','CONTROL_ARTIFACT_PATH_INVALID');
 const fd=fs.openSync(target,'r');try{const opened=fs.fstatSync(fd);if(before.dev!==opened.dev||before.ino!==opened.ino||before.mode!==opened.mode)fail('control artifact identity changed before read','CONTROL_ARTIFACT_SWAP');return fs.readFileSync(fd);}finally{fs.closeSync(fd)}
}
function readControl(root,cfg,stateRoot){
 const invocationId=crypto.randomUUID();
 const artifactDir=path.join(stateRoot,'control-artifacts');fs.mkdirSync(artifactDir,{recursive:true});assertNoLinksAbsolute(artifactDir);
 const out=path.join(artifactDir,`control-${invocationId}.json`);if(fs.existsSync(out))fail('control artifact already exists','CONTROL_ARTIFACT_COLLISION');
 const a=cfg.control.github_app,exe=trustedPowerShell(cfg.control.powershell),env=minimalPowerShellEnv(exe);
 const args=['-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',path.join(root,'controller','adapters','Read-GitHub-Control.ps1'),'-Owner',cfg.control.owner,'-Repo',cfg.control.repo,'-RootPr',String(cfg.control.root_pr),'-PreferredRepairPr',String(cfg.control.preferred_repair_pr||0),'-AppId',String(a.app_id),'-InstallationId',String(a.installation_id),'-PemPath',String(a.pem_path),'-InvocationId',invocationId,'-Output',out];
 const r=run(exe,args,{cwd:root,timeoutMs:90000,env});
 if(r.exit_code!==0)throw new Error(`Authoritative control read failed: ${(r.stderr||r.stdout||r.error).trim()}`);
 const parsed=parseControlResult(r.stdout,invocationId),c=validateControlResult(parsed.obj,cfg,invocationId),digest=sha256(parsed.raw);
 const disk=readBoundArtifact(out,artifactDir);
 if(!crypto.timingSafeEqual(Buffer.from(sha256(disk),'hex'),Buffer.from(digest,'hex')))fail('authoritative control diagnostic artifact differs from protected producer result','CONTROL_ARTIFACT_SWAP');
 const identity=Object.freeze({schema:1,kind:'github-control',invocation_id:invocationId,sha256:digest,path:out,owner:c.owner,repo:c.repo,root_pr:c.root_pr.number,root_node_id:c.root_pr.node_id,root_head_sha:c.root_pr.head_sha,root_head_ref:c.root_pr.head_ref,repair_pr:c.repair_pr?.number??null,repair_node_id:c.repair_pr?.node_id??null,repair_head_sha:c.repair_pr?.head_sha??null});
 Object.defineProperty(c,'_forgeboss_control_artifact',{value:identity,enumerable:false,writable:false,configurable:false});
 return c;
}
function selectRepairTarget(control){
 if(control?.binding?.status==='EXACT_REPAIR_CHILD_BOUND'&&control.repair_pr)return{mode:'existing-child',root_pr:control.root_pr.number,repair_pr:control.repair_pr.number,target_sha:control.repair_pr.head_sha,base_sha:control.repair_pr.base_sha,target_ref:control.repair_pr.head_ref,base_ref:control.repair_pr.base_ref};
 if(control?.binding?.status==='NO_CURRENT_EXACT_REPAIR_CHILD'&&control.root_pr)return{mode:'parent-head-local',root_pr:control.root_pr.number,repair_pr:null,target_sha:control.root_pr.head_sha,base_sha:control.root_pr.base_sha,target_ref:control.root_pr.head_ref,base_ref:control.root_pr.base_ref};
 throw new Error('Unable to derive repair target from control state');
}
module.exports={readControl,selectRepairTarget,trustedPowerShell,minimalPowerShellEnv,_test:{parseControlResult,validateControlResult,sha256,CONTROL_MARKER,decodeCanonicalBase64,assertNoLinksAbsolute,readBoundArtifact,trustedPowerShell,minimalPowerShellEnv,REPAIR_RUNTIME_ENV_KEYS}};
