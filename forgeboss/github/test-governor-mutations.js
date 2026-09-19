#!/usr/bin/env node
'use strict';
const assert=require('assert'),fs=require('fs'),os=require('os'),path=require('path'),{spawnSync}=require('child_process');

const SRC=__dirname;
const readNormalized=n=>fs.readFileSync(path.join(SRC,n),'utf8').replace(/\r\n/g,'\n');
const originals={
 'request-governor.js':readNormalized('request-governor.js'),
 'audit-governor-bypasses.js':readNormalized('audit-governor-bypasses.js'),
 'test-request-governor.js':readNormalized('test-request-governor.js')
};
let pass=0;

function mutate(name,file,from,to,filter){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'fb-gh-mut-'));
 for(const [n,c] of Object.entries(originals))fs.writeFileSync(path.join(dir,n),c);
 const p=path.join(dir,file),src=fs.readFileSync(p,'utf8');
 assert(src.includes(from),name+': mutation target missing');
 fs.writeFileSync(p,src.replace(from,to));
 const r=spawnSync(process.execPath,[path.join(dir,'test-request-governor.js')],{
  encoding:'utf8',env:{...process.env,FB_GOV_TEST_FILTER:filter},timeout:30000
 });
 const out=(r.stdout||'')+(r.stderr||'');
 if(r.status===0)throw new Error(name+': mutation SURVIVED\n'+out);
 console.log('[PASS] '+name+': regression killed the mutation');
 pass++;
}

mutate('H1-stale-floor','request-governor.js',
 'const STALE_LOCK_MIN_MS=300000,STALE_LOCK_MAX_MS=3600000,CACHE_TTL_MIN_MS=5000,CACHE_TTL_MAX_MS=300000;',
 'const STALE_LOCK_MIN_MS=5000,STALE_LOCK_MAX_MS=3600000,CACHE_TTL_MIN_MS=5000,CACHE_TTL_MAX_MS=300000;',
 'stale lock configuration is clamped safely');

mutate('H1-live-owner-takeover','request-governor.js',
 'if(sameHost&&alive===false){fs.rmSync(p.lock,{recursive:true,force:true});continue}',
 'if(age>c.staleLockMs){fs.rmSync(p.lock,{recursive:true,force:true});continue}',
 'competing writer cannot overlap after stale mtime attack');

mutate('H2-friendly-prefix-exemption','audit-governor-bypasses.js',
 "if(SKIP_SUFFIX.test(rel)||!EXTS.has(ext)||EXPLICIT_EXEMPT_FILES.has(rel))continue;",
 "if(SKIP_SUFFIX.test(rel)||!EXTS.has(ext)||EXPLICIT_EXEMPT_FILES.has(rel)||/^(?:check-|break-)/i.test(path.basename(rel)))continue;",
 'audit catches check-prs.js');

mutate('H2-test-directory-exemption','audit-governor-bypasses.js',
 "if(SKIP_SUFFIX.test(rel)||!EXTS.has(ext)||EXPLICIT_EXEMPT_FILES.has(rel))continue;",
 "if(SKIP_SUFFIX.test(rel)||!EXTS.has(ext)||EXPLICIT_EXEMPT_FILES.has(rel)||/(^|\\/)(?:test|tests|fixtures|examples)(\\/|$)/i.test(rel))continue;",
 'audit does not exempt test directory');

mutate('H3-powershell-module-extension','audit-governor-bypasses.js',
 "'.ps1','.psm1','.psd1','.cmd'",
 "'.ps1','.cmd'",
 'audit catches unmanaged psm1');

mutate('H3-workflow-extension','audit-governor-bypasses.js',
 "'.sh','.yml','.yaml'",
 "'.sh'",
 'audit catches workflow gh api');

mutate('M1-file-wide-governor-awareness','audit-governor-bypasses.js',
 "if(directHttp&&isGithubSignal(win)&&!expectedGovernorPrimitive(rel,line))addFinding(findings,rel,lineNo,'unmanaged GitHub HTTP client');",
 "if(directHttp&&isGithubSignal(win)&&!/request-governor/.test(txt)&&!expectedGovernorPrimitive(rel,line))addFinding(findings,rel,lineNo,'unmanaged GitHub HTTP client');",
 'governor awareness is call scoped');

mutate('M2-state-deletion','request-governor.js',
 "if(hasAnchor||hasMetrics)throw new GitHubStateTamperError('state disappeared while authority evidence remains');",
 "if(false&&hasAnchor&&hasMetrics)throw new GitHubStateTamperError('state disappeared while authority evidence remains');",
 'state deletion after protection history fails closed');

mutate('M2-state-regression','request-governor.js',
 "if(Number(a.sequence)!==Number(s.sequence)||String(a.stateHash||'')!==stateDigest(s))throw new GitHubStateTamperError('state sequence/hash regressed or was replaced');",
 "if(false&&(Number(a.sequence)!==Number(s.sequence)||String(a.stateHash||'')!==stateDigest(s)))throw new GitHubStateTamperError('state sequence/hash regressed or was replaced');",
 'state reset/regression after protection history fails closed');

mutate('M2-anchor-outside-reset-root','request-governor.js',
 "anchor:path.join(path.dirname(r),'github-governor-authority.json')",
 "anchor:path.join(r,'state-authority.json')",
 'whole governor state-root deletion after history fails closed');

mutate('M3-cache-floor','request-governor.js',
 'CACHE_TTL_MIN_MS=5000,CACHE_TTL_MAX_MS=300000',
 'CACHE_TTL_MIN_MS=0,CACHE_TTL_MAX_MS=300000',
 'cache TTL has safe floor and ceiling');

mutate('M4-root-override-authority','request-governor.js',
 "function rejectRootOverride(o={}){\n if(o&&Object.prototype.hasOwnProperty.call(o,'root'))throw new Error('GitHub governor state-root override is not supported');\n}",
 "function rejectRootOverride(o={}){void o}",
 'production root ignores env and argv spoofing and rejects option override');

console.log('Mutation replay PASS: '+pass+'/12 mutations detected');
if(pass!==12)process.exit(2);
