#!/usr/bin/env node
'use strict';

const fs=require('fs');
const path=require('path');
const {getConfig}=require('./request-governor');
const ROOT=path.resolve(__dirname,'..','..');
const failures=[];
for(const rel of ['GITHUB-COMPLIANCE-LAW.md','GITHUB-RECOVERY-SAFETY.md','forgeboss/github/request-governor.js','forgeboss/github/GitHub-Governor.psm1','forgeboss/github/audit-governor-bypasses.js']){
 if(!fs.existsSync(path.join(ROOT,rel)))failures.push('missing required compliance file: '+rel);
}
const c=getConfig({maxRequestsPerMinute:999,maxMutationsPerMinute:999,maxMutationsPerHour:999,minRequestGapMs:0,minMutationGapMs:0});
if(c.maxRequestsPerMinute>30)failures.push('request ceiling can exceed 30/min');
if(c.maxMutationsPerMinute>6)failures.push('mutation ceiling can exceed 6/min');
if(c.maxMutationsPerHour>60)failures.push('mutation ceiling can exceed 60/hour');
if(c.minRequestGapMs<500)failures.push('ordinary request gap can fall below 500ms');
if(c.minMutationGapMs<2500)failures.push('mutation gap can fall below 2500ms');

const EXTS=new Set(['.js','.cjs','.mjs','.ts','.py','.ps1','.cmd','.bat','.sh']);
const SKIP_DIR=new Set(['.git','node_modules','history','evidence','dist','build','coverage','.venv','venv']);
const SKIP_FILE=/(^|\/)(test|tests|selftest|fixtures|examples)(\/|$)|(^|\/)(CHECK-|BREAK-)|\.fullbak$/i;
const allowed=new Set([
 'forgeboss/github/request-governor.js','forgeboss/github/github-gate-cli.js','forgeboss/github/GitHub-Governor.psm1',
 'forgeboss/github/write-gate.js','forgeboss/github/publish-run-report.js','forgeboss/github/audit-governor-bypasses.js',
 'forgeboss/github/check-github-compliance-law.js'
]);
function walk(dir){
 for(const ent of fs.readdirSync(dir,{withFileTypes:true})){
  if(SKIP_DIR.has(ent.name))continue;
  const abs=path.join(dir,ent.name);
  if(ent.isDirectory())walk(abs);
  else{
   const rel=path.relative(ROOT,abs).replace(/\\/g,'/');
   if(SKIP_FILE.test(rel)||!EXTS.has(path.extname(ent.name).toLowerCase()))continue;
   scan(rel,abs);
  }
 }
}
function scan(rel,abs){
 const txt=fs.readFileSync(abs,'utf8');
 const lines=txt.split(/\r?\n/);
 const governed=/request-governor|github-gate-cli|GitHub-Governor\.psm1|Invoke-GovernedGitHub|Invoke-GovernedGitNetwork|Invoke-GovernedGitPush|githubWrite\(/.test(txt);
 if(/\bgh\s+api\b/i.test(txt)&&!allowed.has(rel))failures.push(rel+': direct gh api is forbidden');
 if(/curl[^\r\n]*(?:api\.github\.com|github\.com)/i.test(txt)&&!allowed.has(rel))failures.push(rel+': direct curl GitHub access is forbidden');
 for(let i=0;i<lines.length;i++){
  const line=lines[i],win=lines.slice(Math.max(0,i-3),Math.min(lines.length,i+4)).join('\n');
  if(/api\.github\.com/i.test(win)&&/(Invoke-RestMethod|Invoke-WebRequest|HttpClient|axios\.|\bfetch\s*\()/i.test(line)&&!governed&&!allowed.has(rel)){
   failures.push(rel+':'+(i+1)+': unmanaged GitHub HTTP client');break;
  }
  const directPush=/@\(['"]push['"]|git(?:\.exe)?[^\r\n]{0,80}\bpush\b|spawn(?:Sync)?\([^\r\n]{0,80}['"]git(?:\.exe)?['"][^\r\n]{0,120}['"]push['"]/i.test(line);
  if(directPush&&!/Invoke-GovernedGitPush|governedGitPush/.test(win)&&!allowed.has(rel)){
   failures.push(rel+':'+(i+1)+': unmanaged git push');break;
  }
 }
}
walk(ROOT);
if(failures.length){
 console.error('GITHUB COMPLIANCE LAW: FAIL');
 for(const f of failures)console.error('- '+f);
 process.exit(2);
}
console.log('GITHUB COMPLIANCE LAW: PASS');
console.log('Hard ceilings/floors enforced and no obvious unmanaged GitHub automation bypass found.');
