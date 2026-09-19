#!/usr/bin/env node
'use strict';

const fs=require('fs');
const path=require('path');

const DEFAULT_ROOT=path.resolve(__dirname,'..','..');
const EXTS=new Set(['.js','.cjs','.mjs','.ts','.py','.ps1','.psm1','.psd1','.cmd','.bat','.sh','.yml','.yaml']);
const SKIP_DIR=new Set(['.git','node_modules','dist','build','coverage','.venv','venv']);
const SKIP_SUFFIX=/\.fullbak$/i;
const EXPLICIT_EXEMPT_FILES=new Set([
 'forgeboss/github/audit-governor-bypasses.js',
 'forgeboss/github/check-github-compliance-law.js',
 'forgeboss/github/test-request-governor.js',
 'forgeboss/github/test-governor-mutations.js'
]);

function norm(root,abs){return path.relative(root,abs).replace(/\\/g,'/')}
function isGithubSignal(s){return /api\.github\.com|raw\.githubusercontent\.com|https?:\/\/github\.com|githubusercontent\.com|\bgh\s+(?:api|pr|issue|repo|run|workflow|release|auth|search|gist)\b|@octokit|new\s+Octokit|octokit\.request|RepoUrl|refs\/heads/i.test(s)}
function addFinding(findings,rel,line,msg){
 const key=rel+':'+line+': '+msg;
 if(!findings.includes(key))findings.push(key);
}
function expectedGovernorPrimitive(rel,line){
 if(rel!=='forgeboss/github/request-governor.js')return false;
 return /fetchImpl\(url|runGitAsync\(|spawn\(exe,args|governedGit(?:Network|Push)/.test(line);
}
function scanFile(root,rel,abs){
 const findings=[],txt=fs.readFileSync(abs,'utf8'),lines=txt.split(/\r?\n/);
 for(let i=0;i<lines.length;i++){
  const line=lines[i],lineNo=i+1,win=lines.slice(Math.max(0,i-3),Math.min(lines.length,i+4)).join('\n');
  if(/\bgh\s+(?:api|pr|issue|repo|run|workflow|release|auth|search|gist)\b/i.test(line))addFinding(findings,rel,lineNo,'unmanaged gh command');
  if(/(?:curl|wget)[^\r\n]*(?:api\.github\.com|github\.com|raw\.githubusercontent\.com|githubusercontent\.com)/i.test(line))addFinding(findings,rel,lineNo,'unmanaged curl/wget GitHub access');
  if(/@octokit|new\s+Octokit|octokit\.request/i.test(line))addFinding(findings,rel,lineNo,'unmanaged Octokit GitHub client');

  const directHttp=/(Invoke-RestMethod|Invoke-WebRequest|HttpClient|axios\.|\bfetch\s*\()/i.test(line);
  if(directHttp&&isGithubSignal(win)&&!expectedGovernorPrimitive(rel,line))addFinding(findings,rel,lineNo,'unmanaged GitHub HTTP client');

  const directPush=/@\(\s*['"]push['"]|(?:^|[\s'"\`])git(?:\.exe)?\s+push\b|spawn(?:Sync)?\([^\r\n]{0,80}['"]git(?:\.exe)?['"][^\r\n]{0,120}['"]push['"]/i.test(line);
  if(directPush&&!/Invoke-GovernedGitPush|governedGitPush/.test(win))addFinding(findings,rel,lineNo,'unmanaged git push');

  const directNetwork=/(?:Run|Invoke-Git|Invoke-GitProcess|Invoke-External)[^\r\n]{0,120}@\(\s*['"](?:clone|fetch|ls-remote)['"]|spawn(?:Sync)?\([^\r\n]{0,80}['"]git(?:\.exe)?['"][^\r\n]{0,120}['"](?:clone|fetch|ls-remote)['"]|(?:^|[\s'"\`])git(?:\.exe)?\s+(?:clone|fetch|ls-remote)\b/i.test(line);
  if(directNetwork&&/(github\.com|\borigin\b|RepoUrl|github)/i.test(win)&&!/Invoke-GovernedGitNetwork|governedGitNetwork/.test(win))addFinding(findings,rel,lineNo,'unmanaged GitHub clone/fetch/ls-remote');

  if(/Invoke-GovernedGit(?:Hub|Network|Push)/.test(line)&&/\.(?:ps1|psm1)$/i.test(rel)){
   const head=lines.slice(0,Math.min(lines.length,80)).join('\n');
   if(!/GitHub-Governor\.psm1/.test(head)&&rel!=='forgeboss/github/GitHub-Governor.psm1')addFinding(findings,rel,lineNo,'governed PowerShell call without governor module import');
  }
 }
 return findings;
}

function auditTree(scanRoot){
 scanRoot=path.resolve(scanRoot||DEFAULT_ROOT);
 const findings=[],stats={scanned:0,candidates:0};
 function walk(dir){
  for(const ent of fs.readdirSync(dir,{withFileTypes:true})){
   if(ent.isDirectory()&&SKIP_DIR.has(ent.name))continue;
   const abs=path.join(dir,ent.name);
   if(ent.isDirectory()){walk(abs);continue}
   const rel=norm(scanRoot,abs),ext=path.extname(ent.name).toLowerCase();
   if(SKIP_SUFFIX.test(rel)||!EXTS.has(ext)||EXPLICIT_EXEMPT_FILES.has(rel))continue;
   stats.scanned++;
   const txt=fs.readFileSync(abs,'utf8');
   if(isGithubSignal(txt))stats.candidates++;
   findings.push(...scanFile(scanRoot,rel,abs));
  }
 }
 walk(scanRoot);
 if(stats.scanned===0)findings.push('AUDIT:0: audit scanned zero executable files');
 return{findings,stats};
}

function main(){
 const scanRoot=process.argv[2]?path.resolve(process.argv[2]):DEFAULT_ROOT;
 const r=auditTree(scanRoot);
 for(const f of r.findings)console.error('FAIL '+f);
 if(r.findings.length){
  console.error(r.findings.length+' governor bypass audit failure(s); scanned '+r.stats.scanned+' executable files');
  process.exit(2);
 }
 console.log('PASS dynamic governor bypass audit: scanned '+r.stats.scanned+' executable files; GitHub-signal candidates '+r.stats.candidates);
}

if(require.main===module)main();
module.exports={auditTree,scanFile,EXTS,EXPLICIT_EXEMPT_FILES};
