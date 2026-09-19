#!/usr/bin/env node
'use strict';

const fs=require('fs');
const path=require('path');

const DEFAULT_ROOT=path.resolve(__dirname,'..','..');
const scanRoot=process.argv[2]?path.resolve(process.argv[2]):DEFAULT_ROOT;
const EXTS=new Set(['.js','.cjs','.mjs','.ts','.py','.ps1','.cmd','.bat','.sh']);
const SKIP_DIR=new Set(['.git','node_modules','history','evidence','dist','build','coverage','.venv','venv']);
const SKIP_FILE=/(^|\/)(tests?|selftest|fixtures|examples)(\/|$)|(^|\/)(CHECK-|BREAK-)|\.fullbak$/i;
const ALLOWED_DIRECT=new Set([
 'forgeboss/github/request-governor.js',
 'forgeboss/github/github-gate-cli.js',
 'forgeboss/github/GitHub-Governor.psm1',
 'forgeboss/github/write-gate.js',
 'forgeboss/github/publish-run-report.js',
 'forgeboss/github/audit-governor-bypasses.js',
 'forgeboss/github/check-github-compliance-law.js'
]);

let fail=0, scanned=0, candidates=0;
function bad(msg){console.error('FAIL '+msg);fail++}

function walk(dir){
 for(const ent of fs.readdirSync(dir,{withFileTypes:true})){
  if(SKIP_DIR.has(ent.name))continue;
  const abs=path.join(dir,ent.name);
  if(ent.isDirectory())walk(abs);
  else{
   const rel=path.relative(scanRoot,abs).replace(/\\/g,'/');
   if(SKIP_FILE.test(rel)||!EXTS.has(path.extname(ent.name).toLowerCase()))continue;
   scanned++;scan(rel,abs);
  }
 }
}

function scan(rel,abs){
 const txt=fs.readFileSync(abs,'utf8');
 const lines=txt.split(/\r?\n/);
 const allowed=ALLOWED_DIRECT.has(rel);
 const hasPsGovernor=/GitHub-Governor\.psm1|Invoke-GovernedGitHub|Invoke-GovernedGitNetwork|Invoke-GovernedGitPush/.test(txt);
 const hasJsGovernor=/request-governor|github-gate-cli|githubWrite\(|governedGitNetwork|governedGitPush/.test(txt);
 const githubSignal=/(?:api\.github\.com|raw\.githubusercontent\.com|https?:\/\/github\.com|\bgh\s+(?:api|pr|issue|repo|run|workflow|release|auth|search|gist)\b|@octokit|new\s+Octokit|octokit\.request|RepoUrl|refs\/heads)/i.test(txt);
 if(githubSignal)candidates++;

 if(/\bgh\s+(?:api|pr|issue|repo|run|workflow|release|auth|search|gist)\b/i.test(txt)&&!allowed)bad(rel+': unmanaged gh command');
 if(/(?:curl|wget)[^\r\n]*(?:api\.github\.com|github\.com|raw\.githubusercontent\.com)/i.test(txt)&&!allowed)bad(rel+': unmanaged curl/wget GitHub access');
 if(/@octokit|new\s+Octokit|octokit\.request/i.test(txt)&&!allowed&&!hasJsGovernor)bad(rel+': unmanaged Octokit GitHub client');

 for(let i=0;i<lines.length;i++){
  const line=lines[i],win=lines.slice(Math.max(0,i-3),Math.min(lines.length,i+4)).join('\n');
  if(/(?:api\.github\.com|raw\.githubusercontent\.com|https?:\/\/github\.com)/i.test(win)&&/(Invoke-RestMethod|Invoke-WebRequest|HttpClient|axios\.|\bfetch\s*\()/i.test(line)&&!allowed&&!hasPsGovernor&&!hasJsGovernor){
   bad(rel+':'+(i+1)+': unmanaged GitHub HTTP client');break;
  }
  const directPush=/@\(\s*['"]push['"]|(?:^|[\s'"`])git(?:\.exe)?\s+push\b|spawn(?:Sync)?\([^\r\n]{0,80}['"]git(?:\.exe)?['"][^\r\n]{0,120}['"]push['"]/i.test(line);
  if(directPush&&!allowed&&!/Invoke-GovernedGitPush|governedGitPush/.test(win)){
   bad(rel+':'+(i+1)+': unmanaged git push');break;
  }
  const directNetwork=/(?:Run|Invoke-Git|Invoke-GitProcess|Invoke-External)[^\r\n]{0,120}@\(\s*['"](?:clone|fetch|ls-remote)['"]|spawn(?:Sync)?\([^\r\n]{0,80}['"]git(?:\.exe)?['"][^\r\n]{0,120}['"](?:clone|fetch)['"]|(?:^|[\s'"`])git(?:\.exe)?\s+(?:clone|fetch)\b/i.test(line);
  if(directNetwork&&/(?:github\.com|\borigin\b|RepoUrl)/i.test(win)&&!allowed&&!/Invoke-GovernedGitNetwork|governedGitNetwork/.test(win)){
   bad(rel+':'+(i+1)+': unmanaged GitHub clone/fetch');break;
  }
 }
 if(path.extname(rel).toLowerCase()==='.ps1'&&/Invoke-GovernedGit(?:Hub|Network|Push)/.test(txt)&&!/GitHub-Governor\.psm1/.test(txt)){
  bad(rel+': governed PowerShell GitHub call without governor module import');
 }
}

walk(scanRoot);
if(scanned===0)bad('audit scanned zero executable files');
if(fail){console.error(fail+' governor bypass audit failure(s); scanned '+scanned+' executable files');process.exit(2)}
console.log('PASS dynamic governor bypass audit: scanned '+scanned+' executable files; GitHub-signal candidates '+candidates);
