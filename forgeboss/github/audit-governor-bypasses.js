#!/usr/bin/env node
'use strict';
const fs=require('fs'),path=require('path');
const ROOT=path.resolve(__dirname,'..','..');
const psTargets=[
 'controller/adapters/Read-GitHub-Control.ps1',
 'components/Child-Cycle.ps1',
 'components/Executor-v0.4.ps1',
 'components/Repair-PR.ps1',
 'components/Review-PR.ps1',
 'SiteBoss-Rat-Review.ps1',
 'SiteBoss-Diagnostics.ps1',
 'components/Controller-v0.5.10.ps1',
 'SiteBoss-Repair-Lab.ps1',
 'SiteBoss-Repair-Rat.ps1',
 'engines/Repo-Mirror.ps1'
];
const jsTargets=['controller/lib/mirror.js'];
let fail=0;
function bad(msg){console.error('FAIL '+msg);fail++}
for(const rel of psTargets){
 const txt=fs.readFileSync(path.join(ROOT,rel),'utf8'),lines=txt.split(/\r?\n/);
 if(!/GitHub-Governor\.psm1/.test(txt))bad('missing governor import: '+rel);
 for(let i=0;i<lines.length;i++){
  const line=lines[i],window=lines.slice(Math.max(0,i-3),Math.min(lines.length,i+4)).join('\n');
  if(/api\.github\.com/i.test(window)&&/(Invoke-RestMethod|Invoke-WebRequest|HttpClient)/i.test(line))bad('direct GitHub REST near '+rel+':'+(i+1));
  const directPush=/@\(['"]push['"]|\bpush\b.*refs\/heads|git(?:\.exe)?\s+push/i.test(line)&&!/Invoke-GovernedGitPush/.test(line);
  if(directPush)bad('direct git push at '+rel+':'+(i+1));
  const netCommand=/(?:Run|Invoke-Git|Invoke-GitProcess|Invoke-External).*?(?:@\()?['"](?:clone|fetch|ls-remote)['"]|@\(['"]remote['"],['"]update['"]/i.test(line);
  const remoteHint=/github\.com|\borigin\b|RepoUrl|remote.*update/i.test(line);
  if(netCommand&&remoteHint&&!/Invoke-GovernedGitNetwork/.test(line)){
    // Explicit local Repair Rat workspace fetch is not GitHub traffic.
    if(!(rel==='SiteBoss-Rat-Review.ps1'&&/\$sourceRepo/.test(line)))bad('direct GitHub git network call at '+rel+':'+(i+1));
  }
 }
}
for(const rel of jsTargets){
 const txt=fs.readFileSync(path.join(ROOT,rel),'utf8'),lines=txt.split(/\r?\n/);
 if(!/github-gate-cli\.js/.test(txt))bad('JS mirror does not invoke governor CLI: '+rel);
 for(let i=0;i<lines.length;i++){
  const line=lines[i];
  if(/\bgit\(\[.*['"]clone['"]/.test(line)||/\bgit\(\[.*['"]fetch['"]/.test(line))bad('direct JS GitHub git network call at '+rel+':'+(i+1));
 }
}
if(fail){console.error(fail+' governor bypass audit failure(s)');process.exit(2)}
console.log('PASS governor bypass audit: '+(psTargets.length+jsTargets.length)+' known runtime entrypoints');
