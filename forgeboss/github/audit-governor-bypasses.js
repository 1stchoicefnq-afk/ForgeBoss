#!/usr/bin/env node
'use strict';
const fs=require('fs'),path=require('path');const ROOT=path.resolve(__dirname,'..','..');
const targets=['controller/adapters/Read-GitHub-Control.ps1','components/Child-Cycle.ps1','components/Executor-v0.4.ps1','components/Repair-PR.ps1','components/Review-PR.ps1','SiteBoss-Rat-Review.ps1','SiteBoss-Diagnostics.ps1','components/Controller-v0.5.10.ps1'];
let fail=0;
for(const rel of targets){const txt=fs.readFileSync(path.join(ROOT,rel),'utf8'),lines=txt.split(/\r?\n/);if(!/GitHub-Governor\.psm1/.test(txt)){console.error('FAIL missing governor import: '+rel);fail++;continue}for(let i=0;i<lines.length;i++){const w=lines.slice(Math.max(0,i-4),Math.min(lines.length,i+5)).join('\n');if(/api\.github\.com/i.test(lines[i])&&/(Invoke-RestMethod|Invoke-WebRequest|HttpClient)/i.test(w)){console.error('FAIL direct GitHub HTTP near '+rel+':'+(i+1));fail++;break}}if(/git[^\r\n]{0,80}\bpush\b|@\(['"]push['"]|\bpush\b[^\r\n]{0,80}origin/i.test(txt)&&!/Invoke-GovernedGitPush/.test(txt)){console.error('FAIL direct git push: '+rel);fail++}}
if(fail){console.error(fail+' governor bypass audit failure(s)');process.exit(2)}console.log('PASS governor bypass audit: '+targets.length+' runtime entrypoints route through shared governor');
