#!/usr/bin/env node
'use strict';

const fs=require('fs');
const path=require('path');
const {getConfig}=require('./request-governor');
const {auditTree}=require('./audit-governor-bypasses');

const ROOT=path.resolve(__dirname,'..','..');
const failures=[];
for(const rel of ['GITHUB-COMPLIANCE-LAW.md','GITHUB-RECOVERY-SAFETY.md','forgeboss/github/request-governor.js','forgeboss/github/GitHub-Governor.psm1','forgeboss/github/audit-governor-bypasses.js']){
 if(!fs.existsSync(path.join(ROOT,rel)))failures.push('missing required compliance file: '+rel);
}

const c=getConfig({
 maxRequestsPerMinute:999,maxMutationsPerMinute:999,maxMutationsPerHour:999,
 minRequestGapMs:0,minMutationGapMs:0,staleLockMs:1,cacheTtlMs:0
});
if(c.maxRequestsPerMinute>30)failures.push('request ceiling can exceed 30/min');
if(c.maxMutationsPerMinute>6)failures.push('mutation ceiling can exceed 6/min');
if(c.maxMutationsPerHour>60)failures.push('mutation ceiling can exceed 60/hour');
if(c.minRequestGapMs<500)failures.push('ordinary request gap can fall below 500ms');
if(c.minMutationGapMs<2500)failures.push('mutation gap can fall below 2500ms');
if(c.staleLockMs<300000||c.staleLockMs>3600000)failures.push('stale-lock authority is outside the safe 5m-60m range');
if(c.cacheTtlMs<5000)failures.push('cache TTL can fall below the safe minimum');

const audit=auditTree(ROOT);
failures.push(...audit.findings);

if(failures.length){
 console.error('GITHUB COMPLIANCE LAW: FAIL');
 for(const f of failures)console.error('- '+f);
 process.exit(2);
}
console.log('GITHUB COMPLIANCE LAW: PASS');
console.log('Hard ceilings/floors enforced; audit scanned '+audit.stats.scanned+' executable files with '+audit.stats.candidates+' GitHub-signal candidates.');
