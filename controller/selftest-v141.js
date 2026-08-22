'use strict';
const path=require('path');
const fs=require('fs');
const ROOT=path.resolve(__dirname,'..');
const {doctor}=require('./lib/doctor');
const cfg=JSON.parse(fs.readFileSync(path.join(__dirname,'config.default.json'),'utf8'));
let pass=0,fail=0;
function ok(n,v,d=''){console.log(`[${v?'PASS':'FAIL'}] ${n}${d?': '+d:''}`);v?pass++:fail++;}
const d=doctor(ROOT,cfg);
const by=Object.fromEntries(d.checks.map(x=>[x.name,x]));
ok('guarded live execution accepted',by['config.live_execution_guarded']?.ok===true,by['config.live_execution_guarded']?.detail);
ok('draft-only GitHub writes accepted',by['config.github_writes_draft_guarded']?.ok===true,by['config.github_writes_draft_guarded']?.detail);
ok('model calls remain default-off',by['config.model_calls_default_off']?.ok===true);
ok('merge remains off',by['config.merge_off']?.ok===true);
ok('deploy remains off',by['config.deploy_off']?.ok===true);
ok('legacy contradictory live_execution_off removed',!by['config.live_execution_off']);
ok('legacy contradictory github_writes_off removed',!by['config.github_writes_off']);
console.log(`V1.4.1 PREFLIGHT CONTRACT SELFTEST: PASS=${pass} FAIL=${fail}`);
process.exit(fail?2:0);
