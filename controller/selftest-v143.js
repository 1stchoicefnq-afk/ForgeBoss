'use strict';
const fs=require('fs'),path=require('path');
let pass=0,fail=0;
const ok=(n,v,d='')=>{console.log(`[${v?'PASS':'FAIL'}] ${n}${d?': '+d:''}`);v?pass++:fail++;};
const root=path.resolve(__dirname,'..');
const rat=fs.readFileSync(path.join(root,'SiteBoss-Repair-Rat.ps1'),'utf8');
for(const n of [
 'Get-FreshTargetEvidence',
 'fresh_target_evidence',
 'authoritative_target_head',
 'historical repair-lab evidence is background only',
 'Record-OpenAIUsage',
 'input_tokens_details.cached_tokens',
 '[COST] This AI call',
 'Assert-CostBudget',
 'SITEBOSS_RUN_BUDGET_USD',
 'SITEBOSS_DAILY_BUDGET_USD',
 'usage_estimated_usd'
]) ok(`Repair Rat contains ${n}`,rat.includes(n));
ok('fresh evidence runs before attempt loop',rat.indexOf('Get-FreshTargetEvidence $work $head')<rat.indexOf('for($attempt=1;'));
ok('first attempt sees baseline failures',rat.includes("$lastAcceptance=$(if($null-ne$freshEvidence){$freshEvidence}else{$null})"));
const cfg=JSON.parse(fs.readFileSync(path.join(__dirname,'config.default.json'),'utf8'));
ok('default run budget 3 USD',cfg.cost_control.run_budget_usd_default===3);
ok('default daily budget 10 USD',cfg.cost_control.daily_budget_usd_default===10);
console.log(`V1.4.3 FRESH-EVIDENCE/COST SELFTEST: PASS=${pass} FAIL=${fail}`);
process.exit(fail?2:0);
