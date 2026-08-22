'use strict';
const fs=require('fs'),path=require('path');
const root=path.resolve(__dirname,'..');
let fail=0;
function ok(n,v,d=''){console.log(`[${v?'PASS':'FAIL'}] ${n}${d?': '+d:''}`);if(!v)fail++;}
const names=['SITEBOSS-AUTOPILOT.cmd','START-SITEBOSS.cmd','ONE-CLICK-SITEBOSS.cmd'];
for(const n of names){
 const t=fs.readFileSync(path.join(root,n),'utf8');
 ok(`${n}.routes_controller`,t.includes('controller\\siteboss-autopilot.js') && t.includes(' run'));
 ok(`${n}.does_not_call_legacy`,!t.includes('SiteBoss-OneClick.ps1') && !t.includes('SiteBoss-Builder.ps1'));
}
for(const n of ['RUN-BUILDER.cmd','DIAGNOSE-BUILDER.cmd']){
 const t=fs.readFileSync(path.join(root,n),'utf8');
 ok(`${n}.blocked`,t.includes('[BLOCKED]') && !t.includes('pwsh'));
}
process.exit(fail?2:0);
