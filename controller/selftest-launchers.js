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

const start=fs.readFileSync(path.join(root,'START-FORGEBOSS.vbs'),'utf8');
ok('START-FORGEBOSS.routes_real_dashboard',start.includes('\\dashboard\\pro_shell.py')&&!start.includes('ForgeBoss-Internal'));
ok('START-FORGEBOSS.setup_message_real_root',start.includes('SETUP-FORGEBOSS-ENGINES.cmd from this ForgeBoss folder'));

const fbProject=JSON.parse(fs.readFileSync(path.join(root,'projects','forgeboss','project.json'),'utf8'));
const fbScope=JSON.parse(fs.readFileSync(path.join(root,'projects','forgeboss','scope.json'),'utf8'));
const fbAcceptance=JSON.parse(fs.readFileSync(path.join(root,'projects','forgeboss','acceptance.json'),'utf8'));
ok('forgeboss.profile.self_build',fbProject.id==='forgeboss'&&fbProject.profile_type==='self-build');
ok('forgeboss.profile.packet_scope_required',fbScope.packet_scope_required===true);
ok('forgeboss.profile.known_good_required',fbAcceptance.known_good_activation_required===true&&fbAcceptance.independent_review_required===true);

const shell=fs.readFileSync(path.join(root,'dashboard','pro_shell.py'),'utf8');
const intake=fs.readFileSync(path.join(root,'forgeboss','control','project_intake.py'),'utf8');
const html=fs.readFileSync(path.join(root,'dashboard','pro.html'),'utf8');
ok('dashboard.self_project_detection',shell.includes('detect_project_source')&&intake.includes('FORGEBOSS_MARKERS'));
ok('dashboard.self_build_fail_closed',shell.includes('self_build_preflight')&&shell.includes('PREFLIGHT_BLOCKED')&&shell.includes('ProtectedAuthorityClient.from_environment')&&shell.includes('launch_initial')&&shell.includes('_mandatory_b2')&&shell.includes('TWO_BUILDERS_RUNNING'));
ok('dashboard.drag_drop_present',html.includes('DROP FORGEBOSS HERE')&&shell.includes('pywebviewFullPath')&&shell.includes('DOMEventHandler'));

process.exit(fail?2:0);
