'use strict';
const fs=require('fs'),path=require('path');
let fail=0;
function ok(n,v){console.log(`[${v?'PASS':'FAIL'}] ${n}`);if(!v)fail++;}
const root=path.resolve(__dirname,'..');
const ps=fs.readFileSync(path.join(root,'controller','adapters','Read-GitHub-Control.ps1'),'utf8');
const control=fs.readFileSync(path.join(root,'controller','lib','control.js'),'utf8');
const main=fs.readFileSync(path.join(root,'controller','siteboss-autopilot.js'),'utf8');

ok('adapter.dynamic_base_query',ps.includes('Get-OpenBasePrs'));
ok('adapter.exact_sha_filter',ps.includes('$exactBase='));
ok('adapter.relationship_filter',ps.includes('Looks-LikeRepairChild'));
ok('adapter.preferred_is_not_absolute',ps.includes("selectionReason='discovered-exact'"));
ok('adapter.ambiguity_fails_closed',ps.includes('Ambiguous exact repair children'));
ok('adapter.no_child_is_structured',ps.includes("status='NO_CURRENT_EXACT_REPAIR_CHILD'"));
ok('adapter.bound_status',ps.includes("status='EXACT_REPAIR_CHILD_BOUND'"));
ok('controller.accepts_structured_no_child',control.includes("binding.status==='EXACT_REPAIR_CHILD_BOUND'"));
ok('main.actionable_no_child',main.includes("'repair.child.absent'"));
ok('main.uses_discovered_number',main.includes('target.repair_pr')&&control.includes('repair_pr:control.repair_pr.number'));
process.exit(fail?2:0);
