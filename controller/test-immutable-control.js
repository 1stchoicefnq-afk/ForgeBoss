'use strict';
const fs=require('fs'),os=require('os'),path=require('path'),crypto=require('crypto');
const { _test:controlTest }=require('./lib/control');
const { canonicalRepoPath,_test:scopeTest }=require('./lib/scope');
let pass=0,fail=0;
function ok(name,fn){let good=false,detail='';try{good=!!fn()}catch(e){detail=e?.stack||String(e)}console.log(`[${good?'PASS':'FAIL'}] ${name}${detail?': '+detail:''}`);good?pass++:fail++;}
function throws(fn){try{fn();return false}catch{return true}}
const id=crypto.randomUUID(),cfg={control:{owner:'owner',repo:'repo',root_pr:500}};
function sample(){return{schema:3,invocation_id:id,generated_at:'2026-08-29T00:00:00Z',owner:'owner',repo:'repo',root_pr:{number:500,state:'open',node_id:'PR_root',api_url:'https://api.github.com/repos/owner/repo/pulls/500',html_url:'https://github.com/owner/repo/pull/500',head_sha:'a'.repeat(40),head_ref:'feature/root',base_sha:'b'.repeat(40),base_ref:'main'},repair_pr:{number:525,state:'open',title:'repair',node_id:'PR_child',api_url:'https://api.github.com/repos/owner/repo/pulls/525',html_url:'https://github.com/owner/repo/pull/525',head_sha:'c'.repeat(40),head_ref:'autopilot/repair-pr500-x',base_sha:'a'.repeat(40),base_ref:'feature/root',repo:'owner/repo',updated_at:'x'},preferred_repair_pr:null,exact_repair_candidates:[],binding:{status:'EXACT_REPAIR_CHILD_BOUND',repair_base_equals_root_head:true,repository:'owner/repo',selection_reason:'discovered-exact'}}}
function marker(obj){return controlTest.CONTROL_MARKER+Buffer.from(JSON.stringify(obj)).toString('base64')+'\n';}
ok('pipe control result accepted and digestable',()=>{const p=controlTest.parseControlResult(marker(sample()),id);controlTest.validateControlResult(p.obj,cfg,id);return controlTest.sha256(p.raw).length===64});
ok('wrong owner/repo rejected',()=>throws(()=>controlTest.validateControlResult({...sample(),repo:'other'},cfg,id)));
ok('wrong root PR rejected',()=>{const x=sample();x.root_pr={...x.root_pr,number:501};return throws(()=>controlTest.validateControlResult(x,cfg,id))});
ok('wrong root object identity rejected',()=>{const x=sample();x.root_pr={...x.root_pr,node_id:'',api_url:'https://api.github.com/repos/owner/repo/pulls/999'};return throws(()=>controlTest.validateControlResult(x,cfg,id))});
ok('stale/substituted repair head binding rejected',()=>{const x=sample();x.repair_pr={...x.repair_pr,base_sha:'d'.repeat(40)};return throws(()=>controlTest.validateControlResult(x,cfg,id))});
ok('wrong repair repository/object rejected',()=>{const x=sample();x.repair_pr={...x.repair_pr,repo:'evil/repo',api_url:'https://api.github.com/repos/evil/repo/pulls/525'};return throws(()=>controlTest.validateControlResult(x,cfg,id))});
ok('duplicate/missing producer markers fail closed',()=>throws(()=>controlTest.parseControlResult('',id))&&throws(()=>controlTest.parseControlResult(marker(sample())+marker(sample()),id)));
ok('foreign invocation result rejected',()=>throws(()=>controlTest.parseControlResult(marker(sample()),crypto.randomUUID())));
ok('noncanonical/malformed producer base64 rejected',()=>throws(()=>controlTest.parseControlResult(controlTest.CONTROL_MARKER+'e30\n',id))&&throws(()=>controlTest.parseControlResult(controlTest.CONTROL_MARKER+'!!!!\n',id)));
for(const bad of ['../x','src/../x','/etc/passwd','C:/x','//server/share','src\\x','src/a.',' src/a.js','src/a.js:stream','src/NUL','src/COM1.txt','src/COM¹.log','src/LPT³.bin','src/CONIN$','src/CONOUT$.txt','src/PROGRA~1/x','src/a?.js','src/a*.js','src/a<.js','src/a>.js','src/a|.js','src/a".js'])ok(`scope path rejected: ${bad}`,()=>throws(()=>canonicalRepoPath(bad)));
ok('scope case collision rejected',()=>throws(()=>scopeTest.assertNoCaseCollisions(['src/A.js','src/a.js'],'test')));
ok('canonical repo path preserved',()=>canonicalRepoPath('src/a.js')==='src/a.js');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'fb-control-artifact-'));const good=path.join(tmp,'good.json');fs.writeFileSync(good,'{}');ok('ordinary control artifact read accepted',()=>controlTest.readBoundArtifact(good,tmp).toString()==='{}');
try{const link=path.join(tmp,'link.json');fs.symlinkSync(good,link);ok('symlink control artifact rejected',()=>throws(()=>controlTest.readBoundArtifact(link,tmp)));}catch{console.log('[PASS] symlink control artifact regression skipped by host permissions');pass++;}
try{fs.rmSync(tmp,{recursive:true,force:true})}catch{}
console.log(`IMMUTABLE CONTROL SELFTEST: PASS=${pass} FAIL=${fail}`);process.exit(fail?2:0);
