'use strict';
const fs=require('fs'),path=require('path'),os=require('os'),cp=require('child_process');const {buildScope}=require('./lib/scope');
const exe=process.platform==='win32'?'git.exe':'git';const r=(a,c)=>cp.spawnSync(exe,a,{cwd:c,encoding:'utf8'});
let fails=0;const ok=(n,v)=>{console.log(`[${v?'PASS':'FAIL'}] ${n}`);if(!v)fails++;};
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'sb-v09-'));const bare=tmp+'-bare.git';
try{
 r(['init'],tmp);r(['config','user.name','SB'],tmp);r(['config','user.email','sb@example.invalid'],tmp);
 fs.mkdirSync(path.join(tmp,'src','services'),{recursive:true});fs.mkdirSync(path.join(tmp,'src','persistence'),{recursive:true});fs.mkdirSync(path.join(tmp,'tests'),{recursive:true});
 fs.writeFileSync(path.join(tmp,'src','persistence','postgres.js'),"exports.withTransaction=async cb=>cb();\n");
 fs.writeFileSync(path.join(tmp,'src','services','businessInvitation.js'),"const pg=require('../persistence/postgres'); exports.acceptInvitation=()=>pg.withTransaction(async()=>{});\n");
 fs.writeFileSync(path.join(tmp,'tests','postgresBusinessInvitations.integration.test.js'),"const svc=require('../src/services/businessInvitation'); // SERIALIZABLE 40001 invitation membership\n");
 r(['add','.'],tmp);r(['commit','-m','base'],tmp);const base=r(['rev-parse','HEAD'],tmp).stdout.trim();
 fs.appendFileSync(path.join(tmp,'tests','postgresBusinessInvitations.integration.test.js'),"// retry\n");r(['add','.'],tmp);r(['commit','-m','repair'],tmp);const head=r(['rev-parse','HEAD'],tmp).stdout.trim();
 r(['clone','--bare',tmp,bare],path.dirname(tmp));
 const cfg={scope:{max_source_files:20,max_write_files:20,max_dependency_depth:4,seed_paths:['tests/postgresBusinessInvitations.integration.test.js']}};
 const c={root_pr:{number:1,head_sha:base},repair_pr:{number:2,base_sha:base,head_sha:head}};
 const s=buildScope(cfg,c,{mirror:bare});
 ok('includes invitation test',s.source_paths.includes('tests/postgresBusinessInvitations.integration.test.js'));
 ok('dependency adds invitation service',s.source_paths.includes('src/services/businessInvitation.js'));
 ok('dependency adds postgres',s.source_paths.includes('src/persistence/postgres.js'));
 ok('service writable',s.write_allowlist.includes('src/services/businessInvitation.js'));
 ok('exact head bound',s.exact_head===head);ok('scope hash',s.scope_sha256.length===64);
}finally{try{fs.rmSync(tmp,{recursive:true,force:true});}catch{}try{fs.rmSync(bare,{recursive:true,force:true});}catch{}}
process.exit(fails?2:0);
