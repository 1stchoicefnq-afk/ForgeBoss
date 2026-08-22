'use strict';
const fs=require('fs'),path=require('path'),os=require('os'),cp=require('child_process');
const {buildScope}=require('./lib/scope');
const git=process.platform==='win32'?'git.exe':'git';
const run=(args,cwd)=>cp.spawnSync(git,args,{cwd,encoding:'utf8'});
let fail=0;
const ok=(n,v,d='')=>{console.log(`[${v?'PASS':'FAIL'}] ${n}${d?': '+d:''}`);if(!v)fail++;};

const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'sb-v095-'));
const bare=tmp+'-bare.git';
try{
 run(['init'],tmp);
 run(['config','user.name','SB'],tmp);
 run(['config','user.email','sb@example.invalid'],tmp);

 const files=[];
 for(let i=0;i<30;i++){
  const f=`src/a${String(i).padStart(2,'0')}.js`;
  files.push(f);
 }
 files.push(
  'src/persistence/postgres.js',
  'src/persistence/postgresApplicationServices.js',
  'src/persistence/platformStore.js',
  'src/travis/conversation.js',
  'src/intake/postgresApplication.js',
  'tests/postgresTravisIntake.integration.test.js',
  'tests/postgresProductionHttp.integration.test.js',
  'tests/postgresBusinessInvitations.integration.test.js'
 );

 for(const f of files){
  fs.mkdirSync(path.join(tmp,path.dirname(f)),{recursive:true});
  let body=`module.exports={};\n`;
  if(f==='src/persistence/postgres.js')body=`exports.withTransaction=async cb=>cb(); // SERIALIZABLE 40001\n`;
  if(f==='src/persistence/postgresApplicationServices.js')body=`const pg=require('./postgres'); module.exports=pg;\n`;
  if(f==='src/persistence/platformStore.js')body=`const pg=require('./postgres'); module.exports=pg;\n`;
  if(f==='src/travis/conversation.js')body=`const pg=require('../persistence/postgres'); // retry invitation membership\n`;
  if(f==='src/intake/postgresApplication.js')body=`const pg=require('../persistence/postgres'); // INTAKE_CONVERSION_CONFLICT\n`;
  if(f.startsWith('tests/'))body=`// SERIALIZABLE 40001 invitation membership retry\n`;
  fs.writeFileSync(path.join(tmp,f),body);
 }

 run(['add','.'],tmp);run(['commit','-m','base'],tmp);
 const base=run(['rev-parse','HEAD'],tmp).stdout.trim();
 fs.appendFileSync(path.join(tmp,'src/intake/postgresApplication.js'),'// changed\n');
 run(['add','.'],tmp);run(['commit','-m','target'],tmp);
 const head=run(['rev-parse','HEAD'],tmp).stdout.trim();
 run(['clone','--bare',tmp,bare],path.dirname(tmp));

 const cfg={scope:{
  max_source_files:48,max_write_files:24,max_dependency_depth:4,
  seed_paths:files,
  must_write_paths:[
   'src/persistence/postgres.js',
   'src/persistence/postgresApplicationServices.js',
   'src/persistence/platformStore.js',
   'src/travis/conversation.js',
   'src/intake/postgresApplication.js',
   'tests/postgresTravisIntake.integration.test.js',
   'tests/postgresProductionHttp.integration.test.js',
   'tests/postgresBusinessInvitations.integration.test.js'
  ]
 }};
 const control={root_pr:{number:168},repair_pr:null};
 const target={mode:'parent-head-local',repair_pr:null,target_sha:head,base_sha:base};
 const s=buildScope(cfg,control,{mirror:bare},target);

 ok('write cap respected',s.write_allowlist.length<=24,String(s.write_allowlist.length));
 for(const f of cfg.scope.must_write_paths){
  ok(`must write retained ${f}`,s.write_allowlist.includes(f));
 }
 ok('selection metadata',s.write_selection?.strategy==='relevance-score-v2');
 ok('ranked candidates present',Array.isArray(s.write_selection?.ranked_candidates)&&s.write_selection.ranked_candidates.length>24);
}finally{
 try{fs.rmSync(tmp,{recursive:true,force:true});}catch{}
 try{fs.rmSync(bare,{recursive:true,force:true});}catch{}
}
process.exit(fail?2:0);
