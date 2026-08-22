'use strict';
const fs=require('fs'),path=require('path'),cp=require('child_process');
const root=path.resolve(__dirname,'..','..');let p=0,f=0;
const ok=(n,v,d='')=>{console.log(`[${v?'PASS':'FAIL'}] ${n}${d?': '+d:''}`);v?p++:f++;};
const reg=JSON.parse(fs.readFileSync(path.join(root,'forgeboss','executor-registry.json'),'utf8'));
ok('Repair Rat remains proven fallback',reg.default==='repair-rat');
ok('OpenHands candidate present',!!reg.candidates.openhands);
ok('mini-SWE candidate present',!!reg.candidates['mini-swe']);
ok('OpenCode candidate present',!!reg.candidates.opencode);
ok('Deep Agents not promoted blindly',reg.candidates.deepagents.status.includes('DURABILITY'));
for(const file of ['openhands_runner.py','mini_swe_runner.py']){
 const r=cp.spawnSync('python',['-m','py_compile',path.join(root,'forgeboss','executors',file)],{encoding:'utf8'});
 ok(`${file} compiles`,r.status===0,(r.stderr||'').trim());
}
const r=cp.spawnSync(process.execPath,['--check',path.join(root,'forgeboss','executors','opencode_runner.js')],{encoding:'utf8'});
ok('OpenCode wrapper syntax',r.status===0,(r.stderr||'').trim());
const manifest=JSON.parse(fs.readFileSync(path.join(root,'forgeboss','upstream-manifest.json'),'utf8'));
ok('all upstreams explicitly licensed',manifest.components.every(x=>x.license==='MIT'));
console.log(`FORGEBOSS EXECUTOR SELFTEST PASS=${p} FAIL=${f}`);
process.exit(f?2:0);
