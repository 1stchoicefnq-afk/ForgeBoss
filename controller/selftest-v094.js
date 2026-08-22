'use strict';
const fs=require('fs'),path=require('path');
const root=path.resolve(__dirname,'..');
const rat=fs.readFileSync(path.join(root,'SiteBoss-Repair-Rat.ps1'),'utf8');
let fail=0;
function ok(n,v){console.log(`[${v?'PASS':'FAIL'}] ${n}`);if(!v)fail++;}

ok('manifest limits required',rat.includes('Controller scope manifest is missing limits'));
ok('source limit read from manifest',rat.includes("max_source_files"));
ok('write limit read from manifest',rat.includes("max_write_files"));
ok('absolute source ceiling',rat.includes('manifestMaxSource-gt64'));
ok('absolute write ceiling',rat.includes('manifestMaxWrite-gt32'));
ok('source checked against manifest',rat.includes('source.Count-gt$manifestMaxSource'));
ok('write checked against manifest',rat.includes('write.Count-gt$manifestMaxWrite'));
ok('stale config source cap removed from controller scope validation',
   !rat.includes('Controller scope source count exceeds $($Config.MaxSourceFiles)'));
ok('stale config write cap removed from controller scope validation',
   !rat.includes('Controller scope write count exceeds $($Config.MaxFiles)'));

process.exit(fail?2:0);
