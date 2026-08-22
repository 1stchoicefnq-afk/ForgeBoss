'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { route } = require('./model-router');
const { GuardedCodingTools, SecurityDenial } = require('./coding-tools');

let pass=0, fail=0;
const ok=(n,v,d='')=>{console.log(`[${v?'PASS':'FAIL'}] ${n}${d?': '+d:''}`);v?pass++:fail++;};

ok('database escalates OpenAI',
  route({objective:'PostgreSQL database SERIALIZABLE 40001 bug'}, {local:{enabled:true,endpoint:'x'}}).provider==='openai');

ok('simple bounded task may use local',
  route({objective:'simple typo', context_files:['src/a.js'], allowed_files:['src/a.js']},
        {local:{enabled:true,endpoint:'x'}}).provider==='local');

ok('missing local provider falls back OpenAI',
  route({objective:'simple typo'}, {local:{enabled:false}}).provider==='openai');

const root=fs.mkdtempSync(path.join(os.tmpdir(),'siteboss-hybrid-selftest-'));
try {
  fs.mkdirSync(path.join(root,'src'));
  fs.writeFileSync(path.join(root,'src','a.js'),'const x=1;\n');
  fs.writeFileSync(path.join(root,'src','no.js'),'secret\n');

  const tools=new GuardedCodingTools(root,{
    context_files:['src/a.js'],
    allowed_files:['src/a.js']
  });

  ok('authorized read',tools.read('src/a.js').includes('x=1'));

  let denied=false;
  try{tools.read('src/no.js')}catch(e){denied=e instanceof SecurityDenial}
  ok('unauthorized read denied',denied);

  denied=false;
  try{tools.editExact('../outside','a','b')}catch(e){denied=e instanceof SecurityDenial}
  ok('traversal denied',denied);

  denied=false;
  try{tools.editExact('C:\\outside\\x.js','a','b')}catch(e){denied=e instanceof SecurityDenial}
  ok('Windows absolute path denied',denied);

  tools.editExact('src/a.js','const x=1;','const x=2;');
  ok('authorized exact edit',tools.read('src/a.js').includes('x=2'));

  ok('bounded grep',tools.grep('const',['src/a.js','src/no.js']).length===1);
} finally {
  fs.rmSync(root,{recursive:true,force:true});
}

console.log(`HYBRID SELFTEST COMPLETE: PASS=${pass} FAIL=${fail}`);
process.exit(fail?2:0);
