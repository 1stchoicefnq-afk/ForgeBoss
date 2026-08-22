'use strict';
const fs=require('fs'),path=require('path');
const {routeSpecialists}=require('./lib/specialists');
const ROOT=path.resolve(__dirname,'..');
let pass=0,fail=0;
function ok(n,v,d=''){console.log(`[${v?'PASS':'FAIL'}] ${n}${d?': '+d:''}`);v?pass++:fail++;}

const packet={
 objective:'Repair PostgreSQL SERIALIZABLE whole-transaction retry with transaction timeout and invitation membership regression evidence',
 context_files:[
  'src/persistence/postgres.js',
  'src/auth/businessInvitations.js',
  'src/auth/businessMemberships.js',
  'tests/postgresBusinessInvitations.integration.test.js'
 ],
 allowed_files:['src/persistence/postgres.js','src/auth/businessInvitations.js']
};
const r=routeSpecialists(ROOT,packet,{mode:'builder'});
ok('DB optimizer primary',r.specialists[0]==='database-optimizer',r.specialists.join(','));
ok('Minimal Change paired',r.specialists.includes('minimal-change-engineer'),r.specialists.join(','));
ok('IAM not selected for transaction-primary packet',!r.specialists.includes('identity-access-engineer'),r.specialists.join(','));
ok('max two specialists',r.specialists.length<=2,String(r.specialists.length));

const scope=fs.readFileSync(path.join(__dirname,'lib','scope.js'),'utf8');
for(const needle of ['statement_timeout','lock_timeout','idle_in_transaction_session_timeout','transaction timeout','businessInvitations','businessMemberships','invitation membership','regression-seed']){
 ok(`scope contains ${needle}`,scope.includes(needle));
}
ok('source truncation protects regression seeds',scope.includes("has('regression-seed')?20:0"));

const dbReview=routeSpecialists(ROOT,{
 objective:'Review PostgreSQL transaction retry and timeout repair',
 changed_files:['src/persistence/postgres.js']
},{mode:'reviewer',builderSpecialists:r.specialists});
ok('DB reliability remains independent reviewer',dbReview.specialists.includes('database-reliability-engineer'),dbReview.specialists.join(','));
ok('Reality Checker final gate retained',dbReview.specialists.includes('reality-checker'),dbReview.specialists.join(','));

console.log(`V1.4.2 CONTEXT/ROUTING SELFTEST: PASS=${pass} FAIL=${fail}`);
process.exit(fail?2:0);
