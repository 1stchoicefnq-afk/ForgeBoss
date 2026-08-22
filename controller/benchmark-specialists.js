'use strict';
const fs=require('fs'),path=require('path');
const {routeSpecialists,composePrompt}=require('./lib/specialists');
const ROOT=path.resolve(__dirname,'..');
const cases=[
 {id:'postgres-transaction',objective:'Fix PostgreSQL SERIALIZABLE 40001 transaction retry and migration bug',files:['src/persistence/postgres.js'],expect:['database-optimizer']},
 {id:'auth-permission',objective:'Fix OIDC authentication authorization session permission bug',files:['src/auth/oidc.js'],expect:['identity-access-engineer']},
 {id:'travis-orchestration',objective:'Fix OpenAI LLM multi-agent Travis worker orchestration prompt routing',files:['src/travis/conversation.js'],expect:['multi-agent-systems-architect']},
 {id:'frontend-bug',objective:'Fix React frontend UI CSS accessibility component bug',files:['src/ui/App.jsx'],expect:['frontend-developer']},
 {id:'ci-build',objective:'Fix GitHub Actions CI Docker npm build pipeline',files:['.github/workflows/test.yml'],expect:['devops-automator']},
 {id:'code-review',objective:'Review exact code diff for correctness and regression',files:['src/x.js'],expect:['code-reviewer'],mode:'reviewer'}
];
const results=[];
for(const c of cases){
 const packet={objective:c.objective,allowed_files:c.files,changed_files:c.files};
 const mode=c.mode||'builder';
 const route=routeSpecialists(ROOT,packet,{mode,builderSpecialists:[]});
 const comp=composePrompt(ROOT,packet,route,{mode});
 results.push({
  id:c.id,mode,expected:c.expect,selected:route.specialists,
  routing_correct:c.expect.some(x=>route.specialists.includes(x)),
  profile_count:route.specialists.length,
  specialist_prompt_chars:comp.approx_chars,
  baseline_generic_profile_chars:0,
  scope_adherence_static:comp.boundaries.scope_widening===false,
  completion_quality:'NOT_MEASURED_NO_MODEL_CALL',
  latency_ms:'NOT_MEASURED_NO_MODEL_CALL',
  failure_rate:'NOT_MEASURED_NO_MODEL_CALL'
 });
}
const correct=results.filter(x=>x.routing_correct).length;
const out={
 schema:1,benchmark:'specialist-routing-vs-generic-worker',model_calls:0,
 note:'This benchmark measures deterministic routing, prompt/context overhead and static scope preservation only. It does not claim model-quality improvement.',
 cases:results,
 summary:{cases:results.length,routing_correct:correct,routing_accuracy:correct/results.length,
  max_profiles:Math.max(...results.map(x=>x.profile_count)),
  avg_specialist_prompt_chars:Math.round(results.reduce((n,x)=>n+x.specialist_prompt_chars,0)/results.length)}
};
const outPath=path.join(ROOT,'state','benchmarks','specialists-v1.json');
fs.mkdirSync(path.dirname(outPath),{recursive:true});fs.writeFileSync(outPath,JSON.stringify(out,null,2));
console.log(JSON.stringify(out,null,2));
process.exit(correct===results.length?0:2);
