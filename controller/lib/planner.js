'use strict';
const { sha256Text } = require('./state');
function buildDryRunPlan(root,cfg,doctorReport){
  const packet={
    packet_id:`FOUNDATION-${sha256Text(JSON.stringify(doctorReport)).slice(0,12)}`,
    objective:'Validate controller foundation and identify next authoritative-control milestone.',
    reason:'M1/M2 foundation is active; live execution remains disabled.',
    repository:cfg.repository.url,
    expected_base_revision:null,
    allowed_scope:['controller/**','state/**'],
    forbidden_scope:['application repository mutation','GitHub writes','merge','deploy'],
    dependencies:['doctor pass','exclusive controller lock'],
    acceptance_criteria:['configuration valid','state root writable','controller lock works','run state persists atomically','dry-run performs no repository mutation'],
    required_tests:['controller selftest','doctor'],
    validation_commands:['node controller/siteboss-autopilot.js doctor','node controller/siteboss-autopilot.js dry-run'],
    risk:'LOW',estimated_api_cost_usd:0,retry_limit:0,write_authority:'controller state only',
    completion_evidence:'machine-readable run state and logs'
  };
  return {schema:1,generated_at:new Date().toISOString(),mode:'dry-run',model_calls_planned:0,github_writes_planned:0,repository_mutations_planned:0,packets:[packet]};
}
module.exports={buildDryRunPlan};
