'use strict';
const crypto=require('crypto');const h=v=>crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex');
function buildPacket(cfg,c,s,target){
 const p={schema:1,packet_id:`SB-${c.root_pr.number}-${target.repair_pr?`R${target.repair_pr}`:'LOCAL'}-${s.scope_sha256.slice(0,12)}`,created_at:new Date().toISOString(),
 objective:'Repair the independently rejected PostgreSQL candidate without introducing replay-unsafe generic transaction behavior.',
 reason:'Review evidence requires dependency-expanded transaction/invitation scope.',repository:`${c.owner}/${c.repo}`,
 root_pr:c.root_pr.number,repair_pr:target.repair_pr,target_mode:target.mode,candidate_parent_sha:target.target_sha,target_upstream_base_sha:target.base_sha,expected_head_revision:target.target_sha,
 allowed_files:s.write_allowlist,context_files:s.source_paths,
 forbidden_scope:['.github/**','secrets/**','credentials/**','generated/**','force push','merge to main','deploy'],
 dependencies:['authoritative GitHub binding','exact repair mirror','dependency-expanded scope'],
 acceptance_criteria:['Repair Rat clean validation passes','independent clean reconstruction passes','independent review PASS','no change outside allowed_files','no replay-unsafe generic transaction retry'],
 risk:'HIGH',estimated_model_calls_max:cfg.budgets.max_model_calls_per_run,retry_limit:cfg.budgets.max_repair_retries,
 write_authority:'local disposable repair workspace only',publication_authority:'NONE in v0.9'};
 p.packet_sha256=h(p);return p;
}
module.exports={buildPacket};
