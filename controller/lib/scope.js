'use strict';
const p=require('path').posix;const crypto=require('crypto');const {git}=require('./mirror');
const lines=s=>String(s||'').split(/\r?\n/).filter(Boolean);
const digest=v=>crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex');
const WIN_DEVICE=/^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/i;
let pendingScopeAuthority=null;
function canonicalRepoPath(value){
 const raw=String(value??'');
 if(!raw||raw!==raw.trim()||raw.includes('\\')||raw.startsWith('/')||raw.startsWith('//')||/^[A-Za-z]:/.test(raw)||/[\x00-\x1f\x7f]/.test(raw)||/[<>:"|?*~]/.test(raw))throw new Error(`Unsafe controller scope path: ${raw}`);
 const parts=raw.split('/');
 if(parts.some(x=>!x||x==='.'||x==='..'||x!==x.replace(/[ .]+$/,'')||WIN_DEVICE.test(x)))throw new Error(`Unsafe controller scope path: ${raw}`);
 const norm=p.normalize(raw);
 if(norm!==raw||norm.startsWith('../')||norm==='..')throw new Error(`Non-canonical controller scope path: ${raw}`);
 return norm;
}
function assertNoCaseCollisions(values,label='scope'){
 const seen=new Map();
 for(const input of values){const v=canonicalRepoPath(input),k=v.toLocaleLowerCase('en-US');if(seen.has(k)&&seen.get(k)!==v)throw new Error(`${label} contains Windows-case-colliding paths: ${seen.get(k)} <> ${v}`);seen.set(k,v);}
 return values;
}
function consumeScopeAuthority(){if(!pendingScopeAuthority)throw new Error('Controller scope authority is unavailable or already consumed');const out=pendingScopeAuthority;pendingScopeAuthority=null;return out;}
function inventory(mirror,sha){const xs=lines(git(['--git-dir',mirror,'ls-tree','-r','--name-only',sha])).map(canonicalRepoPath);assertNoCaseCollisions(xs,'repository inventory');return new Set(xs);}
function show(mirror,sha,file){try{return git(['--git-dir',mirror,'show',`${sha}:${file}`],undefined,30000);}catch{return '';}}
function grepFiles(mirror,sha,pattern){try{return lines(git(['--git-dir',mirror,'grep','-l','-I','-E',pattern,sha,'--','src','tests'],undefined,60000)).map(canonicalRepoPath);}catch(e){if(e.git_exit===1)return [];return [];}}
function importsOf(content){const out=[];for(const r of [/\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,/\bfrom\s+['"]([^'"]+)['"]/g,/\bimport\s*\(\s*['"]([^'"]+)['"]/g]){let m;while((m=r.exec(content)))out.push(m[1]);}return [...new Set(out)];}
function resolveImport(from,spec,inv){if(!spec.startsWith('.'))return null;const base=p.normalize(p.join(p.dirname(from),spec));for(const c of [base,`${base}.js`,`${base}.mjs`,`${base}.cjs`,p.join(base,'index.js')])if(inv.has(c))return c;return null;}
function buildScope(cfg,c,mi,target){
 target=target||{mode:'existing-child',repair_pr:c.repair_pr?.number??null,target_sha:c.repair_pr?.head_sha,base_sha:c.repair_pr?.base_sha};
 if(!target.target_sha)throw new Error('Scope target SHA missing');
 const controlArtifact=c?._forgeboss_control_artifact;
 if(!controlArtifact||!controlArtifact.sha256||!controlArtifact.invocation_id)throw new Error('Scope build requires controller-held authoritative control artifact');
 if(pendingScopeAuthority)throw new Error('Previous controller scope authority was not consumed');
 const mirror=mi.mirror,sha=target.target_sha,inv=inventory(mirror,sha);
 const reasons=new Map();const add=(input,r)=>{const f=canonicalRepoPath(input);if(!inv.has(f)||!(f.startsWith('src/')||f.startsWith('tests/')))return;if(!reasons.has(f))reasons.set(f,new Set());reasons.get(f).add(r);};
 for(const f of cfg.scope.seed_paths||[])add(f,'configured-seed');
 const regressionSeeds=['tests/postgresTransactionTimeout.integration.test.js','tests/postgresTransactionTimeouts.integration.test.js','tests/postgresBusinessInvitations.integration.test.js','tests/postgresBusinessMemberships.integration.test.js','tests/postgresMembershipAuthentication.integration.test.js','tests/postgresProductionHttp.integration.test.js','tests/postgresTravisIntake.integration.test.js'].filter(f=>inv.has(f));
 for(const f of regressionSeeds)add(f,'regression-seed');
 let diff=[];if(target.mode==='existing-child'){try{diff=lines(git(['--git-dir',mirror,'diff','--name-only',target.base_sha,target.target_sha,'--','src','tests'])).map(canonicalRepoPath);}catch{}for(const f of diff)add(f,'repair-pr-diff');}
 for(const term of ['withTransaction','SERIALIZABLE','40001','40P01','retry','statement_timeout','lock_timeout','idle_in_transaction_session_timeout','transaction timeout','timeout','invitation','Invitation','businessInvitations','membership','Membership','businessMemberships','acceptInvitation','business invitation','invitation membership','recordQualification','INTAKE_CONVERSION_CONFLICT','Trade pack fencing'])for(const f of grepFiles(mirror,sha,term))add(f,`grep:${term}`);
 let frontier=[...reasons.keys()],seen=new Set(frontier);for(let depth=0;depth<(cfg.scope.max_dependency_depth||4);depth++){const next=[];for(const f of frontier){for(const spec of importsOf(show(mirror,sha,f))){const dep=resolveImport(f,spec,inv);if(dep){add(dep,`imported-by:${f}`);if(!seen.has(dep)){seen.add(dep);next.push(dep);}}}}frontier=next;if(!frontier.length)break;}
 for(const f of [...reasons.keys()]){const stem=p.basename(f).replace(/\.(integration\.)?test\.js$/,'').replace(/\.js$/,'');if(stem.length<5)continue;for(const ref of grepFiles(mirror,sha,stem))add(ref,`references:${stem}`);}
 let source=[...reasons.keys()].sort();
 if(source.length>(cfg.scope.max_source_files||48))source=source.map(f=>({f,score:(reasons.get(f)?.size||0)+(f.startsWith('src/')?2:1)+(diff.includes(f)?5:0)+(reasons.get(f)?.has('regression-seed')?20:0)+(reasons.get(f)?.has('configured-seed')?10:0)})).sort((a,b)=>b.score-a.score||a.f.localeCompare(b.f)).slice(0,cfg.scope.max_source_files||48).map(x=>x.f).sort();
 assertNoCaseCollisions(source,'source_paths');
 const writableCandidates=source.filter(f=>(f.startsWith('src/')&&/\.(js|mjs|cjs)$/.test(f))||(f.startsWith('tests/')&&/\.test\.js$/.test(f)));
 const mustWrite=new Set((cfg.scope.must_write_paths||[]).map(canonicalRepoPath).filter(f=>writableCandidates.includes(f)));
 function writeScore(f){const rs=[...(reasons.get(f)||[])];let score=0;if(mustWrite.has(f))score+=1000;if(rs.includes('repair-pr-diff'))score+=250;if(rs.includes('configured-seed'))score+=200;if(rs.includes('regression-seed'))score+=240;for(const r of rs){if(/^grep:(withTransaction|SERIALIZABLE|40001|40P01|retry|statement_timeout|lock_timeout|idle_in_transaction_session_timeout|transaction timeout|timeout)$/i.test(r))score+=180;if(/^grep:(invitation|Invitation|businessInvitations|membership|Membership|businessMemberships|acceptInvitation|business invitation|invitation membership|recordQualification)$/i.test(r))score+=140;if(/^grep:(INTAKE_CONVERSION_CONFLICT|Trade pack fencing)$/i.test(r))score+=100;if(r.startsWith('imported-by:'))score+=70;if(r.startsWith('references:'))score+=50;}if(f.startsWith('src/'))score+=20;if(f.startsWith('tests/'))score+=10;if(/src\/persistence\/(postgres|postgresApplicationServices|platformStore)\.js$/.test(f))score+=300;if(f==='src/travis/conversation.js')score+=300;if(f==='src/intake/postgresApplication.js')score+=250;return score;}
 let write=writableCandidates.map(f=>({f,score:writeScore(f)})).sort((a,b)=>b.score-a.score||a.f.localeCompare(b.f)).slice(0,cfg.scope.max_write_files||24).map(x=>x.f).sort();
 assertNoCaseCollisions(write,'write_allowlist');
 const droppedMustWrite=[...mustWrite].filter(f=>!write.includes(f));if(droppedMustWrite.length)throw new Error(`Write allowlist cap dropped required repair paths: ${droppedMustWrite.join(', ')}`);
 const why={};for(const f of source)why[f]=[...(reasons.get(f)||[])].sort();
 const m={schema:1,generated_at:new Date().toISOString(),repair_pr:target.repair_pr,root_pr:c.root_pr.number,target_mode:target.mode,exact_head:target.target_sha,exact_base:target.base_sha,source_paths:source.map(canonicalRepoPath),write_allowlist:write.map(canonicalRepoPath),reasons:why,write_selection:{strategy:'relevance-score-v2',must_write_paths:[...mustWrite].sort(),ranked_candidates:writableCandidates.map(f=>({path:f,score:writeScore(f)})).sort((a,b)=>b.score-a.score||a.path.localeCompare(b.path))},limits:{max_source_files:cfg.scope.max_source_files,max_write_files:cfg.scope.max_write_files,max_dependency_depth:cfg.scope.max_dependency_depth}};
 m.scope_sha256=digest(m);
 pendingScopeAuthority=Object.freeze({schema:1,kind:'controller-scope',artifact_id:crypto.randomUUID(),scope_sha256:m.scope_sha256,exact_head:m.exact_head,exact_base:m.exact_base,root_pr:m.root_pr,repair_pr:m.repair_pr,control_invocation_id:controlArtifact.invocation_id,control_sha256:controlArtifact.sha256,control_root_node_id:controlArtifact.root_node_id,control_repair_node_id:controlArtifact.repair_node_id});
 return m;
}
module.exports={buildScope,importsOf,resolveImport,canonicalRepoPath,consumeScopeAuthority,_test:{digest,assertNoCaseCollisions,WIN_DEVICE}};
