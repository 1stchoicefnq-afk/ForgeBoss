from __future__ import annotations
import hashlib,json,os,subprocess
from dataclasses import dataclass
from pathlib import Path
from forgeboss.security import executor_guard as guard
from .crypto import broker_root
from .runtime import git,_git_env,_assert_private_root,_linklike
class ReintegrationError(RuntimeError):pass
ZERO_OID="0"*40
@dataclass(frozen=True)
class HandoffResult:
    base_commit:str;result_commit:str;result_tree:str;result_ref:str;old_oid:str;new_oid:str;applied_paths:tuple[str,...];diff_sha256:str;handoff_repo_id:str
def _digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
def _z(raw):return [x for x in raw.split("\0") if x]
def _safe_ref_component(raw):return hashlib.sha256(raw.encode()).hexdigest()[:24]
def result_ref(task_id,run_id):return f"refs/forgeboss/results/{_safe_ref_component(task_id)}/{_safe_ref_component(run_id)}"
def _changed_paths(repo):
    tracked=_z(git(repo,"diff","--name-only","-z","HEAD"));untracked=_z(git(repo,"ls-files","--others","--exclude-standard","-z"));out=[];seen=set()
    for raw in tracked+untracked:
        rel=guard.norm(raw);k=rel.casefold()
        if k in seen:raise ReintegrationError("case-colliding changed paths")
        seen.add(k);out.append(rel)
    return sorted(out,key=str.casefold)
def validate_private_diff(repo,allowed_paths):
    allowed=[guard.norm(x) for x in allowed_paths];amap={x.casefold():x for x in allowed}
    if len(amap)!=len(allowed):raise ReintegrationError("allowed path case collision")
    changed=_changed_paths(repo);bad=[p for p in changed if p.casefold() not in amap]
    if bad:raise ReintegrationError("out-of-scope private result: "+json.dumps(bad))
    canonical=[]
    for p in changed:
        target=Path(repo)/p
        if target.exists() and (guard.is_linklike(target) or not target.is_file()):raise ReintegrationError("linklike/nonregular result denied: "+p)
        canonical.append(amap[p.casefold()])
    return canonical
def _run(repo,args,input_text=None):
    cp=subprocess.run(["git",*args],cwd=repo,input=input_text,capture_output=True,text=True,timeout=180,env=_git_env(Path(repo)))
    if cp.returncode:raise ReintegrationError((cp.stdout+cp.stderr).strip() or "git result operation failed")
    return cp.stdout.strip()
def create_result_commit(repo,base_sha,allowed_paths,task_id,run_id):
    repo=Path(repo)
    if git(repo,"rev-parse","HEAD").lower()!=base_sha.lower():raise ReintegrationError("private repo HEAD drifted from exact base")
    changed=validate_private_diff(repo,allowed_paths)
    if changed:_run(repo,["add","-A","--",*changed])
    staged=sorted(_z(_run(repo,["diff","--cached","--name-only","-z",base_sha])),key=str.casefold)
    if [x.casefold() for x in staged]!=[x.casefold() for x in changed]:raise ReintegrationError("staged result path set differs from validated diff")
    tree=_run(repo,["write-tree"]);msg=f"ForgeBoss protected result {task_id}/{run_id}\n";commit=_run(repo,["-c","user.name=ForgeBoss Isolation Broker","-c","user.email=broker@localhost","commit-tree",tree,"-p",base_sha],input_text=msg)
    if _run(repo,["rev-parse",f"{commit}^{{tree}}"])!=tree:raise ReintegrationError("result tree identity mismatch")
    diff_paths=sorted(_z(_run(repo,["diff-tree","--no-commit-id","--name-only","-r","-z",base_sha,commit])),key=str.casefold)
    if [x.casefold() for x in diff_paths]!=[x.casefold() for x in changed]:raise ReintegrationError("result commit diff differs from validated path set")
    return commit,tree,tuple(changed),_digest({"base":base_sha.lower(),"result":commit,"tree":tree,"paths":changed})
def _handoff_repo():
    root=_assert_private_root(broker_root());repo=root/"handoff.git"
    if repo.exists():
        if _linklike(repo) or not repo.is_dir():raise ReintegrationError("protected handoff repository is unsafe")
    else:
        cp=subprocess.run(["git","init","--bare",str(repo)],capture_output=True,text=True,timeout=60,env=_git_env(root))
        if cp.returncode:raise ReintegrationError((cp.stdout+cp.stderr).strip() or "cannot initialize protected handoff repository")
    if _linklike(repo):raise ReintegrationError("protected handoff repository is link/junction")
    alt=repo/"objects"/"info"/"alternates"
    if alt.exists() or alt.is_symlink():raise ReintegrationError("protected handoff repository has external object alternates")
    if os.name!="nt":
        import stat
        st=repo.stat()
        if st.st_uid!=0 or stat.S_IMODE(st.st_mode)&0o022:raise ReintegrationError("protected handoff repository ownership/mode invalid")
    for p in repo.rglob("*"):
        if _linklike(p):raise ReintegrationError("protected handoff Git metadata contains link/junction: "+str(p.relative_to(repo)))
    return repo
def _bare(repo,*args,check=True):
    repo=Path(repo);empty=repo.parent/"empty-hooks";empty.mkdir(parents=True,exist_ok=True)
    cp=subprocess.run(["git","--git-dir",str(repo),"-c",f"core.hooksPath={empty}",*args],capture_output=True,text=True,timeout=180,env=_git_env(repo.parent))
    if check and cp.returncode:raise ReintegrationError((cp.stdout+cp.stderr).strip() or "protected handoff Git operation failed")
    return cp.stdout.strip(),cp.returncode
def handoff_result(private_repo,base_sha,result_commit,result_tree,paths,diff_sha,task_id,run_id):
    handoff=_handoff_repo();ref=result_ref(task_id,run_id);_old,rc=_bare(handoff,"show-ref","--verify","--hash",ref,check=False)
    if rc==0:raise ReintegrationError("protected result ref already exists/replay")
    export=f"refs/forgeboss/export/{_safe_ref_component(task_id+':'+run_id)}";_run(private_repo,["update-ref",export,result_commit,ZERO_OID])
    try:_bare(handoff,"-c","protocol.file.allow=always","-c","fetch.fsckObjects=true","fetch","--no-tags","--no-write-fetch-head",str(Path(private_repo).resolve()),export)
    finally:_run(private_repo,["update-ref","-d",export])
    got,_=_bare(handoff,"rev-parse",result_commit);tree,_=_bare(handoff,"rev-parse",f"{result_commit}^{{tree}}")
    if got!=result_commit or tree!=result_tree:raise ReintegrationError("imported protected result object identity mismatch")
    _bare(handoff,"update-ref",ref,result_commit,ZERO_OID);final,_=_bare(handoff,"show-ref","--verify","--hash",ref)
    if final!=result_commit:raise ReintegrationError("protected result-ref CAS verification failed")
    return HandoffResult(base_sha.lower(),result_commit,result_tree,ref,ZERO_OID,result_commit,paths,diff_sha,_digest({"root":"protected-handoff-v1","ref":ref}))
def build_and_handoff(repo,base_sha,allowed_paths,task_id,run_id):
    commit,tree,paths,diff_sha=create_result_commit(repo,base_sha,allowed_paths,task_id,run_id);return handoff_result(repo,base_sha,commit,tree,paths,diff_sha,task_id,run_id)
