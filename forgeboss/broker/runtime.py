from __future__ import annotations
import json,os,subprocess,time
from dataclasses import dataclass
from pathlib import Path
from .crypto import broker_root
class BrokerRuntimeError(RuntimeError):pass
@dataclass
class RuntimeResult:repo:Path;base_sha:str;cost_usd:float|None;calls:int|None;completed:bool;error:str|None
def _git_env(root:Path):
    home=root/"git-home";home.mkdir(parents=True,exist_ok=True);return {**os.environ,"HOME":str(home),"USERPROFILE":str(home),"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,"GIT_CONFIG_SYSTEM":os.devnull,"GIT_TERMINAL_PROMPT":"0","GIT_OPTIONAL_LOCKS":"0"}
def git(repo:Path,*args,check=True,timeout=120):
    cp=subprocess.run(["git",*args],cwd=repo,capture_output=True,text=True,timeout=timeout,env=_git_env(repo))
    if check and cp.returncode:raise BrokerRuntimeError((cp.stdout+cp.stderr).strip() or "git failed")
    return cp.stdout.strip()
def _safe_id(raw):
    import hashlib
    return hashlib.sha256(raw.encode()).hexdigest()[:24]
def _assert_private_root(root:Path):
    root=root.resolve();expected=broker_root().resolve()
    if root!=expected:raise BrokerRuntimeError("broker private root is not fixed protected root")
    root.mkdir(parents=True,exist_ok=True)
    if root.is_symlink():raise BrokerRuntimeError("broker private root cannot be symlink")
    if os.name!="nt":
        import stat
        st=root.stat()
        if st.st_uid!=0 or stat.S_IMODE(st.st_mode)&0o022:raise BrokerRuntimeError("broker private root is not root-owned/write-protected")
    return root
def _linklike(p:Path):
    try:
        if p.is_symlink():return True
        return bool(hasattr(p,"is_junction") and p.is_junction())
    except OSError:return True
def materialize_base(source_worktree:Path,base_sha:str,run_id:str,root:Path|None=None)->Path:
    root=_assert_private_root(root or broker_root());runs=root/"runs";runs.mkdir(parents=True,exist_ok=True);target=runs/_safe_id(run_id)
    if target.exists():raise BrokerRuntimeError("private run directory already exists/replay")
    target.mkdir(mode=0o700);repo=target/"repo";source=Path(source_worktree).resolve();dotgit=source/".git"
    if not dotgit.exists() or _linklike(dotgit):raise BrokerRuntimeError("source worktree Git metadata is missing/linklike")
    cp=subprocess.run(["git","clone","--no-hardlinks","--no-checkout","--no-tags",str(source),str(repo)],capture_output=True,text=True,timeout=180,env=_git_env(target))
    if cp.returncode:raise BrokerRuntimeError((cp.stdout+cp.stderr).strip() or "private exact-base clone failed")
    private_git=repo/".git";alt=private_git/"objects"/"info"/"alternates"
    if alt.exists() or alt.is_symlink():raise BrokerRuntimeError("private clone retained external object alternates")
    for p in private_git.rglob("*"):
        if _linklike(p):raise BrokerRuntimeError("private Git metadata contains link/junction: "+str(p.relative_to(private_git)))
    empty=target/"empty-hooks";empty.mkdir();git(repo,"config","core.hooksPath",str(empty));git(repo,"remote","remove","origin");git(repo,"checkout","--detach","--force",base_sha)
    got=git(repo,"rev-parse","HEAD")
    if got.lower()!=base_sha.lower():raise BrokerRuntimeError("private snapshot HEAD differs from protected authority baseSha")
    return repo
def _task_text(packet):return f"""You are a bounded coding worker inside ForgeBoss. Product: SiteBoss.\nObjective: {packet.get('objective','')}\n\nIMMUTABLE RULES:\n- Modify ONLY: {json.dumps(packet.get('allowed_files',[]))}\n- Relevant context: {json.dumps(packet.get('context_files',[]))}\n- Do not modify .github, credentials, generated files, Git metadata, or anything outside allowed_files.\n- Do not push, publish, merge, deploy, alter remotes, or access network.\n- Do not weaken tests.\n- Use the repository mounted at /workspace.\n- When finished, leave the working tree with only the justified repair.\n\nRequired acceptance intent:\n{json.dumps(packet.get('acceptance_criteria',[]))}\n"""
def run_mini_swe(repo:Path,packet:dict,budget:float,model_name:str,image:str)->RuntimeResult:
    env_obj=None;agent=None
    try:
        from minisweagent.agents.default import DefaultAgent
        from minisweagent.environments.docker import DockerEnvironment
        from minisweagent.models.litellm_model import LitellmModel
        mount=f"type=bind,src={repo},dst=/workspace";env_obj=DockerEnvironment(image=image,cwd="/workspace",run_args=["--rm","--network","none","--mount",mount],timeout=180,container_timeout="45m");model=LitellmModel(model_name=model_name)
        system='''You are a bounded software-engineering worker operating through a shell.\nYour response must contain exactly ONE bash command block in this format:\n```mswea_bash_command\nyour_command_here\n```\nWork iteratively: inspect, edit, test, and verify. Never publish or change remote Git state.\nWhen complete issue exactly:\n```mswea_bash_command\necho COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\n```''';instance="{{ task }}\n\nYou are in {{ cwd }}. Work only inside the bounded repository and obey the task contract."
        agent=DefaultAgent(model,env_obj,system_template=system,instance_template=instance,cost_limit=budget,step_limit=30,wall_time_limit_seconds=900);agent.run(_task_text(packet));return RuntimeResult(repo,git(repo,"rev-parse","HEAD"),float(getattr(agent,"cost",0.0) or 0.0),int(getattr(agent,"n_calls",0) or 0),True,None)
    except Exception as e:
        cost=calls=None
        try:
            if agent is not None:cost=float(getattr(agent,"cost",0.0) or 0.0);calls=int(getattr(agent,"n_calls",0) or 0)
        except Exception:pass
        return RuntimeResult(repo,git(repo,"rev-parse","HEAD") if repo.exists() else "",cost,calls,False,f"{type(e).__name__}: {e}")
    finally:
        try:
            if env_obj is not None:env_obj.cleanup()
        except Exception:pass
def quarantine_run(repo:Path):
    try:
        root=broker_root().resolve();repo=repo.resolve()
        if root not in repo.parents:return
        run_dir=repo.parent;q=root/"quarantine";q.mkdir(parents=True,exist_ok=True);os.replace(run_dir,q/(run_dir.name+"-"+str(int(time.time()))))
    except Exception:pass
