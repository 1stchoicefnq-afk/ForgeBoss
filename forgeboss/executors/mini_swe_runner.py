from __future__ import annotations
import hashlib, json, os, sys, traceback, subprocess
from pathlib import Path

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

def _persist_result(result:dict)->None:
    raw=os.environ.get("FORGEBOSS_RESULT_FILE")
    if not raw:return
    state_raw=os.environ.get("FORGEBOSS_STATE_ROOT")
    if not state_raw:raise RuntimeError("FORGEBOSS_STATE_ROOT required for result evidence")
    root=Path(state_raw).expanduser().resolve()
    target=Path(raw).expanduser().resolve()
    try:
        if Path(os.path.commonpath([str(root),str(target)]))!=root:
            raise RuntimeError("result evidence path escapes external state root")
    except ValueError as ex:
        raise RuntimeError("result evidence path escapes external state root") from ex
    target.parent.mkdir(parents=True,exist_ok=True)
    tmp=target.with_name(target.name+f".tmp-{os.getpid()}")
    data=(json.dumps(result,sort_keys=True,indent=2,allow_nan=False)+"\n").encode("utf-8")
    fd=os.open(str(tmp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as fh:
            fh.write(data);fh.flush();os.fsync(fh.fileno())
    finally:
        try:os.close(fd)
        except OSError:pass
    os.replace(tmp,target)

def _initial_result(packet_path:str|os.PathLike[str],workspace:str,model_name:str)->dict:
    pp=Path(packet_path)
    packet=json.loads(pp.read_text(encoding="utf-8"))
    return {
        "schema":1,
        "executor":"mini-swe",
        "model":model_name,
        "cost_usd":0.0,
        "calls":0,
        "completed":False,
        "error":None,
        "task_id":str(packet.get("task_id") or ""),
        "builder_id":str(packet.get("builder_id") or ""),
        "run_id":str(packet.get("run_id") or ""),
        "expected_head_revision":str(packet.get("expected_head_revision") or "").lower(),
        "workspace":str(Path(workspace).resolve()),
        "packet_sha256":hashlib.sha256(pp.read_bytes()).hexdigest(),
        "postflight":None,
    }

def _persist_early_failure(result:dict,message:str,code:int)->int:
    result["error"]=message
    try:_persist_result(result)
    except Exception as evidence_error:
        print("FORGEBOSS RESULT EVIDENCE ERROR: "+str(evidence_error),file=sys.stderr)
    print("FORGEBOSS SAFE STOP: "+message,file=sys.stderr)
    print("FORGEBOSS_RESULT_JSON="+json.dumps(result,separators=(",",":")))
    return code

def _exception_detail(ex: BaseException) -> str:
    parts=[f"{type(ex).__name__}: {ex}"]
    for name in ("stderr","stdout","output"):
        value=getattr(ex,name,None)
        if value is None:
            continue
        if isinstance(value,bytes):
            value=value.decode("utf-8","replace")
        text=str(value).strip()
        if text and text not in parts:
            parts.append(f"{name}: {text}")
    return " | ".join(parts)[-6000:]

def _hidden_run(args:list[str], **kwargs):
    kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
    return subprocess.run(args, **kwargs)

def _guard_subprocess(args:list[str]):
    engine_root=Path(__file__).resolve().parents[2]
    env=dict(os.environ)
    env["PYTHONPATH"]=str(engine_root)
    env["PYTHONNOUSERSITE"]="1"
    env["PYTHONDONTWRITEBYTECODE"]="1"
    env.pop("PYTHONHOME",None)
    return _hidden_run(
        [sys.executable,"-m","forgeboss.security.executor_guard",*args],
        cwd=str(engine_root),env=env,capture_output=True,text=True,
    )

def main() -> int:
    if len(sys.argv)<4:
        print("usage: mini_swe_runner.py PACKET.json WORKSPACE BUDGET_USD",file=sys.stderr);return 2

    packet=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    workspace=str(Path(sys.argv[2]).resolve())
    budget=float(sys.argv[3])
    model_name=os.environ.get("FORGEBOSS_MINISWE_MODEL","openai/gpt-5.6-luna")
    result=_initial_result(sys.argv[1],workspace,model_name)

    if os.environ.get("FORGEBOSS_ALLOW_PAID_EXECUTOR")!="YES":
        return _persist_early_failure(result,"paid executor gate is not enabled",3)
    lease=os.environ.get("FORGEBOSS_EXECUTOR_LEASE","");lease_token=os.environ.get("FORGEBOSS_EXECUTOR_LEASE_TOKEN","")
    if not lease or not lease_token:
        return _persist_early_failure(result,"unified executor lease missing",13)
    if os.environ.get("FORGEBOSS_SELF_BUILD_MODE")=="YES":
        launch_bundle=os.environ.get("FORGEBOSS_PROTECTED_LAUNCH_BUNDLE","")
        if not launch_bundle:
            return _persist_early_failure(result,"protected self-build launch bundle missing",13)
        v=_guard_subprocess([
            "protected-paid-start","--lease",lease,"--token",lease_token,
            "--packet",sys.argv[1],"--workspace",workspace,"--executor","mini-swe",
            "--launch-bundle",launch_bundle,"--budget",str(budget),
        ])
    else:
        v=_guard_subprocess([
            "verify","--lease",lease,"--token",lease_token,
            "--packet",sys.argv[1],"--workspace",workspace,"--executor","mini-swe",
        ])
    if v.returncode:
        detail=(v.stdout or v.stderr or "protected paid-start guard denied").strip()[-2000:]
        return _persist_early_failure(result,"protected paid-start guard denied: "+detail,13)
    env_obj=None
    try:
        from minisweagent.agents.default import DefaultAgent
        from minisweagent.environments.docker import DockerEnvironment
        from minisweagent.models.litellm_textbased_model import LitellmTextbasedModel

        class ForgeBossDockerEnvironment(DockerEnvironment):
            """Windows-safe, synchronous container cleanup for protected self-build."""
            def cleanup(self):
                cid=getattr(self,"container_id",None)
                if not cid:return
                exe=self.config.executable
                _hidden_run([exe,"stop","--time","10",cid],capture_output=True,text=True,timeout=20,check=False)
                _hidden_run([exe,"rm","-f",cid],capture_output=True,text=True,timeout=20,check=False)
                probe=_hidden_run([exe,"inspect",cid],capture_output=True,text=True,timeout=10,check=False)
                self.container_id=None
                if probe.returncode==0:
                    raise RuntimeError("ForgeBoss Docker containment cleanup failed")

        # Model runs on host; shell runs in a network-disabled container.
        # The container receives the disposable repo only, not API/GitHub credentials.
        mount=f"type=bind,src={workspace},dst=/workspace"
        run_id=str(packet.get("run_id") or "")
        builder_id=str(packet.get("builder_id") or "")
        env_obj=ForgeBossDockerEnvironment(
            image=os.environ.get("FORGEBOSS_MINISWE_IMAGE","node:22-bookworm"),
            cwd="/workspace",
            env={"PYTHONDONTWRITEBYTECODE":"1","PYTHONUTF8":"1"},
            run_args=[
                "--rm","--network","none","--mount",mount,
                "--label",f"forgeboss.stage1.run={run_id}",
                "--label",f"forgeboss.stage1.worker={builder_id}",
            ],
            timeout=180,
            container_timeout="45m",
        )
        model=LitellmTextbasedModel(model_name=model_name)
        system_template=r"""You are a bounded software-engineering worker operating through a shell.
Your response must contain exactly ONE bash command block in this format:

```mswea_bash_command
your_command_here
```

Work iteratively: inspect, edit, test, and verify. Never publish or change remote Git state.
When the task is complete, issue exactly:
```mswea_bash_command
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```
"""
        instance_template=r"""{{ task }}

You are in {{ cwd }}. Work only inside the bounded repository and obey the task contract.
"""
        agent=DefaultAgent(
            model,env_obj,
            system_template=system_template,
            instance_template=instance_template,
            cost_limit=budget,
            step_limit=30,
            wall_time_limit_seconds=900,
        )
        product=str(packet.get("product") or "ForgeBoss")
        task=f"""You are a bounded coding worker inside ForgeBoss. Product: {product}.
Objective: {packet.get('objective','')}

IMMUTABLE RULES:
- Modify ONLY: {json.dumps(packet.get('allowed_files',[]))}
- Relevant context: {json.dumps(packet.get('context_files',[]))}
- Do not modify .github, credentials, generated files, or anything outside allowed_files.
- Do not push, publish, merge, deploy, alter remotes, or access network.
- Do not weaken tests.
- Use the repository already mounted at /workspace.
- When finished, leave the working tree with only the justified repair.

Required acceptance intent:
{json.dumps(packet.get('acceptance_criteria',[]))}
"""
        agent.run(task)
        result["cost_usd"]=float(getattr(agent,"cost",0.0) or 0.0)
        result["calls"]=int(getattr(agent,"n_calls",0) or 0)
        post=_guard_subprocess([
            "postflight","--lease",lease,"--token",lease_token,
            "--packet",sys.argv[1],"--workspace",workspace,"--executor","mini-swe",
        ])
        if post.returncode:
            result["error"]="ForgeBoss postflight denied worker result: "+(post.stdout or post.stderr)[-1200:]
            return 13
        try:
            line=(post.stdout or "").strip().splitlines()[-1]
            postflight=json.loads(line)
        except Exception:
            result["error"]="ForgeBoss postflight produced unreadable evidence"
            return 13
        if postflight.get("ok") is not True or postflight.get("scope_ok") is not True or postflight.get("paid_consumed") is not True:
            result["error"]="ForgeBoss postflight evidence did not prove paid bounded execution"
            return 13
        result["postflight"]=postflight
        result["completed"]=True
        return 0
    except Exception as e:
        try:
            if 'agent' in locals():
                result["cost_usd"]=float(getattr(agent,"cost",0.0) or 0.0)
                result["calls"]=int(getattr(agent,"n_calls",0) or 0)
        except Exception: pass
        result["error"]=_exception_detail(e)
        print(result["error"],file=sys.stderr)
        return 10
    finally:
        try:
            if env_obj is not None: env_obj.cleanup()
        except Exception: pass
        try:
            _persist_result(result)
        except Exception as evidence_error:
            print("FORGEBOSS RESULT EVIDENCE ERROR: "+str(evidence_error),file=sys.stderr)
        print("FORGEBOSS_RESULT_JSON="+json.dumps(result,separators=(",",":")))

if __name__=="__main__":raise SystemExit(main())