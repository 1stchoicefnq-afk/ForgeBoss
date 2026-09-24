from __future__ import annotations
import hashlib, importlib.metadata, json, os, sys, traceback, subprocess
from pathlib import Path

GOVERNED_MINISWE_VERSION="2.4.6"
GOVERNED_MINISWE_IMAGE="node@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a"

def main() -> int:
    if len(sys.argv)<4:
        print("usage: mini_swe_runner.py PACKET.json WORKSPACE BUDGET_USD",file=sys.stderr);return 2
    if os.environ.get("FORGEBOSS_ALLOW_PAID_EXECUTOR")!="YES":
        print("FORGEBOSS SAFE STOP: paid executor gate is not enabled.");return 3

    packet=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    workspace=str(Path(sys.argv[2]).resolve())
    budget=float(sys.argv[3])
    model_name=os.environ.get("FORGEBOSS_MINISWE_MODEL","openai/gpt-5.6-luna")

    result={"executor":"mini-swe","model":model_name,"cost_usd":0.0,"completed":False,"error":None}
    guard=Path(__file__).resolve().parents[1]/"security"/"executor_guard.py"
    lease=os.environ.get("FORGEBOSS_EXECUTOR_LEASE","");lease_token=os.environ.get("FORGEBOSS_EXECUTOR_LEASE_TOKEN","")
    if not lease or not lease_token:
        print("FORGEBOSS SAFE STOP: unified executor lease missing.",file=sys.stderr);return 13

    governed=os.environ.get("FORGEBOSS_GOVERNED_RUN")=="YES"
    expected_runner_hash=os.environ.get("FORGEBOSS_EXPECTED_RUNNER_SHA256","")
    control_envelope=os.environ.get("FORGEBOSS_CONTROL_ENVELOPE","")
    if governed:
        runner_text=Path(__file__).read_text(encoding="utf-8").replace("\r\n","\n").replace("\r","\n")
        actual_runner_hash=hashlib.sha256(runner_text.encode("utf-8")).hexdigest()
        if not expected_runner_hash or actual_runner_hash!=expected_runner_hash:
            print("FORGEBOSS SAFE STOP: governed runner identity mismatch.",file=sys.stderr);return 13
        try:
            actual_version=importlib.metadata.version("mini-swe-agent")
        except Exception:
            actual_version=""
        if actual_version!=GOVERNED_MINISWE_VERSION:
            print(f"FORGEBOSS SAFE STOP: mini-swe-agent identity mismatch ({actual_version!r}).",file=sys.stderr);return 13
        if not control_envelope:
            print("FORGEBOSS SAFE STOP: governed control envelope missing.",file=sys.stderr);return 13
        try:
            root=Path(__file__).resolve().parents[2]
            if str(root) not in sys.path:sys.path.insert(0,str(root))
            from forgeboss.security.executor_guard import paid_start_authority
            with paid_start_authority(
                lease,lease_token,sys.argv[1],workspace,"mini-swe",control_envelope,budget
            ):
                pass
        except Exception as ex:
            print("FORGEBOSS SAFE STOP: governed paid-start denied: "+str(ex),file=sys.stderr);return 13
    else:
        v=subprocess.run([sys.executable,str(guard),"verify","--lease",lease,"--token",lease_token,"--packet",sys.argv[1],"--workspace",workspace,"--executor","mini-swe"],capture_output=True,text=True)
        if v.returncode:
            print("FORGEBOSS SAFE STOP: "+(v.stdout or v.stderr),file=sys.stderr);return 13

    # Do not leave control authority/token material in the worker's inherited environment.
    os.environ.pop("FORGEBOSS_CONTROL_ENVELOPE",None)
    os.environ.pop("FORGEBOSS_EXPECTED_RUNNER_SHA256",None)
    os.environ.pop("FORGEBOSS_EXECUTOR_LEASE_TOKEN",None)
    env_obj=None
    try:
        from minisweagent.agents.default import DefaultAgent
        from minisweagent.environments.docker import DockerEnvironment
        from minisweagent.models.litellm_model import LitellmModel

        # Model runs on host; shell runs in a network-disabled container.
        # The container receives the disposable repo only, not API/GitHub credentials.
        mount=f"type=bind,src={workspace},dst=/workspace"
        env_obj=DockerEnvironment(
            image=GOVERNED_MINISWE_IMAGE if governed else os.environ.get("FORGEBOSS_MINISWE_IMAGE","node:22-bookworm"),
            cwd="/workspace",
            run_args=["--rm","--network","none","--mount",mount],
            timeout=180,
            container_timeout="45m",
        )
        model=LitellmModel(model_name=model_name)
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
        task=f"""You are a bounded coding worker inside ForgeBoss. Product: SiteBoss.
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
        post=subprocess.run([sys.executable,str(guard),"postflight","--lease",lease,"--token",lease_token,"--packet",sys.argv[1],"--workspace",workspace,"--executor","mini-swe"],capture_output=True,text=True)
        if post.returncode:
            result["error"]="ForgeBoss postflight denied worker result: "+(post.stdout or post.stderr)[-1200:]
            return 13
        result["completed"]=True
        return 0
    except Exception as e:
        try:
            if 'agent' in locals():
                result["cost_usd"]=float(getattr(agent,"cost",0.0) or 0.0)
                result["calls"]=int(getattr(agent,"n_calls",0) or 0)
        except Exception: pass
        result["error"]=f"{type(e).__name__}: {e}"
        print(result["error"],file=sys.stderr)
        return 10
    finally:
        try:
            if env_obj is not None: env_obj.cleanup()
        except Exception: pass
        print("FORGEBOSS_RESULT_JSON="+json.dumps(result,separators=(",",":")))

if __name__=="__main__":raise SystemExit(main())
