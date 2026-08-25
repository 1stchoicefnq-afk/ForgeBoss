from __future__ import annotations
import json,math,os,sys,subprocess
from pathlib import Path
from forgeboss.security.private_paid_start import prepare_private_paid_start,commit_private_result,cleanup_private_session

def _positive_budget(raw):
    if isinstance(raw,bool):raise ValueError("budget must be a finite positive number")
    try:value=float(raw)
    except (TypeError,ValueError,OverflowError) as ex:raise ValueError("budget must be a finite positive number") from ex
    if not math.isfinite(value) or value<=0:raise ValueError("budget must be a finite positive number")
    return value

def _observed_cost(value):
    if value is None or isinstance(value,bool):return None
    try:result=float(value)
    except (TypeError,ValueError,OverflowError):return None
    return result if math.isfinite(result) and result>=0 else None

def main()->int:
    if len(sys.argv)<4:
        print("usage: mini_swe_runner.py PACKET.json WORKSPACE BUDGET_USD",file=sys.stderr);return 2
    if os.environ.get("FORGEBOSS_ALLOW_PAID_EXECUTOR")!="YES":
        print("FORGEBOSS SAFE STOP: paid executor gate is not enabled.");return 3
    packet_path=Path(sys.argv[1]);packet=json.loads(packet_path.read_text(encoding="utf-8"));workspace=str(Path(sys.argv[2]).resolve())
    try:cli_budget=_positive_budget(sys.argv[3])
    except Exception as ex:
        print("FORGEBOSS SAFE STOP: "+str(ex),file=sys.stderr);return 12
    lease=os.environ.get("FORGEBOSS_EXECUTOR_LEASE","");lease_token=os.environ.get("FORGEBOSS_EXECUTOR_LEASE_TOKEN","");control_envelope=os.environ.get("FORGEBOSS_CONTROL_ENVELOPE","")
    if not lease or not lease_token or not control_envelope:
        print("FORGEBOSS SAFE STOP: paid executor authority is incomplete",file=sys.stderr);return 12
    model_name=os.environ.get("FORGEBOSS_MINISWE_MODEL","openai/gpt-5.6-luna")
    result={"executor":"mini-swe","model":model_name,"cost_usd":None,"completed":False,"error":None};env_obj=None;private_session=None
    guard=Path(__file__).resolve().parents[1]/"security"/"executor_guard.py"
    try:
        # FB-026 REWORK11 boundary: verify the exact signed current run/epoch,
        # durably consume its paid authority, then materialize a private clean
        # exact-commit snapshot. The paid executor never sees the mutable host
        # worktree, so another local ForgeBoss process cannot alter its execution
        # view after final validation. Failure to establish this private view is
        # a hard stop before model construction.
        private_session=prepare_private_paid_start(lease,lease_token,packet_path,workspace,"mini-swe",control_envelope,cli_budget)
        authority=private_session["authority"];budget=float(authority["budgetUsd"]);private_workspace=private_session["workspace"]

        from minisweagent.agents.default import DefaultAgent
        from minisweagent.environments.docker import DockerEnvironment
        from minisweagent.models.litellm_model import LitellmModel
        system_template=r"""You are a bounded software-engineering worker operating through a shell.
Your response must contain exactly ONE bash command block in this format:
```mswea_bash_command
your_command_here
```
Work iteratively: inspect, edit, test, and verify. Never publish or change remote Git state.
When complete issue exactly:
```mswea_bash_command
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```"""
        instance_template=r"""{{ task }}
You are in {{ cwd }}. Work only inside the bounded repository and obey the task contract."""
        task=f"""You are a bounded coding worker inside ForgeBoss.
Objective: {packet.get('objective','')}
IMMUTABLE RULES:
- Modify ONLY: {json.dumps(packet.get('allowed_files',[]))}
- Relevant context: {json.dumps(packet.get('context_files',[]))}
- Do not modify .github, credentials, generated files, or anything outside allowed_files.
- Do not push, publish, merge, deploy, alter remotes, or access network.
- Do not weaken tests.
- Use the private repository snapshot already mounted at /workspace.
Required acceptance intent:
{json.dumps(packet.get('acceptance_criteria',[]))}"""
        mount=f"type=bind,src={private_workspace},dst=/workspace"
        env_obj=DockerEnvironment(image=os.environ.get("FORGEBOSS_MINISWE_IMAGE","node:22-bookworm"),cwd="/workspace",run_args=["--rm","--network","none","--mount",mount],timeout=180,container_timeout="45m")
        model=LitellmModel(model_name=model_name)
        agent=DefaultAgent(model,env_obj,system_template=system_template,instance_template=instance_template,cost_limit=budget,step_limit=30,wall_time_limit_seconds=900)
        agent.run(task)
        result["cost_usd"]=_observed_cost(getattr(agent,"cost",None));result["calls"]=int(getattr(agent,"n_calls",0) or 0)

        # Copy back only after proving the private diff is in scope and the host
        # worktree did not change concurrently while paid execution was running.
        commit_private_result(private_session)
        post=subprocess.run([sys.executable,str(guard),"postflight","--lease",lease,"--token",lease_token,"--packet",str(packet_path),"--workspace",workspace,"--executor","mini-swe"],capture_output=True,text=True)
        if post.returncode:
            result["error"]="ForgeBoss postflight denied worker result: "+(post.stdout or post.stderr)[-1200:];return 13
        result["completed"]=True;return 0
    except Exception as ex:
        try:
            if "agent" in locals():
                result["cost_usd"]=_observed_cost(getattr(agent,"cost",None));result["calls"]=int(getattr(agent,"n_calls",0) or 0)
        except Exception:pass
        result["error"]=f"{type(ex).__name__}: {ex}";print(result["error"],file=sys.stderr);return 10
    finally:
        try:
            if env_obj is not None:env_obj.cleanup()
        except Exception:pass
        cleanup_private_session(private_session)
        print("FORGEBOSS_RESULT_JSON="+json.dumps(result,separators=(",",":")))

if __name__=="__main__":raise SystemExit(main())
