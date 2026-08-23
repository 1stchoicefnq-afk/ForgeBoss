from __future__ import annotations
import inspect, json, math, os, sys, tempfile, shutil
from pathlib import Path


def _validated_budget(raw) -> float:
    try:
        value=float(raw)
    except (TypeError,ValueError,OverflowError) as ex:
        raise ValueError("BUDGET_USD must be a finite positive number") from ex
    if not math.isfinite(value) or value<=0:
        raise ValueError("BUDGET_USD must be a finite positive number")
    return value


def _conversation_budget_kwargs(Conversation,budget:float):
    try:
        params=inspect.signature(Conversation).parameters
    except (TypeError,ValueError) as ex:
        raise RuntimeError("OpenHands budget capability cannot be verified") from ex
    if "max_budget_per_run" not in params:
        raise RuntimeError("OpenHands SDK lacks max_budget_per_run; refusing paid execution")
    return {"max_budget_per_run":budget}


def _observed_cost(llm):
    try:
        value=float(getattr(llm.metrics,"accumulated_cost",None))
    except (TypeError,ValueError,OverflowError,AttributeError):
        return None
    if not math.isfinite(value) or value<0:
        return None
    return value


def main() -> int:
    if len(sys.argv)<4:
        print("usage: openhands_runner.py PACKET.json WORKSPACE BUDGET_USD",file=sys.stderr);return 2
    if os.environ.get("FORGEBOSS_ALLOW_PAID_EXECUTOR")!="YES":
        print("FORGEBOSS SAFE STOP: paid executor gate is not enabled.");return 3

    packet=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    workspace=str(Path(sys.argv[2]).resolve())
    model_name=os.environ.get("FORGEBOSS_OPENHANDS_MODEL","openai/gpt-5.6-luna")
    result={"executor":"openhands","model":model_name,"cost_usd":None,"completed":False,"error":None,
            "budget_enforcement":"openhands_max_budget_per_run"}
    try:
        budget=_validated_budget(sys.argv[3])
    except ValueError as ex:
        result["error"]=str(ex)
        print("FORGEBOSS_RESULT_JSON="+json.dumps(result,separators=(",",":")))
        print("FORGEBOSS SAFE STOP: "+str(ex),file=sys.stderr)
        return 12

    guard=Path(__file__).resolve().parents[1]/"security"/"executor_guard.py"
    lease=os.environ.get("FORGEBOSS_EXECUTOR_LEASE","");lease_token=os.environ.get("FORGEBOSS_EXECUTOR_LEASE_TOKEN","")
    if not lease or not lease_token:
        print("FORGEBOSS SAFE STOP: unified executor lease missing.",file=sys.stderr);return 13
    v=subprocess.run([sys.executable,str(guard),"verify","--lease",lease,"--token",lease_token,"--packet",sys.argv[1],"--workspace",workspace,"--executor","openhands"],capture_output=True,text=True)
    if v.returncode:
        print("FORGEBOSS SAFE STOP: "+(v.stdout or v.stderr),file=sys.stderr);return 13

    try:
        from pydantic import SecretStr
        from openhands.sdk import LLM, Agent, Conversation, Tool
        from openhands.tools.file_editor import FileEditorTool
        from openhands.tools.task_tracker import TaskTrackerTool

        # A paid OpenHands run is allowed only when the installed SDK exposes a
        # real in-run cost guard. Older/unknown SDKs fail closed before LLM use.
        conversation_budget_kwargs=_conversation_budget_kwargs(Conversation,budget)

        key=os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY")
        if not key: raise RuntimeError("OPENAI_API_KEY/LLM_API_KEY missing")

        llm=LLM(
            usage_id="forgeboss-tournament",
            model=model_name,
            api_key=SecretStr(key),
            max_output_tokens=12000,
            reasoning_effort="low",
            timeout=180,
        )

        # Remove credentials before any terminal tool is allowed to run.
        for k in ["OPENAI_API_KEY","LLM_API_KEY","GH_TOKEN","GITHUB_TOKEN","GITHUB_PAT"]:
            os.environ.pop(k,None)

        # Runtime/cache state MUST live outside the repository so .openhands/AppData
        # cannot be confused with candidate source changes.
        runtime_home=tempfile.mkdtemp(prefix="forgeboss-openhands-home-",dir=str(Path.home()/".forgeboss"))
        os.environ["HOME"]=runtime_home
        os.environ["USERPROFILE"]=runtime_home
        os.environ["LOCALAPPDATA"]=str(Path(runtime_home)/"AppData"/"Local")
        os.environ["APPDATA"]=str(Path(runtime_home)/"AppData"/"Roaming")
        os.environ["XDG_CACHE_HOME"]=str(Path(runtime_home)/".cache")
        os.environ["XDG_CONFIG_HOME"]=str(Path(runtime_home)/".config")
        os.environ["GIT_TERMINAL_PROMPT"]="0"

        agent=Agent(
            llm=llm,
            tools=[Tool(name=FileEditorTool.name),Tool(name=TaskTrackerTool.name)]
        )
        conversation=Conversation(agent=agent,workspace=workspace,**conversation_budget_kwargs)
        prompt=f"""You are a bounded execution worker inside ForgeBoss. Product: SiteBoss.
Objective: {packet.get('objective','')}

HARD TASK CONTRACT:
- Modify ONLY these repository-relative files: {json.dumps(packet.get('allowed_files',[]))}
- Relevant context files: {json.dumps(packet.get('context_files',[]))}
- You have NO terminal tool. Edit only through the workspace file editor. Never push, publish, merge, deploy, alter Git remotes, access GitHub, or read secrets.
- Do not create files outside the repository.
- Do not weaken/skip tests.
- If the correct repair cannot be completed within scope or assigned cost budget ${budget:.4f}, stop.
- Leave only justified source changes in this disposable workspace.

Acceptance intent:
{json.dumps(packet.get('acceptance_criteria',[]))}
"""
        conversation.send_message(prompt)
        conversation.run()
        cost=_observed_cost(llm)
        result["cost_usd"]=cost
        if cost is None:
            result["error"]="OpenHands cost metrics unavailable after paid execution"
            return 12
        post=subprocess.run([sys.executable,str(guard),"postflight","--lease",lease,"--token",lease_token,"--packet",sys.argv[1],"--workspace",workspace,"--executor","openhands"],capture_output=True,text=True)
        if post.returncode:
            result["error"]="ForgeBoss postflight denied worker result: "+(post.stdout or post.stderr)[-1200:]
            return 13
        # max_budget_per_run is the OpenHands in-run guard. Keep this truthful
        # postflight check because a final provider call can report cost at/over
        # the threshold; never describe this post-hoc comparison as the hard cap.
        if cost>budget:
            result["error"]=f"OpenHands reported spend above assigned budget after SDK budget stop: ${cost:.4f} > ${budget:.4f}"
            return 11
        result["completed"]=True
        return 0
    except Exception as e:
        try:
            if 'llm' in locals():
                result["cost_usd"]=_observed_cost(llm)
        except Exception: pass
        result["error"]=f"{type(e).__name__}: {e}"
        print(result["error"],file=sys.stderr)
        return 10
    finally:
        try:
            if 'runtime_home' in locals():
                shutil.rmtree(runtime_home,ignore_errors=True)
        except Exception:
            pass
        print("FORGEBOSS_RESULT_JSON="+json.dumps(result,separators=(",",":")))

if __name__=="__main__":raise SystemExit(main())
