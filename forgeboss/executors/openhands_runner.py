from __future__ import annotations
import inspect, json, math, os, sys, tempfile, shutil
from datetime import date, datetime, timezone
from pathlib import Path

PINNED_MODEL="openai/gpt-5.6-luna"
MAX_OUTPUT_TOKENS=12000
MAX_CONTEXT_TOKENS=1_050_000
# Conservative 2026-08-23 ceiling for Luna. This intentionally uses the
# highest published input/output tier observed for Luna plus regional uplift
# and rounds the resulting one-request maximum upward.
ITERATION_COST_CEILING_USD=2.50
MAX_ITERATIONS=30
RATE_CARD_VALID_THROUGH=date(2026,9,30)

def _rate_card_current(today=None):
    today=today or datetime.now(timezone.utc).date()
    if today>RATE_CARD_VALID_THROUGH:
        raise RuntimeError(f"OpenHands conservative rate card expired on {RATE_CARD_VALID_THROUGH.isoformat()}; refusing paid execution")
    return True

def _finite_positive_budget(value)->float:
    try:budget=float(value)
    except Exception as ex:raise ValueError("assigned budget must be numeric") from ex
    if not math.isfinite(budget) or budget<=0:
        raise ValueError("assigned budget must be finite and > 0")
    return budget

def _iteration_budget_plan(budget:float,model_name:str,today=None)->dict:
    _rate_card_current(today)
    budget=_finite_positive_budget(budget)
    if model_name!=PINNED_MODEL:
        raise RuntimeError(f"OpenHands hard-cap surrogate supports only pinned model {PINNED_MODEL}; got {model_name}")
    iterations=int(math.floor((budget+1e-12)/ITERATION_COST_CEILING_USD))
    if iterations<1:
        raise RuntimeError(
            f"assigned budget ${budget:.4f} is below one conservatively reserved OpenHands iteration "
            f"(${ITERATION_COST_CEILING_USD:.2f}); refusing paid execution"
        )
    iterations=min(iterations,MAX_ITERATIONS)
    reserved=iterations*ITERATION_COST_CEILING_USD
    if reserved>budget+1e-9:raise RuntimeError("internal iteration reservation exceeds assigned budget")
    return {
        "max_iterations":iterations,
        "reserved_usd":reserved,
        "iteration_cost_ceiling_usd":ITERATION_COST_CEILING_USD,
        "model":model_name,
    }

def _conversation_iteration_kwargs(conversation_cls,plan:dict)->dict:
    try:sig=inspect.signature(conversation_cls)
    except Exception as ex:raise RuntimeError("cannot inspect pinned OpenHands Conversation API") from ex
    if "max_iteration_per_run" not in sig.parameters:
        raise RuntimeError("pinned OpenHands Conversation lacks max_iteration_per_run; refusing paid execution")
    return {"max_iteration_per_run":int(plan["max_iterations"])}

def _observed_cost(llm):
    try:
        value=getattr(getattr(llm,"metrics",None),"accumulated_cost",None)
        if value is None:return None
        cost=float(value)
        return cost if math.isfinite(cost) and cost>=0 else None
    except Exception:return None

def main() -> int:
    if len(sys.argv)<4:
        print("usage: openhands_runner.py PACKET.json WORKSPACE BUDGET_USD",file=sys.stderr);return 2
    if os.environ.get("FORGEBOSS_ALLOW_PAID_EXECUTOR")!="YES":
        print("FORGEBOSS SAFE STOP: paid executor gate is not enabled.");return 3

    packet=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    workspace=str(Path(sys.argv[2]).resolve())
    model_name=os.environ.get("FORGEBOSS_OPENHANDS_MODEL",PINNED_MODEL)
    try:
        budget=_finite_positive_budget(sys.argv[3])
        plan=_iteration_budget_plan(budget,model_name)
    except Exception as e:
        print("FORGEBOSS SAFE STOP: "+str(e),file=sys.stderr);return 12

    result={
        "executor":"openhands","model":model_name,"cost_usd":None,"completed":False,"error":None,
        "budget_usd":budget,"budget_control":"conservative_iteration_ceiling",
        "iteration_cost_ceiling_usd":plan["iteration_cost_ceiling_usd"],
        "max_iterations":plan["max_iterations"],"reserved_usd":plan["reserved_usd"],
    }
    guard=Path(__file__).resolve().parents[1]/"security"/"executor_guard.py"
    lease=os.environ.get("FORGEBOSS_EXECUTOR_LEASE","");lease_token=os.environ.get("FORGEBOSS_EXECUTOR_LEASE_TOKEN","")
    if not lease or not lease_token:
        print("FORGEBOSS SAFE STOP: unified executor lease missing.",file=sys.stderr);return 13
    # NOTE: subprocess is intentionally not imported here. FB-FINDING-015 is a
    # separate authorized fix and remains visible rather than being silently
    # absorbed into FB-FINDING-016.
    v=subprocess.run([sys.executable,str(guard),"verify","--lease",lease,"--token",lease_token,"--packet",sys.argv[1],"--workspace",workspace,"--executor","openhands"],capture_output=True,text=True)
    if v.returncode:
        print("FORGEBOSS SAFE STOP: "+(v.stdout or v.stderr),file=sys.stderr);return 13

    try:
        from pydantic import SecretStr
        from openhands.sdk import LLM, Agent, Conversation, Tool
        from openhands.tools.file_editor import FileEditorTool
        from openhands.tools.task_tracker import TaskTrackerTool

        key=os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY")
        if not key: raise RuntimeError("OPENAI_API_KEY/LLM_API_KEY missing")

        conversation_kwargs=_conversation_iteration_kwargs(Conversation,plan)
        llm=LLM(
            usage_id="forgeboss-tournament",
            model=model_name,
            api_key=SecretStr(key),
            max_output_tokens=MAX_OUTPUT_TOKENS,
            reasoning_effort="low",
            timeout=180,
            num_retries=0,
        )

        for k in ["OPENAI_API_KEY","LLM_API_KEY","GH_TOKEN","GITHUB_TOKEN","GITHUB_PAT"]:
            os.environ.pop(k,None)

        runtime_home=tempfile.mkdtemp(prefix="forgeboss-openhands-home-",dir=str(Path.home()/".forgeboss"))
        os.environ["HOME"]=runtime_home
        os.environ["USERPROFILE"]=runtime_home
        os.environ["LOCALAPPDATA"]=str(Path(runtime_home)/"AppData"/"Local")
        os.environ["APPDATA"]=str(Path(runtime_home)/"AppData"/"Roaming")
        os.environ["XDG_CACHE_HOME"]=str(Path(runtime_home)/".cache")
        os.environ["XDG_CONFIG_HOME"]=str(Path(runtime_home)/".config")
        os.environ["GIT_TERMINAL_PROMPT"]="0"

        agent=Agent(llm=llm,tools=[Tool(name=FileEditorTool.name),Tool(name=TaskTrackerTool.name)])
        conversation=Conversation(agent=agent,workspace=workspace,**conversation_kwargs)
        prompt=f"""You are a bounded execution worker inside ForgeBoss. Product: SiteBoss.
Objective: {packet.get('objective','')}

HARD TASK CONTRACT:
- Modify ONLY these repository-relative files: {json.dumps(packet.get('allowed_files',[]))}
- Relevant context files: {json.dumps(packet.get('context_files',[]))}
- You have NO terminal tool. Edit only through the workspace file editor. Never push, publish, merge, deploy, alter Git remotes, access GitHub, or read secrets.
- Do not create files outside the repository.
- Do not weaken/skip tests.
- If the correct repair cannot be completed within scope, stop and explain why.
- Leave only justified source changes in this disposable workspace.

Acceptance intent:
{json.dumps(packet.get('acceptance_criteria',[]))}
"""
        conversation.send_message(prompt)
        conversation.run()
        cost=_observed_cost(llm)
        result["cost_usd"]=cost
        post=subprocess.run([sys.executable,str(guard),"postflight","--lease",lease,"--token",lease_token,"--packet",sys.argv[1],"--workspace",workspace,"--executor","openhands"],capture_output=True,text=True)
        if post.returncode:
            result["error"]="ForgeBoss postflight denied worker result: "+(post.stdout or post.stderr)[-1200:]
            return 13
        if cost is None:
            result["error"]="OpenHands completed but provider cost metrics are unavailable"
            return 10
        if cost>budget+1e-9:
            result["error"]=f"OpenHands exceeded assigned budget despite conservative iteration reservation: ${cost:.4f} > ${budget:.4f}"
            return 11
        result["completed"]=True
        return 0
    except Exception as e:
        try:
            if 'llm' in locals():result["cost_usd"]=_observed_cost(llm)
        except Exception:pass
        result["error"]=f"{type(e).__name__}: {e}"
        print(result["error"],file=sys.stderr)
        return 10
    finally:
        try:
            if 'runtime_home' in locals():shutil.rmtree(runtime_home,ignore_errors=True)
        except Exception:pass
        print("FORGEBOSS_RESULT_JSON="+json.dumps(result,separators=(",",":")))

if __name__=="__main__":raise SystemExit(main())
