from __future__ import annotations
import json,math,os,sys,subprocess
from pathlib import Path
from forgeboss.executors.isolation_broker import run_isolated_mini_swe


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
    packet_path=Path(sys.argv[1]);workspace=str(Path(sys.argv[2]).resolve())
    try:cli_budget=_positive_budget(sys.argv[3])
    except Exception as ex:
        print("FORGEBOSS SAFE STOP: "+str(ex),file=sys.stderr);return 12
    lease=os.environ.get("FORGEBOSS_EXECUTOR_LEASE","");lease_token=os.environ.get("FORGEBOSS_EXECUTOR_LEASE_TOKEN","");control_envelope=os.environ.get("FORGEBOSS_CONTROL_ENVELOPE","")
    if not lease or not lease_token or not control_envelope:
        print("FORGEBOSS SAFE STOP: paid executor authority is incomplete",file=sys.stderr);return 12
    model_name=os.environ.get("FORGEBOSS_MINISWE_MODEL","openai/gpt-5.6-luna")
    image=os.environ.get("FORGEBOSS_MINISWE_IMAGE","node:22-bookworm")
    result={"executor":"mini-swe","model":model_name,"cost_usd":None,"completed":False,"error":None}
    guard=Path(__file__).resolve().parents[1]/"security"/"executor_guard.py"
    try:
        # FB-026 REWORK11: the ordinary ForgeBoss worker does not construct a
        # paid model and does not control Docker/VM execution. A separately
        # privileged isolation broker owns the private execution filesystem,
        # validates/consumes exact paid authority and performs the paid run.
        # Missing/misconfigured broker => fail closed before any paid call.
        broker_result=run_isolated_mini_swe(
            lease,lease_token,packet_path,workspace,control_envelope,cli_budget,model_name,image
        )
        result["cost_usd"]=_observed_cost(broker_result.get("cost_usd"))
        calls=broker_result.get("calls")
        if calls is not None:
            try:result["calls"]=int(calls)
            except Exception:pass
        if broker_result.get("error"):
            result["error"]=str(broker_result.get("error"))
        if broker_result.get("completed") is not True:
            if not result["error"]:result["error"]="privilege-separated isolation broker did not complete paid run"
            return 10
        post=subprocess.run([sys.executable,str(guard),"postflight","--lease",lease,"--token",lease_token,"--packet",str(packet_path),"--workspace",workspace,"--executor","mini-swe"],capture_output=True,text=True)
        if post.returncode:
            result["error"]="ForgeBoss postflight denied broker result: "+(post.stdout or post.stderr)[-1200:];return 13
        result["completed"]=True;return 0
    except Exception as ex:
        result["error"]=f"{type(ex).__name__}: {ex}";print(result["error"],file=sys.stderr);return 10
    finally:
        print("FORGEBOSS_RESULT_JSON="+json.dumps(result,separators=(",",":")))


if __name__=="__main__":raise SystemExit(main())
