from pathlib import Path
import ast, subprocess, sys
ROOT=Path(__file__).resolve().parents[2]
SERVER=ROOT/"dashboard"/"server.py"
checks={}
q=subprocess.run([sys.executable,"-m","py_compile",str(SERVER)],capture_output=True,text=True)
checks["server compiles"]=q.returncode==0
tree=ast.parse(SERVER.read_text(encoding="utf-8"))
wanted={"normalize_ai_mode","is_auto_mode","choose_openai_lane","auto_forge_escalation_decision"}
nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in wanted]
checks["router functions present"]={n.name for n in nodes}==wanted
ns={}
if checks["router functions present"]:
    mod=ast.Module(body=nodes,type_ignores=[]); ast.fix_missing_locations(mod)
    exec(compile(mod,str(SERVER),"exec"),ns)
    norm,lane,decide=ns["normalize_ai_mode"],ns["choose_openai_lane"],ns["auto_forge_escalation_decision"]
    checks["legacy cost optimized becomes auto"]=norm("cost-optimized")=="auto"
    checks["auto starts Luna"]=lane("auto",1,0,0)["model"]=="gpt-5.6-luna"
    checks["auto level1 Terra"]=lane("auto",3,1,1)["model"]=="gpt-5.6-terra"
    checks["auto level2 Sol"]=lane("auto",4,2,2)["model"]=="gpt-5.6-sol"
    checks["repair rat fixed Luna"]=lane("repair-rat",9,9,2)["model"]=="gpt-5.6-luna"
    checks["balanced fixed Terra"]=lane("balanced",1,0,0)["model"]=="gpt-5.6-terra"
    checks["strong fixed Sol"]=lane("strong",1,0,0)["model"]=="gpt-5.6-sol"
    checks["full forge high reasoning"]=lane("full",1,0,0)["reasoning"]=="high"
    d0,d1,d2,d3=decide("auto",0,0),decide("auto",1,0),decide("auto",2,1),decide("auto",3,2)
    checks["no evidence no escalation"]=d0["action"]=="hold"
    checks["repeat -> Terra"]=d1["action"]=="escalate" and d1["level"]==1
    checks["repeat through Terra -> Sol"]=d2["action"]=="escalate" and d2["level"]==2
    checks["max heat repeat stops"]=d3["action"]=="stop"
    checks["fixed modes ignore repeats"]=decide("balanced",99,1)["action"]=="hold"
sv=SERVER.read_text(encoding="utf-8")
checks["new signature resets heat"]="AUTO FORGE: failure signature changed; dropping back to LOW HEAT." in sv
checks["new failure family resets heat"]="AUTO FORGE: new remaining-failure family; dropping back to LOW HEAT." in sv
checks["route reason exposed"]="selected_ai_route_reason=lane.get(\"route_reason\")" in sv
checks["hard spend guard retained"]="SITEBOSS_RUN_BUDGET_USD" in sv and "budget-cumulative" in sv
for k,v in checks.items(): print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"AUTO FORGE SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
