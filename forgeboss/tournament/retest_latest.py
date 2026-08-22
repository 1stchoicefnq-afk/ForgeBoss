from __future__ import annotations
import json, subprocess, time
from pathlib import Path
CREATE_NO_WINDOW=getattr(subprocess,"CREATE_NO_WINDOW",0)

ROOT=Path(__file__).resolve().parents[2]
WORKROOT=Path.home()/".siteboss"/"autopilot"/"case-sensitive-repair-workspaces"/"forgeboss-tournament"
STATE=ROOT/"state"/"tournament";STATE.mkdir(parents=True,exist_ok=True)

def run(a,timeout=1800):
    return subprocess.run(a,capture_output=True,text=True,timeout=timeout,creationflags=CREATE_NO_WINDOW)

def latest(kind):
    xs=[p for p in WORKROOT.glob(f"*-{kind}") if (p/".git").exists()]
    return max(xs,key=lambda p:p.stat().st_mtime) if xs else None

def validate(kind,w):
    out=STATE/f"retest-{kind}.json"
    p=run(["powershell.exe","-NoProfile","-ExecutionPolicy","Bypass","-File",str(ROOT/"forgeboss"/"tournament"/"validate.ps1"),"-Repo",str(w),"-Out",str(out)])
    try:j=json.loads(out.read_text(encoding="utf-8-sig"))
    except Exception:j={"passed":False,"failure_count":999,"runs":[]}
    return {"executor":kind,"workspace":str(w),"validator_exit_code":p.returncode,
            "acceptance_passed":bool(j.get("passed")),"failure_count":j.get("failure_count"),
            "validation":j,"output_tail":(p.stdout+p.stderr)[-3500:]}

def main():
    rows=[]
    for kind in ("mini-swe","openhands"):
        w=latest(kind)
        if not w: rows.append({"executor":kind,"missing":True});continue
        rows.append(validate(kind,w))
    good=[x for x in rows if x.get("acceptance_passed")]
    winner=None
    if len(good)==1:winner=good[0]["executor"]
    elif len(good)>1:
        # Existing tournament cost evidence was mini-SWE ~$0.0224, OpenHands ~$0.0391.
        # Retest intentionally does not invent new cost telemetry; both are marked green.
        winner="both-pass-needs-cost-tiebreak"
    obj={"schema":1,"kind":"zero-cost-retest","generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
         "model_calls":0,"github_writes":0,"results":rows,"winner":winner}
    (STATE/"retest-last.json").write_text(json.dumps(obj,indent=2),encoding="utf-8")
    print("FORGEBOSS_RETEST_RESULT="+json.dumps(obj,separators=(",",":")))
    return 0 if good else 2
if __name__=="__main__":raise SystemExit(main())
