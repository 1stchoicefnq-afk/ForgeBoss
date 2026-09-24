from __future__ import annotations
import argparse,json,sys
from decimal import Decimal
from pathlib import Path
def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--engine-root",required=True);ns=ap.parse_args()
    engine=Path(ns.engine_root).resolve(strict=True);sys.path.insert(0,str(engine))
    from forgeboss.control.self_build_preflight import SELF_BUILD_CYCLE_CAP_USD,SELF_BUILD_MAX_AUTOMATIC_CYCLES,self_build_session_plan
    per_cycle=Decimal(SELF_BUILD_CYCLE_CAP_USD);cycles=int(SELF_BUILD_MAX_AUTOMATIC_CYCLES)
    if per_cycle<=0 or cycles<1:raise RuntimeError("engine self-build budget constants invalid")
    maximum=per_cycle*cycles;plan=self_build_session_plan(maximum,max_cycles=cycles)
    if int(plan["cycle_target"])!=cycles:raise RuntimeError("engine self-build cycle target mismatch")
    if Decimal(str(plan["reserved_cap_usd"]))!=maximum:raise RuntimeError("engine reserved budget mismatch")
    if Decimal(str(plan["session_budget_usd"]))!=maximum:raise RuntimeError("engine session budget mismatch")
    print(json.dumps({"ok":True,"perCycleCapUsd":format(per_cycle,".2f"),"maxAutomaticCycles":cycles,"maxAutomaticUsd":format(maximum,".2f")},sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
