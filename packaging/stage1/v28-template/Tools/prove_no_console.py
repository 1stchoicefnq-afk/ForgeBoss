from __future__ import annotations
import argparse,json,os,sys
from pathlib import Path
def main()->int:
    if os.name!="nt":raise SystemExit("Windows-only proof")
    ap=argparse.ArgumentParser();ap.add_argument("--engine-root",required=True);ns=ap.parse_args()
    engine=Path(ns.engine_root).resolve(strict=True);sys.path.insert(0,str(engine))
    from forgeboss.executors import mini_swe_runner
    flags=int(mini_swe_runner.CREATE_NO_WINDOW or 0)
    if not flags:raise SystemExit("ForgeBoss CREATE_NO_WINDOW unavailable")
    code="import ctypes;print(int(bool(ctypes.windll.kernel32.GetConsoleWindow())))"
    cp=mini_swe_runner._hidden_run([sys.executable,"-I","-S","-c",code],capture_output=True,text=True,check=True)
    ok=cp.stdout.strip()=="0"
    print(json.dumps({"ok":ok,"childConsoleWindow":cp.stdout.strip(),"creationflags":flags,"mechanism":"forgeboss.executors.mini_swe_runner._hidden_run"},sort_keys=True))
    return 0 if ok else 13
if __name__=="__main__":raise SystemExit(main())
