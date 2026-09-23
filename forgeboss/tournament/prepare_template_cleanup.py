from __future__ import annotations
import json, subprocess, shutil, time
from pathlib import Path

CREATE_NO_WINDOW=getattr(subprocess,"CREATE_NO_WINDOW",0)
ROOT=Path(__file__).resolve().parents[2]
MIRROR=Path.home()/".siteboss"/"autopilot"/"mirrors"/"siteboss-monster.git"
CTRL=Path.home()/".siteboss"/"autopilot"/"controller-state"
CASE_ROOT=Path.home()/".siteboss"/"autopilot"/"case-sensitive-repair-workspaces"/"forgeboss-hygiene"
CANON=".github/pull_request_template.md"
LEGACY=".github/PULL_REQUEST_TEMPLATE.md"

def run(a,cwd=None):
    return subprocess.run(a,cwd=cwd,capture_output=True,text=True,timeout=180,creationflags=CREATE_NO_WINDOW)
def git(w,*a):
    p=run(["git.exe",*a],w)
    if p.returncode:raise RuntimeError((p.stdout+p.stderr).strip())
    return p.stdout.strip()

def main():
    packet=json.loads((CTRL/"packet-latest.json").read_text(encoding="utf-8"))
    sha=packet["expected_head_revision"]
    CASE_ROOT.mkdir(parents=True,exist_ok=True)
    run(["fsutil.exe","file","SetCaseSensitiveInfo",str(CASE_ROOT),"enable"])
    w=CASE_ROOT/f"template-cleanup-{int(time.time())}";w.mkdir()
    run(["fsutil.exe","file","SetCaseSensitiveInfo",str(w),"enable"])
    p=run(["git.exe","clone","--no-checkout",str(MIRROR),str(w)])
    if p.returncode:raise RuntimeError(p.stderr)
    git(w,"config","core.autocrlf","false");git(w,"config","core.ignorecase","false");git(w,"checkout","--detach",sha)
    paths=git(w,"ls-tree","-r","--name-only",sha).splitlines()
    if CANON not in paths:
        raise RuntimeError(f"Canonical template missing: {CANON}. Refusing deletion.")
    if LEGACY not in paths:
        out={"schema":1,"exact_head":sha,"status":"ALREADY_CLEAN","canonical":CANON}
    else:
        canon_blob=git(w,"rev-parse",f"{sha}:{CANON}")
        legacy_blob=git(w,"rev-parse",f"{sha}:{LEGACY}")
        git(w,"rm","--",LEGACY)
        patch=git(w,"diff","--binary","--",LEGACY)
        state=ROOT/"state"/"tournament";state.mkdir(parents=True,exist_ok=True)
        patch_path=state/"pr-template-collision-cleanup.patch";patch_path.write_text(patch,encoding="utf-8")
        out={"schema":1,"exact_head":sha,"status":"PATCH_PREPARED","canonical":CANON,"delete":LEGACY,
             "canonical_blob":canon_blob,"legacy_blob":legacy_blob,"contents_identical":canon_blob==legacy_blob,
             "patch":str(patch_path),"published":False,
             "note":"Dedicated hygiene patch only. It is not mixed into application repairs and is not published automatically."}
    print(json.dumps(out,indent=2))
    return 0

if __name__=="__main__":raise SystemExit(main())
