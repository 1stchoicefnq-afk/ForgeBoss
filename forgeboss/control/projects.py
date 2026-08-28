from __future__ import annotations
import json, os, re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PROJECTS=ROOT/"projects"
_VALID_PROJECT_ID=re.compile(r"^[A-Za-z0-9_-]+$")
class ProjectProfileError(RuntimeError): pass
def _load(path): return json.loads(Path(path).read_text(encoding="utf-8"))
def list_profiles():
    out=[]
    if not PROJECTS.exists(): return out
    for d in sorted(PROJECTS.iterdir()):
        p=d/"project.json"
        if p.exists():
            obj=_load(p)
            if obj.get("id")!="template": out.append(obj)
    return out
def load_profile(project_id):
    # project_id is attacker-controlled client input (the daemon's project.get RPC
    # passes it straight through). Without this check, a value like
    # "../../../../home/user/.ssh" would let Path(...)/project_id traverse outside
    # PROJECTS and read arbitrary project.json/acceptance.json/scope.json files
    # elsewhere on disk.
    if not isinstance(project_id,str) or not _VALID_PROJECT_ID.match(project_id):
        raise ProjectProfileError(f"unknown project profile: {project_id}")
    d=PROJECTS/project_id
    projects_root=PROJECTS.resolve()
    resolved=d.resolve()
    if os.path.commonpath([str(projects_root),str(resolved)])!=str(projects_root):
        raise ProjectProfileError(f"unknown project profile: {project_id}")
    if not d.exists(): raise ProjectProfileError(f"unknown project profile: {project_id}")
    project=_load(d/"project.json")
    acceptance=_load(d/"acceptance.json") if (d/"acceptance.json").exists() else {"schema":1,"commands":[]}
    scope=_load(d/"scope.json") if (d/"scope.json").exists() else {"schema":1,"write_roots":[],"deny_roots":[]}
    return {"project":project,"acceptance":acceptance,"scope":scope,"path":str(d)}
def validate_profile(profile):
    p=profile["project"]
    for k in ("id","name","purpose","repository_env","default_branch"):
        if not p.get(k): raise ProjectProfileError(f"project profile missing {k}")
    if int(p.get("max_parallel_workers",1))<1: raise ProjectProfileError("max_parallel_workers must be >=1")
    return True
