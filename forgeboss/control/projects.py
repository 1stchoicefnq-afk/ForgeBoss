from __future__ import annotations
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PROJECTS=ROOT/"projects"
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
    d=PROJECTS/project_id
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
