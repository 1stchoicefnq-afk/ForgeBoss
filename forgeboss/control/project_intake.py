from __future__ import annotations
import json, time, zipfile
from pathlib import Path

FORGEBOSS_MARKERS=(
    "forgeboss/control/activation.py",
    "forgeboss/control/known_good.py",
    "dashboard/pro_shell.py",
    "START-FORGEBOSS.vbs",
)

def _folder_is_forgeboss(root:Path)->bool:
    return all((root/rel).is_file() for rel in FORGEBOSS_MARKERS)

def _find_forgeboss_root(path:Path):
    candidates=[path] if path.is_dir() else [path.parent]
    candidates.extend(path.parents)
    seen=set()
    for candidate in candidates:
        try: candidate=candidate.resolve(strict=True)
        except Exception: continue
        key=str(candidate).casefold()
        if key in seen: continue
        seen.add(key)
        if candidate.is_dir() and _folder_is_forgeboss(candidate):
            return candidate
    return None

def detect_project_source(raw_path):
    raw=str(raw_path or "").strip()
    if not raw: raise ValueError("Drop a ForgeBoss folder or ForgeBoss ZIP.")
    p=Path(raw).expanduser()
    if not p.is_absolute():
        raise ValueError("ForgeBoss needs the full dropped file/folder path.")
    p=p.resolve(strict=True)
    root=_find_forgeboss_root(p)
    if root:
        return {"project_id":"forgeboss","name":"ForgeBoss","source_path":str(root),"source_kind":"folder","self_build":True}
    if p.is_file() and p.suffix.lower()==".zip":
        with zipfile.ZipFile(p,"r") as z:
            names={n.replace("\\","/").lstrip("./") for n in z.namelist() if not n.endswith("/")}
        prefixes={""}
        for name in names:
            if "/" in name: prefixes.add(name.split("/",1)[0]+"/")
        for prefix in prefixes:
            if all(prefix+rel in names for rel in FORGEBOSS_MARKERS):
                return {"project_id":"forgeboss","name":"ForgeBoss","source_path":str(p),"source_kind":"zip","zip_prefix":prefix,"self_build":True}
        raise ValueError("ZIP is not a complete ForgeBoss package.")
    raise ValueError("That drop is not recognised as ForgeBoss.")

def load_selected_project(path):
    path=Path(path)
    try:
        data=json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data,dict): return None
        source=Path(str(data.get("source_path") or ""))
        if not source.exists(): return None
        return data
    except Exception:
        return None

def save_selected_project(path,data):
    path=Path(path)
    value=dict(data or {})
    value.setdefault("selected_at",time.time())
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2),encoding="utf-8")
    return value
