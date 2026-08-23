from __future__ import annotations
from dataclasses import dataclass,field
from typing import List,Set

@dataclass
class WorkItem:
    task_id:str
    family:str
    files:Set[str]=field(default_factory=set)
    write_roots:Set[str]=field(default_factory=set)
    estimated_cost:float=.0
    priority:int=100

def _canonical_path(value:str)->str:
    raw=str(value or '').replace('\\','/')
    parts=[]
    for part in raw.split('/'):
        # Win32 ignores trailing spaces before interpreting dot segments.
        # This is significant for components such as ". " and ".. ".
        part=part.rstrip(' ')
        if part in ('','.'): continue
        if part=='..':
            if parts and parts[-1]!='..': parts.pop()
            else: parts.append(part)
            continue
        # Ordinary Win32 path components ignore trailing dots/spaces.
        part=part.rstrip(' .')
        if not part: continue
        parts.append(part.casefold())
    return '/'.join(parts)

def _contains(root:str,path:str)->bool:
    return root=='' or path==root or path.startswith(root+'/')

def conflicts(a,b):
    a_files={_canonical_path(x) for x in a.files}
    b_files={_canonical_path(x) for x in b.files}
    if a_files & b_files: return True

    a_roots={_canonical_path(x) for x in a.write_roots}
    b_roots={_canonical_path(x) for x in b.write_roots}

    for file_path in a_files:
        if any(_contains(root,file_path) for root in b_roots): return True
    for file_path in b_files:
        if any(_contains(root,file_path) for root in a_roots): return True
    for x in a_roots:
        for y in b_roots:
            if _contains(x,y) or _contains(y,x): return True
    return False

def smart_parallel_batches(items:List[WorkItem],max_workers:int=4):
    remaining=sorted(items,key=lambda x:(x.priority,x.estimated_cost,x.task_id)); batches=[]
    while remaining:
        batch=[]; deferred=[]
        for item in remaining:
            if len(batch)>=max_workers or any(conflicts(item,x) for x in batch): deferred.append(item)
            else: batch.append(item)
        if not batch: batch=[remaining[0]]; deferred=remaining[1:]
        batches.append(batch); remaining=deferred
    return batches
