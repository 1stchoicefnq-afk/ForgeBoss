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
def conflicts(a,b):
    if a.files & b.files: return True
    for x in a.write_roots:
        for y in b.write_roots:
            if x.startswith(y) or y.startswith(x): return True
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
