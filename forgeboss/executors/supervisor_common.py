from __future__ import annotations
import ntpath, os, subprocess, time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

CREATE_SUSPENDED=0x00000004
CREATE_UNICODE_ENVIRONMENT=0x00000400
CREATE_NO_WINDOW=0x08000000
CREATE_BREAKAWAY_FROM_JOB=0x01000000
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE=0x00002000
WAIT_OBJECT_0=0
WAIT_TIMEOUT=258

class SupervisorError(RuntimeError):pass

@dataclass(frozen=True)
class SupervisedResult:
    exit_code:int|None;revoked:bool;escalated:bool;quarantined:bool;tree_terminated:bool;reason:str;pid:int;started_at:float;finished_at:float
    def as_dict(self)->dict:
        return {"exitCode":self.exit_code,"revoked":self.revoked,"escalated":self.escalated,"quarantined":self.quarantined,"treeTerminated":self.tree_terminated,"reason":self.reason,"pid":self.pid,"startedAt":self.started_at,"finishedAt":self.finished_at}

def validate_argv(argv:Sequence[str])->list[str]:
    if not argv or not isinstance(argv[0],str) or not argv[0] or "\x00" in argv[0]:raise ValueError("argv[0] must be a non-empty NUL-free string")
    if any(not isinstance(x,str) or "\x00" in x for x in argv[1:]):raise ValueError("argv arguments must be NUL-free strings")
    if not Path(argv[0]).is_absolute():raise ValueError("argv[0] must be an explicit absolute executable path")
    return list(argv)

def validate_cwd(cwd)->str|None:
    if cwd is None:return None
    value=os.fspath(cwd)
    if not isinstance(value,str) or not value or "\x00" in value or not os.path.isabs(value):raise ValueError("cwd must be an absolute NUL-free path")
    return value

def validate_env(env:Mapping[str,str]|None)->dict[str,str]:
    source=dict(os.environ) if env is None else dict(env);out={};seen=set()
    for k,v in source.items():
        if not isinstance(k,str) or not isinstance(v,str) or not k or "\x00" in k or "\x00" in v or "=" in k:raise ValueError("invalid environment key/value")
        folded=k.casefold()
        if os.name=="nt" and folded in seen:raise ValueError("case-colliding Windows environment key")
        seen.add(folded);out[k]=v
    return out

def windows_environment_block(env:Mapping[str,str])->str:
    seen=set();items=[]
    for k,v in env.items():
        if not isinstance(k,str) or not isinstance(v,str) or not k or "\x00" in k or "\x00" in v or "=" in k:raise ValueError("invalid Windows environment")
        folded=k.casefold()
        if folded in seen:raise ValueError("case-colliding Windows environment key")
        seen.add(folded);items.append((k,v))
    items.sort(key=lambda kv:kv[0].casefold())
    return "".join(f"{k}={v}\x00" for k,v in items)+"\x00"

def windows_command_line(argv:Sequence[str])->str:
    if not argv or not isinstance(argv[0],str) or not argv[0] or "\x00" in argv[0] or not ntpath.isabs(argv[0]):raise ValueError("Windows argv[0] must be an absolute NUL-free executable path")
    if any(not isinstance(x,str) or "\x00" in x for x in argv[1:]):raise ValueError("Windows argv arguments must be NUL-free strings")
    return subprocess.list2cmdline(list(argv))

def posix_group_alive(pgid:int)->bool:
    proc="/proc"
    if os.path.isdir(proc):
        saw=False
        try:
            for name in os.listdir(proc):
                if not name.isdigit():continue
                try:
                    raw=Path(proc,name,"stat").read_text(encoding="utf-8");tail=raw[raw.rfind(")")+2:].split();state,group=tail[0],int(tail[2])
                except (OSError,ValueError,IndexError):continue
                if group==int(pgid):
                    saw=True
                    if state!="Z":return True
            if saw:return False
        except OSError:pass
    try:os.killpg(int(pgid),0);return True
    except ProcessLookupError:return False
    except PermissionError:return True

def wait_until(predicate:Callable[[],bool],timeout:float,poll:float)->bool:
    end=time.monotonic()+max(0.0,float(timeout))
    while time.monotonic()<end:
        if predicate():return True
        time.sleep(max(.005,float(poll)))
    return predicate()

def configure_windows_api(kernel,ctypes,wintypes)->None:
    V=wintypes.LPVOID;D=wintypes.DWORD;H=wintypes.HANDLE
    specs={
        "CreateJobObjectW":([V,wintypes.LPCWSTR],H),"SetInformationJobObject":([H,ctypes.c_int,V,D],wintypes.BOOL),
        "AssignProcessToJobObject":([H,H],wintypes.BOOL),"TerminateJobObject":([H,wintypes.UINT],wintypes.BOOL),
        "QueryInformationJobObject":([H,ctypes.c_int,V,D,ctypes.POINTER(D)],wintypes.BOOL),
        "CreateProcessW":([wintypes.LPCWSTR,wintypes.LPWSTR,V,V,wintypes.BOOL,D,V,wintypes.LPCWSTR,V,V],wintypes.BOOL),
        "ResumeThread":([H],D),"TerminateProcess":([H,wintypes.UINT],wintypes.BOOL),"WaitForSingleObject":([H,D],D),
        "GetExitCodeProcess":([H,ctypes.POINTER(D)],wintypes.BOOL),"GetProcessTimes":([H,V,V,V,V],wintypes.BOOL),
        "QueryFullProcessImageNameW":([H,D,wintypes.LPWSTR,ctypes.POINTER(D)],wintypes.BOOL),"CloseHandle":([H],wintypes.BOOL),
    }
    for name,(args,restype) in specs.items():fn=getattr(kernel,name);fn.argtypes=args;fn.restype=restype
