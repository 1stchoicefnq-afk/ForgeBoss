from __future__ import annotations
import ctypes,json,math,os,signal,subprocess,sys,threading,time,uuid
from dataclasses import dataclass,replace
from pathlib import Path
from types import MappingProxyType
from typing import Mapping,Sequence

MAX_TIMEOUT_SECONDS=3600.0
DEFAULT_POLL_SECONDS=0.05
LINUX_DISCOVERY_TIMEOUT_SECONDS=0.5
LINUX_DISCOVERY_MAX_RECORDS=4096
_KEEPER_QUERY_FAILED_RC=124
_KEEPER_STOPPED_RC=75

STATE_RUNNING="RUNNING";STATE_STOPPING="STOPPING";STATE_STOPPED="STOPPED";STATE_FAILED="FAILED";STATE_STOP_FAILED="STOP_FAILED";STATE_IDENTITY_LOST="IDENTITY_LOST";STATE_QUARANTINED="QUARANTINED"
_ADVANCEABLE=frozenset({STATE_STOPPED})

class SupervisorError(RuntimeError):
    def __init__(self,code:str,message:str): super().__init__(message);self.code=code

def _timeout(value,field:str,*,allow_zero:bool=False)->float:
    if isinstance(value,bool) or not isinstance(value,(int,float)): raise SupervisorError("TIMING_INVALID",f"{field} must be a finite number")
    number=float(value)
    if not math.isfinite(number): raise SupervisorError("TIMING_INVALID",f"{field} must be finite")
    if number<0 or (not allow_zero and number<=0) or number>MAX_TIMEOUT_SECONDS: raise SupervisorError("TIMING_INVALID",f"{field} is outside the allowed range")
    return number

def _argv(value:Sequence[str])->tuple[str,...]:
    if isinstance(value,(str,bytes)) or not isinstance(value,Sequence) or not value: raise SupervisorError("ARGV_INVALID","argv must be a non-empty sequence")
    out=[]
    for part in value:
        if not isinstance(part,str) or not part or "\x00" in part: raise SupervisorError("ARGV_INVALID","argv entries must be non-empty NUL-free strings")
        out.append(part)
    if not Path(out[0]).is_absolute(): raise SupervisorError("ARGV_INVALID","argv[0] must be an absolute executable path")
    return tuple(out)

def _cwd(value)->str|None:
    if value is None:return None
    path=os.fspath(value)
    if not isinstance(path,str) or not path or "\x00" in path or not os.path.isabs(path): raise SupervisorError("CWD_INVALID","cwd must be an absolute NUL-free path")
    return path

def _env(value:Mapping[str,str]|None)->dict[str,str]:
    source=os.environ if value is None else value
    if not isinstance(source,Mapping):raise SupervisorError("ENV_INVALID","env must be a mapping")
    out={};seen=set()
    for key,item in source.items():
        if not isinstance(key,str) or not isinstance(item,str) or not key or "=" in key or "\x00" in key or "\x00" in item: raise SupervisorError("ENV_INVALID","environment contains an invalid entry")
        folded=key.casefold()
        if os.name=="nt" and folded in seen:raise SupervisorError("ENV_INVALID","Windows environment contains case-colliding keys")
        seen.add(folded);out[key]=item
    return out

@dataclass(frozen=True)
class Evidence:
    operation_id:str;worker_id:str;generation:int;state:str;reason:str;exit_code:int|None;containment_empty:bool;started_at:float;finished_at:float
    def as_dict(self):return {"operationId":self.operation_id,"workerId":self.worker_id,"generation":self.generation,"state":self.state,"reason":self.reason,"exitCode":self.exit_code,"containmentEmpty":self.containment_empty,"startedAt":self.started_at,"finishedAt":self.finished_at}
@dataclass(frozen=True)
class Assignment:
    worker_id:str;generation:int;state:str;argv:tuple[str,...];pid:int;containment_id:str;started_at:float;exit_code:int|None=None;last_evidence:Evidence|None=None
    def as_dict(self):return MappingProxyType({"workerId":self.worker_id,"generation":self.generation,"state":self.state,"argv":self.argv,"pid":self.pid,"containmentId":self.containment_id,"startedAt":self.started_at,"exitCode":self.exit_code,"lastEvidence":None if self.last_evidence is None else self.last_evidence.as_dict()})

class _Containment:
    pid:int;containment_id:str
    def poll(self):raise NotImplementedError
    def empty(self,timeout):raise NotImplementedError
    def terminate(self,timeout):raise NotImplementedError
    def close(self):raise NotImplementedError

def _linux_subreaper_available():return sys.platform.startswith("linux") and Path("/proc/self").exists()

def _deadline(deadline:float)->None:
    if time.monotonic()>=deadline:raise SupervisorError("CONTAINMENT_QUERY_TIMEOUT","Linux containment discovery deadline expired")

def _proc_existing(proc_root:Path,pid:int)->bool:
    try:return (proc_root/str(pid)).exists()
    except OSError:return True

def _read_proc_text(proc_root:Path,pid:int,relative:str,deadline:float)->str|None:
    _deadline(deadline);path=proc_root/str(pid)/relative
    try:value=path.read_text(encoding="utf-8")
    except (FileNotFoundError,ProcessLookupError):
        _deadline(deadline)
        if not _proc_existing(proc_root,pid):return None
        raise SupervisorError("CONTAINMENT_QUERY_FAILED",f"owned process {pid} {relative} disappeared ambiguously")
    except OSError as ex:
        _deadline(deadline)
        if not _proc_existing(proc_root,pid):return None
        raise SupervisorError("CONTAINMENT_QUERY_FAILED",f"cannot read owned process {pid} {relative}") from ex
    _deadline(deadline);return value

def _proc_identity_linux(proc_root:Path,pid:int,deadline:float)->tuple[int,int]|None:
    raw=_read_proc_text(proc_root,pid,"stat",deadline)
    if raw is None:return None
    close=raw.rfind(")");open_=raw.find("(")
    if open_<=0 or close<=open_+1:raise SupervisorError("CONTAINMENT_QUERY_FAILED",f"malformed owned process {pid} stat")
    try:
        observed=int(raw[:open_].strip());tail=raw[close+2:].split();ppid=int(tail[1]);starttime=int(tail[19])
    except (ValueError,IndexError) as ex:raise SupervisorError("CONTAINMENT_QUERY_FAILED",f"malformed owned process {pid} stat") from ex
    if observed!=pid or ppid<0 or starttime<=0:raise SupervisorError("CONTAINMENT_QUERY_FAILED",f"invalid owned process {pid} identity")
    return ppid,starttime

def _proc_children_linux(proc_root:Path,pid:int,deadline:float)->tuple[int,...]|None:
    raw=_read_proc_text(proc_root,pid,f"task/{pid}/children",deadline)
    if raw is None:return None
    out=[];seen=set()
    for token in raw.split():
        if not token.isdigit():raise SupervisorError("CONTAINMENT_QUERY_FAILED",f"malformed owned process {pid} children")
        child=int(token)
        if child<=1 or child in seen:raise SupervisorError("CONTAINMENT_QUERY_FAILED",f"invalid owned process {pid} children")
        seen.add(child);out.append(child)
    return tuple(out)

def _descendants_linux_scan(root_pid:int,*,deadline:float,max_records:int,proc_root:Path)->set[int]:
    parent:dict[int,int]={};records=0
    try:items=list(proc_root.iterdir())
    except OSError as ex:raise SupervisorError("CONTAINMENT_QUERY_FAILED","cannot enumerate procfs for bounded fallback") from ex
    for item in items:
        _deadline(deadline)
        if not item.name.isdigit():continue
        pid=int(item.name);records+=1
        if records>max_records:raise SupervisorError("CONTAINMENT_QUERY_OVERFLOW","Linux containment record ceiling exceeded")
        identity=_proc_identity_linux(proc_root,pid,deadline)
        if identity is None:continue
        parent[pid]=identity[0]
    out:set[int]=set();frontier=[root_pid]
    while frontier:
        _deadline(deadline);pid=frontier.pop()
        for child,ppid in parent.items():
            if ppid==pid and child not in out:
                out.add(child);frontier.append(child)
    return out

def _descendants_linux(root_pid:int,*,timeout:float=LINUX_DISCOVERY_TIMEOUT_SECONDS,max_records:int=LINUX_DISCOVERY_MAX_RECORDS,proc_root:Path|str=Path("/proc"))->set[int]:
    timeout=_timeout(timeout,"Linux containment discovery timeout")
    if isinstance(max_records,bool) or not isinstance(max_records,int) or max_records<=0:raise SupervisorError("CONTAINMENT_QUERY_INVALID","Linux containment record ceiling invalid")
    if not isinstance(root_pid,int) or isinstance(root_pid,bool) or root_pid<=1:raise SupervisorError("CONTAINMENT_QUERY_INVALID","Linux containment root pid invalid")
    root=Path(proc_root);deadline=time.monotonic()+timeout
    root_children=root/str(root_pid)/"task"/str(root_pid)/"children"
    if not root_children.exists():
        if not _proc_existing(root,root_pid):raise SupervisorError("CONTAINMENT_QUERY_FAILED","keeper identity disappeared")
        return _descendants_linux_scan(root_pid,deadline=deadline,max_records=max_records,proc_root=root)
    frontier=[root_pid];seen={root_pid};out=set();records=0
    while frontier:
        _deadline(deadline);parent=frontier.pop();records+=1
        if records>max_records:raise SupervisorError("CONTAINMENT_QUERY_OVERFLOW","Linux containment record ceiling exceeded")
        children=_proc_children_linux(root,parent,deadline)
        if children is None:
            if parent==root_pid:raise SupervisorError("CONTAINMENT_QUERY_FAILED","keeper identity disappeared")
            continue
        for child in children:
            _deadline(deadline);records+=1
            if records>max_records:raise SupervisorError("CONTAINMENT_QUERY_OVERFLOW","Linux containment record ceiling exceeded")
            identity=_proc_identity_linux(root,child,deadline)
            if identity is None:continue
            if child in seen:continue
            seen.add(child);out.add(child);frontier.append(child)
    return out

class _PosixKeeperContainment(_Containment):
    def __init__(self,argv:tuple[str,...],cwd:str|None,env:dict[str,str]):
        if not _linux_subreaper_available():raise SupervisorError("CONTAINMENT_UNAVAILABLE","Linux subreaper containment is unavailable")
        spec=json.dumps({"argv":list(argv),"cwd":cwd,"env":env},separators=(",",":"));keeper_env={"PYTHONIOENCODING":"utf-8"}
        self._proc=subprocess.Popen([sys.executable,"-S",str(Path(__file__).resolve()),"--keeper"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=keeper_env,start_new_session=True,close_fds=True)
        try:
            assert self._proc.stdin is not None;self._proc.stdin.write(spec+"\n");self._proc.stdin.flush();self._proc.stdin.close()
        except Exception as ex:self._kill_keeper();raise SupervisorError("CONTAINMENT_START_FAILED","cannot transfer private keeper launch spec") from ex
        line=self._readline_bounded(5.0)
        try:hello=json.loads(line)
        except Exception as ex:self._kill_keeper();raise SupervisorError("CONTAINMENT_START_FAILED","keeper did not provide valid launch identity") from ex
        if hello.get("ok") is not True or not isinstance(hello.get("pid"),int) or hello["pid"]<=1:
            detail=str(hello.get("error") or "keeper launch failed");self._kill_keeper();raise SupervisorError("CONTAINMENT_START_FAILED",detail)
        self.pid=int(hello["pid"]);self.containment_id=f"linux-subreaper:{self._proc.pid}:{self.pid}"
    def _readline_bounded(self,timeout):
        result=[];error=[]
        def reader():
            try:result.append(self._proc.stdout.readline() if self._proc.stdout else "")
            except BaseException as ex:error.append(ex)
        t=threading.Thread(target=reader,daemon=True);t.start();t.join(timeout)
        if t.is_alive():self._kill_keeper();raise SupervisorError("CONTAINMENT_QUERY_TIMEOUT","keeper identity query timed out")
        if error or not result or not result[0]:raise SupervisorError("CONTAINMENT_START_FAILED","keeper exited before launch identity")
        return result[0]
    def poll(self):
        rc=self._proc.poll();return None if rc is None else int(rc)
    def empty(self,timeout):
        timeout=_timeout(timeout,"containment query timeout")
        try:self._proc.wait(timeout=timeout);return self._proc.returncode!=_KEEPER_QUERY_FAILED_RC
        except subprocess.TimeoutExpired:return False
    def terminate(self,timeout):
        timeout=_timeout(timeout,"termination timeout");existing=self._proc.poll()
        if existing is not None:
            if existing==_KEEPER_QUERY_FAILED_RC:raise SupervisorError("CONTAINMENT_QUERY_FAILED","keeper containment proof failed")
            return True
        try:os.kill(self._proc.pid,signal.SIGTERM)
        except ProcessLookupError:return self.empty(min(timeout,1.0))
        try:
            rc=self._proc.wait(timeout=timeout)
            if rc==_KEEPER_QUERY_FAILED_RC:raise SupervisorError("CONTAINMENT_QUERY_FAILED","keeper containment proof failed")
            return rc==_KEEPER_STOPPED_RC
        except subprocess.TimeoutExpired:
            try:os.kill(self._proc.pid,signal.SIGKILL)
            except ProcessLookupError:return self.empty(min(timeout,1.0))
            try:self._proc.wait(timeout=min(timeout,5.0))
            except subprocess.TimeoutExpired:return False
            return False
    def _kill_keeper(self):
        try:self._proc.kill()
        except Exception:pass
        try:self._proc.wait(timeout=2.0)
        except Exception:pass
    def close(self):
        if self._proc.poll() is None:self.terminate(2.0)
        for stream in (self._proc.stdout,self._proc.stderr):
            try:
                if stream:stream.close()
            except Exception:pass

if os.name=="nt":
    from ctypes import wintypes
    CREATE_SUSPENDED=0x4;CREATE_UNICODE_ENVIRONMENT=0x400;CREATE_NO_WINDOW=0x08000000;JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE=0x2000;JobObjectExtendedLimitInformation=9;JobObjectBasicAccountingInformation=1
    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_=[("PerProcessUserTimeLimit",ctypes.c_int64),("PerJobUserTimeLimit",ctypes.c_int64),("LimitFlags",wintypes.DWORD),("MinimumWorkingSetSize",ctypes.c_size_t),("MaximumWorkingSetSize",ctypes.c_size_t),("ActiveProcessLimit",wintypes.DWORD),("Affinity",ctypes.c_size_t),("PriorityClass",wintypes.DWORD),("SchedulingClass",wintypes.DWORD)]
    class _IO_COUNTERS(ctypes.Structure):_fields_=[(name,ctypes.c_uint64) for name in ("ReadOperationCount","WriteOperationCount","OtherOperationCount","ReadTransferCount","WriteTransferCount","OtherTransferCount")]
    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):_fields_=[("BasicLimitInformation",_JOBOBJECT_BASIC_LIMIT_INFORMATION),("IoInfo",_IO_COUNTERS),("ProcessMemoryLimit",ctypes.c_size_t),("JobMemoryLimit",ctypes.c_size_t),("PeakProcessMemoryUsed",ctypes.c_size_t),("PeakJobMemoryUsed",ctypes.c_size_t)]
    class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):_fields_=[("TotalUserTime",ctypes.c_int64),("TotalKernelTime",ctypes.c_int64),("ThisPeriodTotalUserTime",ctypes.c_int64),("ThisPeriodTotalKernelTime",ctypes.c_int64),("TotalPageFaultCount",wintypes.DWORD),("TotalProcesses",wintypes.DWORD),("ActiveProcesses",wintypes.DWORD),("TotalTerminatedProcesses",wintypes.DWORD)]
    class _STARTUPINFOW(ctypes.Structure):_fields_=[("cb",wintypes.DWORD),("lpReserved",wintypes.LPWSTR),("lpDesktop",wintypes.LPWSTR),("lpTitle",wintypes.LPWSTR),("dwX",wintypes.DWORD),("dwY",wintypes.DWORD),("dwXSize",wintypes.DWORD),("dwYSize",wintypes.DWORD),("dwXCountChars",wintypes.DWORD),("dwYCountChars",wintypes.DWORD),("dwFillAttribute",wintypes.DWORD),("dwFlags",wintypes.DWORD),("wShowWindow",wintypes.WORD),("cbReserved2",wintypes.WORD),("lpReserved2",ctypes.POINTER(ctypes.c_ubyte)),("hStdInput",wintypes.HANDLE),("hStdOutput",wintypes.HANDLE),("hStdError",wintypes.HANDLE)]
    class _PROCESS_INFORMATION(ctypes.Structure):_fields_=[("hProcess",wintypes.HANDLE),("hThread",wintypes.HANDLE),("dwProcessId",wintypes.DWORD),("dwThreadId",wintypes.DWORD)]

class _WindowsJobContainment(_Containment):
    def __init__(self,argv,cwd,env):
        if os.name!="nt":raise SupervisorError("CONTAINMENT_UNAVAILABLE","Windows Job containment is unavailable")
        from ctypes import wintypes
        self._k=ctypes.WinDLL("kernel32",use_last_error=True);self._configure();self._job=self._k.CreateJobObjectW(None,None)
        if not self._job:raise SupervisorError("CONTAINMENT_START_FAILED","CreateJobObjectW failed")
        info=_JOBOBJECT_EXTENDED_LIMIT_INFORMATION();info.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self._k.SetInformationJobObject(self._job,JobObjectExtendedLimitInformation,ctypes.byref(info),ctypes.sizeof(info)):self._k.CloseHandle(self._job);raise SupervisorError("CONTAINMENT_START_FAILED","SetInformationJobObject failed")
        cmd=ctypes.create_unicode_buffer(subprocess.list2cmdline(argv));block="\0".join(f"{k}={v}" for k,v in sorted(env.items(),key=lambda kv:kv[0].casefold()))+"\0\0";envbuf=ctypes.create_unicode_buffer(block);si=_STARTUPINFOW();si.cb=ctypes.sizeof(si);pi=_PROCESS_INFORMATION();flags=CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW
        if not self._k.CreateProcessW(argv[0],cmd,None,None,False,flags,ctypes.cast(envbuf,wintypes.LPVOID),cwd,ctypes.byref(si),ctypes.byref(pi)):self._k.CloseHandle(self._job);raise SupervisorError("CONTAINMENT_START_FAILED","CreateProcessW failed")
        self._process,self._thread=pi.hProcess,pi.hThread;self.pid=int(pi.dwProcessId)
        try:
            if not self._k.AssignProcessToJobObject(self._job,self._process):raise SupervisorError("CONTAINMENT_START_FAILED","AssignProcessToJobObject failed")
            if self._k.ResumeThread(self._thread)==0xFFFFFFFF:raise SupervisorError("CONTAINMENT_START_FAILED","ResumeThread failed")
        except Exception:self._k.TerminateProcess(self._process,70);self.close();raise
        self.containment_id=f"windows-job:{int(getattr(self._job,'value',self._job) or 0)}:{self.pid}"
    def _configure(self):
        from ctypes import wintypes
        H,D,V=wintypes.HANDLE,wintypes.DWORD,wintypes.LPVOID
        specs={"CreateJobObjectW":([V,wintypes.LPCWSTR],H),"SetInformationJobObject":([H,ctypes.c_int,V,D],wintypes.BOOL),"AssignProcessToJobObject":([H,H],wintypes.BOOL),"TerminateJobObject":([H,wintypes.UINT],wintypes.BOOL),"QueryInformationJobObject":([H,ctypes.c_int,V,D,ctypes.POINTER(D)],wintypes.BOOL),"CreateProcessW":([wintypes.LPCWSTR,wintypes.LPWSTR,V,V,wintypes.BOOL,D,V,wintypes.LPCWSTR,V,V],wintypes.BOOL),"ResumeThread":([H],D),"GetExitCodeProcess":([H,ctypes.POINTER(D)],wintypes.BOOL),"WaitForSingleObject":([H,D],D),"TerminateProcess":([H,wintypes.UINT],wintypes.BOOL),"CloseHandle":([H],wintypes.BOOL)}
        for name,(args,result) in specs.items():fn=getattr(self._k,name);fn.argtypes=args;fn.restype=result
    def poll(self):
        from ctypes import wintypes
        code=wintypes.DWORD()
        if not self._k.GetExitCodeProcess(self._process,ctypes.byref(code)):raise SupervisorError("IDENTITY_LOST","cannot query stable worker process handle")
        return None if code.value==259 else int(code.value)
    def empty(self,timeout):
        timeout=_timeout(timeout,"containment query timeout");deadline=time.monotonic()+timeout;info=_JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        while time.monotonic()<deadline:
            if not self._k.QueryInformationJobObject(self._job,JobObjectBasicAccountingInformation,ctypes.byref(info),ctypes.sizeof(info),None):raise SupervisorError("CONTAINMENT_QUERY_FAILED","QueryInformationJobObject failed")
            if int(info.ActiveProcesses)==0:return True
            time.sleep(min(DEFAULT_POLL_SECONDS,max(.001,deadline-time.monotonic())))
        return False
    def terminate(self,timeout):
        timeout=_timeout(timeout,"termination timeout")
        if not self._k.TerminateJobObject(self._job,75):raise SupervisorError("STOP_FAILED","TerminateJobObject failed")
        return self.empty(timeout)
    def close(self):
        for handle in (getattr(self,"_thread",None),getattr(self,"_process",None),getattr(self,"_job",None)):
            if handle:
                try:self._k.CloseHandle(handle)
                except Exception:pass

def _launch_containment(argv,cwd,env):
    if os.name=="nt":return _WindowsJobContainment(argv,cwd,env)
    if sys.platform.startswith("linux"):return _PosixKeeperContainment(argv,cwd,env)
    raise SupervisorError("CONTAINMENT_UNAVAILABLE","no non-escapable containment backend for this platform")

class ProcessSupervisor:
    def __init__(self):self._lock=threading.RLock();self._slots={};self._containments={};self._stop_ops={}
    def launch(self,worker_id,argv,*,cwd=None,env=None):return self._bind(worker_id,argv,cwd=cwd,env=env,expected_generation=None)
    def reassign(self,worker_id,expected_generation,argv,*,cwd=None,env=None):return self._bind(worker_id,argv,cwd=cwd,env=env,expected_generation=expected_generation)
    def _bind(self,worker_id,argv,*,cwd,env,expected_generation):
        if not isinstance(worker_id,str) or not worker_id or worker_id.strip()!=worker_id:raise SupervisorError("WORKER_ID_INVALID","worker_id must be a non-empty canonical string")
        args=_argv(argv);workdir=_cwd(cwd);environment=_env(env)
        with self._lock:
            current=self._slots.get(worker_id)
            if current is not None:
                if expected_generation is None:raise SupervisorError("GENERATION_OCCUPIED","worker already has a generation")
                if not isinstance(expected_generation,int) or isinstance(expected_generation,bool) or expected_generation!=current.generation:raise SupervisorError("GENERATION_STALE","expected generation does not match")
                if current.state not in _ADVANCEABLE:raise SupervisorError("GENERATION_NOT_STOPPED",f"cannot advance from {current.state}")
                containment=self._containments.get(worker_id)
                if containment is None:raise SupervisorError("IDENTITY_LOST","prior containment identity is missing")
                if not containment.empty(1.0):raise SupervisorError("GENERATION_NOT_STOPPED","prior containment is not empty")
                generation=current.generation+1
            else:
                if expected_generation is not None:raise SupervisorError("GENERATION_UNKNOWN","worker has no prior generation")
                generation=1
        containment=_launch_containment(args,workdir,environment);started=time.time();assignment=Assignment(worker_id,generation,STATE_RUNNING,args,containment.pid,containment.containment_id,started)
        with self._lock:
            latest=self._slots.get(worker_id)
            if current is None:
                if latest is not None:containment.terminate(2.0);containment.close();raise SupervisorError("GENERATION_RACE","worker generation changed during launch")
            elif latest!=current:containment.terminate(2.0);containment.close();raise SupervisorError("GENERATION_RACE","worker generation changed during launch")
            else:
                old=self._containments.get(worker_id)
                if old is not None:old.close()
            self._slots[worker_id]=assignment;self._containments[worker_id]=containment;return assignment
    def refresh(self,worker_id):
        with self._lock:current=self._require(worker_id);containment=self._containments.get(worker_id)
        if containment is None:updated=replace(current,state=STATE_IDENTITY_LOST)
        else:
            try:rc=containment.poll()
            except Exception:updated=replace(current,state=STATE_IDENTITY_LOST)
            else:
                if rc is None:return current
                empty=containment.empty(1.0)
                if not empty:updated=replace(current,state=STATE_QUARANTINED,exit_code=rc)
                elif rc==0:updated=replace(current,state=STATE_QUARANTINED,exit_code=0)
                else:updated=replace(current,state=STATE_FAILED,exit_code=rc)
        with self._lock:
            if self._slots.get(worker_id)==current:self._slots[worker_id]=updated
            return self._slots[worker_id]
    def stop(self,worker_id,expected_generation,*,timeout=10.0):
        timeout=_timeout(timeout,"stop timeout")
        if not isinstance(expected_generation,int) or isinstance(expected_generation,bool) or expected_generation<=0:raise SupervisorError("GENERATION_INVALID","expected_generation must be a positive integer")
        key=(worker_id,expected_generation);leader=False
        with self._lock:
            current=self._require(worker_id)
            if current.generation!=expected_generation:raise SupervisorError("GENERATION_STALE","stop targets a stale generation")
            existing=self._stop_ops.get(key)
            if existing is None:operation_id=uuid.uuid4().hex;event=threading.Event();self._stop_ops[key]=(operation_id,event);self._slots[worker_id]=replace(current,state=STATE_STOPPING);leader=True
            else:operation_id,event=existing
        if not leader:
            if not event.wait(timeout):raise SupervisorError("STOP_JOIN_TIMEOUT","duplicate stop did not finish within timeout")
            with self._lock:
                done=self._require(worker_id)
                if done.generation!=expected_generation or done.last_evidence is None or done.last_evidence.operation_id!=operation_id:raise SupervisorError("STOP_EVIDENCE_LOST","stop completion evidence is unavailable")
                return done.last_evidence
        started=time.time();state=STATE_STOP_FAILED;reason="stop-failed";exit_code=None;empty=False
        try:
            with self._lock:containment=self._containments.get(worker_id)
            if containment is None:state,reason=STATE_IDENTITY_LOST,"containment-identity-lost"
            else:
                try:
                    if not containment.terminate(timeout):state,reason=STATE_STOP_FAILED,"containment-survived-stop"
                    else:
                        empty=containment.empty(min(timeout,5.0))
                        if not empty:state,reason=STATE_STOP_FAILED,"containment-not-empty"
                        else:exit_code=containment.poll();state,reason=STATE_STOPPED,"verified-stopped"
                except SupervisorError as ex:state,reason=STATE_STOP_FAILED,ex.code.lower()
                except Exception:state,reason=STATE_STOP_FAILED,"containment-query-failed"
        finally:
            evidence=Evidence(operation_id,worker_id,expected_generation,state,reason,exit_code,empty,started,time.time())
            with self._lock:
                latest=self._slots.get(worker_id)
                if latest is not None and latest.generation==expected_generation and latest.state==STATE_STOPPING:self._slots[worker_id]=replace(latest,state=state,exit_code=exit_code,last_evidence=evidence)
                op=self._stop_ops.pop(key,None)
                if op:op[1].set()
            return evidence
    def get(self,worker_id,*,refresh=False):return self.refresh(worker_id) if refresh else self._require_public(worker_id)
    def _require(self,worker_id):
        value=self._slots.get(worker_id)
        if value is None:raise SupervisorError("WORKER_UNKNOWN","worker is unknown")
        return value
    def _require_public(self,worker_id):
        with self._lock:return self._require(worker_id)
    def close(self):
        with self._lock:items=list(self._containments.items())
        for worker_id,containment in items:
            try:
                current=self.get(worker_id)
                if current.state!=STATE_STOPPED:self.stop(worker_id,current.generation,timeout=2.0)
            except Exception:pass
            try:containment.close()
            except Exception:pass

def _keeper_main()->int:
    if not _linux_subreaper_available():print(json.dumps({"ok":False,"error":"subreaper unavailable"}),flush=True);return 125
    libc=ctypes.CDLL(None,use_errno=True);PR_SET_CHILD_SUBREAPER=36
    if libc.prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0)!=0:print(json.dumps({"ok":False,"error":"prctl subreaper failed"}),flush=True);return 125
    try:
        line=sys.stdin.readline()
        if not line:raise ValueError("missing keeper launch spec")
        spec=json.loads(line);proc=subprocess.Popen(spec["argv"],cwd=spec.get("cwd"),env=spec.get("env"),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
    except Exception as ex:print(json.dumps({"ok":False,"error":str(ex)}),flush=True);return 125
    print(json.dumps({"ok":True,"pid":proc.pid}),flush=True);stopping=False
    def request_stop(_sig,_frame):
        nonlocal stopping;stopping=True
    signal.signal(signal.SIGTERM,request_stop);signal.signal(signal.SIGINT,request_stop);root_rc=None;stop_started=None
    while True:
        if root_rc is None:root_rc=proc.poll()
        try:descendants=_descendants_linux(os.getpid())
        except SupervisorError:return _KEEPER_QUERY_FAILED_RC
        descendants.discard(proc.pid)
        if stopping:
            if stop_started is None:stop_started=time.monotonic()
            try:os.killpg(proc.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            for pid in descendants:
                try:os.kill(pid,signal.SIGTERM)
                except ProcessLookupError:pass
            if time.monotonic()-stop_started>1.0:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                for pid in descendants:
                    try:os.kill(pid,signal.SIGKILL)
                    except ProcessLookupError:pass
        while True:
            try:waited,status=os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:break
            if waited==0:break
            if waited==proc.pid and root_rc is None:root_rc=os.waitstatus_to_exitcode(status)
        try:descendants=_descendants_linux(os.getpid())
        except SupervisorError:return _KEEPER_QUERY_FAILED_RC
        if root_rc is not None and not descendants:
            if stopping:return _KEEPER_STOPPED_RC
            if root_rc<0:return min(255,128+abs(root_rc))
            return min(125,int(root_rc))
        time.sleep(.02)

if __name__=="__main__" and len(sys.argv)==2 and sys.argv[1]=="--keeper":raise SystemExit(_keeper_main())
