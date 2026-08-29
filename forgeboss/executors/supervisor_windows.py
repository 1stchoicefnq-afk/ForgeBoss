from __future__ import annotations
import os
from typing import Mapping,Sequence
from .supervisor_common import *

class WindowsSuspendedProcess:
    def __init__(self,argv:Sequence[str],cwd:str|None,env:Mapping[str,str]):
        if os.name!="nt":raise SupervisorError("native Windows launcher used on non-Windows host")
        import ctypes
        from ctypes import wintypes
        self.ctypes,self.wintypes=ctypes,wintypes;self.kernel=ctypes.WinDLL("kernel32",use_last_error=True);configure_windows_api(self.kernel,ctypes,wintypes)
        U=ctypes.c_size_t
        class STARTUPINFOW(ctypes.Structure):
            _fields_=[("cb",wintypes.DWORD),("lpReserved",wintypes.LPWSTR),("lpDesktop",wintypes.LPWSTR),("lpTitle",wintypes.LPWSTR),("dwX",wintypes.DWORD),("dwY",wintypes.DWORD),("dwXSize",wintypes.DWORD),("dwYSize",wintypes.DWORD),("dwXCountChars",wintypes.DWORD),("dwYCountChars",wintypes.DWORD),("dwFillAttribute",wintypes.DWORD),("dwFlags",wintypes.DWORD),("wShowWindow",wintypes.WORD),("cbReserved2",wintypes.WORD),("lpReserved2",ctypes.POINTER(ctypes.c_ubyte)),("hStdInput",wintypes.HANDLE),("hStdOutput",wintypes.HANDLE),("hStdError",wintypes.HANDLE)]
        class PI(ctypes.Structure):_fields_=[("hProcess",wintypes.HANDLE),("hThread",wintypes.HANDLE),("dwProcessId",wintypes.DWORD),("dwThreadId",wintypes.DWORD)]
        class BASIC(ctypes.Structure):_fields_=[("PerProcessUserTimeLimit",ctypes.c_int64),("PerJobUserTimeLimit",ctypes.c_int64),("LimitFlags",wintypes.DWORD),("MinimumWorkingSetSize",U),("MaximumWorkingSetSize",U),("ActiveProcessLimit",wintypes.DWORD),("Affinity",U),("PriorityClass",wintypes.DWORD),("SchedulingClass",wintypes.DWORD)]
        class IO(ctypes.Structure):_fields_=[("ReadOperationCount",ctypes.c_uint64),("WriteOperationCount",ctypes.c_uint64),("OtherOperationCount",ctypes.c_uint64),("ReadTransferCount",ctypes.c_uint64),("WriteTransferCount",ctypes.c_uint64),("OtherTransferCount",ctypes.c_uint64)]
        class EXT(ctypes.Structure):_fields_=[("BasicLimitInformation",BASIC),("IoInfo",IO),("ProcessMemoryLimit",U),("JobMemoryLimit",U),("PeakProcessMemoryUsed",U),("PeakJobMemoryUsed",U)]
        self.job=self.kernel.CreateJobObjectW(None,None)
        if not self.job:raise SupervisorError("cannot create Windows Job Object")
        info=EXT();info.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(self.job,9,ctypes.byref(info),ctypes.sizeof(info)):self.close();raise SupervisorError("cannot configure Windows Job Object")
        cmd=ctypes.create_unicode_buffer(windows_command_line(argv));envbuf=ctypes.create_unicode_buffer(windows_environment_block(env));si=STARTUPINFOW();si.cb=ctypes.sizeof(si);pi=PI()
        flags=CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW
        if flags&CREATE_BREAKAWAY_FROM_JOB:self.close();raise SupervisorError("breakaway flag denied")
        ok=self.kernel.CreateProcessW(str(argv[0]),cmd,None,None,False,flags,ctypes.cast(envbuf,wintypes.LPVOID),cwd,ctypes.byref(si),ctypes.byref(pi))
        if not ok:self.close();raise SupervisorError("CreateProcessW suspended launch failed")
        self.process,self.thread,self.pid=pi.hProcess,pi.hThread,int(pi.dwProcessId)
        if not self.kernel.AssignProcessToJobObject(self.job,self.process):self._terminate_suspended();self.close();raise SupervisorError("cannot assign suspended child to Job Object")
        try:self.identity=self._identity()
        except Exception:self._terminate_suspended();self.close();raise
        self.resumed=False
    def _terminate_suspended(self):
        if getattr(self,"process",None):
            try:self.kernel.TerminateProcess(self.process,75)
            except Exception:pass
    def _identity(self):
        c=self.ctypes;w=self.wintypes;created=w.FILETIME();exited=w.FILETIME();kt=w.FILETIME();ut=w.FILETIME()
        if not self.kernel.GetProcessTimes(self.process,c.byref(created),c.byref(exited),c.byref(kt),c.byref(ut)):raise SupervisorError("cannot read suspended process creation identity")
        n=w.DWORD(32768);buf=c.create_unicode_buffer(n.value)
        if not self.kernel.QueryFullProcessImageNameW(self.process,0,buf,c.byref(n)):raise SupervisorError("cannot read suspended process image identity")
        token=(int(created.dwHighDateTime)<<32)|int(created.dwLowDateTime)
        return {"pid":self.pid,"startToken":str(token),"exe":os.path.normcase(os.path.realpath(buf.value))}
    def resume(self):
        if self.resumed:raise SupervisorError("suspended child already resumed")
        previous=int(self.kernel.ResumeThread(self.thread))
        if previous!=1:self.terminate();raise SupervisorError("ResumeThread returned unexpected suspend count")
        self.resumed=True;self.kernel.CloseHandle(self.thread);self.thread=None
    def poll(self):
        rc=int(self.kernel.WaitForSingleObject(self.process,0))
        if rc==WAIT_TIMEOUT:return None
        if rc!=WAIT_OBJECT_0:raise SupervisorError("Windows child wait failed")
        code=self.wintypes.DWORD()
        if not self.kernel.GetExitCodeProcess(self.process,self.ctypes.byref(code)):raise SupervisorError("cannot read Windows child exit code")
        return int(code.value)
    def tree_alive(self):
        c=self.ctypes;w=self.wintypes
        class A(c.Structure):_fields_=[("TotalUserTime",c.c_int64),("TotalKernelTime",c.c_int64),("ThisPeriodTotalUserTime",c.c_int64),("ThisPeriodTotalKernelTime",c.c_int64),("TotalPageFaultCount",w.DWORD),("TotalProcesses",w.DWORD),("ActiveProcesses",w.DWORD),("TotalTerminatedProcesses",w.DWORD)]
        info=A();ret=w.DWORD()
        if not self.kernel.QueryInformationJobObject(self.job,1,c.byref(info),c.sizeof(info),c.byref(ret)):raise SupervisorError("cannot query Windows Job Object")
        return int(info.ActiveProcesses)>0
    def terminate(self):
        if getattr(self,"job",None) and not self.kernel.TerminateJobObject(self.job,75):raise SupervisorError("TerminateJobObject failed")
    def wait_leader(self,timeout):
        rc=int(self.kernel.WaitForSingleObject(self.process,max(1,int(float(timeout)*1000))))
        if rc==WAIT_TIMEOUT:raise SupervisorError("Windows process leader did not exit")
        if rc!=WAIT_OBJECT_0:raise SupervisorError("Windows process wait failed")
    def close(self):
        for name in ("thread","process","job"):
            h=getattr(self,name,None)
            if h:
                try:self.kernel.CloseHandle(h)
                except Exception:pass
                setattr(self,name,None)
