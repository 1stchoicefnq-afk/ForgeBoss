from __future__ import annotations
import ctypes,os,signal,threading
from .server import serve_forever,wake_windows_pipe

SERVICE_NAME="ForgeBossIsolationBroker"

def _linux_main():
    stop=threading.Event()
    def handler(_sig,_frame):stop.set()
    signal.signal(signal.SIGTERM,handler);signal.signal(signal.SIGINT,handler)
    serve_forever(stop)

def _windows_service_main():
    from ctypes import wintypes
    adv=ctypes.WinDLL("advapi32",use_last_error=True)
    SERVICE_WIN32_OWN_PROCESS=0x10;SERVICE_START_PENDING=2;SERVICE_STOP_PENDING=3;SERVICE_RUNNING=4;SERVICE_STOPPED=1;SERVICE_ACCEPT_STOP=1;SERVICE_ACCEPT_SHUTDOWN=4;SERVICE_CONTROL_STOP=1;SERVICE_CONTROL_SHUTDOWN=5
    class SERVICE_STATUS(ctypes.Structure):
        _fields_=[("dwServiceType",wintypes.DWORD),("dwCurrentState",wintypes.DWORD),("dwControlsAccepted",wintypes.DWORD),("dwWin32ExitCode",wintypes.DWORD),("dwServiceSpecificExitCode",wintypes.DWORD),("dwCheckPoint",wintypes.DWORD),("dwWaitHint",wintypes.DWORD)]
    HANDLER=ctypes.WINFUNCTYPE(wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.LPVOID)
    MAIN=ctypes.WINFUNCTYPE(None,wintypes.DWORD,ctypes.POINTER(wintypes.LPWSTR))
    class TABLE(ctypes.Structure):_fields_=[("lpServiceName",wintypes.LPWSTR),("lpServiceProc",MAIN)]
    adv.RegisterServiceCtrlHandlerExW.argtypes=[wintypes.LPCWSTR,HANDLER,wintypes.LPVOID];adv.RegisterServiceCtrlHandlerExW.restype=wintypes.HANDLE
    adv.SetServiceStatus.argtypes=[wintypes.HANDLE,ctypes.POINTER(SERVICE_STATUS)];adv.SetServiceStatus.restype=wintypes.BOOL
    adv.StartServiceCtrlDispatcherW.argtypes=[ctypes.POINTER(TABLE)];adv.StartServiceCtrlDispatcherW.restype=wintypes.BOOL
    stop=threading.Event();state={"handle":None,"checkpoint":0}
    def set_status(current,accepted=0,wait=0,exit_code=0):
        state["checkpoint"]+=1
        s=SERVICE_STATUS(SERVICE_WIN32_OWN_PROCESS,current,accepted,exit_code,0,state["checkpoint"] if current in (SERVICE_START_PENDING,SERVICE_STOP_PENDING) else 0,wait)
        if state["handle"] and not adv.SetServiceStatus(state["handle"],ctypes.byref(s)):raise OSError(ctypes.get_last_error(),"SetServiceStatus failed")
    @HANDLER
    def control(code,_event_type,_event_data,_context):
        if code in (SERVICE_CONTROL_STOP,SERVICE_CONTROL_SHUTDOWN):
            if not stop.is_set():
                set_status(SERVICE_STOP_PENDING,0,5000);stop.set();wake_windows_pipe()
            return 0
        return 0
    @MAIN
    def service_main(_argc,_argv):
        state["handle"]=adv.RegisterServiceCtrlHandlerExW(SERVICE_NAME,control,None)
        if not state["handle"]:return
        try:
            set_status(SERVICE_START_PENDING,0,5000);set_status(SERVICE_RUNNING,SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN)
            serve_forever(stop);set_status(SERVICE_STOPPED)
        except Exception:
            try:set_status(SERVICE_STOPPED,0,0,1)
            except Exception:pass
    table=(TABLE*2)();table[0]=TABLE(SERVICE_NAME,service_main);table[1]=TABLE(None,MAIN())
    # Keep callbacks/table alive for the lifetime of StartServiceCtrlDispatcherW.
    if not adv.StartServiceCtrlDispatcherW(table):raise OSError(ctypes.get_last_error(),"StartServiceCtrlDispatcherW failed")

def main():
    if os.name=="nt":_windows_service_main()
    else:_linux_main()

if __name__=="__main__":main()
