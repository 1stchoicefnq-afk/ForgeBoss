from __future__ import annotations
import ctypes,os,socket,stat,threading
from ctypes import wintypes
from pathlib import Path
from .boundary import windows_pipe_peer_context
from .ipc import serve_unix_once
from .protocol import AuthorityError,MAX_REQUEST_BYTES
from .root_chain import assert_machine_anchored_root
from .win32_ffi import is_invalid_handle,load_win32
FIXED_PIPE_NAME=r'\\.\pipe\ForgeBossAuthority';FIXED_SOCKET_NAME='authority.sock';FIXED_SERVICE_NAME='ForgeBossAuthoritySvc'
def _assert_linux_endpoint_dir(path:Path,*,service_uid:int,allowed_gid:int)->Path:
    p=Path(path)
    if not p.is_absolute() or p.is_symlink():raise AuthorityError('IPC_ENDPOINT_DIR_INVALID')
    try:r=p.resolve(strict=True);st=r.stat()
    except Exception as e:raise AuthorityError('IPC_ENDPOINT_DIR_INVALID') from e
    mode=stat.S_IMODE(st.st_mode)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in {0,service_uid} or st.st_gid!=allowed_gid or mode&0o022:raise AuthorityError('IPC_ENDPOINT_DIR_PERMISSIONS')
    cur=r
    while True:
        lst=cur.lstat()
        if stat.S_ISLNK(lst.st_mode) or stat.S_IMODE(lst.st_mode)&0o022:raise AuthorityError('IPC_ENDPOINT_DIR_PERMISSIONS')
        if cur.parent==cur:break
        cur=cur.parent
    return r
class LinuxAuthorityDaemon:
    def __init__(self,*,service,boundary,protected_root:Path,endpoint_dir:Path,allowed_gid:int):
        if os.name=='nt':raise AuthorityError('IPC_PLATFORM_INVALID')
        self.service=service;self.boundary=boundary;self.root=assert_machine_anchored_root(boundary,protected_root);self.service_uid=int(boundary.expected[4:]);self.endpoint_dir=_assert_linux_endpoint_dir(endpoint_dir,service_uid=self.service_uid,allowed_gid=int(allowed_gid));self.allowed_gid=int(allowed_gid);self.path=self.endpoint_dir/FIXED_SOCKET_NAME;self.listener=None;self._stop=False
    def start(self):
        if self.listener is not None:raise AuthorityError('SERVICE_ALREADY_STARTED')
        if self.path.exists() or self.path.is_symlink():raise AuthorityError('IPC_ENDPOINT_EXISTS')
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            s.bind(str(self.path));os.chown(self.path,self.service_uid,self.allowed_gid);os.chmod(self.path,0o660);st=self.path.stat()
            if st.st_uid!=self.service_uid or st.st_gid!=self.allowed_gid or stat.S_IMODE(st.st_mode)!=0o660 or not stat.S_ISSOCK(st.st_mode):raise AuthorityError('IPC_ENDPOINT_PERMISSIONS')
            s.listen(16);self.listener=s;return self.path
        except Exception:
            s.close()
            try:self.path.unlink()
            except OSError:pass
            raise
    def serve_once(self):
        if self.listener is None:raise AuthorityError('SERVICE_NOT_STARTED')
        return serve_unix_once(self.listener,self.service)
    def run_forever(self):
        self.start()
        try:
            while not self._stop:self.serve_once()
        finally:self.close()
    def stop(self):self._stop=True;self.close()
    def close(self):
        if self.listener is not None:self.listener.close();self.listener=None
        try:self.path.unlink()
        except FileNotFoundError:pass
def _windows_sddl(allowed_peer_sids:set[str])->str:
    sids=[]
    for sid in sorted({str(x).upper() for x in allowed_peer_sids}):
        if not sid.startswith('S-1-'):raise AuthorityError('IPC_PEER_SID_INVALID')
        sids.append(f'(A;;GRGW;;;{sid})')
    if not sids:raise AuthorityError('IPC_PEER_SID_INVALID')
    return 'D:P(A;;GA;;;SY)(A;;GA;;;BA)'+''.join(sids)
class QSC(ctypes.Structure):_fields_=[('dwServiceType',wintypes.DWORD),('dwStartType',wintypes.DWORD),('dwErrorControl',wintypes.DWORD),('lpBinaryPathName',wintypes.LPWSTR),('lpLoadOrderGroup',wintypes.LPWSTR),('dwTagId',wintypes.DWORD),('lpDependencies',wintypes.LPWSTR),('lpServiceStartName',wintypes.LPWSTR),('lpDisplayName',wintypes.LPWSTR)]
def assert_windows_scm_registration(*,service_name:str=FIXED_SERVICE_NAME,expected_image_command:str)->None:
    if os.name!='nt':raise AuthorityError('IPC_PLATFORM_INVALID')
    api=load_win32();scm=api.advapi32.OpenSCManagerW(None,None,0x0001);svc=None
    if is_invalid_handle(scm):raise AuthorityError('SCM_UNAVAILABLE')
    try:
        svc=api.advapi32.OpenServiceW(scm,service_name,0x0001)
        if is_invalid_handle(svc):raise AuthorityError('SCM_SERVICE_MISSING')
        needed=wintypes.DWORD(0);api.advapi32.QueryServiceConfigW(svc,None,0,ctypes.byref(needed))
        if not needed.value:raise AuthorityError('SCM_CONFIG_INVALID')
        buf=ctypes.create_string_buffer(needed.value)
        if not api.advapi32.QueryServiceConfigW(svc,ctypes.cast(buf,wintypes.LPVOID),needed,ctypes.byref(needed)):raise AuthorityError('SCM_CONFIG_INVALID')
        cfg=ctypes.cast(buf,ctypes.POINTER(QSC)).contents;actual=' '.join(str(cfg.lpBinaryPathName or '').split());expected=' '.join(str(expected_image_command).split())
        if actual!=expected:raise AuthorityError('SCM_IMAGE_MISMATCH')
    finally:
        if svc and not is_invalid_handle(svc):api.advapi32.CloseServiceHandle(svc)
        if scm and not is_invalid_handle(scm):api.advapi32.CloseServiceHandle(scm)
class SA(ctypes.Structure):_fields_=[('nLength',wintypes.DWORD),('lpSecurityDescriptor',wintypes.LPVOID),('bInheritHandle',wintypes.BOOL)]
class WindowsNamedPipeServer:
    def __init__(self,*,service,boundary,protected_root:Path,allowed_peer_sids:set[str]):
        if os.name!='nt':raise AuthorityError('IPC_PLATFORM_INVALID')
        self.service=service;self.boundary=boundary;self.root=assert_machine_anchored_root(boundary,protected_root);self.allowed_peer_sids=set(allowed_peer_sids);self.handle=None;self._sd=None
    def start(self):
        if self.handle is not None:raise AuthorityError('SERVICE_ALREADY_STARTED')
        api=load_win32();sd=wintypes.LPVOID();sddl=_windows_sddl(self.allowed_peer_sids)
        if not api.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(sd),None):raise AuthorityError('IPC_ACL_INVALID')
        sa=SA(ctypes.sizeof(SA),sd,False);h=api.kernel32.CreateNamedPipeW(FIXED_PIPE_NAME,0x00000003|0x00080000,0x00000004|0x00000002|0x00000008,1,MAX_REQUEST_BYTES,MAX_REQUEST_BYTES,5000,ctypes.byref(sa))
        if is_invalid_handle(h):api.kernel32.LocalFree(sd);raise AuthorityError('IPC_CREATE_FAILED')
        self.handle=h;self._sd=sd;return h
    def serve_once(self):
        if self.handle is None:raise AuthorityError('SERVICE_NOT_STARTED')
        api=load_win32();ok=api.kernel32.ConnectNamedPipe(self.handle,None)
        if not ok and ctypes.get_last_error()!=535:raise AuthorityError('IPC_CONNECT_FAILED')
        try:
            raw=int(ctypes.cast(self.handle,ctypes.c_void_p).value or 0);ctx=windows_pipe_peer_context(raw);chunks=[];total=0
            while True:
                buf=ctypes.create_string_buffer(65536);read=wintypes.DWORD(0);ok=api.kernel32.ReadFile(self.handle,buf,len(buf),ctypes.byref(read),None);err=ctypes.get_last_error()
                if read.value:chunks.append(buf.raw[:read.value]);total+=read.value
                if total>MAX_REQUEST_BYTES:raise AuthorityError('REQUEST_SIZE_INVALID')
                if ok:break
                if err!=234:raise AuthorityError('IPC_READ_FAILED')
            out=self.service.handle_json(b''.join(chunks),peer_context=ctx);written=wintypes.DWORD(0)
            if not api.kernel32.WriteFile(self.handle,out,len(out),ctypes.byref(written),None) or written.value!=len(out):raise AuthorityError('IPC_WRITE_FAILED')
            return out
        finally:api.kernel32.DisconnectNamedPipe(self.handle)
    def close(self):
        if os.name!='nt':return
        api=load_win32()
        if self.handle is not None:api.kernel32.CloseHandle(self.handle);self.handle=None
        if self._sd:api.kernel32.LocalFree(self._sd);self._sd=None
def run_windows_scm_service(*,service_name:str=FIXED_SERVICE_NAME,server_factory):
    if os.name!='nt':raise AuthorityError('IPC_PLATFORM_INVALID')
    api=load_win32();OWN=0x10;START_PENDING=2;STOP_PENDING=3;RUNNING=4;STOPPED=1;ACCEPT_STOP=1;ACCEPT_SHUTDOWN=4;CTRL_STOP=1;CTRL_SHUTDOWN=5
    class STATUS(ctypes.Structure):_fields_=[('dwServiceType',wintypes.DWORD),('dwCurrentState',wintypes.DWORD),('dwControlsAccepted',wintypes.DWORD),('dwWin32ExitCode',wintypes.DWORD),('dwServiceSpecificExitCode',wintypes.DWORD),('dwCheckPoint',wintypes.DWORD),('dwWaitHint',wintypes.DWORD)]
    SERVICE_MAIN=ctypes.WINFUNCTYPE(None,wintypes.DWORD,ctypes.POINTER(wintypes.LPWSTR));HANDLER=ctypes.WINFUNCTYPE(None,wintypes.DWORD);state={'server':None,'handle':None,'stop':threading.Event()}
    def set_status(code,accepted=0):
        s=STATUS(OWN,code,accepted,0,0,0,0)
        if state['handle'] and not api.advapi32.SetServiceStatus(state['handle'],ctypes.byref(s)):raise AuthorityError('SCM_STATUS_FAILED')
    @HANDLER
    def handler(control):
        if control in (CTRL_STOP,CTRL_SHUTDOWN):
            state['stop'].set()
            try:set_status(STOP_PENDING)
            except Exception:pass
            try:
                if state['server'] is not None:state['server'].close()
            except Exception:pass
    @SERVICE_MAIN
    def service_main(_argc,_argv):
        state['handle']=api.advapi32.RegisterServiceCtrlHandlerW(service_name,ctypes.cast(handler,wintypes.LPVOID))
        if not state['handle']:return
        try:
            set_status(START_PENDING);srv=server_factory();state['server']=srv;srv.start();set_status(RUNNING,ACCEPT_STOP|ACCEPT_SHUTDOWN)
            while not state['stop'].is_set():
                try:srv.serve_once()
                except Exception:
                    if state['stop'].is_set():break
                    raise
        finally:
            try:
                if state['server'] is not None:state['server'].close()
            finally:set_status(STOPPED)
    class ENTRY(ctypes.Structure):_fields_=[('lpServiceName',wintypes.LPWSTR),('lpServiceProc',SERVICE_MAIN)]
    table=(ENTRY*2)();table[0]=ENTRY(service_name,service_main);table[1].lpServiceName=None
    if not api.advapi32.StartServiceCtrlDispatcherW(ctypes.cast(table,wintypes.LPVOID)):raise AuthorityError('SCM_DISPATCH_FAILED')
