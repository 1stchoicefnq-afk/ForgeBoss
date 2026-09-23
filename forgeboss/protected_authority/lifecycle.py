from __future__ import annotations
import ctypes,os,socket,stat,threading,time
from ctypes import wintypes
from pathlib import Path
from .boundary import windows_pipe_peer_context
from .ipc import serve_unix_once
from .protocol import AuthorityError,MAX_REQUEST_BYTES
from .root_chain import assert_machine_anchored_root
from .win32_ffi import handle_value,is_invalid_handle,load_win32
FIXED_PIPE_NAME=r'\\.\pipe\ForgeBossAuthority';FIXED_SOCKET_NAME='authority.sock';FIXED_SERVICE_NAME='ForgeBossAuthoritySvc'
_PIPE_ACCESS_DUPLEX=0x00000003;_FILE_FLAG_FIRST_PIPE_INSTANCE=0x00080000;_PIPE_TYPE_MESSAGE=0x4;_PIPE_READMODE_MESSAGE=0x2;_PIPE_NOWAIT=0x1
_ERROR_BROKEN_PIPE=109;_ERROR_NO_DATA=232;_ERROR_MORE_DATA=234;_ERROR_PIPE_CONNECTED=535;_ERROR_PIPE_LISTENING=536

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
    def __init__(self,*,service,boundary,protected_root:Path,endpoint_dir:Path,allowed_gid:int,max_workers:int=4,preauth_timeout:float=1.0,accept_poll:float=0.1):
        if os.name=='nt':raise AuthorityError('IPC_PLATFORM_INVALID')
        if not isinstance(max_workers,int) or not 2<=max_workers<=16:raise AuthorityError('IPC_CONCURRENCY_INVALID')
        if not isinstance(preauth_timeout,(int,float)) or not 0.05<=float(preauth_timeout)<=30.0:raise AuthorityError('IPC_TIMEOUT_INVALID')
        if not isinstance(accept_poll,(int,float)) or not 0.01<=float(accept_poll)<=1.0:raise AuthorityError('IPC_TIMEOUT_INVALID')
        self.service=service;self.boundary=boundary;self.root=assert_machine_anchored_root(boundary,protected_root);self.service_uid=int(boundary.expected[4:]);self.endpoint_dir=_assert_linux_endpoint_dir(endpoint_dir,service_uid=self.service_uid,allowed_gid=int(allowed_gid));self.allowed_gid=int(allowed_gid);self.path=self.endpoint_dir/FIXED_SOCKET_NAME;self.listener=None;self.max_workers=max_workers;self.preauth_timeout=float(preauth_timeout);self.accept_poll=float(accept_poll);self._stop=threading.Event();self._active=set();self._active_lock=threading.Lock();self._workers=[]
    def start(self):
        # A timed-out shutdown must not silently forget a still-executing
        # authenticated/backend worker and then permit a second daemon instance.
        if self.listener is not None:raise AuthorityError('SERVICE_ALREADY_STARTED')
        if any(t.is_alive() for t in self._workers):raise AuthorityError('IPC_WORKER_STUCK')
        self._workers=[]
        with self._active_lock:
            if self._active:raise AuthorityError('IPC_WORKER_STUCK')
        if self.path.exists() or self.path.is_symlink():raise AuthorityError('IPC_ENDPOINT_EXISTS')
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            s.bind(str(self.path));os.chown(self.path,self.service_uid,self.allowed_gid);os.chmod(self.path,0o660);st=self.path.stat()
            if st.st_uid!=self.service_uid or st.st_gid!=self.allowed_gid or stat.S_IMODE(st.st_mode)!=0o660 or not stat.S_ISSOCK(st.st_mode):raise AuthorityError('IPC_ENDPOINT_PERMISSIONS')
            s.listen(max(16,self.max_workers*2));s.settimeout(self.accept_poll);self.listener=s;self._stop.clear();return self.path
        except Exception:
            s.close()
            try:self.path.unlink()
            except OSError:pass
            raise
    def _track(self,conn,add):
        with self._active_lock:
            if add:self._active.add(conn)
            else:self._active.discard(conn)
    def serve_once(self):
        if self.listener is None:raise AuthorityError('SERVICE_NOT_STARTED')
        return serve_unix_once(self.listener,self.service,accept_timeout=self.accept_poll,preauth_timeout=self.preauth_timeout,stop_event=self._stop,on_connection=self._track)
    def _worker_loop(self):
        while not self._stop.is_set():
            try:self.serve_once()
            except AuthorityError as e:
                if self._stop.is_set() or e.code=='IPC_STOPPED':break
                if e.code in {'IPC_ACCEPT_TIMEOUT','IPC_PREAUTH_TIMEOUT','IPC_CLIENT_DISCONNECTED','REQUEST_SIZE_INVALID','IPC_READ_FAILED','PEER_CONTEXT_UNAVAILABLE'}:continue
            except Exception:
                if self._stop.is_set():break
    def run_forever(self):
        self.start();self._workers=[]
        try:
            for _ in range(self.max_workers):
                t=threading.Thread(target=self._worker_loop,daemon=True);self._workers.append(t);t.start()
            while not self._stop.wait(self.accept_poll):
                if any(not t.is_alive() for t in self._workers) and not self._stop.is_set():raise AuthorityError('IPC_WORKER_STUCK')
        finally:self.close()
    def stop(self):self.close()
    def close(self):
        self._stop.set();listener=self.listener;self.listener=None
        if listener is not None:
            try:listener.close()
            except OSError:pass
        with self._active_lock:active=list(self._active)
        for conn in active:
            try:conn.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            try:conn.close()
            except OSError:pass
        current=threading.current_thread();workers=list(self._workers)
        for t in workers:
            if t is not current:t.join(self.preauth_timeout+self.accept_poll+0.5)
        survivors=[t for t in workers if t is not current and t.is_alive()]
        try:self.path.unlink()
        except FileNotFoundError:pass
        except OSError:pass
        if survivors:
            # Preserve the surviving worker and active-connection tracking. A
            # second start is denied until the blocked handler actually exits.
            self._workers=survivors
            raise AuthorityError('IPC_WORKER_STUCK')
        self._workers=[]
        with self._active_lock:self._active.clear()

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
    def __init__(self,*,service,boundary,protected_root:Path,allowed_peer_sids:set[str],max_instances:int=4,preauth_timeout_ms:int=1000,handler_timeout_ms:int=300000,poll_interval:float=0.01):
        if os.name!='nt':raise AuthorityError('IPC_PLATFORM_INVALID')
        if not isinstance(max_instances,int) or not 2<=max_instances<=16:raise AuthorityError('IPC_CONCURRENCY_INVALID')
        if not isinstance(preauth_timeout_ms,int) or not 100<=preauth_timeout_ms<=30000:raise AuthorityError('IPC_TIMEOUT_INVALID')
        if not isinstance(handler_timeout_ms,int) or not 1000<=handler_timeout_ms<=600000:raise AuthorityError('IPC_TIMEOUT_INVALID')
        if not isinstance(poll_interval,(int,float)) or not 0.001<=float(poll_interval)<=0.1:raise AuthorityError('IPC_TIMEOUT_INVALID')
        self.service=service;self.boundary=boundary;self.root=assert_machine_anchored_root(boundary,protected_root);self.allowed_peer_sids=set(allowed_peer_sids);self.max_instances=max_instances;self.preauth_timeout_ms=preauth_timeout_ms;self.handler_timeout_ms=handler_timeout_ms;self.poll_interval=float(poll_interval);self.handles=[];self.handle=None;self._sd=None;self._stop=threading.Event();self._stuck=[];self._quarantined=set();self._worker_lock=threading.Lock()
    def start(self):
        if self.handles:raise AuthorityError('SERVICE_ALREADY_STARTED')
        with self._worker_lock:
            self._stuck=[row for row in self._stuck if row[0].is_alive()]
            if self._stuck:raise AuthorityError('IPC_WORKER_STUCK')
            self._quarantined.clear()
        api=load_win32();sd=wintypes.LPVOID();sddl=_windows_sddl(self.allowed_peer_sids)
        if not api.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(sd),None):raise AuthorityError('IPC_ACL_INVALID')
        created=[]
        try:
            for i in range(self.max_instances):
                open_mode=_PIPE_ACCESS_DUPLEX|(_FILE_FLAG_FIRST_PIPE_INSTANCE if i==0 else 0)
                pipe_mode=_PIPE_TYPE_MESSAGE|_PIPE_READMODE_MESSAGE|_PIPE_NOWAIT
                h=api.kernel32.CreateNamedPipeW(FIXED_PIPE_NAME,open_mode,pipe_mode,self.max_instances,MAX_REQUEST_BYTES,MAX_REQUEST_BYTES,self.preauth_timeout_ms,ctypes.byref(SA(ctypes.sizeof(SA),sd,False)))
                if is_invalid_handle(h):raise AuthorityError('IPC_CREATE_FAILED')
                mode=wintypes.DWORD(_PIPE_READMODE_MESSAGE|_PIPE_NOWAIT)
                if not api.kernel32.SetNamedPipeHandleState(h,ctypes.byref(mode),None,None):api.kernel32.CloseHandle(h);raise AuthorityError('IPC_MODE_FAILED')
                created.append(h)
            self.handles=created;self.handle=created[0];self._sd=sd;self._stop.clear();return self.handle
        except Exception:
            for h in created:api.kernel32.CloseHandle(h)
            api.kernel32.LocalFree(sd);raise
    def _deadline(self):return time.monotonic()+self.preauth_timeout_ms/1000.0
    def _check_wait(self,deadline):
        if self._stop.is_set():raise AuthorityError('IPC_STOPPED')
        if time.monotonic()>=deadline:raise AuthorityError('IPC_PREAUTH_TIMEOUT')
        time.sleep(self.poll_interval)
    def _connect(self,h,deadline):
        api=load_win32()
        while True:
            ctypes.set_last_error(0);ok=api.kernel32.ConnectNamedPipe(h,None);err=ctypes.get_last_error()
            if ok or err==_ERROR_PIPE_CONNECTED:return
            if err in (_ERROR_PIPE_LISTENING,_ERROR_NO_DATA):self._check_wait(deadline);continue
            raise AuthorityError('IPC_CONNECT_FAILED')
    def _read_request(self,h,deadline):
        api=load_win32();chunks=[];total=0
        while True:
            buf=ctypes.create_string_buffer(min(65536,MAX_REQUEST_BYTES+1-total));read=wintypes.DWORD(0);ctypes.set_last_error(0);ok=api.kernel32.ReadFile(h,buf,len(buf),ctypes.byref(read),None);err=ctypes.get_last_error()
            if read.value:chunks.append(buf.raw[:read.value]);total+=read.value
            if total>MAX_REQUEST_BYTES:raise AuthorityError('REQUEST_SIZE_INVALID')
            if ok:
                if not total:self._check_wait(deadline);continue
                return b''.join(chunks)
            if err==_ERROR_MORE_DATA:continue
            if err in (_ERROR_NO_DATA,_ERROR_PIPE_LISTENING):self._check_wait(deadline);continue
            if err==_ERROR_BROKEN_PIPE:raise AuthorityError('IPC_CLIENT_DISCONNECTED')
            raise AuthorityError('IPC_READ_FAILED')
    def _serve_handle(self,h):
        api=load_win32();deadline=self._deadline();connected=False
        try:
            self._connect(h,deadline);connected=True;raw=self._read_request(h,deadline);ctx=windows_pipe_peer_context(handle_value(h));out=self.service.handle_json(raw,peer_context=ctx);written=wintypes.DWORD(0)
            if not api.kernel32.WriteFile(h,out,len(out),ctypes.byref(written),None) or written.value!=len(out):raise AuthorityError('IPC_WRITE_FAILED')
            # Microsoft requires the server to flush before disconnecting so the
            # client can consume the complete message. Disconnecting immediately
            # after WriteFile can surface as IPC_READ_FAILED/ERROR_BROKEN_PIPE.
            if not api.kernel32.FlushFileBuffers(h):raise AuthorityError('IPC_FLUSH_FAILED')
            return out
        finally:
            if connected:
                try:api.kernel32.DisconnectNamedPipe(h)
                except Exception:pass
    def serve_once(self):
        if not self.handles:raise AuthorityError('SERVICE_NOT_STARTED')
        return self._serve_handle(self.handles[0])
    def serve_batch(self):
        if not self.handles:raise AuthorityError('SERVICE_NOT_STARTED')
        snapshot=tuple(self.handles);results=[None]*len(snapshot);threads=[]
        def run(i,h):
            try:results[i]=self._serve_handle(h)
            except AuthorityError as e:results[i]=e
            except Exception:results[i]=AuthorityError('IPC_INTERNAL_FAILED')
            finally:
                hv=handle_value(h)
                with self._worker_lock:quarantined=hv in self._quarantined
                if quarantined:
                    try:load_win32().kernel32.CloseHandle(h)
                    except Exception:pass
                    with self._worker_lock:self._quarantined.discard(hv)
        for i,h in enumerate(snapshot):
            t=threading.Thread(target=run,args=(i,h),daemon=True);threads.append((t,h));t.start()
        deadline=time.monotonic()+(self.preauth_timeout_ms+self.handler_timeout_ms)/1000.0
        for t,_h in threads:t.join(max(0.0,deadline-time.monotonic()))
        survivors=[(t,h) for t,h in threads if t.is_alive()]
        if survivors:
            survivor_values={handle_value(h) for _t,h in survivors}
            with self._worker_lock:
                self._quarantined.update(survivor_values);self._stuck.extend(survivors)
            self.handles=[h for h in self.handles if handle_value(h) not in survivor_values]
            self.handle=self.handles[0] if self.handles else None
            for i,(_t,h) in enumerate(threads):
                if handle_value(h) in survivor_values:results[i]=AuthorityError('IPC_HANDLER_QUARANTINED')
            # A post-authenticated worker that exceeds its bounded handler budget
            # is a fail-closed authority fault. Do not keep serving new requests
            # concurrently with work whose completion is no longer proven.
            raise AuthorityError('IPC_WORKER_STUCK')
        if results and all(isinstance(x,AuthorityError) and x.code=='IPC_PREAUTH_TIMEOUT' for x in results):
            self._stop.wait(min(0.1,max(self.poll_interval,0.01)))
        return results
    def close(self):
        if os.name!='nt':return
        self._stop.set();api=load_win32();handles=self.handles;self.handles=[];self.handle=None
        for h in handles:
            try:api.kernel32.DisconnectNamedPipe(h)
            except Exception:pass
            try:api.kernel32.CloseHandle(h)
            except Exception:pass
        with self._worker_lock:stuck=list(self._stuck)
        for _t,h in stuck:
            try:api.kernel32.DisconnectNamedPipe(h)
            except Exception:pass
            try:api.kernel32.CloseHandle(h)
            except Exception:pass
        for t,_h in stuck:t.join(2.0)
        survivors=[row for row in stuck if row[0].is_alive()]
        with self._worker_lock:self._stuck=survivors
        if self._sd:api.kernel32.LocalFree(self._sd);self._sd=None
        if survivors:raise AuthorityError('IPC_WORKER_STUCK')

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
                try:srv.serve_batch()
                except AuthorityError as e:
                    if state['stop'].is_set() or e.code=='IPC_STOPPED':break
        finally:
            try:
                if state['server'] is not None:state['server'].close()
            finally:set_status(STOPPED)
    class ENTRY(ctypes.Structure):_fields_=[('lpServiceName',wintypes.LPWSTR),('lpServiceProc',SERVICE_MAIN)]
    table=(ENTRY*2)();table[0]=ENTRY(service_name,service_main);table[1].lpServiceName=None
    if not api.advapi32.StartServiceCtrlDispatcherW(ctypes.cast(table,wintypes.LPVOID)):raise AuthorityError('SCM_DISPATCH_FAILED')