from __future__ import annotations

import ctypes, json, os, socket, stat, threading, time
from ctypes import wintypes
from pathlib import Path

from .boundary import windows_pipe_peer_context
from .ipc import serve_unix_once
from .protocol import AuthorityError, MAX_REQUEST_BYTES
from .root_chain import assert_machine_anchored_root
from .win32_ffi import handle_value, is_invalid_handle, load_win32

FIXED_PIPE_NAME = r'\\.\pipe\ForgeBossAuthority'
FIXED_SOCKET_NAME = 'authority.sock'
FIXED_SERVICE_NAME = 'ForgeBossAuthoritySvc'
_PIPE_ACCESS_DUPLEX = 0x00000003
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_PIPE_TYPE_MESSAGE = 0x4
_PIPE_READMODE_MESSAGE = 0x2
_PIPE_NOWAIT = 0x1
_ERROR_BROKEN_PIPE = 109
_ERROR_NO_DATA = 232
_ERROR_MORE_DATA = 234
_ERROR_PIPE_CONNECTED = 535
_ERROR_PIPE_LISTENING = 536


def _assert_linux_endpoint_dir(path: Path, *, service_uid: int, allowed_gid: int) -> Path:
    p = Path(path)
    if not p.is_absolute() or p.is_symlink():
        raise AuthorityError('IPC_ENDPOINT_DIR_INVALID')
    try:
        resolved = p.resolve(strict=True); st = resolved.stat()
    except Exception as exc:
        raise AuthorityError('IPC_ENDPOINT_DIR_INVALID') from exc
    mode = stat.S_IMODE(st.st_mode)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in {0, service_uid} or st.st_gid != allowed_gid or mode & 0o022:
        raise AuthorityError('IPC_ENDPOINT_DIR_PERMISSIONS')
    cur = resolved
    while True:
        lst = cur.lstat()
        if stat.S_ISLNK(lst.st_mode) or stat.S_IMODE(lst.st_mode) & 0o022:
            raise AuthorityError('IPC_ENDPOINT_DIR_PERMISSIONS')
        if cur.parent == cur:
            break
        cur = cur.parent
    return resolved


class LinuxAuthorityDaemon:
    def __init__(self, *, service, boundary, protected_root: Path, endpoint_dir: Path, allowed_gid: int, max_workers: int = 4, preauth_timeout: float = 1.0, accept_poll: float = 0.1):
        if os.name == 'nt':
            raise AuthorityError('IPC_PLATFORM_INVALID')
        if not isinstance(max_workers, int) or not 2 <= max_workers <= 16:
            raise AuthorityError('IPC_CONCURRENCY_INVALID')
        if not isinstance(preauth_timeout, (int, float)) or not 0.05 <= float(preauth_timeout) <= 30.0:
            raise AuthorityError('IPC_TIMEOUT_INVALID')
        if not isinstance(accept_poll, (int, float)) or not 0.01 <= float(accept_poll) <= 1.0:
            raise AuthorityError('IPC_TIMEOUT_INVALID')
        self.service = service
        self.boundary = boundary
        self.root = assert_machine_anchored_root(boundary, protected_root)
        self.service_uid = int(boundary.expected[4:])
        self.endpoint_dir = _assert_linux_endpoint_dir(endpoint_dir, service_uid=self.service_uid, allowed_gid=int(allowed_gid))
        self.allowed_gid = int(allowed_gid)
        self.path = self.endpoint_dir / FIXED_SOCKET_NAME
        self.listener = None
        self.max_workers = max_workers
        self.preauth_timeout = float(preauth_timeout)
        self.accept_poll = float(accept_poll)
        self._stop = threading.Event()
        self._active = set()
        self._active_lock = threading.Lock()
        self._workers = []
        self._close_lock = threading.Lock()
        self.shutdown_failure_path = self.root / 'shutdown-failure.json'

    def start(self):
        if self.listener is not None:
            raise AuthorityError('SERVICE_ALREADY_STARTED')
        if self.path.exists() or self.path.is_symlink():
            raise AuthorityError('IPC_ENDPOINT_EXISTS')
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.bind(str(self.path))
            os.chown(self.path, self.service_uid, self.allowed_gid)
            os.chmod(self.path, 0o660)
            st = self.path.stat()
            if st.st_uid != self.service_uid or st.st_gid != self.allowed_gid or stat.S_IMODE(st.st_mode) != 0o660 or not stat.S_ISSOCK(st.st_mode):
                raise AuthorityError('IPC_ENDPOINT_PERMISSIONS')
            s.listen(max(16, self.max_workers * 2)); s.settimeout(self.accept_poll)
            self.listener = s; self._stop.clear()
            return self.path
        except Exception:
            s.close()
            try:
                self.path.unlink()
            except OSError:
                pass
            raise

    def _track(self, conn, add):
        with self._active_lock:
            if add:
                self._active.add(conn)
            else:
                self._active.discard(conn)

    def serve_once(self):
        if self.listener is None:
            raise AuthorityError('SERVICE_NOT_STARTED')
        peer_principals = getattr(self.boundary, 'peer_principals', None)
        allowed = None if not peer_principals else set(peer_principals.values())
        return serve_unix_once(
            self.listener,
            self.service,
            accept_timeout=self.accept_poll,
            preauth_timeout=self.preauth_timeout,
            stop_event=self._stop,
            on_connection=self._track,
            allowed_peer_principals=allowed,
        )

    def _worker_loop(self):
        while not self._stop.is_set():
            try:
                self.serve_once()
            except AuthorityError as exc:
                if self._stop.is_set() or exc.code == 'IPC_STOPPED':
                    break
                if exc.code in {
                    'IPC_ACCEPT_TIMEOUT', 'IPC_PREAUTH_TIMEOUT', 'IPC_CLIENT_DISCONNECTED',
                    'REQUEST_SIZE_INVALID', 'IPC_READ_FAILED', 'PEER_CONTEXT_UNAVAILABLE',
                    'PEER_CONTEXT_DENIED', 'PEER_AUTH_DENIED', 'PEER_POLICY_DENIED',
                    'PEER_OBJECT_DENIED', 'REPOSITORY_DENIED',
                }:
                    continue
            except Exception:
                if self._stop.is_set():
                    break

    def run_forever(self):
        self.start(); self._workers = []
        try:
            for _ in range(self.max_workers):
                thread = threading.Thread(target=self._worker_loop, daemon=True)
                self._workers.append(thread); thread.start()
            while not self._stop.wait(self.accept_poll):
                if any(not thread.is_alive() for thread in self._workers) and not self._stop.is_set():
                    raise AuthorityError('IPC_WORKER_STUCK')
        finally:
            self.close()

    def stop(self):
        self.close()

    def _record_shutdown_failure(self, survivors) -> None:
        payload = {
            'schema': 1,
            'code': 'IPC_SHUTDOWN_INCOMPLETE',
            'aliveWorkerCount': len(survivors),
            'recordedAtUnixNs': time.time_ns(),
        }
        tmp = self.root / f'.shutdown-failure-{os.getpid()}-{threading.get_ident()}-{time.time_ns()}.tmp'
        data = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        fd = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW
            fd = os.open(tmp, flags, 0o600)
            with os.fdopen(fd, 'wb', closefd=True) as handle:
                fd = None
                handle.write(data); handle.flush(); os.fsync(handle.fileno())
            os.replace(tmp, self.shutdown_failure_path)
            os.chmod(self.shutdown_failure_path, 0o600)
            try:
                directory_fd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        except Exception as exc:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                tmp.unlink()
            except OSError:
                pass
            raise AuthorityError('IPC_SHUTDOWN_EVIDENCE_FAILED') from exc

    def close(self):
        with self._close_lock:
            self._stop.set()
            listener = self.listener; self.listener = None
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    pass
            with self._active_lock:
                active = list(self._active)
            for conn in active:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    conn.close()
                except OSError:
                    pass
            current = threading.current_thread()
            timeout = self.preauth_timeout + self.accept_poll + 0.5
            for thread in list(self._workers):
                if thread is not current:
                    thread.join(timeout)
            survivors = [thread for thread in self._workers if thread is not current and thread.is_alive()]
            if survivors:
                self._record_shutdown_failure(survivors)
                # Deliberately preserve _workers/_active and endpoint pathname.
                # A restart must fail closed until the old execution authority is
                # positively drained; we never advertise STOPPED after timeout.
                raise AuthorityError('IPC_SHUTDOWN_INCOMPLETE')
            self._workers = []
            with self._active_lock:
                self._active.clear()
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                if not self._stop.is_set():
                    raise


def _windows_sddl(allowed_peer_sids: set[str]) -> str:
    sids = []
    for sid in sorted({str(x).upper() for x in allowed_peer_sids}):
        if not sid.startswith('S-1-'):
            raise AuthorityError('IPC_PEER_SID_INVALID')
        sids.append(f'(A;;GRGW;;;{sid})')
    if not sids:
        raise AuthorityError('IPC_PEER_SID_INVALID')
    return 'D:P(A;;GA;;;SY)(A;;GA;;;BA)' + ''.join(sids)


class QSC(ctypes.Structure):
    _fields_ = [
        ('dwServiceType', wintypes.DWORD), ('dwStartType', wintypes.DWORD),
        ('dwErrorControl', wintypes.DWORD), ('lpBinaryPathName', wintypes.LPWSTR),
        ('lpLoadOrderGroup', wintypes.LPWSTR), ('dwTagId', wintypes.DWORD),
        ('lpDependencies', wintypes.LPWSTR), ('lpServiceStartName', wintypes.LPWSTR),
        ('lpDisplayName', wintypes.LPWSTR),
    ]


def assert_windows_scm_registration(*, service_name: str = FIXED_SERVICE_NAME, expected_image_command: str) -> None:
    if os.name != 'nt':
        raise AuthorityError('IPC_PLATFORM_INVALID')
    api = load_win32(); scm = api.advapi32.OpenSCManagerW(None, None, 0x0001); svc = None
    if is_invalid_handle(scm):
        raise AuthorityError('SCM_UNAVAILABLE')
    try:
        svc = api.advapi32.OpenServiceW(scm, service_name, 0x0001)
        if is_invalid_handle(svc):
            raise AuthorityError('SCM_SERVICE_MISSING')
        needed = wintypes.DWORD(0); api.advapi32.QueryServiceConfigW(svc, None, 0, ctypes.byref(needed))
        if not needed.value:
            raise AuthorityError('SCM_CONFIG_INVALID')
        buf = ctypes.create_string_buffer(needed.value)
        if not api.advapi32.QueryServiceConfigW(svc, ctypes.cast(buf, wintypes.LPVOID), needed, ctypes.byref(needed)):
            raise AuthorityError('SCM_CONFIG_INVALID')
        cfg = ctypes.cast(buf, ctypes.POINTER(QSC)).contents
        actual = ' '.join(str(cfg.lpBinaryPathName or '').split()); expected = ' '.join(str(expected_image_command).split())
        if actual != expected:
            raise AuthorityError('SCM_IMAGE_MISMATCH')
    finally:
        if svc and not is_invalid_handle(svc):
            api.advapi32.CloseServiceHandle(svc)
        if scm and not is_invalid_handle(scm):
            api.advapi32.CloseServiceHandle(scm)


class SA(ctypes.Structure):
    _fields_ = [('nLength', wintypes.DWORD), ('lpSecurityDescriptor', wintypes.LPVOID), ('bInheritHandle', wintypes.BOOL)]


class WindowsNamedPipeServer:
    def __init__(self, *, service, boundary, protected_root: Path, allowed_peer_sids: set[str], max_instances: int = 4, preauth_timeout_ms: int = 1000, poll_interval: float = 0.01):
        if os.name != 'nt':
            raise AuthorityError('IPC_PLATFORM_INVALID')
        if not isinstance(max_instances, int) or not 2 <= max_instances <= 16:
            raise AuthorityError('IPC_CONCURRENCY_INVALID')
        if not isinstance(preauth_timeout_ms, int) or not 100 <= preauth_timeout_ms <= 30000:
            raise AuthorityError('IPC_TIMEOUT_INVALID')
        if not isinstance(poll_interval, (int, float)) or not 0.001 <= float(poll_interval) <= 0.1:
            raise AuthorityError('IPC_TIMEOUT_INVALID')
        self.service = service; self.boundary = boundary
        self.root = assert_machine_anchored_root(boundary, protected_root)
        self.allowed_peer_sids = set(allowed_peer_sids); self.max_instances = max_instances
        self.preauth_timeout_ms = preauth_timeout_ms; self.poll_interval = float(poll_interval)
        self.handles = []; self.handle = None; self._sd = None; self._stop = threading.Event()

    def start(self):
        if self.handles:
            raise AuthorityError('SERVICE_ALREADY_STARTED')
        api = load_win32(); sd = wintypes.LPVOID(); sddl = _windows_sddl(self.allowed_peer_sids)
        if not api.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
            raise AuthorityError('IPC_ACL_INVALID')
        created = []
        try:
            for i in range(self.max_instances):
                open_mode = _PIPE_ACCESS_DUPLEX | (_FILE_FLAG_FIRST_PIPE_INSTANCE if i == 0 else 0)
                pipe_mode = _PIPE_TYPE_MESSAGE | _PIPE_READMODE_MESSAGE | _PIPE_NOWAIT
                h = api.kernel32.CreateNamedPipeW(FIXED_PIPE_NAME, open_mode, pipe_mode, self.max_instances, MAX_REQUEST_BYTES, MAX_REQUEST_BYTES, self.preauth_timeout_ms, ctypes.byref(SA(ctypes.sizeof(SA), sd, False)))
                if is_invalid_handle(h):
                    raise AuthorityError('IPC_CREATE_FAILED')
                mode = wintypes.DWORD(_PIPE_READMODE_MESSAGE | _PIPE_NOWAIT)
                if not api.kernel32.SetNamedPipeHandleState(h, ctypes.byref(mode), None, None):
                    api.kernel32.CloseHandle(h); raise AuthorityError('IPC_MODE_FAILED')
                created.append(h)
            self.handles = created; self.handle = created[0]; self._sd = sd; self._stop.clear()
            return self.handle
        except Exception:
            for h in created:
                api.kernel32.CloseHandle(h)
            api.kernel32.LocalFree(sd)
            raise

    def _deadline(self):
        return time.monotonic() + self.preauth_timeout_ms / 1000.0

    def _check_wait(self, deadline):
        if self._stop.is_set():
            raise AuthorityError('IPC_STOPPED')
        if time.monotonic() >= deadline:
            raise AuthorityError('IPC_PREAUTH_TIMEOUT')
        time.sleep(self.poll_interval)

    def _connect(self, h, deadline):
        api = load_win32()
        while True:
            ctypes.set_last_error(0); ok = api.kernel32.ConnectNamedPipe(h, None); err = ctypes.get_last_error()
            if ok or err == _ERROR_PIPE_CONNECTED:
                return
            if err in (_ERROR_PIPE_LISTENING, _ERROR_NO_DATA):
                self._check_wait(deadline); continue
            raise AuthorityError('IPC_CONNECT_FAILED')

    def _read_request(self, h, deadline):
        api = load_win32(); chunks = []; total = 0
        while True:
            buf = ctypes.create_string_buffer(min(65536, MAX_REQUEST_BYTES + 1 - total)); read = wintypes.DWORD(0)
            ctypes.set_last_error(0); ok = api.kernel32.ReadFile(h, buf, len(buf), ctypes.byref(read), None); err = ctypes.get_last_error()
            if read.value:
                chunks.append(buf.raw[:read.value]); total += read.value
            if total > MAX_REQUEST_BYTES:
                raise AuthorityError('REQUEST_SIZE_INVALID')
            if ok:
                if not total:
                    self._check_wait(deadline); continue
                return b''.join(chunks)
            if err == _ERROR_MORE_DATA:
                continue
            if err in (_ERROR_NO_DATA, _ERROR_PIPE_LISTENING):
                self._check_wait(deadline); continue
            if err == _ERROR_BROKEN_PIPE:
                raise AuthorityError('IPC_CLIENT_DISCONNECTED')
            raise AuthorityError('IPC_READ_FAILED')

    def _serve_handle(self, h):
        api = load_win32(); deadline = self._deadline(); connected = False
        try:
            self._connect(h, deadline); connected = True
            raw = self._read_request(h, deadline); ctx = windows_pipe_peer_context(handle_value(h))
            out = self.service.handle_json(raw, peer_context=ctx); written = wintypes.DWORD(0)
            if not api.kernel32.WriteFile(h, out, len(out), ctypes.byref(written), None) or written.value != len(out):
                raise AuthorityError('IPC_WRITE_FAILED')
            return out
        finally:
            if connected:
                try:
                    api.kernel32.DisconnectNamedPipe(h)
                except Exception:
                    pass

    def serve_once(self):
        if not self.handles:
            raise AuthorityError('SERVICE_NOT_STARTED')
        return self._serve_handle(self.handles[0])

    def serve_batch(self):
        if not self.handles:
            raise AuthorityError('SERVICE_NOT_STARTED')
        results = [None] * len(self.handles); threads = []
        def run(i, h):
            try:
                results[i] = self._serve_handle(h)
            except AuthorityError as exc:
                results[i] = exc
            except Exception:
                results[i] = AuthorityError('IPC_INTERNAL_FAILED')
        for i, h in enumerate(tuple(self.handles)):
            thread = threading.Thread(target=run, args=(i, h), daemon=True); threads.append(thread); thread.start()
        deadline = time.monotonic() + self.preauth_timeout_ms / 1000.0 + 1.0
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            raise AuthorityError('IPC_WORKER_STUCK')
        return results

    def close(self):
        if os.name != 'nt':
            return
        self._stop.set(); api = load_win32(); handles = self.handles; self.handles = []; self.handle = None
        for h in handles:
            try:
                api.kernel32.DisconnectNamedPipe(h)
            except Exception:
                pass
            try:
                api.kernel32.CloseHandle(h)
            except Exception:
                pass
        if self._sd:
            api.kernel32.LocalFree(self._sd); self._sd = None


def run_windows_scm_service(*, service_name: str = FIXED_SERVICE_NAME, server_factory):
    if os.name != 'nt':
        raise AuthorityError('IPC_PLATFORM_INVALID')
    api = load_win32(); OWN = 0x10; START_PENDING = 2; STOP_PENDING = 3; RUNNING = 4; STOPPED = 1
    ACCEPT_STOP = 1; ACCEPT_SHUTDOWN = 4; CTRL_STOP = 1; CTRL_SHUTDOWN = 5

    class STATUS(ctypes.Structure):
        _fields_ = [('dwServiceType', wintypes.DWORD), ('dwCurrentState', wintypes.DWORD), ('dwControlsAccepted', wintypes.DWORD), ('dwWin32ExitCode', wintypes.DWORD), ('dwServiceSpecificExitCode', wintypes.DWORD), ('dwCheckPoint', wintypes.DWORD), ('dwWaitHint', wintypes.DWORD)]

    SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
    HANDLER = ctypes.WINFUNCTYPE(None, wintypes.DWORD)
    state = {'server': None, 'handle': None, 'stop': threading.Event()}

    def set_status(code, accepted=0):
        status = STATUS(OWN, code, accepted, 0, 0, 0, 0)
        if state['handle'] and not api.advapi32.SetServiceStatus(state['handle'], ctypes.byref(status)):
            raise AuthorityError('SCM_STATUS_FAILED')

    @HANDLER
    def handler(control):
        if control in (CTRL_STOP, CTRL_SHUTDOWN):
            state['stop'].set()
            try:
                set_status(STOP_PENDING)
            except Exception:
                pass
            try:
                if state['server'] is not None:
                    state['server'].close()
            except Exception:
                pass

    @SERVICE_MAIN
    def service_main(_argc, _argv):
        state['handle'] = api.advapi32.RegisterServiceCtrlHandlerW(service_name, ctypes.cast(handler, wintypes.LPVOID))
        if not state['handle']:
            return
        try:
            set_status(START_PENDING); server = server_factory(); state['server'] = server; server.start(); set_status(RUNNING, ACCEPT_STOP | ACCEPT_SHUTDOWN)
            while not state['stop'].is_set():
                try:
                    server.serve_batch()
                except AuthorityError as exc:
                    if state['stop'].is_set() or exc.code == 'IPC_STOPPED':
                        break
        finally:
            try:
                if state['server'] is not None:
                    state['server'].close()
            finally:
                set_status(STOPPED)

    class ENTRY(ctypes.Structure):
        _fields_ = [('lpServiceName', wintypes.LPWSTR), ('lpServiceProc', SERVICE_MAIN)]

    table = (ENTRY * 2)(); table[0] = ENTRY(service_name, service_main); table[1].lpServiceName = None
    if not api.advapi32.StartServiceCtrlDispatcherW(ctypes.cast(table, wintypes.LPVOID)):
        raise AuthorityError('SCM_DISPATCH_FAILED')
