from __future__ import annotations

import hashlib
import json
import os
import secrets
import select
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from .known_good import IdentityError, verify_build_manifest
from .activation_probe import ActivationProbeError,probe_control_endpoint,read_activation_ready,run_activation_core_tests

CNW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _canonical_digest(value)->str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")).hexdigest()

_ENTRY_COMPONENT = __import__("re").compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ACTIVATION_BOOTSTRAP = (
    "import importlib,pathlib,sys;"
    "root=pathlib.Path(sys.argv[1]).resolve(strict=True);"
    "entry=pathlib.Path(sys.argv[2]).resolve(strict=True);"
    "name=sys.argv[3];extra=sys.argv[4:];"
    "sys.path.insert(0,str(root));"
    "module=importlib.import_module(name);"
    "origin=pathlib.Path(module.__file__).resolve(strict=True);"
    "assert origin==entry,'entrypoint origin mismatch';"
    "pkg=sys.modules.get('forgeboss');"
    "paths=list(getattr(pkg,'__path__',()));"
    "expected=(root/'forgeboss').resolve(strict=True);"
    "assert paths and all(pathlib.Path(p).resolve(strict=True)==expected for p in paths),'package origin mismatch';"
    "sys.argv=[str(entry),*extra];"
    "module.main()"
)


def _entrypoint_module(entrypoint: str) -> str:
    rel=PurePosixPath(str(entrypoint).replace("\\","/"))
    if rel.is_absolute() or ".." in rel.parts or len(rel.parts)<2 or rel.parts[0]!="forgeboss":
        raise ActivationError("candidate entrypoint module path is invalid")
    if rel.suffix!=".py" or rel.name=="__init__.py":
        raise ActivationError("candidate entrypoint must be an importable Python module")
    parts=list(rel.with_suffix("").parts)
    if any(not _ENTRY_COMPONENT.fullmatch(part) for part in parts):
        raise ActivationError("candidate entrypoint module path is invalid")
    return ".".join(parts)


def _candidate_launch_command(root: Path, entry: Path, entrypoint: str, extra_args=None) -> list[str]:
    root=Path(root).resolve(strict=True);entry=Path(entry).resolve(strict=True)
    module=_entrypoint_module(entrypoint)
    expected=(root/Path(*PurePosixPath(entrypoint).parts)).resolve(strict=True)
    if expected!=entry:
        raise ActivationError("candidate entrypoint origin is not exact")
    return [sys.executable,"-I","-S","-c",_ACTIVATION_BOOTSTRAP,str(root),str(entry),module,*list(extra_args or [])]


class ActivationError(RuntimeError):
    pass


def _sync_dir(path: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_json(path: Path, value) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(value, fh, sort_keys=True, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        _sync_dir(path.parent)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass


def _read_json(path: Path, label: str):
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as ex:
        raise ActivationError(f"{label} is unreadable") from ex
    if not isinstance(value, dict):
        raise ActivationError(f"{label} is invalid")
    return value


@contextmanager
def _state_lock(path: Path, timeout: float = 10.0):
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = path.open("a+b")
    deadline = time.monotonic() + float(timeout)
    locked = False
    try:
        while not locked:
            try:
                if os.name == "nt":
                    import msvcrt
                    fh.seek(0)
                    if not fh.read(1):
                        fh.seek(0)
                        fh.write(b"0")
                        fh.flush()
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except OSError:
                if time.monotonic() >= deadline:
                    raise ActivationError("activation state lock timed out")
                time.sleep(0.025)
        yield
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        fh.close()


def _posix_identity(pid: int):
    proc = Path("/proc") / str(int(pid))
    if not proc.exists():
        return None
    try:
        stat = (proc / "stat").read_text(encoding="utf-8")
        tail = stat[stat.rfind(")") + 2 :].split()
        start_token = tail[19]
        exe = os.path.realpath(os.readlink(proc / "exe"))
        return {"pid": int(pid), "startToken": str(start_token), "exe": exe}
    except FileNotFoundError:
        return None
    except Exception as ex:
        raise ActivationError("cannot establish candidate process identity") from ex


def _win_api():
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateProcess.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    return ctypes, wintypes, kernel


def _win_identity_from_handle(handle, pid: int):
    ctypes, wintypes, kernel = _win_api()
    creation = wintypes.FILETIME()
    exit_ft = wintypes.FILETIME()
    kernel_ft = wintypes.FILETIME()
    user_ft = wintypes.FILETIME()
    if not kernel.GetProcessTimes(
        handle,
        ctypes.byref(creation),
        ctypes.byref(exit_ft),
        ctypes.byref(kernel_ft),
        ctypes.byref(user_ft),
    ):
        raise ActivationError("cannot read candidate process creation time")
    size = wintypes.DWORD(32768)
    buf = ctypes.create_unicode_buffer(size.value)
    if not kernel.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
        raise ActivationError("cannot read candidate process image")
    token = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
    return {
        "pid": int(pid),
        "startToken": str(token),
        "exe": os.path.normcase(os.path.realpath(buf.value)),
    }


def _win_identity(pid: int):
    ctypes, _wintypes, kernel = _win_api()
    handle = kernel.OpenProcess(0x1000, False, int(pid))
    if not handle:
        if ctypes.get_last_error() in {87, 1168}:
            return None
        raise ActivationError("cannot query candidate process identity")
    try:
        return _win_identity_from_handle(handle, pid)
    finally:
        kernel.CloseHandle(handle)


def process_identity(pid: int):
    if int(pid) <= 0:
        return None
    return _win_identity(pid) if os.name == "nt" else _posix_identity(pid)


def _same_process(expected, current) -> bool:
    return (
        bool(current)
        and int(current.get("pid", -1)) == int(expected.get("pid", -2))
        and str(current.get("startToken")) == str(expected.get("startToken"))
        and os.path.normcase(str(current.get("exe") or ""))
        == os.path.normcase(str(expected.get("exe") or ""))
    )


def _wait_pidfd(pidfd: int, timeout: float) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(max(1, int(float(timeout) * 1000))))


def _terminate_posix_pidfd(expected, timeout: float) -> bool:
    if not callable(getattr(os, "pidfd_open", None)) or not callable(getattr(signal, "pidfd_send_signal", None)):
        raise ActivationError("stable POSIX process handle unavailable")
    pid = int(expected["pid"])
    try:
        pidfd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return True
    except OSError as ex:
        raise ActivationError("cannot acquire stable candidate pidfd") from ex
    try:
        current = _posix_identity(pid)
        if not _same_process(expected, current):
            return True
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
        except ProcessLookupError:
            return True
        except OSError as ex:
            raise ActivationError("candidate TERM via pidfd failed") from ex
        first = min(2.0, float(timeout))
        if _wait_pidfd(pidfd, first):
            return True
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
        except ProcessLookupError:
            return True
        except OSError as ex:
            raise ActivationError("candidate KILL via pidfd failed") from ex
        return _wait_pidfd(pidfd, max(0.5, float(timeout) - first))
    finally:
        os.close(pidfd)


def _terminate_windows_handle(expected, timeout: float) -> bool:
    ctypes, _wintypes, kernel = _win_api()
    handle = kernel.OpenProcess(0x1000 | 0x0001 | 0x00100000, False, int(expected["pid"]))
    if not handle:
        err = ctypes.get_last_error()
        if err in {87, 1168}:
            return True
        raise ActivationError(f"cannot acquire stable candidate process handle: winerror={err}")
    try:
        current = _win_identity_from_handle(handle, int(expected["pid"]))
        if not _same_process(expected, current):
            return True
        if not kernel.TerminateProcess(handle, 75):
            raise ActivationError(f"candidate termination failed: winerror={ctypes.get_last_error()}")
        wait = kernel.WaitForSingleObject(handle, max(1, int(float(timeout) * 1000)))
        if wait == 0x00000102:
            return False
        if wait == 0xFFFFFFFF:
            raise ActivationError(f"candidate termination wait failed: winerror={ctypes.get_last_error()}")
        return True
    finally:
        kernel.CloseHandle(handle)


def terminate_verified_process(expected, timeout: float = 5.0) -> bool:
    if (
        not isinstance(expected, dict)
        or not expected.get("pid")
        or not expected.get("startToken")
        or not expected.get("exe")
    ):
        raise ActivationError("candidate process identity is missing or incomplete")
    if os.name == "nt":
        return _terminate_windows_handle(expected, timeout)
    if sys.platform.startswith("linux"):
        return _terminate_posix_pidfd(expected, timeout)
    raise ActivationError("stable POSIX process termination authority is unavailable")


class ActivationManager:
    def __init__(self, state_dir, running_identity):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.state_dir / "activation.json"
        self.pointer_path = self.state_dir / "known-good.json"
        self.lock_path = self.state_dir / "activation.lock"
        self.running_identity = dict(running_identity or {})
        self._probe_authority = object()
        self._health_authority = object()

    def status(self):
        value = _read_json(self.state_path, "activation state")
        if value is None:
            return {"schema": 2, "phase": "IDLE", "generation": 0, "running": self.running_identity}
        if value.get("schema") != 2 or not isinstance(value.get("generation"), int):
            raise ActivationError("activation state schema/generation is invalid")
        return value

    def known_good_pointer(self):
        value = _read_json(self.pointer_path, "known-good pointer")
        if value is None:
            return None
        if value.get("schema") != 2 or not isinstance(value.get("generation"), int):
            raise ActivationError("known-good pointer schema/generation is invalid")
        return value

    def initialize_known_good(self):
        if self.running_identity.get("verified") is not True:
            raise ActivationError("known-good initialization requires verified running identity")
        with _state_lock(self.lock_path):
            pointer = self.known_good_pointer()
            if pointer:
                if (pointer.get("current") or {}).get("revision") != self.running_identity.get("revision"):
                    raise ActivationError("existing known-good pointer disagrees with running identity")
                return pointer
            pointer = {"schema": 2, "generation": 0, "current": self.running_identity, "previous": None, "updatedAt": time.time()}
            _atomic_json(self.pointer_path, pointer)
            return pointer

    @staticmethod
    def _check_generation(state, expected):
        if expected is not None and int(expected) != int(state.get("generation", -1)):
            raise ActivationError("stale activation generation")

    def stage(self, candidate_root, manifest_path, expected_revision=None, expected_manifest_sha256=None, *, expected_generation=None):
        if self.running_identity.get("verified") is not True:
            raise ActivationError("activation requires a verified running known-good controller identity")
        root = Path(candidate_root).resolve(strict=True)
        running = Path(self.running_identity.get("codeRoot") or "").resolve(strict=True)
        if root == running:
            raise ActivationError("candidate must be a distinct checkout; in-place activation denied")
        try:
            candidate = verify_build_manifest(manifest_path, root, expected_revision, expected_manifest_sha256)
        except IdentityError as ex:
            raise ActivationError(str(ex)) from ex
        with _state_lock(self.lock_path):
            state = self.status()
            self._check_generation(state, expected_generation)
            if state.get("phase") in {"STAGED", "STARTING", "PROBING", "PROBED", "PROMOTING", "PROMOTED", "ROLLBACK_PENDING"}:
                old = state.get("candidate") or {}
                if state.get("phase") == "STAGED" and old.get("revision") == candidate.get("revision") and old.get("manifestSha256") == candidate.get("manifestSha256"):
                    return state
                raise ActivationError("another activation generation is already active")
            pointer = self.known_good_pointer()
            prior = (pointer or {}).get("current") or self.running_identity
            if prior.get("revision") != self.running_identity.get("revision"):
                raise ActivationError("running identity is not current known-good authority")
            state = {"schema": 2, "phase": "STAGED", "generation": int(state.get("generation", 0)) + 1, "requestId": secrets.token_hex(16), "prior": prior, "candidate": candidate, "probe": None, "probeEvidence": None, "activationHealth": None, "pid": None, "processIdentity": None, "activationNonce": None, "readyPath": None, "candidateStateRoot": None, "reason": None, "updatedAt": time.time()}
            _atomic_json(self.state_path, state)
            return state

    def start_candidate(self, extra_args=None, extra_env=None, *, expected_generation=None):
        with _state_lock(self.lock_path):
            state = self.status()
            self._check_generation(state, expected_generation)
            if state.get("phase") != "STAGED":
                raise ActivationError("candidate must be STAGED before start")
            candidate = state["candidate"]
            root = Path(candidate["codeRoot"]).resolve(strict=True)
            entry = (root / candidate["entrypoint"]).resolve(strict=True)
            if entry.suffix.lower() != ".py":
                raise ActivationError("candidate entrypoint must be a Python file")
            try:
                if os.path.commonpath([str(root), str(entry)]) != str(root):
                    raise ActivationError("candidate entrypoint escapes candidate root")
            except ValueError as ex:
                raise ActivationError("candidate entrypoint escapes candidate root") from ex
            nonce = secrets.token_hex(32)
            ready_path=(self.state_dir/f"activation-ready-{state['generation']}.json").resolve()
            candidate_state_root=(self.state_dir/f"candidate-runtime-{state['generation']}").resolve()
            if ready_path.exists() or ready_path.is_symlink():
                raise ActivationError("activation ready file already exists")
            if candidate_state_root.exists() or candidate_state_root.is_symlink():
                raise ActivationError("activation candidate state root already exists")
            extras=list(extra_args or [])
            denied={"--host","--port","--activation-ready-file"}
            if any(str(x) in denied for x in extras):
                raise ActivationError("activation launch network/readiness arguments are controller-owned")
            state.update({"phase": "STARTING", "activationNonce": nonce, "readyPath": str(ready_path), "candidateStateRoot": str(candidate_state_root), "updatedAt": time.time()})
            _atomic_json(self.state_path, state)
            env = os.environ.copy()
            env.update(extra_env or {})
            for key in list(env):
                upper=key.upper()
                if upper in {"PYTHONPATH","PYTHONHOME","PYTHONSTARTUP","PYTHONINSPECT","GH_TOKEN","GITHUB_TOKEN","GITHUB_PAT","OPENAI_API_KEY","LLM_API_KEY","ANTHROPIC_API_KEY","GOOGLE_API_KEY","GEMINI_API_KEY"} or upper.startswith("FORGEBOSS_AUTHORITY_") or upper.startswith("GITHUB_") or upper.startswith("GH_") or upper.startswith("GIT_"):
                    env.pop(key,None)
            env.update({"FORGEBOSS_SELF_BUILD_MODE": "YES", "FORGEBOSS_ALLOW_PAID_EXECUTOR":"NO", "PYTHONDONTWRITEBYTECODE":"1", "PYTHONUTF8":"1", "FORGEBOSS_DAEMON_STATE_ROOT":str(candidate_state_root), "FORGEBOSS_WORKTREE_ROOT":str(candidate_state_root/"worktrees"), "FORGEBOSS_BUILD_MANIFEST": candidate["manifestPath"], "FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA": candidate["revision"], "FORGEBOSS_EXPECTED_MANIFEST_SHA256": candidate["manifestSha256"], "FORGEBOSS_ACTIVATION_NONCE": nonce, "FORGEBOSS_ACTIVATION_GENERATION": str(state["generation"])})
            argv=_candidate_launch_command(root,entry,candidate["entrypoint"],["--host","127.0.0.1","--port","0","--activation-ready-file",str(ready_path),*extras])
            try:
                proc = subprocess.Popen(argv, cwd=str(root), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CNW)
            except Exception as ex:
                state.update({"phase": "QUARANTINED", "reason": "candidate start failed", "updatedAt": time.time()})
                _atomic_json(self.state_path, state)
                raise ActivationError("candidate process failed to start") from ex
            identity = process_identity(proc.pid)
            if not identity:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    pass
                state.update({"phase": "QUARANTINED", "reason": "candidate process identity unavailable", "updatedAt": time.time()})
                _atomic_json(self.state_path, state)
                raise ActivationError("candidate process identity unavailable")
            state.update({"pid": int(proc.pid), "processIdentity": identity, "updatedAt": time.time()})
            _atomic_json(self.state_path, state)
            return proc

    def begin_probe(self, *, expected_generation=None):
        with _state_lock(self.lock_path):
            state = self.status()
            self._check_generation(state, expected_generation)
            if state.get("phase") not in {"STAGED", "STARTING"}:
                raise ActivationError("candidate is not ready for probe")
            state["phase"] = "PROBING"
            state["updatedAt"] = time.time()
            _atomic_json(self.state_path, state)
            return state

    def authoritative_probe(self, *, expected_generation=None, timeout:float=15.0):
        state=self.begin_probe(expected_generation=expected_generation)
        generation=state["generation"]
        candidate=state.get("candidate") or {}
        root=Path(candidate.get("codeRoot") or "").resolve(strict=True)
        ready_path=Path(state.get("readyPath") or "")
        try:
            ready,ready_sha=read_activation_ready(ready_path,timeout=timeout)
            if ready.get("generation")!=generation or ready.get("nonce")!=state.get("activationNonce"):
                raise ActivationError("activation ready authority binding mismatch")
            if ready.get("stateRoot")!=state.get("candidateStateRoot"):
                raise ActivationError("activation ready state-root binding mismatch")
            process=state.get("processIdentity") or {}
            if int(ready.get("pid") or 0)!=int(process.get("pid") or -1):
                raise ActivationError("activation ready pid binding mismatch")
            if not _same_process(process,process_identity(int(process["pid"]))):
                raise ActivationError("candidate process identity changed before probe")
            ready_identity=ready.get("identity") or {}
            for key in ("revision","manifestSha256","treeSha256","identitySha256"):
                if ready_identity.get(key)!=candidate.get(key):
                    raise ActivationError("activation ready identity mismatch: "+key)
            control=probe_control_endpoint(root,ready["host"],ready["port"],candidate,state_root=ready["stateRoot"],timeout=min(float(timeout),5.0))
            tests=run_activation_core_tests(root)
            if tests.get("selftests") is not True or tests.get("multiAgent") is not True:
                raise ActivationError("candidate activation core tests failed")
            verify_build_manifest(candidate["manifestPath"],root,candidate["revision"],candidate["manifestSha256"])
            if not _same_process(process,process_identity(int(process["pid"]))):
                raise ActivationError("candidate process identity changed during probe")
            evidence={
                "schema":1,"generation":generation,"readySha256":ready_sha,
                "endpoint":{"host":ready["host"],"port":ready["port"]},
                "control":control,"tests":tests,"identity":ready_identity,
                "processIdentity":process,
            }
            result={
                "startup":True,"health":control.get("healthy") is True,
                "control":control.get("control") is True,
                "selftests":tests.get("selftests") is True,
                "multiAgent":tests.get("multiAgent") is True and control.get("multiAgentCapability") is True,
                "identity":ready_identity,"evidence":evidence,
                "evidenceSha256":_canonical_digest(evidence),
            }
            return self.record_probe(result,expected_generation=generation,_authority=self._probe_authority)
        except Exception as ex:
            try:self.rollback("candidate authoritative probe failed",expected_generation=generation)
            except Exception as rollback_ex:
                raise ActivationError("candidate authoritative probe failed and rollback could not be proven") from rollback_ex
            if isinstance(ex,ActivationError):raise
            if isinstance(ex,ActivationProbeError):raise ActivationError(str(ex)) from ex
            raise ActivationError("candidate authoritative probe failed") from ex

    def record_probe(self, result, *, expected_generation=None, _authority=None):
        if _authority is not self._probe_authority:
            raise ActivationError("caller-supplied activation probe denied")
        with _state_lock(self.lock_path):
            state = self.status()
            self._check_generation(state, expected_generation)
            if state.get("phase") not in {"STARTING", "PROBING"}:
                raise ActivationError("candidate is not in probe phase")
            if not isinstance(result, dict):
                raise ActivationError("probe result must be an object")
            candidate = state.get("candidate") or {}
            required = ("startup", "health", "control", "selftests", "multiAgent")
            identity = result.get("identity") or {}
            evidence=result.get("evidence")
            evidence_digest=str(result.get("evidenceSha256") or "").lower()
            if not isinstance(evidence,dict) or evidence_digest!=_canonical_digest(evidence):
                raise ActivationError("authoritative probe evidence digest mismatch")
            healthy = all(result.get(key) is True for key in required)
            bound = identity.get("revision") == candidate.get("revision") and identity.get("manifestSha256") == candidate.get("manifestSha256") and identity.get("treeSha256") == candidate.get("treeSha256") and identity.get("identitySha256") == candidate.get("identitySha256")
            if state.get("processIdentity"):
                healthy = healthy and _same_process(state["processIdentity"], process_identity(int(state["processIdentity"]["pid"])))
            if healthy and bound:
                state["phase"] = "PROBED"
                state["probe"] = {key: True for key in required}
                state["probe"]["identity"] = identity
                state["probe"]["evidenceSha256"]=evidence_digest
                state["probeEvidence"]=evidence
                state["updatedAt"] = time.time()
                _atomic_json(self.state_path, state)
                return state
            failure = "candidate probe failed" if not healthy else "candidate probe identity mismatch"
        self.rollback(failure, expected_generation=expected_generation)
        raise ActivationError(failure)

    def promote(self, *, expected_generation=None):
        with _state_lock(self.lock_path):
            state = self.status()
            self._check_generation(state, expected_generation)
            if state.get("phase") == "PROMOTED":
                pointer = self.known_good_pointer()
                if pointer and pointer.get("generation") == state.get("generation") and (pointer.get("current") or {}).get("revision") == (state.get("candidate") or {}).get("revision"):
                    return pointer
                raise ActivationError("promoted state disagrees with known-good pointer")
            if state.get("phase") != "PROBED":
                raise ActivationError("candidate must pass probes before promotion")
            pointer = self.known_good_pointer()
            current = (pointer or {}).get("current") or state["prior"]
            if current.get("revision") != state["prior"].get("revision"):
                raise ActivationError("known-good authority changed before promotion")
            if state.get("processIdentity") and not _same_process(state["processIdentity"], process_identity(int(state["processIdentity"]["pid"]))):
                raise ActivationError("candidate process identity is no longer live")
            state["phase"] = "PROMOTING"
            state["updatedAt"] = time.time()
            _atomic_json(self.state_path, state)
            pointer = {"schema": 2, "generation": state["generation"], "current": state["candidate"], "previous": state["prior"], "updatedAt": time.time()}
            _atomic_json(self.pointer_path, pointer)
            state["phase"] = "PROMOTED"
            state["updatedAt"] = time.time()
            _atomic_json(self.state_path, state)
            return pointer

    def rollback(self, reason="activation rollback", *, expected_generation=None):
        with _state_lock(self.lock_path):
            state = self.status()
            self._check_generation(state, expected_generation)
            prior = state.get("prior") or self.running_identity
            pointer = self.known_good_pointer()
            if state.get("phase") == "ROLLED_BACK":
                if pointer and (pointer.get("current") or {}).get("revision") == prior.get("revision"):
                    return pointer
                raise ActivationError("rolled-back state disagrees with known-good pointer")
            if pointer:
                current = (pointer.get("current") or {}).get("revision")
                candidate = (state.get("candidate") or {}).get("revision")
                if current not in {candidate, prior.get("revision")}:
                    raise ActivationError("newer known-good authority prevents stale rollback")
            identity = state.get("processIdentity")
            if identity:
                state["phase"] = "ROLLBACK_PENDING"
                state["reason"] = str(reason)
                state["updatedAt"] = time.time()
                _atomic_json(self.state_path, state)
                try:
                    dead = terminate_verified_process(identity, 5.0)
                except Exception as ex:
                    state["phase"] = "QUARANTINED"
                    state["reason"] = "candidate termination authority failed closed"
                    state["updatedAt"] = time.time()
                    _atomic_json(self.state_path, state)
                    raise ActivationError("rollback quarantined: candidate termination authority unavailable") from ex
                if not dead:
                    state["phase"] = "QUARANTINED"
                    state["reason"] = "candidate remained alive after bounded termination"
                    state["updatedAt"] = time.time()
                    _atomic_json(self.state_path, state)
                    raise ActivationError("rollback quarantined: candidate death not proven")
            pointer = {"schema": 2, "generation": int(state.get("generation", 0)), "current": prior, "previous": None, "rolledBackAt": time.time(), "reason": str(reason), "updatedAt": time.time()}
            _atomic_json(self.pointer_path, pointer)
            state = self.status()
            state.update({"phase": "ROLLED_BACK", "pid": None, "processIdentity": None, "reason": str(reason), "updatedAt": time.time()})
            _atomic_json(self.state_path, state)
            return pointer

    def recover(self):
        with _state_lock(self.lock_path):
            state = self.status()
            pointer = self.known_good_pointer()
            phase = state.get("phase")
            if phase == "PROMOTING" and pointer and pointer.get("generation") == state.get("generation") and (pointer.get("current") or {}).get("revision") == (state.get("candidate") or {}).get("revision"):
                state["phase"] = "PROMOTED"
                state["updatedAt"] = time.time()
                _atomic_json(self.state_path, state)
                return pointer
            if phase == "PROMOTED":
                if not pointer or pointer.get("generation") != state.get("generation") or (pointer.get("current") or {}).get("revision") != (state.get("candidate") or {}).get("revision"):
                    raise ActivationError("promoted activation cannot be reconciled")
                return pointer
            if phase == "ROLLED_BACK":
                prior = state.get("prior") or self.running_identity
                if not pointer or (pointer.get("current") or {}).get("revision") != prior.get("revision"):
                    raise ActivationError("rollback pointer cannot be reconciled")
                return pointer
            if phase == "QUARANTINED":
                raise ActivationError("activation recovery blocked by quarantined candidate")
            incomplete = phase in {"STAGED", "STARTING", "PROBING", "PROBED", "ROLLBACK_PENDING", "PROMOTING"}
            generation = state.get("generation")
        if incomplete:
            return self.rollback("recovered incomplete activation", expected_generation=generation)
        return pointer

    def authoritative_health_check(self, *, expected_generation=None, timeout:float=5.0):
        with _state_lock(self.lock_path):
            state=self.status()
            self._check_generation(state,expected_generation)
            if state.get("phase")!="PROMOTED":
                raise ActivationError("activation health is only valid after promotion")
            generation=state["generation"];candidate=state.get("candidate") or {}
            process=state.get("processIdentity") or {};ready_path=Path(state.get("readyPath") or "")
        try:
            if not _same_process(process,process_identity(int(process["pid"]))):
                raise ActivationError("promoted candidate process identity is no longer live")
            ready,ready_sha=read_activation_ready(ready_path,timeout=timeout)
            if ready.get("generation")!=generation or ready.get("nonce")!=state.get("activationNonce") or int(ready.get("pid") or 0)!=int(process.get("pid") or -1):
                raise ActivationError("promoted activation readiness binding mismatch")
            if ready.get("stateRoot")!=state.get("candidateStateRoot"):
                raise ActivationError("promoted activation state-root binding mismatch")
            control=probe_control_endpoint(Path(candidate["codeRoot"]),ready["host"],ready["port"],candidate,state_root=ready["stateRoot"],timeout=timeout)
            verify_build_manifest(candidate["manifestPath"],candidate["codeRoot"],candidate["revision"],candidate["manifestSha256"])
            evidence={"schema":1,"generation":generation,"readySha256":ready_sha,"control":control,"identity":ready.get("identity"),"processIdentity":process}
            return self.activation_health(True,expected_generation=generation,_authority=self._health_authority,evidence=evidence)
        except Exception as ex:
            try:self.rollback("promoted candidate failed authoritative activation health",expected_generation=generation)
            except Exception as rollback_ex:
                raise ActivationError("promoted health failed and rollback could not be proven") from rollback_ex
            if isinstance(ex,ActivationError):raise
            if isinstance(ex,ActivationProbeError):raise ActivationError(str(ex)) from ex
            raise ActivationError("promoted candidate authoritative health failed") from ex

    def activation_health(self, healthy: bool, *, expected_generation=None, _authority=None, evidence=None):
        if _authority is not self._health_authority:
            raise ActivationError("caller-supplied activation health denied")
        if not healthy:
            return self.rollback("promoted candidate failed activation health window", expected_generation=expected_generation)
        if not isinstance(evidence,dict):
            raise ActivationError("activation health evidence missing")
        with _state_lock(self.lock_path):
            state = self.status()
            self._check_generation(state, expected_generation)
            if state.get("phase") != "PROMOTED":
                raise ActivationError("activation health is only valid after promotion")
            pointer = self.known_good_pointer()
            if not pointer or (pointer.get("current") or {}).get("revision") != (state.get("candidate") or {}).get("revision"):
                raise ActivationError("activation health pointer mismatch")
            if state.get("processIdentity") and not _same_process(state["processIdentity"],process_identity(int(state["processIdentity"]["pid"]))):
                raise ActivationError("activation health process identity mismatch")
            state["activationHealth"]={**evidence,"evidenceSha256":_canonical_digest(evidence)}
            state["updatedAt"]=time.time()
            _atomic_json(self.state_path,state)
            return pointer

