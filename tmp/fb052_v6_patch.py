from pathlib import Path
import re

P = Path('forgeboss/control/process_supervisor.py')
T = Path('forgeboss/control/test_process_supervisor.py')
s = P.read_text(encoding='utf-8')
t = T.read_text(encoding='utf-8')

needle = 'DEFAULT_POLL_SECONDS = 0.05\n'
insert = '''DEFAULT_POLL_SECONDS = 0.05\nLINUX_QUERY_TIMEOUT_SECONDS = 0.25\nLINUX_MAX_DESCENDANTS = 4096\nLINUX_PROC_RECORD_MAX_BYTES = 64 * 1024\nLINUX_STOP_ESCALATION_SECONDS = 1.0\n'''
if s.count(needle) != 1:
    raise SystemExit('constant anchor mismatch')
s = s.replace(needle, insert, 1)

needle = '''        if not _linux_subreaper_available():\n            raise SupervisorError("CONTAINMENT_UNAVAILABLE", "Linux subreaper containment is unavailable")\n        spec = json.dumps({"argv": list(argv), "cwd": cwd, "env": env}, separators=(",", ":"))\n'''
repl = '''        if not _linux_subreaper_available():\n            raise SupervisorError("CONTAINMENT_UNAVAILABLE", "Linux subreaper containment is unavailable")\n        self._stop_requested = False\n        spec = json.dumps({"argv": list(argv), "cwd": cwd, "env": env}, separators=(",", ":"))\n'''
if s.count(needle) != 1:
    raise SystemExit('keeper init anchor mismatch')
s = s.replace(needle, repl, 1)

new_methods = '''    def empty(self, timeout: float) -> bool:\n        timeout = _timeout(timeout, "containment query timeout")\n        try:\n            self._proc.wait(timeout=timeout)\n        except subprocess.TimeoutExpired:\n            return False\n        rc = int(self._proc.returncode)\n        # During an explicit stop, only the keeper's verified-empty terminal\n        # code proves that the owned containment is empty. Keeper death/crash\n        # is never equivalent to descendant absence.\n        if self._stop_requested:\n            return rc == 75\n        # Natural keeper termination is never reassignment authority (refresh\n        # maps it to QUARANTINED/FAILED), but it does mean the keeper completed\n        # its own positive-empty loop.\n        return True\n\n    def terminate(self, timeout: float) -> bool:\n        timeout = _timeout(timeout, "termination timeout")\n        self._stop_requested = True\n        rc = self._proc.poll()\n        if rc is not None:\n            return int(rc) == 75\n        try:\n            os.kill(self._proc.pid, signal.SIGTERM)\n        except ProcessLookupError:\n            rc = self._proc.poll()\n            return rc is not None and int(rc) == 75\n        try:\n            self._proc.wait(timeout=timeout)\n        except subprocess.TimeoutExpired:\n            # Never kill the subreaper keeper merely to satisfy a caller\n            # timeout: doing so destroys containment authority while descendants\n            # may survive. The keeper continues bounded termination in the\n            # background; this stop attempt fails closed and may be retried.\n            return False\n        return int(self._proc.returncode) == 75\n\n'''
pat = re.compile(r'    def empty\(self, timeout: float\) -> bool:\n.*?(?=    def _kill_keeper\(self\):)', re.S)
s2, n = pat.subn(new_methods, s, count=1)
if n != 1:
    raise SystemExit(f'empty/terminate replacement mismatch: {n}')
s = s2

new_linux = r'''class _ProcQueryError(RuntimeError):
    """The keeper could not positively prove its owned Linux process set."""


def _proc_query_check(deadline: float, clock) -> None:
    if clock() > deadline:
        raise _ProcQueryError("owned process query deadline exceeded")


def _proc_pid_exists_linux(pid: int, proc_root: Path) -> bool:
    try:
        os.stat(proc_root / str(pid))
        return True
    except FileNotFoundError:
        return False
    except OSError as ex:
        raise _ProcQueryError(f"cannot establish /proc existence for pid {pid}") from ex


def _read_proc_record_linux(pid: int, relative: str, *, proc_root: Path, deadline: float, clock) -> str | None:
    _proc_query_check(deadline, clock)
    path = proc_root / str(pid) / relative
    try:
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            raw = handle.read(LINUX_PROC_RECORD_MAX_BYTES + 1)
    except FileNotFoundError:
        if not _proc_pid_exists_linux(pid, proc_root):
            return None
        raise _ProcQueryError(f"owned pid {pid} exists but {relative} is unavailable")
    except (OSError, UnicodeError) as ex:
        if not _proc_pid_exists_linux(pid, proc_root):
            return None
        raise _ProcQueryError(f"owned pid {pid} has unreadable {relative}") from ex
    if len(raw.encode("utf-8", "strict")) > LINUX_PROC_RECORD_MAX_BYTES:
        raise _ProcQueryError(f"owned pid {pid} {relative} exceeds record ceiling")
    _proc_query_check(deadline, clock)
    return raw


def _read_linux_ppid(pid: int, *, proc_root: Path, deadline: float, clock) -> int | None:
    raw = _read_proc_record_linux(pid, "stat", proc_root=proc_root, deadline=deadline, clock=clock)
    if raw is None:
        return None
    close = raw.rfind(")")
    if close < 0:
        raise _ProcQueryError(f"owned pid {pid} has malformed stat record")
    tail = raw[close + 1:].split()
    if len(tail) < 20:
        raise _ProcQueryError(f"owned pid {pid} has truncated stat record")
    try:
        ppid = int(tail[1])
    except ValueError as ex:
        raise _ProcQueryError(f"owned pid {pid} has malformed parent identity") from ex
    if ppid < 0:
        raise _ProcQueryError(f"owned pid {pid} has invalid parent identity")
    return ppid


def _read_linux_children(pid: int, *, proc_root: Path, deadline: float, clock) -> tuple[int, ...] | None:
    raw = _read_proc_record_linux(pid, f"task/{pid}/children", proc_root=proc_root, deadline=deadline, clock=clock)
    if raw is None:
        return None
    if not raw.strip():
        return ()
    out: list[int] = []
    seen: set[int] = set()
    for token in raw.split():
        if not token.isdigit():
            raise _ProcQueryError(f"owned pid {pid} has malformed children record")
        child = int(token)
        if child <= 1 or child > 2 ** 31 - 1 or child in seen:
            raise _ProcQueryError(f"owned pid {pid} has invalid children record")
        seen.add(child)
        out.append(child)
    return tuple(out)


def _owned_descendants_linux(keeper_pid: int, root_pid: int, *, proc_root: Path = Path("/proc"),
                             timeout: float = LINUX_QUERY_TIMEOUT_SECONDS,
                             max_records: int = LINUX_MAX_DESCENDANTS,
                             root_known_exited: bool = False, clock=time.monotonic) -> set[int]:
    """Return the keeper-owned process set using only parent/children authority.

    The dedicated keeper is a child subreaper. Walking its kernel children files
    avoids a global process-table scan and makes every relevant unreadable or
    malformed owned record fail closed. A disappearing process is ignored only
    after its /proc identity is positively absent.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(float(timeout)) or float(timeout) <= 0:
        raise _ProcQueryError("owned process query timeout is invalid")
    if isinstance(max_records, bool) or not isinstance(max_records, int) or max_records <= 0:
        raise _ProcQueryError("owned process record ceiling is invalid")
    proc_root = Path(proc_root)
    deadline = clock() + float(timeout)
    keeper_pid = int(keeper_pid)
    root_pid = int(root_pid)
    owned: set[int] = set()
    frontier: list[int] = [keeper_pid]
    scanned: set[int] = set()
    records = 0
    while frontier:
        _proc_query_check(deadline, clock)
        parent = frontier.pop(0)
        if parent in scanned:
            continue
        scanned.add(parent)
        children = _read_linux_children(parent, proc_root=proc_root, deadline=deadline, clock=clock)
        if children is None:
            if parent == keeper_pid:
                raise _ProcQueryError("keeper proc identity disappeared during query")
            continue
        for child in children:
            _proc_query_check(deadline, clock)
            if child == keeper_pid:
                raise _ProcQueryError("keeper appears in its own child set")
            if child in owned:
                continue
            records += 1
            if records > max_records:
                raise _ProcQueryError("owned process record ceiling exceeded")
            ppid = _read_linux_ppid(child, proc_root=proc_root, deadline=deadline, clock=clock)
            if ppid is None:
                # The child disappeared and its /proc identity is now absent.
                continue
            # A child can be reparented to the keeper (nearest subreaper) while
            # the walk is in progress. Any other parent transition is ambiguous
            # and must not be silently dropped or targeted.
            if ppid not in ({keeper_pid, parent} | owned):
                raise _ProcQueryError(f"owned pid {child} changed to unowned parent {ppid}")
            owned.add(child)
            frontier.append(child)
    if not root_known_exited and root_pid not in owned and _proc_pid_exists_linux(root_pid, proc_root):
        raise _ProcQueryError("worker root exists but is absent from keeper-owned child authority")
    _proc_query_check(deadline, clock)
    return owned


def _keeper_main() -> int:
    if not _linux_subreaper_available():
        print(json.dumps({"ok": False, "error": "subreaper unavailable"}), flush=True)
        return 125
    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_CHILD_SUBREAPER = 36
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        print(json.dumps({"ok": False, "error": "prctl subreaper failed"}), flush=True)
        return 125
    try:
        line = sys.stdin.readline()
        if not line:
            raise ValueError("missing keeper launch spec")
        spec = json.loads(line)
        proc = subprocess.Popen(
            spec["argv"],
            cwd=spec.get("cwd"),
            env=spec.get("env"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except Exception as ex:
        print(json.dumps({"ok": False, "error": str(ex)}), flush=True)
        return 125
    print(json.dumps({"ok": True, "pid": proc.pid}), flush=True)
    stopping = False

    def request_stop(_sig, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    root_rc: int | None = None
    stop_started: float | None = None
    keeper_pid = os.getpid()
    while True:
        if root_rc is None:
            root_rc = proc.poll()
        try:
            owned = _owned_descendants_linux(keeper_pid, proc.pid, root_known_exited=(root_rc is not None))
        except _ProcQueryError:
            return 125
        if stopping:
            if stop_started is None:
                stop_started = time.monotonic()
            sig = signal.SIGKILL if time.monotonic() - stop_started >= LINUX_STOP_ESCALATION_SECONDS else signal.SIGTERM
            # Repeat discovery+signal each loop. Late forks/reparenting therefore
            # remain inside the keeper's final positive-empty proof.
            for pid in sorted(owned, reverse=True):
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
                except OSError:
                    return 125
        while True:
            try:
                waited, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if waited == 0:
                break
            if waited == proc.pid and root_rc is None:
                root_rc = os.waitstatus_to_exitcode(status)
        if root_rc is None:
            root_rc = proc.poll()
        try:
            owned = _owned_descendants_linux(keeper_pid, proc.pid, root_known_exited=(root_rc is not None))
        except _ProcQueryError:
            return 125
        if root_rc is not None and not owned:
            if stopping:
                return 75
            if root_rc < 0:
                return min(255, 128 + abs(root_rc))
            return min(125, int(root_rc))
        time.sleep(0.02)


'''
pat = re.compile(r'def _descendants_linux\(root_pid: int\) -> set\[int\]:\n.*?(?=if __name__ == "__main__")', re.S)
s2, n = pat.subn(new_linux, s, count=1)
if n != 1:
    raise SystemExit(f'linux keeper replacement mismatch: {n}')
s = s2

needle = '    _timeout,\n)\n'
repl = '    _timeout, _owned_descendants_linux, _ProcQueryError,\n)\n'
if t.count(needle) != 1:
    raise SystemExit('test import anchor mismatch')
t = t.replace(needle, repl, 1)

new_tests = r'''
    def _fake_proc_entry(self, root: Path, pid: int, ppid: int, children: str = ""):
        base = root / str(pid)
        task = base / "task" / str(pid)
        task.mkdir(parents=True, exist_ok=True)
        (base / "stat").write_text(f"{pid} (worker) S {ppid} " + "0 " * 18, encoding="utf-8")
        (task / "children").write_text(children, encoding="utf-8")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux procfs query proof")
    def test_owned_query_unreadable_existing_child_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._fake_proc_entry(root, 10, 1, "11")
            self._fake_proc_entry(root, 11, 10, "")
            stat_path = root / "11" / "stat"
            stat_path.unlink(); stat_path.mkdir()
            with self.assertRaises(_ProcQueryError):
                _owned_descendants_linux(10, 11, proc_root=root)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux procfs query proof")
    def test_owned_query_malformed_child_record_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._fake_proc_entry(root, 10, 1, "not-a-pid")
            with self.assertRaises(_ProcQueryError):
                _owned_descendants_linux(10, 11, proc_root=root, root_known_exited=True)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux procfs query proof")
    def test_owned_query_deadline_and_record_ceiling_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._fake_proc_entry(root, 10, 1, "11 12")
            self._fake_proc_entry(root, 11, 10, "")
            self._fake_proc_entry(root, 12, 10, "")
            ticks = iter((0.0, 1.0, 2.0, 3.0))
            with self.assertRaises(_ProcQueryError):
                _owned_descendants_linux(10, 11, proc_root=root, timeout=.1, clock=lambda: next(ticks))
            with self.assertRaises(_ProcQueryError):
                _owned_descendants_linux(10, 11, proc_root=root, max_records=1)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux procfs query proof")
    def test_owned_query_disappearing_child_is_gone_only_after_proc_absence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._fake_proc_entry(root, 10, 1, "11")
            got = _owned_descendants_linux(10, 11, proc_root=root, root_known_exited=True)
            self.assertEqual(got, set())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper proof")
    def test_short_timeout_never_kills_keeper_and_false_certifies_empty(self):
        self.sup = ProcessSupervisor()
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "child.pid"
            code = (
                "import os,signal,sys,time\n"
                "marker=sys.argv[1]\n"
                "pid=os.fork()\n"
                "if pid==0:\n"
                " os.setsid(); signal.signal(signal.SIGTERM,signal.SIG_IGN); open(marker,'w').write(str(os.getpid()))\n"
                " while True: time.sleep(1)\n"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                "while True: time.sleep(1)\n"
            )
            a = self.sup.launch("short-timeout", [PY, "-c", code, str(marker)])
            deadline = time.time() + 5
            while time.time() < deadline and not marker.exists():
                time.sleep(.02)
            self.assertTrue(marker.exists(), "daemon child did not start")
            child = int(marker.read_text())
            first = self.sup.stop("short-timeout", a.generation, timeout=.10)
            self.assertEqual(first.state, STATE_STOP_FAILED)
            self.assertFalse(first.containment_empty)
            os.kill(child, 0)
            deadline = time.time() + 4
            while time.time() < deadline:
                try:
                    second = self.sup.stop("short-timeout", a.generation, timeout=.5)
                except SupervisorError:
                    time.sleep(.1); continue
                if second.state == STATE_STOPPED:
                    break
                time.sleep(.1)
            else:
                self.fail("bounded keeper never reached verified empty after escalation")
            self.assertTrue(second.containment_empty)
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
'''
needle = "\nif __name__=='__main__':\n    unittest.main()\n"
if needle not in t:
    needle = '\nif __name__ == "__main__":\n    unittest.main()\n'
if needle not in t:
    raise SystemExit('test tail anchor mismatch')
t = t.replace(needle, new_tests + needle, 1)

P.write_text(s, encoding='utf-8')
T.write_text(t, encoding='utf-8')
