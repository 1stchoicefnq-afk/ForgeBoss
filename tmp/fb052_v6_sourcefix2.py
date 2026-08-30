from pathlib import Path

P=Path('forgeboss/control/process_supervisor.py')
s=P.read_text(encoding='utf-8')
old='''def _read_linux_ppid(pid: int, *, proc_root: Path, deadline: float, clock) -> int | None:
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
'''
new='''def _read_linux_identity(pid: int, *, proc_root: Path, deadline: float, clock) -> tuple[int, int] | None:
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
        starttime = int(tail[19])
    except ValueError as ex:
        raise _ProcQueryError(f"owned pid {pid} has malformed process identity") from ex
    if ppid < 0 or starttime <= 0:
        raise _ProcQueryError(f"owned pid {pid} has invalid process identity")
    return ppid, starttime


def _read_linux_ppid(pid: int, *, proc_root: Path, deadline: float, clock) -> int | None:
    identity = _read_linux_identity(pid, proc_root=proc_root, deadline=deadline, clock=clock)
    return None if identity is None else identity[0]
'''
if s.count(old)!=1:raise SystemExit('identity anchor mismatch')
s=s.replace(old,new,1)
old='''    root_rc: int | None = None
    stop_started: float | None = None
    keeper_pid = os.getpid()
    while True:
'''
new='''    root_rc: int | None = None
    stop_started: float | None = None
    keeper_pid = os.getpid()
    term_sent: dict[int, int] = {}
    while True:
'''
if s.count(old)!=1:raise SystemExit('keeper state anchor mismatch')
s=s.replace(old,new,1)
old='''        try:
            owned = _owned_descendants_linux(keeper_pid, proc.pid, root_known_exited=(root_rc is not None))
        except _ProcQueryError:
            return 125
        if stopping:
'''
new='''        try:
            owned = _owned_descendants_linux(keeper_pid, proc.pid, root_known_exited=(root_rc is not None))
        except _ProcQueryError:
            # Never relinquish subreaper containment merely because authority
            # cannot be proved. A stop caller will time out/fail closed while
            # the keeper remains alive and retries bounded queries.
            time.sleep(0.02)
            continue
        if stopping:
'''
if s.count(old)!=1:raise SystemExit('first query-fault anchor mismatch')
s=s.replace(old,new,1)
old='''            sig = signal.SIGKILL if time.monotonic() - stop_started >= LINUX_STOP_ESCALATION_SECONDS else signal.SIGTERM
            for pid in sorted(owned, reverse=True):
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
                except OSError:
                    return 125
'''
new='''            sig = signal.SIGKILL if time.monotonic() - stop_started >= LINUX_STOP_ESCALATION_SECONDS else signal.SIGTERM
            signal_ambiguous = False
            for pid in sorted(owned, reverse=True):
                try:
                    ident = _read_linux_identity(pid, proc_root=Path("/proc"), deadline=time.monotonic() + LINUX_QUERY_TIMEOUT_SECONDS, clock=time.monotonic)
                except _ProcQueryError:
                    signal_ambiguous = True
                    break
                if ident is None:
                    continue
                starttime = ident[1]
                if sig == signal.SIGTERM and term_sent.get(pid) == starttime:
                    continue
                if sig == signal.SIGTERM and pid not in term_sent and len(term_sent) >= LINUX_MAX_DESCENDANTS:
                    signal_ambiguous = True
                    break
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    continue
                except OSError:
                    signal_ambiguous = True
                    break
                if sig == signal.SIGTERM:
                    term_sent[pid] = starttime
            if signal_ambiguous:
                time.sleep(0.02)
                continue
'''
if s.count(old)!=1:raise SystemExit('signal-loop anchor mismatch')
s=s.replace(old,new,1)
old='''        try:
            owned = _owned_descendants_linux(keeper_pid, proc.pid, root_known_exited=(root_rc is not None))
        except _ProcQueryError:
            return 125
        if root_rc is not None and not owned:
'''
new='''        try:
            owned = _owned_descendants_linux(keeper_pid, proc.pid, root_known_exited=(root_rc is not None))
        except _ProcQueryError:
            time.sleep(0.02)
            continue
        if root_rc is not None and not owned:
'''
if s.count(old)!=1:raise SystemExit('second query-fault anchor mismatch')
s=s.replace(old,new,1)
P.write_text(s,encoding='utf-8')
