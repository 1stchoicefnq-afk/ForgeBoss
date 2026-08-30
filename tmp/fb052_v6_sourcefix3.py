from pathlib import Path

P=Path('forgeboss/control/process_supervisor.py')
T=Path('forgeboss/control/test_process_supervisor.py')
s=P.read_text(encoding='utf-8')
t=T.read_text(encoding='utf-8')
anchor='''def _keeper_main() -> int:
'''
helper='''def _reap_linux_children(root_pid: int, root_rc: int | None) -> tuple[int | None, bool]:
    """Reap terminal children and return whether the subreaper has ECHILD.

    Unlike procfs children listings, waitpid(-1, WNOHANG) returning ECHILD is
    kernel authority that this process has no child processes at all. A zero
    return means at least one live child still exists and can never certify
    containment empty.
    """
    no_children = False
    while True:
        try:
            waited, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            no_children = True
            break
        if waited == 0:
            break
        if waited == root_pid and root_rc is None:
            root_rc = os.waitstatus_to_exitcode(status)
    return root_rc, no_children


'''
if s.count(anchor)!=1:raise SystemExit('keeper helper anchor mismatch')
s=s.replace(anchor,helper+anchor,1)
old='''        while True:
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
            time.sleep(0.02)
            continue
        if root_rc is not None and not owned:
'''
new='''        root_rc, no_children = _reap_linux_children(proc.pid, root_rc)
        if root_rc is None:
            root_rc = proc.poll()
        try:
            owned = _owned_descendants_linux(keeper_pid, proc.pid, root_known_exited=(root_rc is not None))
        except _ProcQueryError:
            time.sleep(0.02)
            continue
        # procfs children is discovery/signal assistance only. Linux documents
        # that it may omit children during exit races, so STOPPED authority is
        # granted only by the subreaper's waitpid ECHILD proof.
        if root_rc is not None and no_children:
'''
if s.count(old)!=1:raise SystemExit('keeper final proof anchor mismatch')
s=s.replace(old,new,1)
old='''    _timeout, _owned_descendants_linux, _ProcQueryError,
)'''
new='''    _timeout, _owned_descendants_linux, _ProcQueryError, _reap_linux_children,
)'''
if t.count(old)!=1:raise SystemExit('test import sourcefix3 anchor mismatch')
t=t.replace(old,new,1)
main='''if __name__=='__main__':
    unittest.main()
'''
test='''    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper wait proof")
    def test_waitpid_echild_not_procfs_empty_is_final_empty_authority(self):
        pid = os.fork()
        if pid == 0:
            time.sleep(5)
            os._exit(0)
        try:
            root_rc, empty = _reap_linux_children(-999999, None)
            self.assertIsNone(root_rc)
            self.assertFalse(empty, "live child must prevent ECHILD empty proof")
        finally:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            os.waitpid(pid, 0)
        root_rc, empty = _reap_linux_children(-999999, None)
        self.assertIsNone(root_rc)
        self.assertTrue(empty, "ECHILD must prove no child processes remain")

'''
if t.count(main)!=1:raise SystemExit('test main anchor sourcefix3 mismatch')
t=t.replace(main,test+main,1)
P.write_text(s,encoding='utf-8')
T.write_text(t,encoding='utf-8')
