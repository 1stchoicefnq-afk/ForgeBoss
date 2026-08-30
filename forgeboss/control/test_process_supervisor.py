from __future__ import annotations
import os, signal, sys, tempfile, threading, time, unittest
from pathlib import Path
from unittest import mock

from forgeboss.control.process_supervisor import (
    ProcessSupervisor, SupervisorError,
    STATE_FAILED, STATE_IDENTITY_LOST, STATE_QUARANTINED,
    STATE_RUNNING, STATE_STOPPED, STATE_STOP_FAILED,
    _timeout, _owned_descendants_linux, _ProcQueryError, _reap_linux_children,
)

PY = str(Path(sys.executable).resolve())


class FakeContainment:
    def __init__(self, *, pid=1234, rc=None, empty=False, terminate_result=True, terminate_delay=0):
        self.pid = pid
        self.containment_id = f"fake:{pid}"
        self.rc = rc
        self.empty_value = empty
        self.terminate_result = terminate_result
        self.terminate_delay = terminate_delay
        self.terminate_calls = 0
        self.closed = False
    def poll(self): return self.rc
    def empty(self, timeout): return self.empty_value
    def terminate(self, timeout):
        self.terminate_calls += 1
        if self.terminate_delay: time.sleep(self.terminate_delay)
        if self.terminate_result:
            self.empty_value = True
            if self.rc is None: self.rc = 75
        return self.terminate_result
    def close(self): self.closed = True


class SupervisorTests(unittest.TestCase):
    def tearDown(self):
        try:
            if hasattr(self, "sup"): self.sup.close()
        except Exception:
            pass

    def test_timing_rejects_bad_values(self):
        for bad in (True, False, None, "1", 0, -1, float("nan"), float("inf"), 3601):
            with self.subTest(bad=bad), self.assertRaises(SupervisorError):
                _timeout(bad, "x")

    def test_launch_and_stop_then_reassign(self):
        first = FakeContainment(pid=10)
        second = FakeContainment(pid=11)
        with mock.patch("forgeboss.control.process_supervisor._launch_containment", side_effect=[first, second]):
            self.sup = ProcessSupervisor()
            a = self.sup.launch("w", [PY, "-c", "pass"])
            self.assertEqual((a.generation, a.state), (1, STATE_RUNNING))
            with self.assertRaises(SupervisorError) as cm:
                self.sup.reassign("w", 1, [PY, "-c", "pass"])
            self.assertEqual(cm.exception.code, "GENERATION_NOT_STOPPED")
            ev = self.sup.stop("w", 1, timeout=.2)
            self.assertEqual((ev.state, ev.containment_empty), (STATE_STOPPED, True))
            b = self.sup.reassign("w", 1, [PY, "-c", "pass"])
            self.assertEqual((b.generation, b.pid), (2, 11))

    def test_stop_failed_blocks_reassignment(self):
        fake = FakeContainment(terminate_result=False)
        with mock.patch("forgeboss.control.process_supervisor._launch_containment", return_value=fake):
            self.sup = ProcessSupervisor()
            self.sup.launch("w", [PY, "-c", "pass"])
            ev = self.sup.stop("w", 1, timeout=.1)
            self.assertEqual(ev.state, STATE_STOP_FAILED)
            with self.assertRaises(SupervisorError) as cm:
                self.sup.reassign("w", 1, [PY, "-c", "pass"])
            self.assertEqual(cm.exception.code, "GENERATION_NOT_STOPPED")

    def test_identity_lost_blocks_reassignment(self):
        fake = FakeContainment()
        with mock.patch("forgeboss.control.process_supervisor._launch_containment", return_value=fake):
            self.sup = ProcessSupervisor()
            self.sup.launch("w", [PY, "-c", "pass"])
            self.sup._containments.pop("w")
            got = self.sup.refresh("w")
            self.assertEqual(got.state, STATE_IDENTITY_LOST)
            with self.assertRaises(SupervisorError):
                self.sup.reassign("w", 1, [PY, "-c", "pass"])

    def test_duplicate_stop_serializes_single_termination(self):
        fake = FakeContainment(terminate_delay=.05)
        with mock.patch("forgeboss.control.process_supervisor._launch_containment", return_value=fake):
            self.sup = ProcessSupervisor()
            self.sup.launch("w", [PY, "-c", "pass"])
            results=[]; errors=[]
            def go():
                try: results.append(self.sup.stop("w",1,timeout=.5))
                except Exception as ex: errors.append(ex)
            t1=threading.Thread(target=go); t2=threading.Thread(target=go)
            t1.start(); t2.start(); t1.join(); t2.join()
            self.assertFalse(errors)
            self.assertEqual(fake.terminate_calls, 1)
            self.assertEqual(len(results),2)
            self.assertEqual(results[0].operation_id, results[1].operation_id)

    def test_returned_objects_are_frozen(self):
        fake=FakeContainment()
        with mock.patch("forgeboss.control.process_supervisor._launch_containment", return_value=fake):
            self.sup=ProcessSupervisor(); a=self.sup.launch("w",[PY,"-c","pass"])
            with self.assertRaises(Exception): a.state="x"
            d=a.as_dict()
            with self.assertRaises(TypeError): d["state"]="x"

    def test_natural_zero_exit_is_not_reassignment_permission(self):
        fake=FakeContainment(rc=0,empty=True)
        with mock.patch("forgeboss.control.process_supervisor._launch_containment", return_value=fake):
            self.sup=ProcessSupervisor(); self.sup.launch("w",[PY,"-c","pass"])
            a=self.sup.refresh("w")
            self.assertEqual(a.state, STATE_QUARANTINED)
            with self.assertRaises(SupervisorError): self.sup.reassign("w",1,[PY,"-c","pass"])

    def test_nonzero_exit_is_failed_not_success(self):
        fake=FakeContainment(rc=7,empty=True)
        with mock.patch("forgeboss.control.process_supervisor._launch_containment", return_value=fake):
            self.sup=ProcessSupervisor(); self.sup.launch("w",[PY,"-c","pass"])
            a=self.sup.refresh("w")
            self.assertEqual((a.state,a.exit_code),(STATE_FAILED,7))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper proof")
    def test_real_posix_stop_owns_daemonized_descendant(self):
        self.sup=ProcessSupervisor()
        code = (
            "import os,sys,time\n"
            "pid=os.fork()\n"
            "if pid==0:\n"
            " os.setsid(); time.sleep(30); os._exit(0)\n"
            "time.sleep(30)\n"
        )
        a=self.sup.launch("real",[PY,"-c",code])
        ev=self.sup.stop("real",a.generation,timeout=3.0)
        self.assertEqual(ev.state, STATE_STOPPED)
        self.assertTrue(ev.containment_empty)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper proof")
    def test_real_root_exits_descendant_keeps_containment_nonempty(self):
        self.sup=ProcessSupervisor()
        code=(
            "import os,time\n"
            "pid=os.fork()\n"
            "if pid==0:\n"
            " os.setsid(); time.sleep(30); os._exit(0)\n"
            "os._exit(0)\n"
        )
        a=self.sup.launch("orphan",[PY,"-c",code])
        time.sleep(.3)
        current=self.sup.refresh("orphan")
        self.assertEqual(current.state, STATE_RUNNING)
        ev=self.sup.stop("orphan",1,timeout=3.0)
        self.assertEqual(ev.state,STATE_STOPPED)
        self.assertTrue(ev.containment_empty)

    def test_stop_vs_reassign_cannot_advance_until_stop_terminal(self):
        fake=FakeContainment(terminate_delay=.15)
        second=FakeContainment(pid=99)
        with mock.patch("forgeboss.control.process_supervisor._launch_containment",side_effect=[fake,second]):
            self.sup=ProcessSupervisor(); self.sup.launch("w",[PY,"-c","pass"])
            result=[]
            t=threading.Thread(target=lambda: result.append(self.sup.stop("w",1,timeout=.5)))
            t.start(); time.sleep(.02)
            with self.assertRaises(SupervisorError) as cm:
                self.sup.reassign("w",1,[PY,"-c","pass"])
            self.assertEqual(cm.exception.code,"GENERATION_NOT_STOPPED")
            t.join()
            b=self.sup.reassign("w",1,[PY,"-c","pass"])
            self.assertEqual(b.generation,2)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper proof")
    def test_descendant_spawned_during_stop_is_still_contained(self):
        self.sup=ProcessSupervisor()
        code=(
            "import os,signal,time\n"
            "def h(*_):\n"
            " pid=os.fork()\n"
            " if pid==0:\n"
            "  os.setsid(); time.sleep(30); os._exit(0)\n"
            " time.sleep(5)\n"
            "signal.signal(signal.SIGTERM,h)\n"
            "time.sleep(30)\n"
        )
        a=self.sup.launch("race",[PY,"-c",code])
        time.sleep(.15)
        ev=self.sup.stop("race",a.generation,timeout=3.0)
        self.assertEqual(ev.state,STATE_STOPPED)
        self.assertTrue(ev.containment_empty)

    @unittest.skipUnless(os.name == "nt", "native Windows Job Object proof")
    def test_native_windows_job_stops_worker_tree(self):
        self.sup=ProcessSupervisor()
        code=(
            "import subprocess,sys,time\n"
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
            "time.sleep(30)\n"
        )
        a=self.sup.launch("win-real",[PY,"-c",code])
        ev=self.sup.stop("win-real",a.generation,timeout=5.0)
        self.assertEqual(ev.state,STATE_STOPPED)
        self.assertTrue(ev.containment_empty)

    def test_bad_generation_and_worker_ids_fail_closed(self):
        self.sup=ProcessSupervisor()
        for wid in ("", " w", "w "):
            with self.assertRaises(SupervisorError):
                self.sup.launch(wid,[PY,"-c","pass"])
        fake=FakeContainment()
        with mock.patch("forgeboss.control.process_supervisor._launch_containment",return_value=fake):
            self.sup.launch("w",[PY,"-c","pass"])
            for bad in (True,0,-1,2):
                with self.assertRaises(SupervisorError):
                    self.sup.stop("w",bad,timeout=.1)

    def test_stale_stop_rejected(self):
        fake=FakeContainment()
        with mock.patch("forgeboss.control.process_supervisor._launch_containment",return_value=fake):
            self.sup=ProcessSupervisor(); self.sup.launch("w",[PY,"-c","pass"])
            with self.assertRaises(SupervisorError) as cm:self.sup.stop("w",2,timeout=.1)
            self.assertEqual(cm.exception.code,"GENERATION_STALE")



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
            ticks = [0]
            def deadline_clock():
                ticks[0] += 1
                return 0.0 if ticks[0] == 1 else 1.0
            with self.assertRaises(_ProcQueryError):
                _owned_descendants_linux(10, 11, proc_root=root, timeout=.1, clock=deadline_clock)
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
            started = time.monotonic()
            first = self.sup.stop("short-timeout", a.generation, timeout=.10)
            self.assertLess(time.monotonic() - started, .75, "short stop exceeded bounded caller window")
            if first.state == STATE_STOPPED:
                self.assertTrue(first.containment_empty)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child, 0)
                return
            self.assertEqual(first.state, STATE_STOP_FAILED)
            self.assertFalse(first.containment_empty)
            os.kill(child, 0)
            with self.assertRaises(SupervisorError) as cm:
                self.sup.reassign("short-timeout", a.generation, [PY, "-c", "pass"])
            self.assertEqual(cm.exception.code, "GENERATION_NOT_STOPPED")
            deadline = time.time() + 4
            second = None
            while time.time() < deadline:
                try:
                    candidate = self.sup.stop("short-timeout", a.generation, timeout=.5)
                except SupervisorError:
                    time.sleep(.1)
                    continue
                if candidate.state == STATE_STOPPED:
                    second = candidate
                    break
                time.sleep(.1)
            self.assertIsNotNone(second, "bounded keeper never reached verified empty after escalation")
            self.assertTrue(second.containment_empty)
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper wait proof")
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

if __name__=="__main__":
    unittest.main()
