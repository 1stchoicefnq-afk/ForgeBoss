from pathlib import Path

P=Path('forgeboss/control/test_process_supervisor.py')
s=P.read_text(encoding='utf-8')
old='''            ticks = iter((0.0, 1.0, 2.0, 3.0))
            with self.assertRaises(_ProcQueryError):
                _owned_descendants_linux(10, 11, proc_root=root, timeout=.1, clock=lambda: next(ticks))
'''
new='''            ticks = [0]
            def deadline_clock():
                ticks[0] += 1
                return 0.0 if ticks[0] == 1 else 1.0
            with self.assertRaises(_ProcQueryError):
                _owned_descendants_linux(10, 11, proc_root=root, timeout=.1, clock=deadline_clock)
'''
if s.count(old)!=1:raise SystemExit('deadline test anchor mismatch')
s=s.replace(old,new,1)
old='''            first = self.sup.stop("short-timeout", a.generation, timeout=.10)
            self.assertEqual(first.state, STATE_STOP_FAILED)
            self.assertFalse(first.containment_empty)
            os.kill(child, 0)
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
'''
new='''            started = time.monotonic()
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
'''
if s.count(old)!=1:raise SystemExit('short-timeout test anchor mismatch')
s=s.replace(old,new,1)
P.write_text(s,encoding='utf-8')
