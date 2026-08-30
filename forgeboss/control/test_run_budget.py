from __future__ import annotations

import threading
import unittest
from decimal import Decimal

from forgeboss.control.run_budget import (
    GlobalRunBudget,
    RunBudgetError,
    STATE_CANCELLED,
    STATE_FAILED,
    STATE_PAID_STARTED,
    STATE_RELEASED,
    STATE_SETTLED,
    STATE_UNKNOWN,
)


class T(unittest.TestCase):
    def code(self, expected, fn, *args, **kwargs):
        with self.assertRaises(RunBudgetError) as ctx:
            fn(*args, **kwargs)
        self.assertEqual(ctx.exception.code, expected)
        return ctx.exception

    def test_exact_cap(self):
        b = GlobalRunBudget("1.00")
        b.reserve("a", "0.6")
        b.reserve("b", "0.4")
        self.assertEqual(b.remaining, Decimal("0"))
        self.code("BUDGET_EXCEEDED", b.reserve, "c", "0.01")

    def test_bad_numbers_fail_closed(self):
        for x in (float("nan"), float("inf"), -1, "-1", "nan", "Infinity", " 1", "1_0", None, True, [], "1e400"):
            with self.subTest(x=x):
                self.code("BUDGET_CAP_INVALID", GlobalRunBudget, x)

    def test_paid_start_required_for_settlement(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".5")
        self.code("PAID_WORK_NOT_STARTED", b.settle, "a", ".1")

    def test_release_before_start_refunds(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".5")
        r = b.release("a")
        self.assertEqual(r.state, STATE_RELEASED)
        self.assertEqual(b.remaining, Decimal("1.0"))

    def test_release_after_start_forbidden(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".5")
        b.start_paid("a")
        self.code("PAID_WORK_STARTED", b.release, "a")
        self.assertEqual(b.get("a").state, STATE_PAID_STARTED)

    def test_settle_truthfully_below_reservation(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".5")
        _, token = b.start_paid("a")
        r = b.settle("a", ".2", authority_token=token)
        self.assertEqual(r.state, STATE_SETTLED)
        self.assertEqual(b.committed, Decimal(".2"))
        self.assertEqual(b.remaining, Decimal(".8"))

    def test_overrun_is_recorded_not_clamped_and_latches(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".5")
        _, token = b.start_paid("a")
        r = b.settle("a", ".75", authority_token=token)
        self.assertEqual(r.committed, Decimal(".75"))
        self.assertTrue(b.latched)
        self.assertEqual(b.latch_reason, "reservation-overrun")
        self.code("BUDGET_LATCHED", b.reserve, "b", ".01")

    def test_started_work_can_settle_after_manual_latch(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".5")
        _, token = b.start_paid("a")
        b.latch("operator-stop")
        self.assertEqual(b.settle("a", ".2", authority_token=token).state, STATE_SETTLED)

    def test_unknown_cost_conservatively_commits_and_latches(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".5")
        _, token = b.start_paid("a")
        r = b.settle_unknown("a", authority_token=token)
        self.assertEqual(r.state, STATE_UNKNOWN)
        self.assertEqual(r.committed, Decimal(".5"))
        self.assertFalse(r.cost_known)
        self.assertTrue(b.latched)

    def test_fail_unknown_cost_is_conservative(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".4")
        _, token = b.start_paid("a")
        r = b.fail("a", authority_token=token)
        self.assertEqual(r.state, STATE_FAILED)
        self.assertEqual(r.committed, Decimal(".4"))
        self.assertTrue(b.latched)

    def test_cancel_before_start_refunds(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".4")
        r = b.cancel("a")
        self.assertEqual(r.state, STATE_CANCELLED)
        self.assertEqual(r.committed, Decimal("0"))
        self.assertEqual(b.remaining, Decimal("1.0"))

    def test_cancel_after_start_requires_cost_or_conservative_charge(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".4")
        _, token = b.start_paid("a")
        r = b.cancel("a", authority_token=token)
        self.assertEqual(r.state, STATE_CANCELLED)
        self.assertEqual(r.committed, Decimal(".4"))
        self.assertTrue(b.latched)

    def test_wrong_authority_token_rejected(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".4")
        b.start_paid("a")
        self.code("AUTHORITY_TOKEN_INVALID", b.settle, "a", ".2", authority_token="wrong")
        self.assertEqual(b.get("a").state, STATE_PAID_STARTED)

    def test_journal_veto_is_atomic(self):
        def journal(event):
            if event["op"] == "start_paid":
                raise RuntimeError("disk down")
        b = GlobalRunBudget(1, journal=journal)
        b.reserve("a", ".4")
        with self.assertRaises(RuntimeError):
            b.start_paid("a")
        self.assertEqual(b.get("a").state, "RESERVED")

    def test_snapshot_roundtrip(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".4", worker_id="w")
        _, token = b.start_paid("a")
        b.settle("a", ".3", authority_token=token)
        snap = b.snapshot()
        c = GlobalRunBudget.from_snapshot(snap)
        self.assertEqual(c.cap, b.cap)
        self.assertEqual(c.committed, b.committed)
        self.assertEqual(c.get("a").as_dict(), b.get("a").as_dict())

    def test_tampered_snapshot_over_cap_requires_latch(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".5")
        _, token = b.start_paid("a")
        b.settle("a", "2", authority_token=token)
        snap = b.snapshot()
        snap["latched"] = False
        snap["latchReason"] = None
        self.code("SNAPSHOT_INVALID", GlobalRunBudget.from_snapshot, snap)

    def test_concurrent_reserve_never_exceeds_cap(self):
        b = GlobalRunBudget(1)
        barrier = threading.Barrier(20)
        success = []
        lock = threading.Lock()
        def run(i):
            barrier.wait()
            try:
                b.reserve(f"r{i}", ".1")
                with lock:
                    success.append(i)
            except RunBudgetError as e:
                self.assertEqual(e.code, "BUDGET_EXCEEDED")
        threads = [threading.Thread(target=run, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(success), 10)
        self.assertEqual(b.outstanding, Decimal("1.0"))

    def test_start_vs_release_race_has_one_winner(self):
        for _ in range(50):
            b = GlobalRunBudget(1)
            b.reserve("a", ".5")
            barrier = threading.Barrier(2)
            outcomes = []
            lock = threading.Lock()
            def starter():
                barrier.wait()
                try:
                    b.start_paid("a")
                    out = "start"
                except RunBudgetError as e:
                    out = e.code
                with lock:
                    outcomes.append(out)
            def releaser():
                barrier.wait()
                try:
                    b.release("a")
                    out = "release"
                except RunBudgetError as e:
                    out = e.code
                with lock:
                    outcomes.append(out)
            t1 = threading.Thread(target=starter)
            t2 = threading.Thread(target=releaser)
            t1.start(); t2.start(); t1.join(); t2.join()
            self.assertEqual(len(outcomes), 2)
            self.assertIn(b.get("a").state, {STATE_PAID_STARTED, STATE_RELEASED})
            if b.get("a").state == STATE_PAID_STARTED:
                self.assertIn("start", outcomes)
                self.assertIn("PAID_WORK_STARTED", outcomes)
            else:
                self.assertIn("release", outcomes)
                self.assertIn("RESERVATION_CONFLICT", outcomes)

    def test_duplicate_terminal_same_cost_is_idempotent(self):
        b = GlobalRunBudget(1)
        b.reserve("a", .5)
        _, token = b.start_paid("a")
        first = b.settle("a", .2, authority_token=token)
        self.assertEqual(b.settle("a", .2, authority_token=token), first)

    def test_duplicate_terminal_different_cost_fails(self):
        b = GlobalRunBudget(1)
        b.reserve("a", .5)
        _, token = b.start_paid("a")
        b.settle("a", .2, authority_token=token)
        self.code("PAID_WORK_NOT_STARTED", b.settle, "a", .3, authority_token=token)

    def test_snapshot_individual_overrun_cannot_unlatch_even_under_global_cap(self):
        b = GlobalRunBudget(10)
        b.reserve("a", "1")
        _, token = b.start_paid("a")
        b.settle("a", "2", authority_token=token)
        snap = b.snapshot()
        snap["latched"] = False
        snap["latchReason"] = None
        self.code("SNAPSHOT_INVALID", GlobalRunBudget.from_snapshot, snap)

    def test_snapshot_released_record_cannot_claim_spend(self):
        b = GlobalRunBudget(10)
        b.reserve("a", "1")
        b.release("a")
        snap = b.snapshot()
        snap["records"][0]["committedUsd"] = "0.5"
        self.code("SNAPSHOT_INVALID", GlobalRunBudget.from_snapshot, snap)

    def test_journal_sees_latch_reason_before_overrun_mutation(self):
        events = []
        b = GlobalRunBudget(10, journal=events.append)
        b.reserve("a", 1)
        _, token = b.start_paid("a")
        b.settle("a", 2, authority_token=token)
        self.assertEqual(events[-1]["latchReason"], "reservation-overrun")
        self.assertTrue(b.latched)


if __name__ == "__main__":
    unittest.main()
