from __future__ import annotations

import copy
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

AUTH_KEY = b"run-budget-r4-test-auth-key-32by"
WRONG_KEY = b"wrong-run-budget-r4-auth-key-32b"


class T(unittest.TestCase):
    def code(self, expected, fn, *args, **kwargs):
        with self.assertRaises(RunBudgetError) as ctx:
            fn(*args, **kwargs)
        self.assertEqual(ctx.exception.code, expected)
        return ctx.exception

    def authenticated(self, budget, key=AUTH_KEY):
        return budget.authenticated_snapshot(key)

    def restored(self, budget, key=AUTH_KEY):
        return GlobalRunBudget.from_snapshot(self.authenticated(budget, key), authentication_key=key)

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

    def test_missing_empty_and_nonstring_authority_token_rejected(self):
        operations = (
            lambda b: b.settle("a", ".2"),
            lambda b: b.fail("a", ".2"),
            lambda b: b.cancel("a", ".2"),
            lambda b: b.settle_unknown("a"),
        )
        for operation in operations:
            for token in (None, "", 123, True):
                with self.subTest(operation=operation, token=token):
                    events = []
                    b = GlobalRunBudget(1, journal=events.append)
                    b.reserve("a", ".4")
                    _, valid = b.start_paid("a")
                    before = (b.get("a"), tuple(events), b.committed, b.outstanding, b.latched)
                    if token is None:
                        self.code("AUTHORITY_TOKEN_INVALID", operation, b)
                    else:
                        name = operation.__code__.co_firstlineno
                        if name == operations[0].__code__.co_firstlineno:
                            self.code("AUTHORITY_TOKEN_INVALID", b.settle, "a", ".2", authority_token=token)
                        elif name == operations[1].__code__.co_firstlineno:
                            self.code("AUTHORITY_TOKEN_INVALID", b.fail, "a", ".2", authority_token=token)
                        elif name == operations[2].__code__.co_firstlineno:
                            self.code("AUTHORITY_TOKEN_INVALID", b.cancel, "a", ".2", authority_token=token)
                        else:
                            self.code("AUTHORITY_TOKEN_INVALID", b.settle_unknown, "a", authority_token=token)
                    self.assertEqual(b.get("a"), before[0])
                    self.assertEqual(tuple(events), before[1])
                    self.assertEqual((b.committed, b.outstanding, b.latched), before[2:])
                    self.assertEqual(b.settle("a", ".2", authority_token=valid).state, STATE_SETTLED)

    def test_duplicate_terminal_requires_original_authority_token(self):
        events = []
        b = GlobalRunBudget(1, journal=events.append)
        b.reserve("a", ".5")
        _, token = b.start_paid("a")
        first = b.settle("a", ".2", authority_token=token)
        count = len(events)
        self.code("AUTHORITY_TOKEN_INVALID", b.settle, "a", ".2")
        self.code("AUTHORITY_TOKEN_INVALID", b.settle, "a", ".2", authority_token="wrong")
        self.assertEqual(b.get("a"), first)
        self.assertEqual(len(events), count)
        self.assertEqual(b.settle("a", ".2", authority_token=token), first)
        self.assertEqual(len(events), count)

    def test_restored_paid_started_snapshot_requires_original_token(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".5")
        _, token = b.start_paid("a")
        restored = self.restored(b)
        self.code("AUTHORITY_TOKEN_INVALID", restored.settle, "a", ".2")
        self.code("AUTHORITY_TOKEN_INVALID", restored.settle, "a", ".2", authority_token="wrong")
        self.assertEqual(restored.get("a").state, STATE_PAID_STARTED)
        self.assertEqual(restored.settle("a", ".2", authority_token=token).state, STATE_SETTLED)

    def test_protected_restore_rejects_plain_snapshot_and_bad_key(self):
        b = GlobalRunBudget(1); b.reserve("a", ".5")
        self.code("SNAPSHOT_AUTH_REQUIRED", GlobalRunBudget.from_snapshot, b.snapshot())
        wrapped = self.authenticated(b)
        self.code("SNAPSHOT_AUTH_INVALID", GlobalRunBudget.from_snapshot, wrapped, authentication_key=WRONG_KEY)
        for bad in (b"", b"short", "not-bytes"):
            self.code("SNAPSHOT_AUTHORITY_INVALID", GlobalRunBudget.from_snapshot, wrapped, authentication_key=bad)

    def test_authenticated_snapshot_roundtrip(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".4", worker_id="w")
        _, token = b.start_paid("a")
        b.settle("a", ".3", authority_token=token)
        c = self.restored(b)
        self.assertEqual(c.cap, b.cap)
        self.assertEqual(c.committed, b.committed)
        self.assertEqual(c.get("a").as_dict(), b.get("a").as_dict())

    def test_paid_started_terminal_forgery_is_rejected_before_refund(self):
        for terminal, fields in (
            (STATE_CANCELLED, {"committedUsd": "0", "measuredUsd": "0", "costKnown": True}),
            (STATE_FAILED, {"committedUsd": "0", "measuredUsd": "0", "costKnown": True}),
            (STATE_SETTLED, {"committedUsd": "0", "measuredUsd": "0", "costKnown": True}),
            (STATE_UNKNOWN, {"committedUsd": ".5", "measuredUsd": None, "costKnown": False}),
            (STATE_RELEASED, {"committedUsd": "0", "measuredUsd": None, "costKnown": True}),
        ):
            with self.subTest(terminal=terminal):
                b = GlobalRunBudget(1); b.reserve("a", ".5"); b.start_paid("a")
                wrapped = self.authenticated(b)
                wrapped["payload"]["records"][0]["state"] = terminal
                wrapped["payload"]["records"][0].update(fields)
                self.code("SNAPSHOT_AUTH_INVALID", GlobalRunBudget.from_snapshot, wrapped, authentication_key=AUTH_KEY)

    def test_complete_snapshot_state_is_authenticated(self):
        b = GlobalRunBudget(3)
        b.reserve("a", ".5", worker_id="w1")
        _, token = b.start_paid("a")
        b.settle("a", ".75", authority_token=token)
        b2 = GlobalRunBudget(3); b2.reserve("x", ".25")
        base = self.authenticated(b)
        mutations = []
        for field, value in (("capUsd", "30"), ("latched", False), ("latchReason", None)):
            m = copy.deepcopy(base); m["payload"][field] = value; mutations.append(m)
        for field, value in (
            ("state", STATE_CANCELLED), ("reservedUsd", "0.1"), ("committedUsd", "0"),
            ("measuredUsd", "0"), ("costKnown", False), ("workerId", "w2"),
            ("authorityTokenSha256", "0" * 64), ("reason", "changed"),
        ):
            m = copy.deepcopy(base); m["payload"]["records"][0][field] = value; mutations.append(m)
        added = copy.deepcopy(base); added["payload"]["records"].append(b2.snapshot()["records"][0]); mutations.append(added)
        deleted = copy.deepcopy(base); deleted["payload"]["records"].clear(); mutations.append(deleted)
        for m in mutations:
            self.code("SNAPSHOT_AUTH_INVALID", GlobalRunBudget.from_snapshot, m, authentication_key=AUTH_KEY)

    def test_record_reordering_is_authenticated_not_ambiguous(self):
        b = GlobalRunBudget(2); b.reserve("a", ".5"); b.reserve("b", ".5")
        wrapped = self.authenticated(b)
        wrapped["payload"]["records"].reverse()
        self.code("SNAPSHOT_AUTH_INVALID", GlobalRunBudget.from_snapshot, wrapped, authentication_key=AUTH_KEY)

    def test_authenticated_wrapper_shape_and_mac_are_strict(self):
        b = GlobalRunBudget(1); wrapped = self.authenticated(b)
        for mutate in (
            lambda x: x.update(extra=True),
            lambda x: x.update(authSchema=2),
            lambda x: x.update(algorithm="sha256"),
            lambda x: x.update(mac="A" * 64),
            lambda x: x.update(mac="0" * 63),
        ):
            candidate = copy.deepcopy(wrapped); mutate(candidate)
            self.code("SNAPSHOT_AUTH_INVALID", GlobalRunBudget.from_snapshot, candidate, authentication_key=AUTH_KEY)

    def test_journal_veto_is_atomic(self):
        def journal(event):
            if event["op"] == "start_paid":
                raise RuntimeError("disk down")
        b = GlobalRunBudget(1, journal=journal)
        b.reserve("a", ".4")
        with self.assertRaises(RuntimeError):
            b.start_paid("a")
        self.assertEqual(b.get("a").state, "RESERVED")

    def test_authenticated_tampered_over_cap_latch_removal_rejected(self):
        b = GlobalRunBudget(1)
        b.reserve("a", ".5")
        _, token = b.start_paid("a")
        b.settle("a", "2", authority_token=token)
        wrapped = self.authenticated(b)
        wrapped["payload"]["latched"] = False
        wrapped["payload"]["latchReason"] = None
        self.code("SNAPSHOT_AUTH_INVALID", GlobalRunBudget.from_snapshot, wrapped, authentication_key=AUTH_KEY)

    def test_concurrent_reserve_never_exceeds_cap(self):
        b = GlobalRunBudget(1)
        barrier = threading.Barrier(20)
        success = []
        lock = threading.Lock()
        def run(i):
            barrier.wait()
            try:
                b.reserve(f"r{i}", ".1")
                with lock: success.append(i)
            except RunBudgetError as e:
                self.assertEqual(e.code, "BUDGET_EXCEEDED")
        threads = [threading.Thread(target=run, args=(i,)) for i in range(20)]
        for t in threads:t.start()
        for t in threads:t.join()
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
                with lock: outcomes.append(out)
            def releaser():
                barrier.wait()
                try:
                    b.release("a")
                    out = "release"
                except RunBudgetError as e:
                    out = e.code
                with lock: outcomes.append(out)
            t1=threading.Thread(target=starter);t2=threading.Thread(target=releaser)
            t1.start();t2.start();t1.join();t2.join()
            self.assertEqual(len(outcomes),2)
            self.assertIn(b.get("a").state, {STATE_PAID_STARTED, STATE_RELEASED})
            if b.get("a").state == STATE_PAID_STARTED:
                self.assertIn("start", outcomes);self.assertIn("PAID_WORK_STARTED", outcomes)
            else:
                self.assertIn("release", outcomes);self.assertIn("RESERVATION_CONFLICT", outcomes)

    def test_duplicate_terminal_same_cost_is_idempotent(self):
        b=GlobalRunBudget(1);b.reserve("a",.5);_,t=b.start_paid("a")
        first=b.settle("a",.2,authority_token=t)
        self.assertEqual(b.settle("a",.2,authority_token=t), first)

    def test_duplicate_terminal_different_cost_fails(self):
        b=GlobalRunBudget(1);b.reserve("a",.5);_,t=b.start_paid("a");b.settle("a",.2,authority_token=t)
        self.code("PAID_WORK_NOT_STARTED", b.settle, "a", .3, authority_token=t)

    def test_snapshot_individual_overrun_cannot_unlatch_even_under_global_cap(self):
        b = GlobalRunBudget(10)
        b.reserve("a", "1")
        _, token = b.start_paid("a")
        b.settle("a", "2", authority_token=token)
        wrapped = self.authenticated(b)
        wrapped["payload"]["latched"] = False; wrapped["payload"]["latchReason"] = None
        self.code("SNAPSHOT_AUTH_INVALID", GlobalRunBudget.from_snapshot, wrapped, authentication_key=AUTH_KEY)

    def test_snapshot_released_record_cannot_claim_spend(self):
        b = GlobalRunBudget(10); b.reserve("a", "1"); b.release("a")
        wrapped=self.authenticated(b); wrapped["payload"]["records"][0]["committedUsd"]="0.5"
        self.code("SNAPSHOT_AUTH_INVALID", GlobalRunBudget.from_snapshot, wrapped, authentication_key=AUTH_KEY)

    def test_journal_sees_latch_reason_before_overrun_mutation(self):
        events=[]
        b=GlobalRunBudget(10,journal=events.append);b.reserve("a",1);_,token=b.start_paid("a")
        b.settle("a",2,authority_token=token)
        self.assertEqual(events[-1]["latchReason"], "reservation-overrun")
        self.assertTrue(b.latched)


if __name__ == "__main__":
    unittest.main()
