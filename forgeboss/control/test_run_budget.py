from __future__ import annotations
import ast, dataclasses, inspect, random, threading, time, unittest
from decimal import Decimal

from forgeboss.control.run_budget import (
    GlobalRunBudget, Reservation, RunBudgetError,
    STATE_OVERRUN, STATE_RELEASED, STATE_RESERVED, STATE_SETTLED,
)

MALFORMED = (
    float("nan"), float("inf"), float("-inf"), Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity"),
    -1, -0.01, "-0.01", "nan", "inf", "Infinity", "abc", "", " 1.00 ", "1_0", "1,00", "$1.00",
    None, True, False, [], {}, (), object(), b"1.00", complex(1, 0), "1e400", "1E+400",
)


class BudgetTestCase(unittest.TestCase):
    def assert_code(self, code, fn, *args, **kwargs):
        with self.assertRaises(RunBudgetError) as ctx:fn(*args, **kwargs)
        self.assertEqual(ctx.exception.code, code)
        return ctx.exception

    def assert_consistent(self, budget):
        """The ledger must always balance and never exceed the cap."""
        records = budget.reservations()
        self.assertEqual(budget.outstanding, sum((r.outstanding for r in records), Decimal(0)))
        self.assertEqual(budget.committed, sum((r.committed for r in records), Decimal(0)))
        self.assertGreaterEqual(budget.outstanding, 0)
        self.assertGreaterEqual(budget.committed, 0)
        self.assertGreaterEqual(budget.remaining, 0)
        self.assertLessEqual(budget.committed + budget.outstanding, budget.cap)
        for r in records:
            if r.state == STATE_RESERVED:
                self.assertEqual((r.committed, r.released), (Decimal(0), Decimal(0)))
            else:
                self.assertLessEqual(r.committed, r.reserved)
                self.assertEqual(r.committed + r.released, r.reserved)


class CapEstablishmentTests(BudgetTestCase):
    def test_cap_must_be_finite_non_negative(self):
        for value in MALFORMED:
            with self.subTest(cap=repr(value)):
                self.assert_code("BUDGET_CAP_INVALID", GlobalRunBudget, value)

    def test_cap_accepts_int_float_str_and_decimal(self):
        for value, expected in ((5, "5"), (5.5, "5.5"), ("5.50", "5.50"), (Decimal("5.50"), "5.50"), (0, "0")):
            with self.subTest(cap=repr(value)):
                budget = GlobalRunBudget(value)
                self.assertEqual(budget.cap, Decimal(expected))
                self.assertEqual((budget.committed, budget.outstanding), (Decimal(0), Decimal(0)))
                self.assertEqual(budget.remaining, Decimal(expected))
                self.assertFalse(budget.breached)

    def test_zero_cap_authorises_only_zero_cost_work(self):
        budget = GlobalRunBudget(0)
        self.assertEqual(budget.reserve("r0", 0).reserved, Decimal(0))
        self.assert_code("BUDGET_EXCEEDED", budget.reserve, "r1", "0.01")
        self.assert_consistent(budget)


class ReservationBoundaryTests(BudgetTestCase):
    def test_reservations_may_consume_the_cap_exactly(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60", worker_id="w1")
        budget.reserve("b", "0.40", worker_id="w2")
        self.assertEqual(budget.remaining, Decimal("0.00"))
        self.assertEqual(budget.outstanding, Decimal("1.00"))
        self.assert_consistent(budget)

    def test_one_cent_over_the_cap_is_rejected(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "1.00")
        error = self.assert_code("BUDGET_EXCEEDED", budget.reserve, "b", "0.01")
        self.assertIn("exceeds remaining global authority", str(error))
        self.assert_consistent(budget)

    def test_epsilon_over_the_cap_is_rejected(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.999999")
        self.assert_code("BUDGET_EXCEEDED", budget.reserve, "b", "0.000002")
        self.assertEqual(budget.reserve("c", "0.000001").reserved, Decimal("0.000001"))
        self.assertEqual(budget.remaining, Decimal("0.000000"))
        self.assert_consistent(budget)

    def test_binary_float_artifacts_do_not_false_reject_exact_cap(self):
        budget = GlobalRunBudget(0.3)
        for index in range(3):
            budget.reserve(f"r{index}", 0.1)
        self.assertEqual(budget.remaining, Decimal("0.0"))
        self.assert_code("BUDGET_EXCEEDED", budget.reserve, "over", "0.000001")
        self.assert_consistent(budget)

    def test_rejected_reservation_consumes_no_authority(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.75")
        self.assert_code("BUDGET_EXCEEDED", budget.reserve, "b", "0.26")
        for index, value in enumerate(MALFORMED):
            self.assert_code("BUDGET_INVALID", budget.reserve, f"bad-{index}", value)
        self.assertIsNone(budget.get("b"))
        self.assertEqual(budget.remaining, Decimal("0.25"))
        self.assertEqual(len(budget.reservations()), 1)
        self.assert_consistent(budget)

    def test_reservation_amount_must_be_finite_non_negative(self):
        budget = GlobalRunBudget("10.00")
        for value in MALFORMED:
            with self.subTest(amount=repr(value)):
                self.assert_code("BUDGET_INVALID", budget.reserve, "r", value)
        self.assertEqual(budget.reservations(), ())
        self.assert_consistent(budget)

    def test_identifiers_must_be_sane_strings(self):
        budget = GlobalRunBudget("10.00")
        for bad in ("", " ", " r", "r ", None, 1, b"r", ["r"], "x" * 257):
            with self.subTest(identifier=repr(bad)):
                self.assert_code("IDENTIFIER_INVALID", budget.reserve, bad, "1.00")
                self.assert_code("IDENTIFIER_INVALID", budget.get, bad)
                if bad is not None:  # worker_id is optional, every other malformed value is rejected
                    self.assert_code("IDENTIFIER_INVALID", budget.reserve, "ok", "1.00", bad)
                self.assert_code("IDENTIFIER_INVALID", budget.reserved_for_worker, bad)
        self.assertEqual(budget.reservations(), ())

    def test_per_worker_outstanding_is_tracked(self):
        budget = GlobalRunBudget("10.00")
        budget.reserve("a", "1.00", worker_id="w1")
        budget.reserve("b", "2.00", worker_id="w1")
        budget.reserve("c", "3.00", worker_id="w2")
        self.assertEqual(budget.reserved_for_worker("w1"), Decimal("3.00"))
        self.assertEqual(budget.reserved_for_worker("w2"), Decimal("3.00"))
        self.assertEqual(budget.reserved_for_worker("absent"), Decimal(0))
        budget.release("b")
        self.assertEqual(budget.reserved_for_worker("w1"), Decimal("1.00"))
        self.assert_consistent(budget)


class DuplicateOperationTests(BudgetTestCase):
    def test_duplicate_reserve_with_identical_arguments_is_idempotent(self):
        budget = GlobalRunBudget("1.00")
        first = budget.reserve("a", "0.60", worker_id="w1")
        second = budget.reserve("a", "0.60", worker_id="w1")
        self.assertEqual(first, second)
        self.assertEqual(budget.outstanding, Decimal("0.60"))
        self.assertEqual(len(budget.reservations()), 1)
        self.assert_consistent(budget)

    def test_duplicate_reserve_with_different_arguments_fails_closed(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60", worker_id="w1")
        self.assert_code("RESERVATION_CONFLICT", budget.reserve, "a", "0.10", "w1")
        self.assert_code("RESERVATION_CONFLICT", budget.reserve, "a", "0.60", "w2")
        self.assert_code("RESERVATION_CONFLICT", budget.reserve, "a", "0.60")
        self.assertEqual(budget.outstanding, Decimal("0.60"))
        self.assert_consistent(budget)

    def test_reservation_ids_are_never_recycled(self):
        for closer in (lambda b: b.settle("a", "0.10"), lambda b: b.release("a"), lambda b: b.settle_unknown("a")):
            with self.subTest(closer=closer):
                budget = GlobalRunBudget("1.00")
                budget.reserve("a", "0.60")
                closer(budget)
                self.assert_code("RESERVATION_CONFLICT", budget.reserve, "a", "0.60")
                self.assert_consistent(budget)

    def test_duplicate_settle_is_idempotent_only_for_the_same_measured_cost(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60")
        first = budget.settle("a", "0.25")
        self.assertEqual(budget.settle("a", "0.25"), first)
        self.assertEqual(budget.committed, Decimal("0.25"))
        self.assert_code("RESERVATION_CONFLICT", budget.settle, "a", "0.30")
        self.assert_code("RESERVATION_CONFLICT", budget.settle_unknown, "a")
        self.assert_code("RESERVATION_CONFLICT", budget.release, "a")
        self.assertEqual(budget.committed, Decimal("0.25"))
        self.assert_consistent(budget)

    def test_duplicate_release_cannot_mint_budget(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60")
        first = budget.release("a")
        for _ in range(5):
            self.assertEqual(budget.release("a"), first)
        self.assertEqual(budget.remaining, Decimal("1.00"))
        self.assertEqual(budget.committed, Decimal(0))
        self.assertEqual(budget.outstanding, Decimal(0))
        self.assert_consistent(budget)

    def test_duplicate_unknown_settlement_is_idempotent(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60")
        first = budget.settle_unknown("a")
        self.assertEqual(budget.settle_unknown("a"), first)
        self.assertEqual(budget.committed, Decimal("0.60"))
        self.assert_code("RESERVATION_CONFLICT", budget.settle, "a", "0.60")
        self.assert_consistent(budget)

    def test_operations_on_unknown_reservations_fail_closed(self):
        budget = GlobalRunBudget("1.00")
        self.assert_code("RESERVATION_UNKNOWN", budget.settle, "ghost", "0.10")
        self.assert_code("RESERVATION_UNKNOWN", budget.settle_unknown, "ghost")
        self.assert_code("RESERVATION_UNKNOWN", budget.release, "ghost")
        self.assertIsNone(budget.get("ghost"))
        self.assert_consistent(budget)


class SettlementTests(BudgetTestCase):
    def test_partial_settlement_returns_only_the_unused_authority(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60", worker_id="w1")
        record = budget.settle("a", "0.25")
        self.assertEqual(record.state, STATE_SETTLED)
        self.assertEqual((record.committed, record.released), (Decimal("0.25"), Decimal("0.35")))
        self.assertTrue(record.cost_known)
        self.assertEqual(budget.remaining, Decimal("0.75"))
        self.assertEqual(budget.outstanding, Decimal(0))
        self.assert_consistent(budget)

    def test_exact_settlement_releases_nothing(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60")
        record = budget.settle("a", "0.60")
        self.assertEqual((record.committed, record.released), (Decimal("0.60"), Decimal("0.00")))
        self.assertEqual(budget.remaining, Decimal("0.40"))
        self.assert_consistent(budget)

    def test_zero_settlement_returns_the_whole_reservation(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60")
        record = budget.settle("a", 0)
        self.assertEqual((record.committed, record.released), (Decimal(0), Decimal("0.60")))
        self.assertEqual(budget.remaining, Decimal("1.00"))
        self.assert_consistent(budget)

    def test_unknown_cost_cannot_silently_release_authority(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60")
        for value in MALFORMED:
            with self.subTest(cost=repr(value)):
                self.assert_code("BUDGET_INVALID", budget.settle, "a", value)
                self.assertEqual(budget.get("a").state, STATE_RESERVED)
                self.assertEqual(budget.outstanding, Decimal("0.60"))
                self.assertEqual(budget.remaining, Decimal("0.40"))
        self.assert_consistent(budget)

    def test_explicit_unknown_settlement_commits_the_whole_reservation(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60")
        record = budget.settle_unknown("a")
        self.assertEqual(record.state, STATE_SETTLED)
        self.assertFalse(record.cost_known)
        self.assertIsNone(record.measured)
        self.assertEqual((record.committed, record.released), (Decimal("0.60"), Decimal(0)))
        self.assertEqual(budget.remaining, Decimal("0.40"))
        self.assert_consistent(budget)

    def test_overrun_settlement_is_a_hard_failure_that_latches_the_budget(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60")
        budget.reserve("b", "0.20")
        error = self.assert_code("SETTLEMENT_EXCEEDS_RESERVATION", budget.settle, "a", "0.61")
        self.assertIn("exceeds reserved authority", str(error))
        record = budget.get("a")
        self.assertEqual(record.state, STATE_OVERRUN)
        self.assertEqual(record.committed, Decimal("0.60"))
        self.assertEqual(record.released, Decimal(0))
        self.assertEqual(record.measured, Decimal("0.61"))
        self.assertEqual(record.unbilled_overrun, Decimal("0.01"))
        self.assertTrue(budget.breached)
        self.assertEqual(budget.breach_reason, str(error))
        self.assert_code("BUDGET_BREACHED", budget.reserve, "c", "0.01")
        self.assert_code("BUDGET_BREACHED", budget.reserve, "c", 0)
        self.assert_consistent(budget)

    def test_overrun_reservation_is_terminal(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60")
        self.assert_code("SETTLEMENT_EXCEEDS_RESERVATION", budget.settle, "a", "5.00")
        for op in (lambda: budget.settle("a", "0.10"), lambda: budget.settle_unknown("a"), lambda: budget.release("a")):
            self.assert_code("RESERVATION_CONFLICT", op)
        self.assertEqual(budget.committed, Decimal("0.60"))
        self.assert_consistent(budget)

    def test_breached_budget_still_permits_closing_open_reservations(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60")
        budget.reserve("b", "0.20")
        self.assert_code("SETTLEMENT_EXCEEDS_RESERVATION", budget.settle, "a", "0.61")
        self.assertEqual(budget.release("b").state, STATE_RELEASED)
        self.assertEqual(budget.outstanding, Decimal(0))
        self.assertEqual(budget.committed, Decimal("0.60"))
        self.assert_consistent(budget)

    def test_idempotent_reserve_replay_survives_a_breach(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.30")
        budget.reserve("b", "0.30")
        self.assert_code("SETTLEMENT_EXCEEDS_RESERVATION", budget.settle, "a", "0.40")
        self.assertEqual(budget.reserve("b", "0.30").state, STATE_RESERVED)
        self.assertEqual(budget.outstanding, Decimal("0.30"))
        self.assert_consistent(budget)


class CancellationTests(BudgetTestCase):
    def test_cancelled_worker_releases_only_unused_authority(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60", worker_id="w1")
        budget.settle("a", "0.10")
        budget.reserve("b", "0.30", worker_id="w1")
        record = budget.release("b")
        self.assertEqual(record.state, STATE_RELEASED)
        self.assertEqual((record.committed, record.released), (Decimal(0), Decimal("0.30")))
        self.assertEqual(budget.committed, Decimal("0.10"))
        self.assertEqual(budget.remaining, Decimal("0.90"))
        self.assert_consistent(budget)

    def test_release_after_settlement_fails_closed(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60")
        budget.settle("a", "0.60")
        self.assert_code("RESERVATION_CONFLICT", budget.release, "a")
        self.assertEqual(budget.committed, Decimal("0.60"))
        self.assert_consistent(budget)

    def test_reserve_release_cycles_never_grow_the_pool(self):
        budget = GlobalRunBudget("1.00")
        for index in range(50):
            budget.reserve(f"r{index}", "1.00")
            budget.release(f"r{index}")
            self.assertEqual(budget.remaining, Decimal("1.00"))
            self.assert_consistent(budget)
        self.assertEqual(budget.committed, Decimal(0))


class ApiSurfaceTests(BudgetTestCase):
    def test_reservation_records_are_immutable(self):
        budget = GlobalRunBudget("1.00")
        record = budget.reserve("a", "0.60")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.reserved = Decimal("1.00")
        self.assertEqual(budget.get("a").reserved, Decimal("0.60"))

    def test_snapshot_and_record_serialisation(self):
        budget = GlobalRunBudget("1.00")
        budget.reserve("a", "0.60", worker_id="w1")
        budget.reserve("b", "0.10", worker_id="w2")
        budget.settle("b", "0.05")
        self.assertEqual(budget.snapshot(), {
            "capUsd": "1.00", "committedUsd": "0.05", "outstandingUsd": "0.60", "remainingUsd": "0.35",
            "reservationCount": 2, "outstandingCount": 1, "breached": False, "breachReason": None,
        })
        self.assertEqual(budget.get("b").as_dict(), {
            "reservationId": "b", "workerId": "w2", "state": STATE_SETTLED, "reservedUsd": "0.10",
            "committedUsd": "0.05", "releasedUsd": "0.05", "measuredUsd": "0.05", "costKnown": True,
            "unbilledOverrunUsd": "0",
        })

    def test_public_api_is_small_and_stable(self):
        expected = {"cap", "committed", "outstanding", "remaining", "breached", "breach_reason",
                    "get", "reservations", "reserved_for_worker", "snapshot",
                    "reserve", "settle", "settle_unknown", "release"}
        actual = {name for name in vars(GlobalRunBudget) if not name.startswith("_")}
        self.assertEqual(actual, expected)
        self.assertEqual(list(inspect.signature(GlobalRunBudget.reserve).parameters),
                         ["self", "reservation_id", "amount_usd", "worker_id"])
        self.assertEqual(list(inspect.signature(GlobalRunBudget.settle).parameters),
                         ["self", "reservation_id", "measured_cost_usd"])
        self.assertTrue(dataclasses.is_dataclass(Reservation))

    def test_module_is_not_integrated_with_the_rest_of_forgeboss(self):
        """FB-050 ships the primitive only; wiring it into daemon/store is a later packet."""
        import forgeboss.control.run_budget as module
        tree = ast.parse(inspect.getsource(module))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, "run_budget.py must not use relative imports")
                imported.add(node.module)
        self.assertEqual(imported, {"__future__", "math", "threading", "dataclasses", "decimal"})


class ConcurrencyTests(BudgetTestCase):
    def _hammer(self, worker, count):
        barrier = threading.Barrier(count)
        results, errors = [], []

        def run(index):
            barrier.wait()
            try:results.append(worker(index))
            except RunBudgetError as ex:errors.append(ex)
            except BaseException as ex:  # pragma: no cover - surfaced by assertions below
                errors.append(ex)

        threads = [threading.Thread(target=run, args=(i,)) for i in range(count)]
        for t in threads:t.start()
        for t in threads:t.join(30)
        self.assertFalse(any(t.is_alive() for t in threads), "hostile reservation threads deadlocked")
        return results, errors

    def test_simultaneous_reservations_cannot_jointly_exceed_the_cap(self):
        budget = GlobalRunBudget("10.00")
        results, errors = self._hammer(lambda i: budget.reserve(f"r{i}", "1.00", worker_id=f"w{i}"), 64)
        self.assertEqual(len(results), 10)
        self.assertTrue(all(isinstance(e, RunBudgetError) and e.code == "BUDGET_EXCEEDED" for e in errors),
                        [getattr(e, "code", repr(e)) for e in errors])
        self.assertEqual(len(errors), 54)
        self.assertEqual(budget.outstanding, Decimal("10.00"))
        self.assertEqual(budget.remaining, Decimal("0.00"))
        self.assert_consistent(budget)

    def test_simultaneous_reservations_with_indivisible_amounts_leave_a_remainder(self):
        budget = GlobalRunBudget("1.00")
        results, errors = self._hammer(lambda i: budget.reserve(f"r{i}", "0.07"), 32)
        self.assertEqual(len(results), 14)
        self.assertEqual(budget.outstanding, Decimal("0.98"))
        self.assertEqual(budget.remaining, Decimal("0.02"))
        self.assertTrue(all(e.code == "BUDGET_EXCEEDED" for e in errors))
        self.assert_consistent(budget)

    def test_simultaneous_duplicate_reservation_ids_grant_authority_once(self):
        budget = GlobalRunBudget("10.00")
        results, errors = self._hammer(lambda i: budget.reserve("shared", "1.00", worker_id="w1"), 32)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 32)
        self.assertEqual({r.reservation_id for r in results}, {"shared"})
        self.assertEqual(budget.outstanding, Decimal("1.00"))
        self.assertEqual(len(budget.reservations()), 1)
        self.assert_consistent(budget)

    def test_simultaneous_settle_and_release_of_one_reservation_stays_consistent(self):
        for attempt in range(20):
            budget = GlobalRunBudget("1.00")
            budget.reserve("a", "0.60")
            results, errors = self._hammer(
                lambda i: budget.settle("a", "0.20") if i % 2 else budget.release("a"), 8)
            states = {r.state for r in results}
            self.assertEqual(len(states), 1, f"attempt {attempt}: divergent terminal states {states}")
            self.assertIn(states.pop(), (STATE_SETTLED, STATE_RELEASED))
            self.assertTrue(all(e.code == "RESERVATION_CONFLICT" for e in errors),
                            [getattr(e, "code", repr(e)) for e in errors])
            self.assertIn(budget.committed, (Decimal("0.20"), Decimal(0)))
            self.assertEqual(budget.outstanding, Decimal(0))
            self.assert_consistent(budget)

    def test_hostile_mixed_churn_preserves_the_global_invariant(self):
        budget = GlobalRunBudget("5.00")
        stop = threading.Event()
        failures = []

        def churn(seed):
            rng = random.Random(seed)
            for step in range(200):
                if stop.is_set():return
                rid = f"s{seed}-{step}"
                try:budget.reserve(rid, "0.05", worker_id=f"w{seed}")
                except RunBudgetError as ex:
                    if ex.code != "BUDGET_EXCEEDED":failures.append(ex)
                    continue
                try:
                    choice = rng.random()
                    if choice < 0.4:budget.settle(rid, "0.05")
                    elif choice < 0.7:budget.settle(rid, "0.01")
                    elif choice < 0.9:budget.release(rid)
                    else:budget.settle_unknown(rid)
                except RunBudgetError as ex:failures.append(ex)

        def audit():
            while not stop.is_set():
                if budget.committed + budget.outstanding > budget.cap or budget.remaining < 0:
                    failures.append(AssertionError(f"invariant breached: {budget.snapshot()}"))
                    return
                time.sleep(0.001)

        threads = [threading.Thread(target=churn, args=(seed,)) for seed in range(8)]
        auditor = threading.Thread(target=audit)
        auditor.start()
        for t in threads:t.start()
        for t in threads:t.join(60)
        stop.set();auditor.join(10)
        self.assertFalse(any(t.is_alive() for t in threads), "churn threads deadlocked")
        self.assertEqual([str(f) for f in failures], [])
        self.assertFalse(budget.breached, budget.breach_reason)
        self.assert_consistent(budget)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
