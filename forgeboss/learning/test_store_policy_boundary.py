from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forgeboss.learning.store import LearningStore


class LearningStorePolicyBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store = LearningStore(Path(self.td.name) / "learning.sqlite3")

    def tearDown(self):
        self.store.db.close()
        self.td.cleanup()

    def _record(self, validation, *, reusable=True, partial_proven=False, evidence=None):
        return self.store.record_verified_lesson(
            "project-a",
            "python-test",
            "summary",
            {"replace": "x"},
            {"case": "same"} if evidence is None else evidence,
            validation,
            confidence=0.9,
            reusable=reusable,
            partial_proven=partial_proven,
        )

    def _row(self, lesson_id):
        return dict(self.store.db.execute("SELECT * FROM lessons WHERE lesson_id=?", (lesson_id,)).fetchone())

    def test_all_required_passed_can_be_reusable(self):
        lid = self._record({"all_required_passed": True, "introduced_regression": False})
        self.assertEqual(self._row(lid)["reusable"], 1)
        self.assertEqual(len(self.store.find_reusable("project-a", "python-test")), 1)

    def test_regression_cannot_be_forced_reusable(self):
        lid = self._record({"all_required_passed": True, "introduced_regression": True}, reusable=True)
        self.assertEqual(self._row(lid)["reusable"], 0)
        self.assertEqual(self.store.find_reusable("project-a", "python-test"), [])

    def test_unproven_cannot_be_forced_reusable(self):
        lid = self._record({"all_required_passed": False, "focused_target_passed": False}, reusable=True)
        self.assertEqual(self._row(lid)["reusable"], 0)

    def test_partial_proven_requires_explicit_boundary_authority(self):
        validation = {"all_required_passed": False, "focused_target_passed": True, "introduced_regression": False}
        lid = self._record(validation, partial_proven=False, evidence={"case": "partial-off"})
        self.assertEqual(self._row(lid)["reusable"], 0)
        lid2 = self._record(validation, partial_proven=True, evidence={"case": "partial-on"})
        self.assertEqual(self._row(lid2)["reusable"], 1)

    def test_caller_can_opt_out_even_when_policy_allows(self):
        lid = self._record({"all_required_passed": True}, reusable=False)
        self.assertEqual(self._row(lid)["reusable"], 0)

    def test_later_regression_demotes_existing_reusable_lesson(self):
        good = {"all_required_passed": True, "introduced_regression": False}
        bad = {"all_required_passed": True, "introduced_regression": True}
        lid = self._record(good)
        self.assertEqual(self._row(lid)["reusable"], 1)
        same = self._record(bad, reusable=True)
        self.assertEqual(same, lid)
        row = self._row(lid)
        self.assertEqual(row["reusable"], 0)
        self.assertEqual(row["success_count"], 2)

    def test_invalid_boolean_authority_fails_before_insert(self):
        for reusable, partial in (("yes", False), (True, 1)):
            with self.subTest(reusable=reusable, partial=partial):
                with self.assertRaises(ValueError):
                    self._record({"all_required_passed": True}, reusable=reusable, partial_proven=partial,
                                 evidence={"case": f"{reusable}-{partial}"})
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0], 0)

    def test_invalid_confidence_fails_closed(self):
        for value in (float("nan"), float("inf"), -0.1, 1.1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.store.record_verified_lesson(
                        "project-a", "python-test", "summary", {}, {"case": str(value)},
                        {"all_required_passed": True}, confidence=value, reusable=True
                    )
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
