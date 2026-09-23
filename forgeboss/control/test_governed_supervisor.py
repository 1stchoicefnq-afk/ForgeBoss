from __future__ import annotations

import unittest

from forgeboss.control.governed_supervisor import _BoundedText, GovernedSupervisorError


class GovernedSupervisorTests(unittest.TestCase):
    def test_bounded_output_keeps_tail(self):
        b=_BoundedText(10)
        b.append("12345")
        b.append("67890")
        b.append("ABCDE")
        self.assertEqual(b.value(),"67890ABCDE")

    def test_invalid_poll_interval_fails_closed_without_launch(self):
        class D: pass
        with self.assertRaises(GovernedSupervisorError):
            from forgeboss.control.governed_supervisor import supervise_governed_run
            supervise_governed_run(
                D(), task_id="T", packet_path="missing", workspace_path="missing",
                allowed_tools=[], adapter="mini-swe", provider="openai", model="m",
                budget_usd=1, poll_seconds=0,
            )

    def test_non_miniswe_is_not_supported_in_r0(self):
        class D: pass
        with self.assertRaisesRegex(GovernedSupervisorError,"mini-swe only"):
            from forgeboss.control.governed_supervisor import supervise_governed_run
            supervise_governed_run(
                D(), task_id="T", packet_path="missing", workspace_path="missing",
                allowed_tools=[], adapter="openhands", provider="openai", model="m",
                budget_usd=1,
            )


if __name__=="__main__":
    unittest.main()
