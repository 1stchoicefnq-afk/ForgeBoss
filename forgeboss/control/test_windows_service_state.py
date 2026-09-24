from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from forgeboss.control.windows_service_state import (
    PrivateAclPlan,
    ServicePrivateStateError,
    apply_private_directory_acl,
    build_private_acl_plan,
    default_private_root,
    inspect_private_directory_acl,
    validate_service_sid,
    verify_private_acl_exact,
)


SERVICE_SID = "S-1-5-80-111-222-333-444-555"
DESKTOP_SID = "S-1-5-21-100-200-300-1001"


class WindowsServicePrivateStateTests(unittest.TestCase):
    def test_service_sid_must_be_service_namespace_and_distinct(self):
        self.assertEqual(
            validate_service_sid(SERVICE_SID, desktop_sid=DESKTOP_SID),
            SERVICE_SID,
        )
        for bad in (
            "S-1-1-0",
            "S-1-5-11",
            "S-1-5-32-545",
            DESKTOP_SID,
            "not-a-sid",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ServicePrivateStateError):
                    validate_service_sid(bad, desktop_sid=DESKTOP_SID)

    def test_plan_allows_only_service_system_and_admins(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            plan = build_private_acl_plan(
                SERVICE_SID,
                desktop_sid=DESKTOP_SID,
                root=root,
            )
        self.assertEqual(
            plan.allowed_sids,
            (
                SERVICE_SID,
                "S-1-5-18",
                "S-1-5-32-544",
            ),
        )
        self.assertNotIn(DESKTOP_SID, plan.allowed_sids)
        self.assertTrue(plan.inheritance_protected)
        self.assertIn("S-1-1-0", plan.denied_broad_sids)
        self.assertIn("S-1-5-11", plan.denied_broad_sids)
        self.assertIn("S-1-5-32-545", plan.denied_broad_sids)

    def test_exact_acl_verifier_rejects_broad_extra_or_missing_principals(self):
        plan = build_private_acl_plan(
            SERVICE_SID,
            desktop_sid=DESKTOP_SID,
            root=Path.cwd().resolve(),
        )
        self.assertTrue(verify_private_acl_exact(plan, plan.allowed_sids))

        for actual in (
            plan.allowed_sids + ("S-1-1-0",),
            plan.allowed_sids + (DESKTOP_SID,),
            plan.allowed_sids[:-1],
        ):
            with self.subTest(actual=actual):
                with self.assertRaises(ServicePrivateStateError):
                    verify_private_acl_exact(plan, actual)

    @unittest.skipIf(os.name == "nt", "non-Windows fail-closed test")
    def test_windows_acl_functions_are_inert_off_windows(self):
        with self.assertRaisesRegex(
            ServicePrivateStateError,
            "unavailable on this platform",
        ):
            default_private_root()
        with self.assertRaisesRegex(
            ServicePrivateStateError,
            "unavailable on this platform",
        ):
            apply_private_directory_acl(
                SERVICE_SID,
                desktop_sid=DESKTOP_SID,
                root=Path.cwd().resolve(),
            )
        with self.assertRaisesRegex(
            ServicePrivateStateError,
            "unavailable on this platform",
        ):
            inspect_private_directory_acl(Path.cwd().resolve())


if __name__ == "__main__":
    unittest.main()
