from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from forgeboss.control.windows_service_bootstrap import (
    BOOTSTRAP_SOURCE_ROOT_FILE,
    BOOTSTRAP_STATUS,
    ServiceBootstrapError,
    load_bootstrap_source_root,
    perform_bootstrap_activation,
)
from forgeboss.control.windows_state_migration import CANDIDATE_DIR


SERVICE_SID = "S-1-5-80-1-2-3-4-5"
DESKTOP_SID = "S-1-5-21-100-200-300-1001"
SOURCE_ROOT = r"C:\ForgeBoss\state\forgebossd"


class BootstrapSourceConfigTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.private = Path(self.td.name)
        self.config = self.private / BOOTSTRAP_SOURCE_ROOT_FILE

    def test_accepts_one_local_absolute_windows_path(self):
        self.config.write_text(SOURCE_ROOT + "\n", encoding="utf-8")
        self.assertEqual(
            load_bootstrap_source_root(self.private),
            SOURCE_ROOT,
        )

    def test_rejects_relative_unc_whitespace_controls_and_oversize(self):
        bad_values = (
            r"state\forgebossd",
            r"\\server\share\forgeboss",
            " C:\\ForgeBoss\\state",
            "C:\\ForgeBoss\\state ",
            "C:\\ForgeBoss\x00state",
            "C:\\ForgeBoss\\..\\state",
            "C:\\ForgeBoss\nsecond",
        )
        for value in bad_values:
            with self.subTest(value=value):
                self.config.write_text(value, encoding="utf-8")
                with self.assertRaises(ServiceBootstrapError):
                    load_bootstrap_source_root(self.private)

        self.config.write_bytes(b"x" * 4097)
        with self.assertRaisesRegex(ServiceBootstrapError, "size is invalid"):
            load_bootstrap_source_root(self.private)

    def test_rejects_symlink_and_hardlink_config_when_supported(self):
        target = self.private / "target.txt"
        target.write_text(SOURCE_ROOT, encoding="utf-8")

        link = self.private / "link.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            link = None
        if link is not None:
            original = self.config
            try:
                original.symlink_to(target)
                with self.assertRaisesRegex(
                    ServiceBootstrapError,
                    "linklike/reparse",
                ):
                    load_bootstrap_source_root(self.private)
            finally:
                try:
                    original.unlink()
                except OSError:
                    pass
                try:
                    link.unlink()
                except OSError:
                    pass

        self.config.write_text(SOURCE_ROOT, encoding="utf-8")
        alias = self.private / "hardlink.txt"
        try:
            os.link(self.config, alias)
        except (OSError, NotImplementedError):
            self.skipTest("hard links unavailable")
        with self.assertRaisesRegex(ServiceBootstrapError, "hard-linked"):
            load_bootstrap_source_root(self.private)


class BootstrapActivationFlowTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.private = Path(self.td.name)
        (self.private / BOOTSTRAP_SOURCE_ROOT_FILE).write_text(
            SOURCE_ROOT,
            encoding="utf-8",
        )
        self.verified = SimpleNamespace(
            source_root=SOURCE_ROOT,
            migration_manifest_sha256="a" * 64,
            schema_version=5,
        )
        self.activated = SimpleNamespace(
            migration_manifest_sha256="a" * 64,
            schema_version=5,
        )

    def patches(self, *, active=None):
        return (
            mock.patch(
                "forgeboss.control.windows_service_bootstrap._require_windows"
            ),
            mock.patch(
                "forgeboss.control.windows_service_bootstrap.load_optional_verified_active_state",
                return_value=active,
            ),
            mock.patch(
                "forgeboss.control.windows_service_bootstrap.verify_unrestricted_service_sid",
                return_value=SimpleNamespace(service_sid=SERVICE_SID),
            ),
            mock.patch(
                "forgeboss.control.windows_service_bootstrap.verify_candidate_copy",
                return_value=self.verified,
            ),
            mock.patch(
                "forgeboss.control.windows_service_bootstrap.copy_verified_state"
            ),
            mock.patch(
                "forgeboss.control.windows_service_bootstrap.activate_verified_state",
                return_value=self.activated,
            ),
        )

    def test_existing_candidate_is_verified_not_overwritten(self):
        (self.private / CANDIDATE_DIR).mkdir()
        p = self.patches()
        with p[0], p[1], p[2], p[3] as verify, p[4] as copy, p[5] as activate:
            result = perform_bootstrap_activation(
                private_root=self.private,
                desktop_sid=DESKTOP_SID,
            )
        self.assertTrue(verify.called)
        copy.assert_not_called()
        activate.assert_called_once()
        self.assertEqual(result["status"], BOOTSTRAP_STATUS)
        self.assertTrue(result["restartRequired"])
        self.assertNotIn("candidateSecrets", result)
        self.assertNotIn("sourceSecrets", result)

    def test_missing_candidate_uses_copy_then_reverifies(self):
        p = self.patches()
        with p[0], p[1], p[2], p[3] as verify, p[4] as copy, p[5]:
            result = perform_bootstrap_activation(
                private_root=self.private,
                desktop_sid=DESKTOP_SID,
            )
        copy.assert_called_once()
        verify.assert_called_once()
        self.assertEqual(result["migrationManifestSha256"], "a" * 64)

    def test_cancel_before_start_refuses_without_copy_or_activation(self):
        p = self.patches()
        with p[0], p[1], p[2], p[3], p[4] as copy, p[5] as activate:
            with self.assertRaisesRegex(ServiceBootstrapError, "cancelled"):
                perform_bootstrap_activation(
                    private_root=self.private,
                    desktop_sid=DESKTOP_SID,
                    cancelled=lambda: True,
                )
        copy.assert_not_called()
        activate.assert_not_called()

    def test_stop_after_copy_leaves_candidate_but_withholds_activation(self):
        states = iter((False, True))
        p = self.patches()
        with p[0], p[1], p[2], p[3] as verify, p[4] as copy, p[5] as activate:
            with self.assertRaisesRegex(ServiceBootstrapError, "cancelled"):
                perform_bootstrap_activation(
                    private_root=self.private,
                    desktop_sid=DESKTOP_SID,
                    cancelled=lambda: next(states),
                )
        copy.assert_called_once()
        verify.assert_called_once()
        activate.assert_not_called()

    def test_already_active_refuses_before_copy_or_activation(self):
        active = SimpleNamespace(status="ACTIVE_VERIFIED_STATE")
        p = self.patches(active=active)
        with p[0], p[1], p[2], p[3], p[4] as copy, p[5] as activate:
            with self.assertRaisesRegex(
                ServiceBootstrapError,
                "unavailable after active state exists",
            ):
                perform_bootstrap_activation(
                    private_root=self.private,
                    desktop_sid=DESKTOP_SID,
                )
        copy.assert_not_called()
        activate.assert_not_called()

    @unittest.skipIf(os.name == "nt", "non-Windows fail-closed test")
    def test_real_bootstrap_entrypoint_is_inert_off_windows(self):
        with self.assertRaisesRegex(
            ServiceBootstrapError,
            "unavailable on this platform",
        ):
            perform_bootstrap_activation(
                private_root=self.private,
                desktop_sid=DESKTOP_SID,
            )


if __name__ == "__main__":
    unittest.main()
