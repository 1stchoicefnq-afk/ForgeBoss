from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from forgeboss.control.windows_control_service import (
    ForgeBossControlService,
    MAX_RESPONSE_BYTES,
    WindowsControlServiceError,
    build_service_class,
    encode_service_response,
    load_allowed_client_sid,
    process_service_message,
    service_command_line,
)


def raw_request(method="health"):
    return json.dumps(
        {
            "version": 1,
            "id": "REQ-1",
            "method": method,
            "params": {},
        },
        separators=(",", ":"),
    ).encode("utf-8")


class WindowsControlServiceHostTests(unittest.TestCase):
    def test_service_class_is_stable_module_attribute_for_scm_reload(self):
        module = importlib.import_module(ForgeBossControlService.__module__)
        self.assertIs(
            getattr(module, ForgeBossControlService.__name__),
            ForgeBossControlService,
        )
        self.assertEqual(
            ForgeBossControlService.__name__,
            "ForgeBossControlService",
        )
        self.assertEqual(
            ForgeBossControlService.__module__,
            "forgeboss.control.windows_control_service",
        )

    @unittest.skipUnless(os.name == "nt", "Windows-native pywin32 registry test")
    def test_pywin32_registry_class_string_resolves_to_same_service_class(self):
        import win32serviceutil

        cls = build_service_class()
        class_string = win32serviceutil.GetServiceClassString(cls)
        self.assertEqual(
            class_string,
            "forgeboss.control.windows_control_service.ForgeBossControlService",
        )
        module_name, class_name = class_string.rsplit(".", 1)
        module = importlib.import_module(module_name)
        self.assertIs(getattr(module, class_name), cls)

    def test_allowed_client_sid_file_requires_one_concrete_user_sid(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sid.txt"
            path.write_text("S-1-5-21-100-200-300-1001\n", encoding="ascii")
            self.assertEqual(
                load_allowed_client_sid(path),
                "S-1-5-21-100-200-300-1001",
            )

            for bad in (
                "S-1-1-0",
                "S-1-5-11",
                "S-1-5-18",
                "S-1-5-32-544",
                "S-1-5-32-545",
                "S-1-5-80-1-2-3-4-5",
                "not-a-sid",
            ):
                path.write_text(bad, encoding="ascii")
                with self.subTest(bad=bad):
                    with self.assertRaises(WindowsControlServiceError):
                        load_allowed_client_sid(path)

    def test_missing_oversized_nonascii_or_symlink_sid_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            missing = root / "missing.txt"
            with self.assertRaises(WindowsControlServiceError):
                load_allowed_client_sid(missing)

            oversized = root / "large.txt"
            oversized.write_bytes(b"x" * 257)
            with self.assertRaises(WindowsControlServiceError):
                load_allowed_client_sid(oversized)

            nonascii = root / "bad.txt"
            nonascii.write_bytes(b"\xff")
            with self.assertRaises(WindowsControlServiceError):
                load_allowed_client_sid(nonascii)

            target = root / "target.txt"
            target.write_text("S-1-5-21-1-2-3-1001", encoding="ascii")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                return
            with self.assertRaisesRegex(
                WindowsControlServiceError,
                "must not be a symlink",
            ):
                load_allowed_client_sid(link)

    def test_health_and_capabilities_round_trip(self):
        for method in ("health", "capabilities"):
            response = json.loads(process_service_message(raw_request(method)))
            self.assertTrue(response["ok"])
            self.assertEqual(response["id"], "REQ-1")
            self.assertEqual(response["version"], 1)

    def test_bootstrap_activation_runs_only_through_trusted_host_handler(self):
        calls = []

        def handler():
            calls.append(True)
            return {
                "status": "ACTIVATED_RESTART_REQUIRED",
                "candidateDir": "candidate-state-v1",
                "migrationManifestSha256": "a" * 64,
                "schemaVersion": 5,
                "restartRequired": True,
            }

        response = json.loads(
            process_service_message(
                raw_request("bootstrap.activate"),
                bootstrap_handler=handler,
                active_state_present=False,
            )
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["status"], "ACTIVATED_RESTART_REQUIRED")
        self.assertEqual(calls, [True])
        self.assertFalse(
            any("secret" in key.casefold() for key in response["result"])
        )

        blocked = json.loads(
            process_service_message(
                raw_request("bootstrap.activate"),
                bootstrap_handler=handler,
                active_state_present=True,
            )
        )
        self.assertFalse(blocked["ok"])
        self.assertEqual(calls, [True])

        direct = json.loads(
            process_service_message(raw_request("bootstrap.activate"))
        )
        self.assertFalse(direct["ok"])
        self.assertEqual(calls, [True])

    def test_forbidden_authority_methods_return_error_not_exception(self):
        for method in (
            "sign",
            "mint.attestation",
            "secret.export",
            "governed.start",
            "envelope.sign",
        ):
            with self.subTest(method=method):
                response = json.loads(process_service_message(raw_request(method)))
                self.assertFalse(response["ok"])
                self.assertNotIn("result", response)

    def test_error_response_does_not_echo_request_payload(self):
        secret_marker = "SUPER-SECRET-MARKER"
        raw = json.dumps(
            {
                "version": 1,
                "id": "REQ-1",
                "method": "health",
                "params": {"x": secret_marker},
            }
        ).encode()
        response = process_service_message(raw)
        self.assertNotIn(secret_marker.encode(), response)

    def test_response_size_and_shape_are_bounded(self):
        result = {"x": "y"}
        raw = encode_service_response(
            request_id="REQ-1",
            ok=True,
            result=result,
        )
        self.assertLessEqual(len(raw), MAX_RESPONSE_BYTES)

        with self.assertRaises(WindowsControlServiceError):
            encode_service_response(
                request_id="REQ-1",
                ok=True,
                result={"x": "a" * MAX_RESPONSE_BYTES},
            )

    @unittest.skipIf(os.name == "nt", "non-Windows fail-closed test")
    def test_windows_service_entrypoints_are_inert_off_windows(self):
        for func in (build_service_class, service_command_line):
            with self.subTest(func=func.__name__):
                with self.assertRaisesRegex(
                    WindowsControlServiceError,
                    "unavailable on this platform",
                ):
                    func()


if __name__ == "__main__":
    unittest.main()
