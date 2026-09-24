from __future__ import annotations

import json
import os
import unittest

from forgeboss.control.windows_service_boundary import (
    MAX_MESSAGE_BYTES,
    PIPE_NAME,
    PROTOCOL_VERSION,
    WindowsServiceBoundaryError,
    assert_distinct_service_identity,
    build_pipe_security,
    create_r0_server_pipe,
    dispatch_service_request,
    parse_service_request,
)


def request(method="health", **overrides):
    doc = {
        "version": PROTOCOL_VERSION,
        "id": "REQ-1",
        "method": method,
        "params": {},
    }
    doc.update(overrides)
    return json.dumps(doc, separators=(",", ":")).encode("utf-8")


class WindowsServiceBoundarySchemaTests(unittest.TestCase):
    def test_health_and_capabilities_are_only_r0_methods(self):
        for method in ("health", "capabilities"):
            parsed = parse_service_request(request(method))
            result = dispatch_service_request(parsed)
            self.assertTrue(result["ok"])

        caps = dispatch_service_request(parse_service_request(request("capabilities")))
        self.assertEqual(caps["methods"], ("capabilities", "health"))
        self.assertFalse(caps["rawSigning"])
        self.assertFalse(caps["rawMinting"])
        self.assertFalse(caps["secretExport"])
        self.assertFalse(caps["governedLaunchStart"])

    def test_bootstrap_activate_is_exact_parameterless_and_not_generic_dispatch(self):
        parsed = parse_service_request(request("bootstrap.activate"))
        self.assertEqual(parsed.method, "bootstrap.activate")
        with self.assertRaisesRegex(
            WindowsServiceBoundaryError,
            "unavailable",
        ):
            dispatch_service_request(parsed)

        with self.assertRaises(WindowsServiceBoundaryError):
            parse_service_request(
                request(
                    "bootstrap.activate",
                    params={"sourceRoot": r"C:\\attacker\\chosen"},
                )
            )

    def test_raw_sign_mint_secret_and_launch_methods_fail_closed(self):
        methods = (
            "sign",
            "mint",
            "mint.attestation",
            "secret.export",
            "raw-launch",
            "launch-secret",
            "policy-secret",
            "daemon-secret",
            "envelope.sign",
            "governed.start",
        )
        for method in methods:
            with self.subTest(method=method):
                with self.assertRaises(WindowsServiceBoundaryError):
                    parse_service_request(request(method))

    def test_unknown_fields_missing_fields_and_params_fail_closed(self):
        with self.assertRaises(WindowsServiceBoundaryError):
            parse_service_request(request(extra=True))

        doc = {
            "version": PROTOCOL_VERSION,
            "id": "REQ-1",
            "method": "health",
        }
        with self.assertRaises(WindowsServiceBoundaryError):
            parse_service_request(json.dumps(doc).encode())

        with self.assertRaises(WindowsServiceBoundaryError):
            parse_service_request(
                request("health", params={"secret": "please"})
            )

    def test_duplicate_keys_nonstandard_json_and_bad_utf8_fail_closed(self):
        samples = (
            b'{"version":1,"version":1,"id":"x","method":"health","params":{}}',
            b'{"version":NaN,"id":"x","method":"health","params":{}}',
            b"\xff\xfe",
        )
        for raw in samples:
            with self.subTest(raw=raw):
                with self.assertRaises(WindowsServiceBoundaryError):
                    parse_service_request(raw)

    def test_oversized_and_empty_messages_fail_closed(self):
        with self.assertRaises(WindowsServiceBoundaryError):
            parse_service_request(b"")
        with self.assertRaises(WindowsServiceBoundaryError):
            parse_service_request(b"x" * (MAX_MESSAGE_BYTES + 1))

    def test_bad_version_id_or_method_shape_fails_closed(self):
        cases = (
            request(version=2),
            request(id="bad id with spaces"),
            request(method=" health"),
            request(method="HEALTH"),
        )
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(WindowsServiceBoundaryError):
                    parse_service_request(raw)

    def test_response_objects_are_read_only(self):
        result = dispatch_service_request(parse_service_request(request()))
        with self.assertRaises(TypeError):
            result["authorityExposed"] = True

    @unittest.skipIf(os.name == "nt", "non-Windows fail-closed test")
    def test_windows_helpers_are_inert_off_windows(self):
        self.assertTrue(PIPE_NAME.startswith("\\\\.\\pipe\\"))
        for func, args in (
            (assert_distinct_service_identity, ("S-1-5-21-1",)),
            (build_pipe_security, ("S-1-5-21-1",)),
            (create_r0_server_pipe, ("S-1-5-21-1",)),
        ):
            with self.subTest(func=func.__name__):
                with self.assertRaisesRegex(
                    WindowsServiceBoundaryError,
                    "unavailable on this platform",
                ):
                    func(*args)


if __name__ == "__main__":
    unittest.main()
