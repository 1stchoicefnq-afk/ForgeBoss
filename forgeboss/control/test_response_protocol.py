from __future__ import annotations

import json
import unittest

from forgeboss.control.response_protocol import (
    MAX_RESPONSE_BYTES,
    ResponseCorrelationError,
    ResponseFrameError,
    parse_response_frame,
)


class ResponseProtocolTests(unittest.TestCase):
    def line(self, obj):
        return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")

    def test_matching_success_response_is_accepted(self):
        out = parse_response_frame(
            self.line({"type": "res", "id": "req-1", "ok": True, "payload": {"x": 1}}),
            "req-1",
        )
        self.assertTrue(out.ok)
        self.assertEqual(out.payload, {"x": 1})
        self.assertIsNone(out.error)

    def test_wrong_id_is_rejected_before_payload_use(self):
        with self.assertRaises(ResponseCorrelationError):
            parse_response_frame(
                self.line({"type": "res", "id": "stale", "ok": True, "payload": {"x": 1}}),
                "req-1",
            )

    def test_missing_empty_and_control_id_are_rejected(self):
        for rid in (None, "", "bad\nid"):
            with self.subTest(rid=rid), self.assertRaises(ResponseFrameError):
                parse_response_frame(
                    self.line({"type": "res", "id": rid, "ok": True, "payload": {}}),
                    "req-1",
                )

    def test_wrong_type_and_non_boolean_ok_are_rejected(self):
        with self.assertRaisesRegex(ResponseFrameError, "type"):
            parse_response_frame(
                self.line({"type": "req", "id": "req-1", "ok": True, "payload": {}}),
                "req-1",
            )
        with self.assertRaisesRegex(ResponseFrameError, "boolean"):
            parse_response_frame(
                self.line({"type": "res", "id": "req-1", "ok": 1, "payload": {}}),
                "req-1",
            )

    def test_success_payload_must_be_object_and_schema_is_closed(self):
        with self.assertRaisesRegex(ResponseFrameError, "payload"):
            parse_response_frame(
                self.line({"type": "res", "id": "req-1", "ok": True, "payload": []}),
                "req-1",
            )
        with self.assertRaisesRegex(ResponseFrameError, "unexpected"):
            parse_response_frame(
                self.line(
                    {"type": "res", "id": "req-1", "ok": True, "payload": {}, "error": {}}
                ),
                "req-1",
            )

    def test_error_response_is_strict_and_preserved(self):
        out = parse_response_frame(
            self.line(
                {
                    "type": "res",
                    "id": "req-1",
                    "ok": False,
                    "error": {"code": "DENIED", "message": "no"},
                }
            ),
            "req-1",
        )
        self.assertFalse(out.ok)
        self.assertEqual(out.error, {"code": "DENIED", "message": "no"})
        for error in (
            None,
            {},
            {"code": "X"},
            {"code": "", "message": "no"},
            {"code": "X", "message": ""},
            {"code": "X", "message": "no", "extra": 1},
        ):
            with self.subTest(error=error), self.assertRaises(ResponseFrameError):
                parse_response_frame(
                    self.line({"type": "res", "id": "req-1", "ok": False, "error": error}),
                    "req-1",
                )

    def test_invalid_utf8_json_empty_and_oversize_fail_closed(self):
        for raw in (b"", b"\xff", b"{"):
            with self.subTest(raw=raw), self.assertRaises(ResponseFrameError):
                parse_response_frame(raw, "req-1")
        with self.assertRaisesRegex(ResponseFrameError, "256 KiB"):
            parse_response_frame(b"x" * (MAX_RESPONSE_BYTES + 1), "req-1")

    def test_stale_frame_is_not_silently_skipped_to_later_correct_frame(self):
        stale = self.line({"type": "res", "id": "old", "ok": True, "payload": {"old": True}})
        correct = self.line({"type": "res", "id": "req-1", "ok": True, "payload": {"ok": True}})
        with self.assertRaises(ResponseCorrelationError):
            parse_response_frame(stale, "req-1")
        self.assertEqual(parse_response_frame(correct, "req-1").payload, {"ok": True})

    def test_expected_request_id_is_validated(self):
        for expected in ("", "bad\nid", None):
            with self.subTest(expected=expected), self.assertRaises(ResponseFrameError):
                parse_response_frame(
                    self.line({"type": "res", "id": "req-1", "ok": True, "payload": {}}),
                    expected,
                )


if __name__ == "__main__":
    unittest.main()
