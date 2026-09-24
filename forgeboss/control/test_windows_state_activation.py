from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from forgeboss.control.windows_state_activation import (
    ACTIVE_STATE_SCHEMA,
    ACTIVE_STATE_STATUS,
    ActiveStateError,
    activate_verified_state,
    load_verified_active_state,
    parse_active_state_bytes,
    parse_migration_manifest_bytes,
    verify_candidate_copy,
)
from forgeboss.control.windows_state_migration import (
    CANDIDATE_DIR,
    MANIFEST_FILE,
    SECRET_FILES,
    SOURCE_DB,
)


SERVICE_SID = "S-1-5-80-1-2-3-4-5"
DESKTOP_SID = "S-1-5-21-100-200-300-1001"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ActiveStateFixture(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.private = self.root / "private"
        self.private.mkdir()
        self.source = self.root / "source"
        self.source.mkdir()
        self.candidate = self.private / CANDIDATE_DIR
        self.candidate.mkdir()

        db = sqlite3.connect(self.source / SOURCE_DB)
        db.executescript("""
        CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE tasks(task_id TEXT PRIMARY KEY,status TEXT);
        CREATE TABLE workspace_leases(
          task_id TEXT PRIMARY KEY,
          released_at REAL,
          expires_at REAL
        );
        INSERT INTO meta(key,value) VALUES('schema_version','4');
        """)
        db.commit()
        db.close()
        shutil.copyfile(self.source / SOURCE_DB, self.candidate / SOURCE_DB)

        for index, name in enumerate(SECRET_FILES, start=1):
            payload = bytes([index]) * 32
            (self.source / name).write_bytes(payload)
            (self.candidate / name).write_bytes(payload)

        self.write_manifest()

    def manifest_payload(self):
        return {
            "schema": 1,
            "status": "VERIFIED_COPY",
            "sourceRoot": str(self.source.resolve()),
            "sourceDbSha256": sha256_file(self.source / SOURCE_DB),
            "candidateDbSha256": sha256_file(self.candidate / SOURCE_DB),
            "schemaVersion": 4,
            "sourceSecrets": {
                name: sha256_file(self.source / name)
                for name in SECRET_FILES
            },
            "candidateSecrets": {
                name: sha256_file(self.candidate / name)
                for name in SECRET_FILES
            },
            "serviceSid": SERVICE_SID,
            "desktopSid": DESKTOP_SID,
            "createdAt": 1.0,
        }

    def write_manifest(self, payload=None):
        if payload is None:
            payload = self.manifest_payload()
        (self.candidate / MANIFEST_FILE).write_text(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ),
            encoding="utf-8",
        )


class CandidateVerificationTests(ActiveStateFixture):
    def test_verified_candidate_binds_manifest_db_schema_secrets_and_source(self):
        verified = verify_candidate_copy(
            self.private,
            expected_service_sid=SERVICE_SID,
            expected_desktop_sid=DESKTOP_SID,
        )
        self.assertEqual(verified.schema_version, 4)
        self.assertEqual(verified.service_sid, SERVICE_SID)
        self.assertEqual(verified.desktop_sid, DESKTOP_SID)
        self.assertEqual(
            verified.candidate_db_sha256,
            sha256_file(self.candidate / SOURCE_DB),
        )
        self.assertEqual(
            dict(verified.candidate_secret_sha256),
            {
                name: sha256_file(self.candidate / name)
                for name in SECRET_FILES
            },
        )

    def test_candidate_secret_tamper_fails_closed(self):
        (self.candidate / SECRET_FILES[0]).write_bytes(b"tampered")
        with self.assertRaisesRegex(ActiveStateError, "candidate secret hash mismatch"):
            verify_candidate_copy(self.private)

    def test_source_drift_after_copy_fails_closed(self):
        (self.source / SECRET_FILES[1]).write_bytes(b"changed-after-copy")
        with self.assertRaisesRegex(ActiveStateError, "source secrets changed"):
            verify_candidate_copy(self.private)

    def test_manifest_unknown_field_and_duplicate_key_are_rejected(self):
        payload = self.manifest_payload()
        payload["unexpected"] = True
        self.write_manifest(payload)
        with self.assertRaisesRegex(ActiveStateError, "fields mismatch"):
            verify_candidate_copy(self.private)

        self.write_manifest()
        path = self.candidate / MANIFEST_FILE
        raw = path.read_bytes()
        raw = raw.replace(b'"schema":1', b'"schema":1,"schema":1', 1)
        path.write_bytes(raw)
        with self.assertRaisesRegex(ActiveStateError, "duplicate JSON key"):
            verify_candidate_copy(self.private)

    def test_candidate_hardlink_is_rejected_when_supported(self):
        secret = self.candidate / SECRET_FILES[0]
        alias = self.candidate / "hardlink-test"
        try:
            os.link(secret, alias)
        except (OSError, NotImplementedError):
            self.skipTest("hard links unavailable")
        self.addCleanup(lambda: alias.exists() and alias.unlink())
        with self.assertRaisesRegex(ActiveStateError, "must not be hard-linked"):
            verify_candidate_copy(self.private)

    def test_candidate_symlink_directory_is_rejected_when_supported(self):
        real = self.candidate
        moved = self.private / "candidate-real"
        real.rename(moved)
        try:
            real.symlink_to(moved, target_is_directory=True)
        except (OSError, NotImplementedError):
            moved.rename(real)
            self.skipTest("directory symlinks unavailable")
        with self.assertRaisesRegex(ActiveStateError, "symlink/junction/reparse"):
            verify_candidate_copy(self.private)


class StrictRecordParserTests(ActiveStateFixture):
    def active_payload(self):
        manifest_hash = hashlib.sha256(
            (self.candidate / MANIFEST_FILE).read_bytes()
        ).hexdigest()
        return {
            "schema": ACTIVE_STATE_SCHEMA,
            "status": ACTIVE_STATE_STATUS,
            "candidateDir": CANDIDATE_DIR,
            "migrationManifestSha256": manifest_hash,
            "candidateDbSha256": sha256_file(self.candidate / SOURCE_DB),
            "schemaVersion": 4,
            "candidateSecrets": {
                name: sha256_file(self.candidate / name)
                for name in SECRET_FILES
            },
            "serviceSid": SERVICE_SID,
            "activatedAt": 2.0,
        }

    def test_active_state_parser_accepts_exact_record(self):
        raw = json.dumps(
            self.active_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        parsed = parse_active_state_bytes(raw)
        self.assertEqual(parsed["status"], ACTIVE_STATE_STATUS)
        self.assertEqual(parsed["candidateDir"], CANDIDATE_DIR)

    def test_active_state_parser_rejects_unknown_duplicate_and_nan(self):
        payload = self.active_payload()
        payload["unexpected"] = True
        with self.assertRaisesRegex(ActiveStateError, "fields mismatch"):
            parse_active_state_bytes(json.dumps(payload).encode())

        raw = json.dumps(
            self.active_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        raw = raw.replace(b'"schema":1', b'"schema":1,"schema":1', 1)
        with self.assertRaisesRegex(ActiveStateError, "duplicate JSON key"):
            parse_active_state_bytes(raw)

        payload = self.active_payload()
        payload["activatedAt"] = float("nan")
        raw = json.dumps(payload, allow_nan=True).encode()
        with self.assertRaisesRegex(ActiveStateError, "non-standard JSON"):
            parse_active_state_bytes(raw)

    def test_migration_parser_rejects_non_identical_secret_copy_claim(self):
        payload = self.manifest_payload()
        payload["candidateSecrets"][SECRET_FILES[0]] = "0" * 64
        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        with self.assertRaisesRegex(ActiveStateError, "byte-identical"):
            parse_migration_manifest_bytes(raw)


class PlatformBoundaryTests(ActiveStateFixture):
    @unittest.skipIf(os.name == "nt", "non-Windows fail-closed test")
    def test_activation_and_load_are_inert_off_windows(self):
        for call in (
            lambda: activate_verified_state(
                private_root=self.private,
                desktop_sid=DESKTOP_SID,
            ),
            lambda: load_verified_active_state(
                private_root=self.private,
                desktop_sid=DESKTOP_SID,
            ),
        ):
            with self.subTest(call=call):
                with self.assertRaisesRegex(
                    ActiveStateError,
                    "unavailable on this platform",
                ):
                    call()


if __name__ == "__main__":
    unittest.main()
