from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from forgeboss.control.windows_state_migration import (
    SECRET_FILES,
    SOURCE_DB,
    StateMigrationError,
    copy_verified_state,
    inspect_source_state,
)


class MigrationFixture(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.source = self.root / "source"
        self.source.mkdir()

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

        for index, name in enumerate(SECRET_FILES, start=1):
            (self.source / name).write_bytes(bytes([index]) * 32)


class StateMigrationTests(MigrationFixture):
    def test_source_state_inspection_requires_offline_valid_state(self):
        state = inspect_source_state(self.source)
        self.assertEqual(state.schema_version, 4)
        self.assertEqual(
            state.db_sha256,
            hashlib.sha256((self.source / SOURCE_DB).read_bytes()).hexdigest(),
        )
        self.assertEqual(set(state.secret_sha256), set(SECRET_FILES))

    def test_wal_or_shm_blocks_migration_source(self):
        for suffix in ("-wal", "-shm"):
            path = self.source / f"{SOURCE_DB}{suffix}"
            path.write_bytes(b"x")
            try:
                with self.assertRaisesRegex(StateMigrationError, "offline/checkpointed"):
                    inspect_source_state(self.source)
            finally:
                path.unlink()

    def test_live_lease_or_running_task_blocks_source(self):
        db = sqlite3.connect(self.source / SOURCE_DB)
        db.execute(
            "INSERT INTO workspace_leases(task_id,released_at,expires_at) VALUES(?,?,?)",
            ("T1", None, 9999999999.0),
        )
        db.commit()
        db.close()
        with self.assertRaisesRegex(StateMigrationError, "live workspace lease"):
            inspect_source_state(self.source)

        db = sqlite3.connect(self.source / SOURCE_DB)
        db.execute("DELETE FROM workspace_leases")
        db.execute(
            "INSERT INTO tasks(task_id,status) VALUES(?,?)",
            ("T1", "running"),
        )
        db.commit()
        db.close()
        with self.assertRaisesRegex(StateMigrationError, "running task"):
            inspect_source_state(self.source)

    def test_linklike_secret_is_rejected(self):
        target = self.source / SECRET_FILES[0]
        original = target.read_bytes()
        target.unlink()
        real = self.source / "real-secret.bin"
        real.write_bytes(original)
        try:
            target.symlink_to(real)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(StateMigrationError, "regular non-link"):
            inspect_source_state(self.source)

    @unittest.skipIf(os.name == "nt", "non-Windows fail-closed test")
    def test_copy_is_inert_off_windows(self):
        with self.assertRaisesRegex(
            StateMigrationError,
            "unavailable on this platform",
        ):
            copy_verified_state(
                source_root=self.source,
                private_root=self.root / "private",
                desktop_sid="S-1-5-21-1-2-3-1001",
            )


if __name__ == "__main__":
    unittest.main()
