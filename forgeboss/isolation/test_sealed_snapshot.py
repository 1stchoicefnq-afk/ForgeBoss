"""Hostile tests for the FB-026 sealed immutable execution snapshot."""
from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from forgeboss.isolation.sealed_snapshot import (  # noqa: E402
    METADATA_PATH,
    SCHEMA,
    IsolationError,
    ScopeError,
    SealedSnapshot,
    SnapshotStateError,
    SourceError,
    UnsafePathError,
    create_sealed_snapshot,
    normalize_relative_path,
)

POSIX = os.name == "posix"


def _symlinks_supported() -> bool:
    probe = tempfile.mkdtemp()
    try:
        os.symlink(probe, os.path.join(probe, "l"))
        return True
    except (OSError, NotImplementedError, AttributeError):
        return False
    finally:
        shutil.rmtree(probe, ignore_errors=True)


SYMLINKS = _symlinks_supported()
needs_symlinks = unittest.skipUnless(SYMLINKS, "symlink creation unavailable on this platform")


class SnapshotTestBase(unittest.TestCase):
    """Builds a small source worktree with host .git metadata and secrets."""

    def setUp(self) -> None:
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="fb-isolation-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.staging = os.path.join(self.tmp, "staging")
        self.source = os.path.join(self.tmp, "source")
        self.outside = os.path.join(self.tmp, "outside")
        for d in (self.staging, self.source, self.outside):
            os.makedirs(d)
        self.write(self.source, "src/app.py", b"print('hello')\n")
        self.write(self.source, "src/util.py", b"X = 1\n")
        self.write(self.source, "docs/readme.md", b"# docs\n")
        self.write(self.source, ".git/HEAD", b"ref: refs/heads/main\n")
        self.write(self.source, ".git/config", b"[remote \"origin\"]\n\turl = git@host:secret/repo.git\n")
        self.write(self.source, ".git/refs/heads/main", b"a" * 40 + b"\n")
        self.write(self.outside, "keep.txt", b"host state\n")
        self.snapshots: list[SealedSnapshot] = []

    def write(self, root: str, rel: str, data: bytes) -> str:
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def read(self, root: str, rel: str) -> bytes:
        with open(os.path.join(root, *rel.split("/")), "rb") as fh:
            return fh.read()

    def make(self, allowed=("src",), source=None, **kw) -> SealedSnapshot:
        snap = create_sealed_snapshot(
            source or self.source, "a" * 40, allowed, parent_dir=self.staging, **kw
        )
        self.snapshots.append(snap)
        self.addCleanup(self._discard, snap)
        return snap

    @staticmethod
    def _discard(snap: SealedSnapshot) -> None:
        try:
            snap.cleanup()
        except Exception:
            shutil.rmtree(str(snap.snapshot_dir), ignore_errors=True)


# ---------------------------------------------------------------------------
# 1. host-side source mutation must not reach the sealed snapshot
# ---------------------------------------------------------------------------

class ImmutabilityTests(SnapshotTestBase):
    def test_source_file_changed_after_snapshot_leaves_snapshot_unchanged(self):
        snap = self.make()
        sealed_digest = snap.manifest_digest
        self.write(self.source, "src/app.py", b"COMPROMISED\n")
        self.assertEqual(self.read(str(snap.work_root), "src/app.py"), b"print('hello')\n")
        self.assertEqual(snap.manifest.digest, sealed_digest)
        self.assertTrue(snap.export_changes().is_empty())

    def test_source_file_deleted_after_snapshot_leaves_snapshot_unchanged(self):
        snap = self.make()
        os.remove(os.path.join(self.source, "src", "util.py"))
        self.assertEqual(self.read(str(snap.work_root), "src/util.py"), b"X = 1\n")
        self.assertTrue(snap.export_changes().is_empty())

    def test_source_file_added_after_snapshot_is_not_visible(self):
        snap = self.make()
        self.write(self.source, "src/injected.py", b"boom\n")
        self.assertFalse((snap.work_root / "src" / "injected.py").exists())
        self.assertNotIn("src/injected.py", snap.manifest.files)

    def test_source_replaced_wholesale_does_not_disturb_manifest_identity(self):
        snap = self.make()
        before = snap.manifest_digest
        shutil.rmtree(self.source)
        os.makedirs(self.source)
        self.assertEqual(snap.manifest.digest, before)
        self.assertTrue(snap.export_changes().is_empty())


# ---------------------------------------------------------------------------
# 2/3. host .git metadata, refs and credentials are never worker-visible
# ---------------------------------------------------------------------------

class HostMetadataTests(SnapshotTestBase):
    def test_git_directory_is_not_materialized(self):
        snap = self.make()
        self.assertFalse((snap.work_root / ".git").exists())
        self.assertFalse(any(p.casefold().startswith(".git/") for p in snap.manifest.files))
        self.assertIn(".git/", snap.manifest.excluded)

    def test_git_ref_mutation_is_not_worker_visible(self):
        snap = self.make()
        self.write(self.source, ".git/refs/heads/attacker", b"b" * 40 + b"\n")
        self.write(self.source, ".git/HEAD", b"ref: refs/heads/attacker\n")
        self.assertFalse((snap.work_root / ".git").exists())
        self.assertTrue(snap.export_changes().is_empty())

    def test_git_worktree_pointer_file_is_excluded(self):
        linked = os.path.join(self.tmp, "linked")
        os.makedirs(linked)
        self.write(linked, "src/app.py", b"x\n")
        self.write(linked, ".git", b"gitdir: /host/.git/worktrees/w\n")
        snap = self.make(source=linked)
        self.assertFalse((snap.work_root / ".git").exists())
        self.assertIn(".git", snap.manifest.excluded)

    def test_credential_bearing_files_are_excluded(self):
        secrets = [".env", ".env.production", ".npmrc", ".netrc", ".git-credentials",
                   "id_rsa", "server.pem", "signing.key", "credentials.json"]
        for name in secrets:
            self.write(self.source, name, b"SECRET\n")
        self.write(self.source, ".ssh/known_hosts", b"SECRET\n")
        snap = self.make()
        for name in secrets:
            self.assertFalse((snap.work_root / name).exists(), name)
            self.assertIn(name, snap.manifest.excluded)
        self.assertFalse((snap.work_root / ".ssh").exists())

    def test_worker_metadata_is_isolation_owned_and_leaks_no_host_path(self):
        snap = self.make(allowed=("src", "docs"))
        meta = json.loads(self.read(str(snap.work_root), METADATA_PATH).decode("utf-8"))
        self.assertEqual(meta, {
            "schema": SCHEMA,
            "snapshot_id": snap.snapshot_id,
            "base_identity": "a" * 40,
            "allowed_paths": ["docs", "src"],
        })
        for path in snap.work_root.rglob("*"):
            if path.is_file():
                self.assertNotIn(self.source.encode(), path.read_bytes())

    def test_manifest_records_source_and_base_identity(self):
        snap = self.make()
        self.assertEqual(snap.manifest.source_root, self.source.replace("\\", "/"))
        self.assertEqual(snap.manifest.base_identity, "a" * 40)
        self.assertEqual(snap.manifest.files["src/app.py"].size, len(b"print('hello')\n"))
        self.assertEqual(len(snap.snapshot_id), 32)

    def test_manifest_lives_outside_the_worker_root(self):
        snap = self.make()
        self.assertTrue((snap.snapshot_dir / "manifest.json").is_file())
        self.assertFalse((snap.work_root / "manifest.json").exists())

    def test_project_files_and_empty_dirs_are_materialized(self):
        os.makedirs(os.path.join(self.source, "src", "empty"))
        snap = self.make()
        self.assertEqual(self.read(str(snap.work_root), "docs/readme.md"), b"# docs\n")
        self.assertTrue((snap.work_root / "src" / "empty").is_dir())
        self.assertIn("src/empty", snap.manifest.dirs)

    @unittest.skipUnless(POSIX, "exec bit is POSIX-only")
    def test_executable_bit_is_preserved(self):
        path = self.write(self.source, "src/run.sh", b"#!/bin/sh\n")
        os.chmod(path, 0o755)
        snap = self.make()
        self.assertTrue(snap.manifest.files["src/run.sh"].executable)
        self.assertTrue(os.stat(snap.work_root / "src" / "run.sh").st_mode & stat.S_IXUSR)

    def test_binary_and_unicode_content_round_trips(self):
        blob = bytes(range(256)) + "héllo — ✓".encode("utf-8")
        self.write(self.source, "src/blob.bin", blob)
        snap = self.make()
        self.assertEqual(self.read(str(snap.work_root), "src/blob.bin"), blob)


# ---------------------------------------------------------------------------
# 4. traversal / symlink / device escapes
# ---------------------------------------------------------------------------

class PathRefusalTests(SnapshotTestBase):
    def test_normalize_rejects_escape_shapes(self):
        hostile = [
            "../secret", "a/../../b", "./../x", "/etc/passwd", "//server/share/x",
            "\\\\server\\share\\x", "\\\\?\\C:\\Windows", "\\\\.\\PhysicalDrive0",
            "C:/Windows/System32", "c:secret", "~/.ssh/id_rsa", "~root/x",
            "con", "NUL", "nul.txt", "COM1", "lpt9.log", "aux/x",
            "a.txt.", "a.txt ", " a.txt", "src/child. /a", "dir./a",
            "a\x00b", "a\nb", "a\tb", "", "   ", ".", "..", "./",
        ]
        for value in hostile:
            with self.subTest(value=value):
                with self.assertRaises(UnsafePathError):
                    normalize_relative_path(value)

    def test_normalize_rejects_non_string(self):
        for value in (None, 5, b"src/a.py", Path("src/a.py"), ["src"]):
            with self.subTest(value=value):
                with self.assertRaises(UnsafePathError):
                    normalize_relative_path(value)

    def test_normalize_accepts_and_canonicalizes_safe_paths(self):
        self.assertEqual(normalize_relative_path("src/a.py"), "src/a.py")
        self.assertEqual(normalize_relative_path("./src/a.py"), "src/a.py")
        self.assertEqual(normalize_relative_path("src\\lib\\a.py"), "src/lib/a.py")
        self.assertEqual(normalize_relative_path("src/./lib/a.py"), "src/lib/a.py")
        self.assertEqual(normalize_relative_path(".gitignore"), ".gitignore")

    def test_allowed_paths_reject_traversal_and_reserved_scopes(self):
        for bad in (["../etc"], ["/etc"], ["C:\\Windows"], ["src/../.."], ["\\\\?\\C:\\x"]):
            with self.subTest(bad=bad):
                with self.assertRaises(UnsafePathError):
                    self.make(allowed=bad)
        for bad in ([".git/config"], [".git"], [".forgeboss-isolation"], [METADATA_PATH], [".ssh"]):
            with self.subTest(bad=bad):
                with self.assertRaises(ScopeError):
                    self.make(allowed=bad)

    def test_allowed_paths_reject_casefold_duplicates_and_bare_string(self):
        with self.assertRaises(SourceError):
            self.make(allowed=["src", "SRC"])
        with self.assertRaises(SourceError):
            self.make(allowed="src")
        with self.assertRaises(SourceError):
            self.make(allowed=42)

    @needs_symlinks
    def test_symlinked_file_escaping_source_root_is_refused(self):
        os.symlink(os.path.join(self.outside, "keep.txt"), os.path.join(self.source, "src", "escape.txt"))
        with self.assertRaises(UnsafePathError):
            self.make()
        self.assertEqual(os.listdir(self.staging), [], "partial snapshot leaked")

    @needs_symlinks
    def test_symlinked_directory_escaping_source_root_is_refused(self):
        os.symlink(self.outside, os.path.join(self.source, "src", "escape"))
        with self.assertRaises(UnsafePathError):
            self.make()
        self.assertEqual(os.listdir(self.staging), [])

    @needs_symlinks
    def test_symlink_pointing_inside_source_is_still_refused(self):
        os.symlink(os.path.join(self.source, "src", "app.py"), os.path.join(self.source, "src", "alias.py"))
        with self.assertRaises(UnsafePathError):
            self.make()

    @needs_symlinks
    def test_source_root_that_is_a_symlink_is_refused(self):
        alias = os.path.join(self.tmp, "alias-source")
        os.symlink(self.source, alias)
        with self.assertRaises(UnsafePathError):
            self.make(source=alias)

    @needs_symlinks
    def test_worker_created_symlink_is_refused_on_export(self):
        snap = self.make()
        os.symlink(os.path.join(self.outside, "keep.txt"), str(snap.work_root / "src" / "steal.txt"))
        with self.assertRaises(UnsafePathError):
            snap.export_changes()

    @needs_symlinks
    def test_worker_replacing_allowed_file_with_symlink_is_refused(self):
        snap = self.make()
        target = snap.work_root / "src" / "app.py"
        target.unlink()
        os.symlink(os.path.join(self.outside, "keep.txt"), str(target))
        with self.assertRaises(UnsafePathError):
            snap.export_changes()

    @unittest.skipUnless(POSIX and hasattr(os, "mkfifo"), "FIFOs are POSIX-only")
    def test_non_regular_file_in_source_is_refused(self):
        os.mkfifo(os.path.join(self.source, "src", "pipe"))
        with self.assertRaises(UnsafePathError):
            self.make()
        self.assertEqual(os.listdir(self.staging), [])


# ---------------------------------------------------------------------------
# 5/7. deterministic manifest and independent snapshots
# ---------------------------------------------------------------------------

class ManifestTests(SnapshotTestBase):
    def test_identical_sources_yield_identical_content_digest_but_distinct_ids(self):
        a, b = self.make(), self.make()
        self.assertEqual(a.manifest.content_digest, b.manifest.content_digest)
        self.assertEqual(
            {k: v.to_dict() for k, v in a.manifest.files.items() if k != METADATA_PATH},
            {k: v.to_dict() for k, v in b.manifest.files.items() if k != METADATA_PATH},
        )
        self.assertNotEqual(a.snapshot_id, b.snapshot_id)
        self.assertNotEqual(a.manifest_digest, b.manifest_digest)
        self.assertNotEqual(str(a.work_root), str(b.work_root))

    def test_content_digest_tracks_content_base_and_scope(self):
        base = self.make().manifest.content_digest
        self.write(self.source, "src/app.py", b"changed\n")
        self.assertNotEqual(self.make().manifest.content_digest, base)
        self.write(self.source, "src/app.py", b"print('hello')\n")
        self.assertEqual(self.make().manifest.content_digest, base)
        self.assertNotEqual(self.make(allowed=("docs",)).manifest.content_digest, base)
        other = create_sealed_snapshot(self.source, "b" * 40, ("src",), parent_dir=self.staging)
        self.addCleanup(self._discard, other)
        self.assertNotEqual(other.manifest.content_digest, base)

    def test_manifest_dict_is_json_serializable_and_stable(self):
        snap = self.make()
        first = json.dumps(snap.manifest.to_dict(), sort_keys=True)
        self.assertEqual(first, json.dumps(snap.manifest.to_dict(), sort_keys=True))
        self.assertEqual(json.loads(first)["schema"], SCHEMA)
        on_disk = json.loads((snap.snapshot_dir / "manifest.json").read_text("utf-8"))
        self.assertEqual(on_disk, snap.manifest.to_dict())

    def test_two_snapshots_have_independent_mutable_state(self):
        a, b = self.make(), self.make()
        self.write(str(a.work_root), "src/app.py", b"only in A\n")
        self.write(str(a.work_root), "src/new_in_a.py", b"A\n")
        os.remove(b.work_root / "src" / "util.py")

        self.assertEqual(self.read(str(b.work_root), "src/app.py"), b"print('hello')\n")
        self.assertFalse((b.work_root / "src" / "new_in_a.py").exists())
        self.assertTrue((a.work_root / "src" / "util.py").exists())

        self.assertEqual(a.export_changes().modified, ("src/app.py",))
        self.assertEqual(a.export_changes().added, ("src/new_in_a.py",))
        self.assertEqual(b.export_changes().deleted, ("src/util.py",))
        self.assertEqual(b.export_changes().modified, ())

        a.cleanup()
        self.assertTrue(b.work_root.is_dir())
        self.assertFalse(b.export_changes().is_empty())


# ---------------------------------------------------------------------------
# 6. bounded, scope-checked export
# ---------------------------------------------------------------------------

class ExportTests(SnapshotTestBase):
    def test_untouched_snapshot_exports_nothing(self):
        cs = self.make().export_changes()
        self.assertTrue(cs.is_empty())
        self.assertEqual(cs.entries, ())
        self.assertEqual(cs.blobs, {})

    def test_allowed_change_is_exported_deterministically(self):
        snap = self.make()
        self.write(str(snap.work_root), "src/app.py", b"patched\n")
        first, second = snap.export_changes(), snap.export_changes()
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.modified, ("src/app.py",))
        self.assertEqual(first.blobs, {"src/app.py": b"patched\n"})
        self.assertEqual(first.base_identity, "a" * 40)
        self.assertEqual(first.manifest_digest, snap.manifest_digest)

        twin = self.make()
        self.write(str(twin.work_root), "src/app.py", b"patched\n")
        self.assertEqual(twin.export_changes().digest, first.digest)

    def test_unauthorized_modification_is_rejected(self):
        snap = self.make(allowed=("src",))
        self.write(str(snap.work_root), "docs/readme.md", b"tampered\n")
        with self.assertRaises(ScopeError) as ctx:
            snap.export_changes()
        self.assertIn("docs/readme.md", str(ctx.exception))

    def test_unauthorized_addition_and_deletion_are_rejected(self):
        snap = self.make(allowed=("src",))
        self.write(str(snap.work_root), "evil.py", b"x\n")
        with self.assertRaises(ScopeError):
            snap.export_changes()
        os.remove(snap.work_root / "evil.py")
        os.remove(snap.work_root / "docs" / "readme.md")
        with self.assertRaises(ScopeError):
            snap.export_changes()

    def test_worker_written_git_directory_is_rejected_not_hidden(self):
        snap = self.make(allowed=("src",))
        self.write(str(snap.work_root), ".git/config", b"[remote]\n")
        with self.assertRaises(ScopeError) as ctx:
            snap.export_changes()
        self.assertIn(".git/config", str(ctx.exception))

    def test_worker_written_secret_file_is_rejected_not_hidden(self):
        snap = self.make(allowed=("src",))
        self.write(str(snap.work_root), ".env", b"TOKEN=1\n")
        with self.assertRaises(ScopeError):
            snap.export_changes()

    def test_isolation_metadata_tampering_is_rejected(self):
        snap = self.make(allowed=("src",))
        self.write(str(snap.work_root), METADATA_PATH, b'{"allowed_paths":["/"]}')
        with self.assertRaises(ScopeError) as ctx:
            snap.export_changes()
        self.assertIn(METADATA_PATH, str(ctx.exception))

    def test_one_unauthorized_change_fails_the_whole_export(self):
        snap = self.make(allowed=("src",))
        self.write(str(snap.work_root), "src/app.py", b"legit\n")
        self.write(str(snap.work_root), "docs/readme.md", b"illegal\n")
        with self.assertRaises(ScopeError):
            snap.export_changes()

    def test_addition_deletion_and_rename_like_changes_are_represented(self):
        snap = self.make(allowed=("src",))
        os.remove(snap.work_root / "src" / "app.py")
        self.write(str(snap.work_root), "src/renamed.py", b"print('hello')\n")
        self.write(str(snap.work_root), "src/nested/deep/new.py", b"deep\n")
        self.write(str(snap.work_root), "src/util.py", b"X = 2\n")
        cs = snap.export_changes()

        self.assertEqual(cs.deleted, ("src/app.py",))
        self.assertEqual(cs.added, ("src/nested/deep/new.py", "src/renamed.py"))
        self.assertEqual(cs.modified, ("src/util.py",))
        # A rename is reported as delete + add, never inferred.
        self.assertEqual(
            snap.manifest.files["src/app.py"].sha256,
            next(e.sha256 for e in cs.entries if e.path == "src/renamed.py"),
        )
        deleted = next(e for e in cs.entries if e.change == "deleted")
        self.assertEqual((deleted.sha256, deleted.size, deleted.executable), (None, None, None))
        self.assertNotIn("src/app.py", cs.blobs)
        self.assertEqual(cs.blobs["src/renamed.py"], b"print('hello')\n")
        self.assertEqual([e.path for e in cs.entries], sorted(e.path for e in cs.entries))

    def test_scope_matching_is_prefix_aware_and_casefolded(self):
        self.write(self.source, "srcextra/a.py", b"a\n")
        snap = self.make(allowed=("src", "docs/readme.md"))
        self.write(str(snap.work_root), "srcextra/a.py", b"b\n")
        with self.assertRaises(ScopeError) as ctx:
            snap.export_changes()
        self.assertIn("srcextra/a.py", str(ctx.exception))

        snap2 = self.make(allowed=("SRC", "docs/readme.md"))
        self.write(str(snap2.work_root), "src/app.py", b"c\n")
        self.write(str(snap2.work_root), "docs/readme.md", b"d\n")
        self.assertEqual(snap2.export_changes().modified, ("docs/readme.md", "src/app.py"))

    def test_empty_allowed_scope_rejects_every_change(self):
        snap = self.make(allowed=())
        self.assertTrue(snap.export_changes().is_empty())
        self.write(str(snap.work_root), "src/app.py", b"x\n")
        with self.assertRaises(ScopeError):
            snap.export_changes()

    def test_export_is_size_bounded(self):
        snap = self.make()
        self.write(str(snap.work_root), "src/big.bin", b"z" * 4096)
        with self.assertRaises(IsolationError):
            snap.export_changes(max_export_bytes=1024)
        self.assertEqual(snap.export_changes(max_export_bytes=1 << 20).added, ("src/big.bin",))

    def test_manifest_drift_is_detected(self):
        snap = self.make()
        snap.manifest.files.pop("src/util.py")
        with self.assertRaises(SnapshotStateError):
            snap.export_changes()


# ---------------------------------------------------------------------------
# 8. deterministic cleanup that never follows attacker links
# ---------------------------------------------------------------------------

class CleanupTests(SnapshotTestBase):
    def test_cleanup_removes_only_the_snapshot(self):
        snap = self.make()
        root = str(snap.snapshot_dir)
        snap.cleanup()
        self.assertFalse(os.path.exists(root))
        self.assertTrue(snap.cleaned)
        self.assertTrue(os.path.isdir(self.source))
        self.assertTrue(os.path.isfile(os.path.join(self.source, "src", "app.py")))
        self.assertEqual(os.listdir(self.staging), [])

    @unittest.skipUnless(os.name == "nt", "Windows junction test")
    def test_cleanup_does_not_follow_windows_junction(self):
        snap = self.make()

        junction = str(snap.work_root / "junction_escape")

        result = subprocess.run(
            [
                "cmd.exe",
                "/c",
                "mklink",
                "/J",
                junction,
                self.outside,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            self.skipTest(
                "could not create Windows junction: "
                + (result.stderr or result.stdout).strip()
            )

        probe = getattr(os.path, "isjunction", None)
        if probe is not None:
            self.assertTrue(probe(junction))

        snap.cleanup()

        self.assertFalse(os.path.exists(str(snap.snapshot_dir)))
        self.assertTrue(os.path.isdir(self.outside))
        self.assertEqual(
            self.read(self.outside, "keep.txt"),
            b"host state\n",
        )

    def test_cleanup_is_idempotent(self):
        snap = self.make()
        snap.cleanup()
        snap.cleanup()
        self.assertTrue(snap.cleaned)

    def test_cleanup_survives_externally_removed_snapshot(self):
        snap = self.make()
        shutil.rmtree(str(snap.snapshot_dir))
        snap.cleanup()
        self.assertTrue(snap.cleaned)

    @needs_symlinks
    def test_cleanup_does_not_delete_through_a_worker_planted_symlink(self):
        snap = self.make()
        os.symlink(self.outside, str(snap.work_root / "escape_dir"))
        os.symlink(os.path.join(self.outside, "keep.txt"), str(snap.work_root / "escape_file"))
        snap.cleanup()
        self.assertFalse(os.path.exists(str(snap.snapshot_dir)))
        self.assertTrue(os.path.isdir(self.outside))
        self.assertEqual(self.read(self.outside, "keep.txt"), b"host state\n")

    @needs_symlinks
    def test_cleanup_refuses_when_snapshot_root_is_swapped_for_a_link(self):
        snap = self.make()
        root = str(snap.snapshot_dir)
        moved = os.path.join(self.staging, "fb-sealed-moved-aside")
        os.rename(root, moved)
        os.symlink(moved, root)
        with self.assertRaises(UnsafePathError):
            snap.cleanup()
        self.assertTrue(os.path.isdir(moved))
        self.assertFalse(snap.cleaned)
        os.unlink(root)
        shutil.rmtree(moved)

    def test_cleanup_refuses_a_root_it_did_not_create(self):
        snap = self.make()
        foreign = os.path.join(self.tmp, "not-a-snapshot")
        os.makedirs(foreign)
        self.write(foreign, "precious.txt", b"keep\n")
        snap._snapshot_dir = foreign
        with self.assertRaises(UnsafePathError):
            snap.cleanup()
        self.assertTrue(os.path.isfile(os.path.join(foreign, "precious.txt")))
        self.snapshots.remove(snap)

    def test_context_manager_cleans_up_and_blocks_further_use(self):
        with self.make() as snap:
            root = str(snap.snapshot_dir)
            self.write(str(snap.work_root), "src/app.py", b"x\n")
        self.assertFalse(os.path.exists(root))
        with self.assertRaises(SnapshotStateError):
            snap.export_changes()
        with self.assertRaises(SnapshotStateError):
            snap.scan()

    def test_export_fails_when_work_root_vanishes(self):
        snap = self.make()
        shutil.rmtree(str(snap.work_root))
        with self.assertRaises(SnapshotStateError):
            snap.export_changes()


# ---------------------------------------------------------------------------
# malformed inputs fail closed
# ---------------------------------------------------------------------------

class InputValidationTests(SnapshotTestBase):
    def test_nonexistent_or_non_directory_source_fails_closed(self):
        with self.assertRaises(SourceError):
            self.make(source=os.path.join(self.tmp, "missing"))
        with self.assertRaises(SourceError):
            self.make(source=os.path.join(self.source, "src", "app.py"))
        for bad in (None, 5, "", "   ", b"/tmp", ["/tmp"]):
            with self.subTest(bad=bad):
                with self.assertRaises(SourceError):
                    create_sealed_snapshot(bad, "a" * 40, ("src",), parent_dir=self.staging)
        self.assertEqual(os.listdir(self.staging), [])

    def test_malformed_base_identity_fails_closed(self):
        for bad in ("", " ", "\n", "a" * 40 + " ", " " + "a" * 40, None, 7, b"abc",
                    "refs/heads/../../etc", "-x", "a b", "a;rm -rf /", "a\nb", "a" * 300):
            with self.subTest(bad=bad):
                with self.assertRaises(SourceError):
                    create_sealed_snapshot(self.source, bad, ("src",), parent_dir=self.staging)
        self.assertEqual(os.listdir(self.staging), [])

    def test_well_formed_base_identities_are_accepted(self):
        for good in ("a" * 40, "refs/heads/main", "v1.2.3", "0123abc"):
            with self.subTest(good=good):
                snap = create_sealed_snapshot(self.source, good, ("src",), parent_dir=self.staging)
                self.addCleanup(self._discard, snap)
                self.assertEqual(snap.manifest.base_identity, good)

    def test_bad_parent_dir_fails_closed(self):
        with self.assertRaises(SourceError):
            create_sealed_snapshot(self.source, "a" * 40, ("src",),
                                   parent_dir=os.path.join(self.tmp, "missing"))

    def test_non_positive_limits_fail_closed(self):
        for kw in ({"max_files": 0}, {"max_total_bytes": 0}, {"max_files": -1}):
            with self.subTest(kw=kw):
                with self.assertRaises(SourceError):
                    self.make(**kw)

    def test_oversized_source_fails_closed_without_leaking_a_snapshot(self):
        with self.assertRaises(IsolationError):
            self.make(max_files=1)
        with self.assertRaises(IsolationError):
            self.make(max_total_bytes=1)
        self.assertEqual(os.listdir(self.staging), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
