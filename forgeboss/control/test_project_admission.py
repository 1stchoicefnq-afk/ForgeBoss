from __future__ import annotations

import copy
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from forgeboss.control.project_admission import (
    ProjectAdmissionError,
    WORK_KIND,
    issue_project_build_admission,
    verify_project_build_admission,
)


@unittest.skipUnless(shutil.which("git"), "git is required")
class ProjectAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name) / "project"
        self.root.mkdir()
        self._git("init", "-q")
        self._git("config", "user.email", "forgeboss-test@example.invalid")
        self._git("config", "user.name", "ForgeBoss Test")
        (self.root / "a.py").write_text("print('a')\n", encoding="utf-8")
        (self.root / "b.py").write_text("print('b')\n", encoding="utf-8")
        self._git("add", "a.py", "b.py")
        self._git("commit", "-qm", "base")
        self.base = self._git("rev-parse", "HEAD").strip().lower()
        self.secret = b"s" * 32
        self.rules = hashlib.sha256(b"rules").hexdigest()
        self.reuse = hashlib.sha256(b"reuse").hexdigest()
        self.scope = ["b.py", "a.py"]
        self.now = 1_800_000_000

    def _git(self, *args):
        p = subprocess.run(
            [shutil.which("git"), "-C", str(self.root), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if p.returncode:
            self.fail(f"git {' '.join(args)} failed: {p.stderr}")
        return p.stdout

    def issue(self, **overrides):
        args = {
            "project_root": self.root,
            "base_sha": self.base,
            "subsystem": "project-builder",
            "allowed_paths": self.scope,
            "rules_canonical_sha256": self.rules,
            "reuse_review_sha256": self.reuse,
            "secret": self.secret,
            "ttl_seconds": 900,
            "now": self.now,
        }
        args.update(overrides)
        return issue_project_build_admission(**args)

    def verify(self, receipt, **overrides):
        args = {
            "secret": self.secret,
            "expected_project_root": self.root,
            "expected_base_sha": self.base,
            "expected_subsystem": "project-builder",
            "expected_allowed_paths": self.scope,
            "expected_rules_canonical_sha256": self.rules,
            "expected_reuse_review_sha256": self.reuse,
            "now": self.now + 1,
        }
        args.update(overrides)
        return verify_project_build_admission(receipt, **args)

    def test_receipt_is_substantial_and_binds_canonical_scope(self):
        receipt = self.issue()
        self.assertEqual(receipt["workKind"], WORK_KIND)
        self.assertEqual(receipt["allowedPaths"], ["a.py", "b.py"])
        verified = self.verify(receipt)
        self.assertEqual(verified["admissionId"], receipt["admissionId"])

    def test_no_caller_selectable_work_kind_exists(self):
        with self.assertRaises(TypeError):
            self.issue(work_kind="small-repair")

    def test_head_must_match_at_issue_and_verify(self):
        with self.assertRaises(ProjectAdmissionError):
            self.issue(base_sha="f" * 40)

        receipt = self.issue()
        (self.root / "a.py").write_text("changed\n", encoding="utf-8")
        self._git("add", "a.py")
        self._git("commit", "-qm", "next")
        with self.assertRaisesRegex(ProjectAdmissionError, "HEAD changed"):
            self.verify(receipt)

    def test_uncommitted_or_untracked_workspace_change_invalidates_receipt(self):
        receipt = self.issue()
        (self.root / "a.py").write_text("DIRTY\n", encoding="utf-8")
        with self.assertRaisesRegex(ProjectAdmissionError, "workspace baseline changed"):
            self.verify(receipt)

        self._git("checkout", "--", "a.py")
        receipt = self.issue()
        (self.root / "untracked.txt").write_text("NEW\n", encoding="utf-8")
        with self.assertRaisesRegex(ProjectAdmissionError, "workspace baseline changed"):
            self.verify(receipt)

    def test_signature_is_checked_before_receipt_controlled_path_access(self):
        receipt = self.issue()
        tampered = copy.deepcopy(receipt)
        tampered["projectRoot"] = str(Path(self.td.name) / "does-not-exist")
        with self.assertRaisesRegex(ProjectAdmissionError, "signature mismatch"):
            self.verify(tampered)

    def test_signature_tamper_is_rejected(self):
        receipt = self.issue()
        tampered = copy.deepcopy(receipt)
        tampered["subsystem"] = "different"
        with self.assertRaises(ProjectAdmissionError):
            self.verify(tampered)

        tampered = copy.deepcopy(receipt)
        tampered["signature"] = "hmac-sha256:" + ("0" * 64)
        with self.assertRaisesRegex(ProjectAdmissionError, "signature mismatch"):
            self.verify(tampered)

    def test_wrong_secret_is_rejected(self):
        receipt = self.issue()
        with self.assertRaisesRegex(ProjectAdmissionError, "signature mismatch"):
            self.verify(receipt, secret=b"x" * 32)

    def test_rules_and_reuse_digests_are_bound(self):
        receipt = self.issue()
        with self.assertRaisesRegex(ProjectAdmissionError, "rules digest mismatch"):
            self.verify(receipt, expected_rules_canonical_sha256="0" * 64)
        with self.assertRaisesRegex(ProjectAdmissionError, "reuse-review digest mismatch"):
            self.verify(receipt, expected_reuse_review_sha256="0" * 64)

    def test_scope_is_exact_casefold_unique_and_order_canonical(self):
        receipt = self.issue()
        with self.assertRaisesRegex(ProjectAdmissionError, "write scope mismatch"):
            self.verify(receipt, expected_allowed_paths=["a.py"])
        with self.assertRaisesRegex(ProjectAdmissionError, "duplicate Windows-equivalent"):
            self.issue(allowed_paths=["A.py", "a.py"])
        with self.assertRaisesRegex(ProjectAdmissionError, "overlapping ancestor/descendant"):
            self.issue(allowed_paths=["src", "src/module.py"])
        with self.assertRaises(ProjectAdmissionError):
            self.issue(allowed_paths=["../escape.py"])
        with self.assertRaises(ProjectAdmissionError):
            self.issue(allowed_paths=[str(self.root / "a.py")])

    def test_expiry_future_and_oversized_ttl_fail_closed(self):
        receipt = self.issue()
        with self.assertRaisesRegex(ProjectAdmissionError, "expired"):
            self.verify(receipt, now=self.now + 901)

        future = self.issue(now=self.now + 100)
        with self.assertRaisesRegex(ProjectAdmissionError, "issued in the future"):
            self.verify(future, now=self.now)

        with self.assertRaises(ProjectAdmissionError):
            self.issue(ttl_seconds=1801)

    def test_unknown_or_missing_fields_fail_closed(self):
        receipt = self.issue()
        extra = copy.deepcopy(receipt)
        extra["authority"] = "WRITE"
        with self.assertRaisesRegex(ProjectAdmissionError, "field mismatch"):
            self.verify(extra)

        missing = copy.deepcopy(receipt)
        del missing["reuseReviewSha256"]
        with self.assertRaisesRegex(ProjectAdmissionError, "field mismatch"):
            self.verify(missing)

    def test_project_root_must_be_effective_git_worktree_root(self):
        child = self.root / "child"
        child.mkdir()
        with self.assertRaisesRegex(ProjectAdmissionError, "effective Git worktree"):
            self.issue(project_root=child)

    def test_replay_against_other_root_or_base_fails(self):
        receipt = self.issue()
        other = Path(self.td.name) / "other"
        other.mkdir()
        with self.assertRaises(ProjectAdmissionError):
            self.verify(receipt, expected_project_root=other)
        with self.assertRaises(ProjectAdmissionError):
            self.verify(receipt, expected_base_sha="0" * 40)


if __name__ == "__main__":
    unittest.main()