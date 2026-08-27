from __future__ import annotations

import copy
import math
import unittest

from forgeboss.control.assignment import AssignmentError, build_assignment, verify_assignment


def packet():
    return {
        "assignmentVersion": 1,
        "taskId": "TASK-1",
        "purpose": "Fix bounded defect",
        "controllerIdentity": "kg-main-001",
        "controllerRevision": 97,
        "builderId": "worker-a",
        "reviewerId": "worker-b",
        "repository": "1stChoiceFNQ-AFK/ForgeBoss",
        "baseSha": "a" * 40,
        "branch": "forgeboss/task-1",
        "allowedPaths": ["Src/One.py", "src/two/"],
        "deniedPaths": ["src/peer/", "secrets/"],
        "allowedTools": ["pytest", "git", "python"],
        "runtime": {"adapter": "mini-swe", "provider": "openai", "model": "gpt-5.6-luna"},
        "contextBundle": {"artefactId": "ctx-001", "sha256": "b" * 64},
        "requiredTests": ["python -m unittest x", "python -m unittest y"],
        "churn": {"maxFiles": 3, "maxChangedLines": 400, "maxChangedBytes": 50000},
        "budget": {"workerUsd": "2.50", "runId": "selfbuild-1", "runContributionUsd": "2.50"},
        "stopReassign": {
            "controllerRevokeRequired": True,
            "freshWorktreeRequired": True,
            "maxAttempts": 2,
        },
    }


class AssignmentContractTests(unittest.TestCase):
    def test_canonical_digest_is_deterministic(self):
        a = build_assignment(packet())
        p = packet()
        p["allowedPaths"] = ["src/two", "src/one.py"]
        p["allowedTools"] = ["python", "git", "pytest"]
        b = build_assignment(p)
        self.assertEqual(a["assignmentSha256"], b["assignmentSha256"])
        self.assertEqual(a["repository"], "1stchoicefnq-afk/forgeboss")
        self.assertEqual(a["allowedPaths"], ["src/one.py", "src/two"])

    def test_any_material_authority_change_changes_digest(self):
        original = build_assignment(packet())["assignmentSha256"]
        mutations = [
            ("purpose", "Different task"),
            ("builderId", "worker-c"),
            ("baseSha", "c" * 40),
            ("branch", "forgeboss/other"),
        ]
        for key, value in mutations:
            with self.subTest(key=key):
                p = packet()
                p[key] = value
                self.assertNotEqual(original, build_assignment(p)["assignmentSha256"])
        p = packet()
        p["runtime"]["model"] = "gpt-5.6-other"
        self.assertNotEqual(original, build_assignment(p)["assignmentSha256"])

    def test_reviewer_must_be_independent(self):
        p = packet()
        p["reviewerId"] = "WORKER-A"
        with self.assertRaisesRegex(AssignmentError, "independent"):
            build_assignment(p)

    def test_scope_equivalence_duplicates_and_contradictions_fail_closed(self):
        p = packet()
        p["allowedPaths"] = ["Src/Child. /file.py", r"src\child\file.py"]
        with self.assertRaisesRegex(AssignmentError, "duplicate"):
            build_assignment(p)
        p = packet()
        p["deniedPaths"] = ["SRC/ONE.PY"]
        with self.assertRaisesRegex(AssignmentError, "contradictory"):
            build_assignment(p)
        p = packet()
        p["deniedPaths"] = ["src/"]
        with self.assertRaisesRegex(AssignmentError, "contradictory"):
            build_assignment(p)

    def test_repository_base_branch_and_tool_authority_are_strict(self):
        for repo in ("../repo", "owner/repo/extra", "https://github.com/o/r", r"C:\o\r", ""):
            p = packet()
            p["repository"] = repo
            with self.subTest(repo=repo), self.assertRaises(AssignmentError):
                build_assignment(p)
        p = packet()
        p["baseSha"] = "a" * 39
        with self.assertRaises(AssignmentError):
            build_assignment(p)
        p = packet()
        p["branch"] = "../evil"
        with self.assertRaises(AssignmentError):
            build_assignment(p)
        p = packet()
        p["allowedTools"].append("shell")
        with self.assertRaisesRegex(AssignmentError, "unsupported"):
            build_assignment(p)

    def test_context_and_required_tests_are_bound(self):
        a = build_assignment(packet())
        p = packet()
        p["contextBundle"] = None
        b = build_assignment(p)
        self.assertNotEqual(a["assignmentSha256"], b["assignmentSha256"])
        p = packet()
        p["requiredTests"] = ["python -m unittest y", "python -m unittest x"]
        self.assertNotEqual(a["assignmentSha256"], build_assignment(p)["assignmentSha256"])
        p = packet()
        p["requiredTests"] = ["same", "same"]
        with self.assertRaisesRegex(AssignmentError, "duplicate"):
            build_assignment(p)

    def test_churn_budget_and_reassign_policy_fail_closed(self):
        for bad in (math.nan, math.inf, -1, True):
            p = packet()
            p["budget"]["workerUsd"] = bad
            with self.subTest(bad=bad), self.assertRaises(AssignmentError):
                build_assignment(p)
        p = packet()
        p["budget"]["runContributionUsd"] = "3"
        with self.assertRaisesRegex(AssignmentError, "cannot exceed"):
            build_assignment(p)
        p = packet()
        p["churn"]["maxFiles"] = 0
        with self.assertRaises(AssignmentError):
            build_assignment(p)
        p = packet()
        p["stopReassign"]["freshWorktreeRequired"] = False
        with self.assertRaisesRegex(AssignmentError, "fresh worktree"):
            build_assignment(p)

    def test_unknown_or_missing_fields_fail_closed(self):
        p = packet()
        p["extra"] = True
        with self.assertRaisesRegex(AssignmentError, "keys mismatch"):
            build_assignment(p)
        p = packet()
        p.pop("reviewerId")
        with self.assertRaisesRegex(AssignmentError, "keys mismatch"):
            build_assignment(p)

    def test_verify_detects_tampering(self):
        a = build_assignment(packet())
        self.assertEqual(verify_assignment(a), a)
        tampered = copy.deepcopy(a)
        tampered["budget"]["workerUsd"] = "99"
        with self.assertRaisesRegex(AssignmentError, "mismatch"):
            verify_assignment(tampered)

    def test_strict_identity_and_control_character_rejection(self):
        p = packet()
        p["taskId"] = "bad/id"
        with self.assertRaises(AssignmentError):
            build_assignment(p)
        p = packet()
        p["purpose"] = "bad\npurpose"
        with self.assertRaisesRegex(AssignmentError, "control"):
            build_assignment(p)

    def test_assignment_version_is_exact(self):
        p = packet()
        p["assignmentVersion"] = 2
        with self.assertRaisesRegex(AssignmentError, "unsupported"):
            build_assignment(p)


if __name__ == "__main__":
    unittest.main()
