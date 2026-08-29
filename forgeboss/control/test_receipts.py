from __future__ import annotations
import copy
import unittest
from dataclasses import FrozenInstanceError

from forgeboss.control.receipts import (
    AssignmentIdentityReference, CandidateHandoff, ReviewerReceipt,
    ControllerAcceptanceReference, ReceiptError, canonical_money,
    policy_path_key, receipt_digest, strict_loads, POLICY_PATH_KEY_VERSION
)

A40="a"*40
B40="b"*40
C40="c"*40


def assignment(**over):
    d={
        "assignmentId":"assign-1","assignmentSha256":"1"*64,
        "taskId":"task-1","runId":"run-1","attempt":1,"ownerEpoch":2,
        "repository":"owner/repo","objectFormat":"sha1","baseSha":A40,
        "workspaceGeneration":3,"workspaceContentSha256":"2"*64,
    }
    d.update(over);return d


def pr(path):
    return {"gitPath":path,"policyPathKey":policy_path_key(path),"policyVersion":POLICY_PATH_KEY_VERSION}


def handoff(**over):
    d={
        "assignment":assignment(),"candidateSha":B40,"candidateTreeSha":C40,
        "changedPaths":[pr("src/A.py"),pr("tests/test_a.py")],"requiredTestReceipts":["3"*64],
        "scopeDiffSha256":"4"*64,"additions":10,"deletions":2,
        "measuredCostUsd":"0.40","reservedCostUsd":"1.00",
        "contributors":["worker-a"],"knownUncertainty":["windows runtime pending"],
    }
    d.update(over);return d


def review(h=None, **over):
    h=h or CandidateHandoff.from_dict(handoff())
    d={
        "assignment":h.assignment.to_dict(),"handoffSha256":h.digest,
        "candidateSha":h.candidate_sha,"candidateTreeSha":h.candidate_tree_sha,
        "reviewerId":"worker-b","verdict":"PASS","evidenceSha256":"5"*64,
        "reviewerTestReceipts":["6"*64],
    }
    d.update(over);return d


class MoneyTests(unittest.TestCase):
    def test_decimal_canonicalization(self):
        self.assertEqual(canonical_money("1.00"),"1")
        self.assertEqual(canonical_money("0.4000"),"0.4")
        self.assertEqual(canonical_money("0.000"),"0")

    def test_float_int_exponent_whitespace_nonfinite_negative_rejected(self):
        for bad in (1.0,1,"1e0"," 1","1 ","+1","-1","NaN","Infinity","inf","",None):
            with self.subTest(bad=bad),self.assertRaises(ReceiptError):canonical_money(bad)


class PathTests(unittest.TestCase):
    def test_backslash_literal_and_slash_path_are_not_aliased(self):
        a=policy_path_key(r"src\a.py")
        b=policy_path_key("src/a.py")
        self.assertNotEqual(a,b)
        obj=CandidateHandoff.from_dict(handoff(changedPaths=[pr(r"src\a.py"),pr("src/a.py")]))
        self.assertEqual([x[0] for x in obj.changed_paths],[r"src\a.py","src/a.py"])

    def test_case_policy_collision_rejected(self):
        with self.assertRaises(ReceiptError):
            CandidateHandoff.from_dict(handoff(changedPaths=[pr("Src/A.py"),pr("src/a.py")]))

    def test_path_record_unknown_key_and_policy_tamper_rejected(self):
        bad=pr("src/a.py");bad["extra"]=1
        with self.assertRaises(ReceiptError):
            CandidateHandoff.from_dict(handoff(changedPaths=[bad]))
        bad=pr("src/a.py");bad["policyPathKey"]=POLICY_PATH_KEY_VERSION+":other"
        with self.assertRaises(ReceiptError):
            CandidateHandoff.from_dict(handoff(changedPaths=[bad]))

    def test_handoff_changed_path_records_are_roundtrip_canonical(self):
        obj=CandidateHandoff.from_dict(handoff())
        rebuilt=CandidateHandoff.from_dict(obj.to_dict())
        self.assertEqual(obj,rebuilt)
        self.assertEqual(obj.digest,rebuilt.digest)

    def test_windows_aliases_rejected(self):
        bad=[
            "/x","//server/share","\\\\server\\share","C:/x","C:\\x",
            "src/../x","src/./x","src/x.","src/x ","src/x:ads",
            "NUL.txt","src/COM1","src/LPT³.log","src/PROGRA~1/x"
        ]
        for p in bad:
            with self.subTest(path=p),self.assertRaises(ReceiptError):policy_path_key(p)


class AssignmentTests(unittest.TestCase):
    def test_closed_keys_and_exact_identity(self):
        obj=AssignmentIdentityReference.from_dict(assignment())
        self.assertEqual(obj.workspace_generation,3)
        for key,val in (("attempt",2),("ownerEpoch",9),("workspaceGeneration",8),
                        ("workspaceContentSha256","9"*64),("assignmentSha256","8"*64)):
            self.assertNotEqual(obj,AssignmentIdentityReference.from_dict(assignment(**{key:val})))
        bad=assignment();bad["extra"]=1
        with self.assertRaises(ReceiptError):AssignmentIdentityReference.from_dict(bad)

    def test_object_format_controls_oid_length(self):
        d=assignment(objectFormat="sha256",baseSha="a"*64)
        self.assertEqual(AssignmentIdentityReference.from_dict(d).object_format,"sha256")
        with self.assertRaises(ReceiptError):AssignmentIdentityReference.from_dict(assignment(objectFormat="sha256"))


class HandoffTests(unittest.TestCase):
    def test_candidate_tree_and_workspace_generation_are_bound(self):
        h1=CandidateHandoff.from_dict(handoff())
        d=handoff();d["candidateTreeSha"]="d"*40
        h2=CandidateHandoff.from_dict(d)
        self.assertNotEqual(h1.digest,h2.digest)
        d=handoff();d["assignment"]=assignment(workspaceGeneration=4)
        h3=CandidateHandoff.from_dict(d)
        self.assertNotEqual(h1.digest,h3.digest)

    def test_unknown_cost_is_distinct_from_zero(self):
        u=CandidateHandoff.from_dict(handoff(measuredCostUsd=None))
        z=CandidateHandoff.from_dict(handoff(measuredCostUsd="0"))
        self.assertNotEqual(u.digest,z.digest)

    def test_empty_contributor_set_rejected(self):
        with self.assertRaises(ReceiptError):
            CandidateHandoff.from_dict(handoff(contributors=[]))

    def test_over_reserved_measured_rejected(self):
        with self.assertRaises(ReceiptError):
            CandidateHandoff.from_dict(handoff(measuredCostUsd="1.01",reservedCostUsd="1.00"))

    def test_caller_mutation_after_construction_cannot_change_receipt(self):
        raw=handoff();obj=CandidateHandoff.from_dict(raw);before=obj.digest
        raw["assignment"]["runId"]="evil";raw["changedPaths"].append(pr("evil"))
        self.assertEqual(obj.digest,before)
        with self.assertRaises((FrozenInstanceError,AttributeError)):
            obj.candidate_sha="c"*40


class ReviewTests(unittest.TestCase):
    def test_assignment_mismatch_rejected(self):
        h=CandidateHandoff.from_dict(handoff())
        r=review(h);r["assignment"]=assignment(ownerEpoch=99)
        with self.assertRaises(ReceiptError):ReviewerReceipt.from_dict(r,handoff=h)

    def test_handoff_and_candidate_tree_mismatch_rejected(self):
        h=CandidateHandoff.from_dict(handoff())
        for field,val in (("handoffSha256","9"*64),("candidateTreeSha","d"*40),("candidateSha","e"*40)):
            d=review(h);d[field]=val
            with self.subTest(field=field),self.assertRaises(ReceiptError):
                ReviewerReceipt.from_dict(d,handoff=h)

    def test_contributor_reviewer_collision_case_insensitive(self):
        h=CandidateHandoff.from_dict(handoff(contributors=["Worker-B"]))
        with self.assertRaises(ReceiptError):ReviewerReceipt.from_dict(review(h),handoff=h)

    def test_fail_blocked_are_valid_review_records_but_not_acceptable(self):
        h=CandidateHandoff.from_dict(handoff())
        for verdict in ("FAIL","BLOCKED"):
            rr=ReviewerReceipt.from_dict(review(h,verdict=verdict),handoff=h)
            self.assertEqual(rr.verdict,verdict.lower())
            with self.assertRaises(ReceiptError):
                ControllerAcceptanceReference.from_records(controller_id="controller-1",handoff=h,review=rr)


class AcceptanceTests(unittest.TestCase):
    def test_pass_review_accepts_and_binds_all_digests(self):
        h=CandidateHandoff.from_dict(handoff())
        rr=ReviewerReceipt.from_dict(review(h),handoff=h)
        a=ControllerAcceptanceReference.from_records(controller_id="controller-1",handoff=h,review=rr)
        self.assertEqual(a.candidate_tree_sha,h.candidate_tree_sha)
        self.assertEqual(a.review_sha256,rr.digest)
        self.assertEqual(a.handoff_sha256,h.digest)

    def test_tamper_stable_digests(self):
        h=CandidateHandoff.from_dict(handoff())
        rr=ReviewerReceipt.from_dict(review(h),handoff=h)
        a=ControllerAcceptanceReference.from_records(controller_id="controller-1",handoff=h,review=rr)
        d1=a.digest
        clone=copy.deepcopy(a.to_dict())
        rebuilt=ControllerAcceptanceReference.from_dict(clone,handoff=h,review=rr)
        self.assertEqual(d1,rebuilt.digest)
        clone["candidateSha"]="f"*40
        with self.assertRaises(ReceiptError):
            ControllerAcceptanceReference.from_dict(clone,handoff=h,review=rr)


class StrictJsonTests(unittest.TestCase):
    def test_duplicate_key_rejected_before_mapping_construction(self):
        with self.assertRaises(ReceiptError):
            strict_loads('{"taskId":"a","taskId":"b"}')

    def test_nonfinite_json_rejected(self):
        for raw in ('{"x":NaN}','{"x":Infinity}','{"x":-Infinity}'):
            with self.subTest(raw=raw),self.assertRaises(ReceiptError):
                strict_loads(raw)

    def test_valid_json_preserves_exact_text_values(self):
        self.assertEqual(strict_loads(r'{"path":"src\\a.py"}')["path"], r"src\a.py")


class CanonicalDigestTests(unittest.TestCase):
    def test_dict_key_order_does_not_change_digest(self):
        self.assertEqual(receipt_digest({"a":1,"b":2}),receipt_digest({"b":2,"a":1}))

    def test_non_json_float_rejected(self):
        with self.assertRaises(ReceiptError):receipt_digest({"bad":1.25})
        with self.assertRaises(ReceiptError):receipt_digest({"bad":float("nan")})


if __name__=="__main__":unittest.main()
