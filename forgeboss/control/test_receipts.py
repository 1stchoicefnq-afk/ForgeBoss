from __future__ import annotations
import copy, unittest
from forgeboss.control.receipts import *

A="a"*40;B="b"*40;T="c"*40;D="d"*64
def path(p): return {"gitPath":p,"policyVersion":PATH_POLICY,"policyPathKey":policy_path_key(p)}
def assignment(**x):
    d={"assignmentId":"a1","assignmentSha256":"1"*64,"taskId":"t1","runId":"r1","attempt":1,"ownerEpoch":2,
       "builderId":"worker-a","assignmentGeneration":3,"repository":"owner/repo","objectFormat":"sha1","baseSha":A,
       "workspaceGeneration":4,"workspaceContentSha256":"2"*64}
    d.update(x); return d
def handoff(**x):
    d={"assignment":assignment(),"candidateSha":B,"candidateTreeSha":T,"changedPaths":[path("src/a.py")],
       "requiredTestReceipts":["3"*64],"scopeDiffSha256":"4"*64,"measuredCostUsd":"0.4","reservedCostUsd":"1.0"}
    d.update(x); return d
def review(h,**x):
    d={"assignment":h.assignment.data(),"handoffSha256":h.sha256,"candidateSha":h.candidate_sha,
       "candidateTreeSha":h.candidate_tree_sha,"reviewerId":"worker-b","verdict":"PASS","evidenceSha256":"5"*64}
    d.update(x); return d

class ReceiptV3Tests(unittest.TestCase):
    def test_assignment_binds_builder_generation_workspace(self):
        a=Assignment.parse(assignment()); b=Assignment.parse(assignment(builderId="worker-x")); c=Assignment.parse(assignment(assignmentGeneration=9))
        self.assertNotEqual(a,b);self.assertNotEqual(a,c)
    def test_builder_cannot_hide_self_from_review(self):
        h=Handoff.parse(handoff())
        with self.assertRaises(ReceiptError): Review.parse(review(h,reviewerId="WORKER-A"),h)
    def test_review_cannot_swap_assignment_or_candidate(self):
        h=Handoff.parse(handoff())
        for field,value in (("candidateSha","e"*40),("handoffSha256","9"*64)):
            r=review(h);r[field]=value
            with self.assertRaises(ReceiptError):Review.parse(r,h)
        r=review(h);r["assignment"]=assignment(ownerEpoch=99)
        with self.assertRaises(ReceiptError):Review.parse(r,h)
    def test_only_pass_is_acceptable_and_controller_independent(self):
        h=Handoff.parse(handoff())
        for v in ("FAIL","BLOCKED"):
            rr=Review.parse(review(h,verdict=v),h)
            with self.assertRaises(ReceiptError):Acceptance.create("controller",h,rr)
        rr=Review.parse(review(h),h)
        self.assertTrue(Acceptance.create("controller",h,rr).sha256)
        with self.assertRaises(ReceiptError):Acceptance.create("worker-a",h,rr)
        with self.assertRaises(ReceiptError):Acceptance.create("worker-b",h,rr)
    def test_money_exact_unknown_distinct_and_overreserve_denied(self):
        h0=Handoff.parse(handoff(measuredCostUsd=None)); hz=Handoff.parse(handoff(measuredCostUsd="0"))
        self.assertNotEqual(h0.sha256,hz.sha256)
        with self.assertRaises(ReceiptError):Handoff.parse(handoff(measuredCostUsd="1.1",reservedCostUsd="1"))
        for bad in (1.0,1,"1e0","-1","NaN"," Infinity "):
            with self.assertRaises(ReceiptError):money(bad,"x")
    def test_exact_git_paths_and_windows_aliases(self):
        self.assertNotEqual(policy_path_key(r"src\a.py"),policy_path_key("src/a.py"))
        for p in ("/x","C:/x","src/../x","src/a.","src/a ","src/a:ads","NUL.txt","src/COM1","src/LPT³.log","src/PROGRA~1/x"):
            with self.subTest(p=p),self.assertRaises(ReceiptError):policy_path_key(p)
        with self.assertRaises(ReceiptError):Handoff.parse(handoff(changedPaths=[path("Src/A.py"),path("src/a.py")]))
    def test_strict_json_rejects_duplicate_and_nonfinite(self):
        for raw in ('{"x":1,"x":2}','{"x":NaN}','{"x":Infinity}'):
            with self.assertRaises(ReceiptError):strict_loads(raw)
    def test_object_format_controls_oid_length(self):
        x=assignment(objectFormat="sha256",baseSha="a"*64)
        self.assertEqual(Assignment.parse(x).base_sha,"a"*64)
        with self.assertRaises(ReceiptError):Assignment.parse(assignment(objectFormat="sha256"))
    def test_handoff_digest_changes_with_builder_generation(self):
        h1=Handoff.parse(handoff())
        h2=Handoff.parse(handoff(assignment=assignment(assignmentGeneration=4)))
        self.assertNotEqual(h1.sha256,h2.sha256)
    def test_unknown_keys_fail_closed(self):
        a=assignment();a["x"]=1
        with self.assertRaises(ReceiptError):Assignment.parse(a)
        h=handoff();h["x"]=1
        with self.assertRaises(ReceiptError):Handoff.parse(h)
if __name__=="__main__":unittest.main()
