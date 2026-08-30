from __future__ import annotations
import hashlib,json,tempfile,unittest
from pathlib import Path
from forgeboss.control.store import ControlStore
from forgeboss.control.receipts import *
A40='a'*40;B40='b'*40;C40='c'*40

def ident(**over):
    d={"taskId":"task-1","runId":"run-1","attempt":1,"ownerEpoch":2,"builderPrincipal":"worker-a","assignmentGeneration":3,
       "assignmentPolicySha256":"1"*64,"repository":"owner/repo","baseSha":A40,"branch":"fb/task-1","worktreePath":"/tmp/fb/task-1",
       "workspaceGeneration":2,"workspaceContentIdentity":"d"*40,"budgetRunId":"budget-1"};d.update(over);return d

def packet_from_identity(i):return {"identity":i,"assignmentIdentitySha256":hashlib.sha256(json.dumps(i,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()}
def packet(**over):return packet_from_identity(ident(**over))
class FakeStore:
    def __init__(self,p=None):self.p=p or packet();self.calls=[]
    def assignment_identity(self,t,r,e):self.calls.append((t,r,e));return self.p

def pr(p):return {"gitPath":p,"policyPathKey":policy_path_key(p),"policyVersion":POLICY_PATH_KEY_VERSION}
def handoff(**over):
    d={"assignment":packet(),"candidateSha":B40,"candidateTreeSha":C40,"changedPaths":[pr('src/a.py')],"requiredTestReceipts":['2'*64],
       "scopeDiffSha256":'3'*64,"additions":1,"deletions":0,"measuredCostUsd":"1.50","reservedCostUsd":"1.00","contributors":['worker-a'],"knownUncertainty":[]};d.update(over);return d

def parsed_handoff(raw=None,store=None):return CandidateHandoff.from_dict(raw or handoff(),store=store or FakeStore())
def review(h,**over):
    d={"assignment":h.assignment.to_store_packet(),"handoffSha256":h.digest,"candidateSha":h.candidate_sha,"candidateTreeSha":h.candidate_tree_sha,"reviewerId":"worker-b","verdict":"PASS","evidenceSha256":'4'*64,"reviewerTestReceipts":['5'*64]};d.update(over);return d

class AssignmentAuthorityTests(unittest.TestCase):
    def test_from_store_direct(self):
        st=FakeStore();a=AssignmentIdentityReference.from_store(st,'task-1','run-1',2);self.assertEqual(a.builder_principal,'worker-a');self.assertEqual(st.calls,[('task-1','run-1',2)])
    def test_packet_must_match_live_store_not_just_self_hash(self):
        forged=packet(builderPrincipal='attacker')
        with self.assertRaises(ReceiptError):AssignmentIdentityReference.from_packet_verified_by_store(forged,FakeStore(packet()))
    def test_store_packet_digest_is_recomputed(self):
        p=packet();p['identity']['runId']='evil'
        with self.assertRaises(ReceiptError):AssignmentIdentityReference.from_store_packet(p)
    def test_parallel_caller_fields_denied(self):
        p=packet();p['assignmentId']='caller'
        with self.assertRaises(ReceiptError):AssignmentIdentityReference.from_store_packet(p)
    def test_real_control_store_packet_consumed_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); st=ControlStore(root/'state.db')
            st.create_budget_run('budget-1','10')
            st.create_task({"taskId":"task-real","repository":"owner/repo","purpose":"test","baseSha":A40,"branch":"fb/task-real","allowedPaths":["src/a.py"],"requiredTests":["t"],"budgetUsd":"2"})
            a=st.assign_builder('task-real','worker-a','budget-1')
            wroot=root/'worktrees';wroot.mkdir();wt=wroot/'task-real';wt.mkdir()
            lease=st.claim_workspace('task-real','run-real',wt,'fb/task-real',A40,worktree_root=wroot,budget_reserved='1',builder_id='worker-a',assignment_token=a['assignmentToken'],assignment_generation=a['assignmentGeneration'],assignment_sha256=a['assignmentSha256'],budget_run_revision=a['budgetRunRevision'])
            ref=AssignmentIdentityReference.from_store(st,'task-real','run-real',lease['owner_epoch'])
            self.assertEqual(ref.identity_sha256,st.assignment_identity('task-real','run-real',lease['owner_epoch'])['assignmentIdentitySha256'])
            self.assertEqual(ref.workspace_content_identity,A40)
            st.db.close()

    def test_workspace_content_git_oid_formats(self):
        self.assertEqual(len(AssignmentIdentityReference.from_store_packet(packet()).workspace_content_identity),40)
        self.assertEqual(len(AssignmentIdentityReference.from_store_packet(packet(baseSha='a'*64,workspaceContentIdentity='b'*64)).workspace_content_identity),64)
        for p in (packet(workspaceContentIdentity='2'*63),packet(baseSha='a'*64,workspaceContentIdentity='b'*40)):
            with self.assertRaises(ReceiptError):AssignmentIdentityReference.from_store_packet(p)

class HandoffTests(unittest.TestCase):
    def test_truthful_overrun_allowed(self):self.assertEqual(parsed_handoff(handoff(measuredCostUsd='7.25')).measured_cost_usd,'7.25')
    def test_unknown_vs_zero_distinct(self):self.assertNotEqual(parsed_handoff(handoff(measuredCostUsd=None)).digest,parsed_handoff(handoff(measuredCostUsd='0')).digest)
    def test_candidate_format_matches_store(self):
        with self.assertRaises(ReceiptError):parsed_handoff(handoff(candidateSha='b'*64))
    def test_store_assignment_mutation_rejected(self):
        raw=handoff();raw['assignment']=packet(builderPrincipal='attacker')
        with self.assertRaises(ReceiptError):parsed_handoff(raw,FakeStore(packet()))
    def test_empty_contributor_rejected(self):
        with self.assertRaises(ReceiptError):parsed_handoff(handoff(contributors=[]))
    def test_digest_binds_tree_generation_identity(self):
        h1=parsed_handoff();h2=parsed_handoff(handoff(candidateTreeSha='e'*40));self.assertNotEqual(h1.digest,h2.digest)

class ReviewTests(unittest.TestCase):
    def test_review_binds_store_and_non_author(self):
        st=FakeStore();h=parsed_handoff(store=st);rr=ReviewerReceipt.from_dict(review(h),store=st,handoff=h);self.assertEqual(rr.verdict,'pass')
        with self.assertRaises(ReceiptError):ReviewerReceipt.from_dict(review(h,reviewerId='WORKER-A'),store=st,handoff=h)
    def test_review_candidate_mismatch_rejected(self):
        st=FakeStore();h=parsed_handoff(store=st)
        with self.assertRaises(ReceiptError):ReviewerReceipt.from_dict(review(h,candidateSha='e'*40),store=st,handoff=h)
    def test_acceptance_requires_pass(self):
        st=FakeStore();h=parsed_handoff(store=st)
        for v in ('FAIL','BLOCKED'):
            rr=ReviewerReceipt.from_dict(review(h,verdict=v),store=st,handoff=h)
            with self.assertRaises(ReceiptError):ControllerAcceptanceReference.from_records(controller_id='controller-1',handoff=h,review=rr)

class CanonicalTests(unittest.TestCase):
    def test_money(self):
        self.assertEqual(canonical_money('1.00'),'1')
        for bad in (1,'1e0','+1','-1','NaN',' 1'):
            with self.assertRaises(ReceiptError):canonical_money(bad)
    def test_paths(self):
        self.assertNotEqual(policy_path_key(r'src\a.py'),policy_path_key('src/a.py'))
        for bad in ('C:/x','src/../x','NUL.txt','src/x:ads','src/x.','src/PROGRA~1/x'):
            with self.assertRaises(ReceiptError):policy_path_key(bad)
    def test_policy_collision(self):
        raw=handoff(changedPaths=[pr('Src/A.py'),pr('src/a.py')])
        with self.assertRaises(ReceiptError):parsed_handoff(raw)
    def test_strict_json(self):
        with self.assertRaises(ReceiptError):strict_loads('{"x":1,"x":2}')
        with self.assertRaises(ReceiptError):strict_loads('{"x":NaN}')
    def test_digest_order_stable_and_float_denied(self):
        self.assertEqual(receipt_digest({'a':1,'b':2}),receipt_digest({'b':2,'a':1}))
        with self.assertRaises(ReceiptError):receipt_digest({'x':1.2})

if __name__=='__main__':unittest.main()
