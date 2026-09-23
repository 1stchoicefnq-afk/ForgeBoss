from __future__ import annotations

import base64,tempfile,threading,unittest,uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from forgeboss.protected_authority.boundary import PeerContext
from forgeboss.protected_authority.protocol import AuthorityError,build_request,canonical_digest,canonical_json,strict_loads
from forgeboss.protected_authority.client import ProtectedAuthorityClient
from forgeboss.protected_authority.service import ProtectedAuthorityService
from forgeboss.protected_authority.signing import ReceiptSigner,verify_signed_receipt

class Boundary:
    def __init__(self,service_ok=True,peer_ok=True):self.service_ok=service_ok;self.peer_ok=peer_ok
    def assert_service_principal(self,_root):
        if not self.service_ok:raise AuthorityError('SERVICE_PRINCIPAL_DENIED')
        return 'machine:svc'
    def verify_peer(self,peer_id,_digest,_signature,peer_context):return self.peer_ok and peer_id=='controller-a' and peer_context==PeerContext('test','principal-a')
class Secrets:
    private_key='PEM-PRIVATE-DO-NOT-LEAK';trust_root='ED25519-TRUST-DO-NOT-LEAK'
    def __init__(self):self.github_reads=0;self.launch_reads=0
    def github_app_private_key(self):self.github_reads+=1;return self.private_key
    def launch_trust_root(self):self.launch_reads+=1;return self.trust_root
class Backend:
    def __init__(self):self.calls=[];self.fail=False;self.leak=False;self.lock=threading.Lock()
    def _r(self,op,kw,private):
        with self.lock:self.calls.append(op)
        if self.fail:raise RuntimeError('provider failed '+str(private))
        if self.leak:return {'token':private}
        return {'ok':True,'operation':op,'repository':kw['repository'],'controlRevision':kw['control_revision']}
    def read_github_control(self,**kw):return self._r('read_github_control',kw,kw['private_key'])
    def publish_report_comment(self,**kw):return self._r('publish_report_comment',kw,kw['private_key'])
    def publish_reviewed_draft_pr(self,**kw):return self._r('publish_reviewed_draft_pr',kw,kw['private_key'])
    def verify_launch_authority(self,**kw):return self._r('verify_launch_authority',kw,kw['trust_root'])

def req(op,payload,request_id=None,repo='owner/repo'):
    return build_request(operation=op,request_id=request_id or str(uuid.uuid4()),peer_id='controller-a',repository=repo,control_revision=129,payload=payload,signature='sig')
CTX=PeerContext('test','principal-a')

class TestService(ProtectedAuthorityService):
    def __init__(self,*,protected_root,boundary,secrets_provider,backend,receipt_signer,self_build_runtime=None,policy_approver_peer_ids=()):
        self.root=Path(protected_root);self.boundary=boundary;self.secrets_provider=secrets_provider;self.backend=backend;self.receipt_signer=receipt_signer;self.service_principal=boundary.assert_service_principal(self.root);self.allowed_repositories={'owner/repo':'owner/repo'};self.self_build_runtime=self_build_runtime;self.github_enabled=True
        self.policy_approver_peer_ids=frozenset(policy_approver_peer_ids)
        from forgeboss.protected_authority.service import ReplayJournal
        self.journal=ReplayJournal(self.root)

class Runtime:
    def __init__(self,leak=False):self.calls=[];self.leak=leak
    def prepare(self,payload):
        self.calls.append(('prepare',dict(payload)))
        if self.leak:return {'assignmentToken':'must-not-escape'}
        return {'schema':1,'run_id':payload['runId'],'base_sha':payload['baseSha'],'builders':[]}
    def prepare_replacement(self,payload):self.calls.append(('replacement',dict(payload)));return {'schema':1,'replacement':True,'run_id':payload['runId']}
    def compose_successor(self,payload):self.calls.append(('compose',dict(payload)));return {'schema':1,'run_id':payload['runId'],'status':'COMPOSED_AWAITING_ACTIVATION'}
    def activate_successor(self,payload):self.calls.append(('activate',dict(payload)));return {'status':'ACTIVATED_KNOWN_GOOD','successor_sha':'f'*40}
    def prove_activation_rollback(self,payload):self.calls.append(('rollback-proof',dict(payload)));return {'status':'ROLLBACK_PROVEN','run_id':payload['runId'],'evidence_digest':'a'*64}
    def current_known_good(self,payload):self.calls.append(('current-known-good',dict(payload)));return {'schema':1,'generation':2,'phase':'READY','revision':'f'*40,'code_root':'/protected/successor'}
    def record_review(self,payload):self.calls.append(('review',dict(payload)));return {'schema':1,'status':'PASS','taskId':payload['taskId']}
    def status(self,payload):self.calls.append(('status',dict(payload)));return {'schema':1,'phase':'PREPARED','run_id':payload['runId']}

class ProtectedAuthorityServiceV3Tests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name);self.boundary=Boundary();self.secrets=Secrets();self.backend=Backend();self.key=Ed25519PrivateKey.generate();self.signer=ReceiptSigner.from_private_key(self.key);self.service=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer);raw=self.key.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw);self.public_b64=base64.b64encode(raw).decode()
    def tearDown(self):self.td.cleanup()
    def test_receipt_is_signed_and_forgery_or_result_swap_fails(self):
        out=self.service.handle(req('read_github_control',{'rootPr':10,'preferredRepairPr':0}),peer_context=CTX);self.assertTrue(verify_signed_receipt(out,self.public_b64));forged=dict(out);forged['receipt']=dict(out['receipt']);forged['receipt']['repository']='evil/repo';self.assertFalse(verify_signed_receipt(forged,self.public_b64));swapped=dict(out);swapped['result']={'ok':False};self.assertFalse(verify_signed_receipt(swapped,self.public_b64));self.assertNotIn(self.secrets.private_key,canonical_json(out).decode())
    def test_explicit_offline_mode_denies_github_without_private_key_read(self):
        self.service.github_enabled=False
        with self.assertRaises(AuthorityError) as cm:
            self.service.handle(req('read_github_control',{'rootPr':10,'preferredRepairPr':0}),peer_context=CTX)
        self.assertEqual(cm.exception.code,'GITHUB_NOT_CONFIGURED')
        self.assertEqual(self.secrets.github_reads,0)
        self.assertEqual(self.backend.calls,[])

    def test_peer_context_required(self):
        r=req('read_github_control',{'rootPr':10,'preferredRepairPr':0})
        with self.assertRaises(TypeError):self.service.handle(r)
        with self.assertRaises(AuthorityError):self.service.handle(r,peer_context=PeerContext('test','wrong'))
    def test_restart_replay_denied(self):
        rid=str(uuid.uuid4());r=req('publish_report_comment',{'issue':11,'body':'report','reportDigest':'a'*64},rid);self.service.handle(r,peer_context=CTX);other=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer)
        with self.assertRaises(AuthorityError) as cm:other.handle(r,peer_context=CTX)
        self.assertEqual(cm.exception.code,'REQUEST_REPLAYED')
    def test_two_service_instances_exactly_one_backend_call(self):
        rid=str(uuid.uuid4());r=req('publish_report_comment',{'issue':11,'body':'report','reportDigest':'a'*64},rid);other=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer);bar=threading.Barrier(2);out=[]
        def run(s):
            bar.wait()
            try:s.handle(r,peer_context=CTX);out.append('win')
            except AuthorityError as e:out.append(e.code)
        a=threading.Thread(target=run,args=(self.service,));b=threading.Thread(target=run,args=(other,));a.start();b.start();a.join();b.join();self.assertEqual(sorted(out),['REQUEST_REPLAYED','win']);self.assertEqual(self.backend.calls.count('publish_report_comment'),1)
    def test_exact_draft_shape_and_secret_redaction(self):
        p={'baseSha':'a'*40,'headSha':'b'*40,'baseRef':'main','headRef':'repair/fix','title':'Reviewed fix','body':'evidence','reviewDigest':'c'*64};out=self.service.handle(req('publish_reviewed_draft_pr',p),peer_context=CTX);self.assertTrue(verify_signed_receipt(out,self.public_b64));self.backend.leak=True
        with self.assertRaises(AuthorityError) as cm:self.service.handle(req('read_github_control',{'rootPr':10,'preferredRepairPr':0}),peer_context=CTX)
        self.assertEqual(cm.exception.code,'SECRET_FIELD_DENIED')
    def test_self_build_prepare_uses_local_runtime_without_github_private_key(self):
        runtime=Runtime()
        svc=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer,self_build_runtime=runtime)
        payload={'sourceRoot':'C:\\ForgeBoss' if __import__('os').name=='nt' else '/opt/ForgeBoss','baseSha':'a'*40,'runId':'fl1-one'}
        out=svc.handle(req('prepare_self_build',payload),peer_context=CTX)
        self.assertTrue(verify_signed_receipt(out,self.public_b64))
        self.assertEqual(runtime.calls[0][0],'prepare')
        self.assertEqual(self.secrets.github_reads,0)
        self.assertEqual(self.backend.calls,[])

    def test_self_build_compose_round_trip_stays_local_and_exact(self):
        runtime=Runtime()
        svc=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer,self_build_runtime=runtime)
        client=ProtectedAuthorityClient(peer_id='controller-a',repository='owner/repo',control_revision=129,peer_private_key=self.key,receipt_public_key_b64=self.public_b64,transport=lambda raw:svc.handle_json(raw,peer_context=CTX))
        out=client.compose_self_build_successor(run_id='fl1-compose')
        self.assertEqual(out['result']['status'],'COMPOSED_AWAITING_ACTIVATION')
        self.assertEqual(runtime.calls,[('compose',{'runId':'fl1-compose'})])
        self.assertEqual(self.secrets.github_reads,0);self.assertEqual(self.backend.calls,[])
        with self.assertRaises(AuthorityError) as cm:req('compose_self_build_successor',{'runId':'fl1-compose','extra':True})
        self.assertEqual(cm.exception.code,'PAYLOAD_INVALID')

    def test_self_build_activation_round_trip_stays_local_and_exact(self):
        runtime=Runtime()
        svc=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer,self_build_runtime=runtime)
        client=ProtectedAuthorityClient(peer_id='controller-a',repository='owner/repo',control_revision=129,peer_private_key=self.key,receipt_public_key_b64=self.public_b64,transport=lambda raw:svc.handle_json(raw,peer_context=CTX))
        out=client.activate_self_build_successor(run_id='fl1-activate')
        self.assertEqual(out['result']['status'],'ACTIVATED_KNOWN_GOOD')
        self.assertEqual(runtime.calls,[('activate',{'runId':'fl1-activate'})])
        self.assertEqual(self.secrets.github_reads,0);self.assertEqual(self.backend.calls,[])
        with self.assertRaises(AuthorityError) as cm:req('activate_self_build_successor',{'runId':'fl1-activate','extra':True})
        self.assertEqual(cm.exception.code,'PAYLOAD_INVALID')

    def test_self_build_rollback_proof_round_trip_stays_local_and_exact(self):
        runtime=Runtime()
        svc=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer,self_build_runtime=runtime)
        client=ProtectedAuthorityClient(peer_id='controller-a',repository='owner/repo',control_revision=129,peer_private_key=self.key,receipt_public_key_b64=self.public_b64,transport=lambda raw:svc.handle_json(raw,peer_context=CTX))
        out=client.prove_self_build_activation_rollback(run_id='fl1-proof')
        self.assertEqual(out['result']['status'],'ROLLBACK_PROVEN')
        self.assertEqual(runtime.calls,[('rollback-proof',{'runId':'fl1-proof'})])
        self.assertEqual(self.secrets.github_reads,0);self.assertEqual(self.backend.calls,[])
        with self.assertRaises(AuthorityError) as cm:req('prove_self_build_activation_rollback',{'runId':'fl1-proof','extra':True})
        self.assertEqual(cm.exception.code,'PAYLOAD_INVALID')

    def test_self_build_current_known_good_round_trip_stays_local_and_empty_payload(self):
        runtime=Runtime()
        svc=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer,self_build_runtime=runtime)
        client=ProtectedAuthorityClient(peer_id='controller-a',repository='owner/repo',control_revision=129,peer_private_key=self.key,receipt_public_key_b64=self.public_b64,transport=lambda raw:svc.handle_json(raw,peer_context=CTX))
        out=client.self_build_current_known_good()
        self.assertEqual(out['result']['phase'],'READY')
        self.assertEqual(runtime.calls,[('current-known-good',{})])
        self.assertEqual(self.secrets.github_reads,0);self.assertEqual(self.backend.calls,[])
        with self.assertRaises(AuthorityError) as cm:req('self_build_current_known_good',{'extra':True})
        self.assertEqual(cm.exception.code,'PAYLOAD_INVALID')

    def test_self_build_independent_review_round_trip_has_no_caller_review_payload(self):
        runtime=Runtime()
        svc=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer,self_build_runtime=runtime)
        client=ProtectedAuthorityClient(peer_id='controller-a',repository='owner/repo',control_revision=129,peer_private_key=self.key,receipt_public_key_b64=self.public_b64,transport=lambda raw:svc.handle_json(raw,peer_context=CTX))
        out=client.review_self_build_candidate(run_id='fl1-review',task_id='task-a',worker_run_id='worker-a',owner_epoch=1)
        self.assertEqual(out['result']['status'],'PASS')
        self.assertEqual(runtime.calls,[('review',{'runId':'fl1-review','taskId':'task-a','workerRunId':'worker-a','ownerEpoch':1})])
        self.assertEqual(self.secrets.github_reads,0);self.assertEqual(self.backend.calls,[])
        with self.assertRaises(AuthorityError) as cm:req('review_self_build_candidate',{'runId':'fl1-review','taskId':'task-a','workerRunId':'worker-a','ownerEpoch':1,'review':{'verdict':'pass'}})
        self.assertEqual(cm.exception.code,'PAYLOAD_INVALID')

    def test_self_build_runtime_secret_shaped_result_is_refused(self):
        runtime=Runtime(leak=True)
        svc=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer,self_build_runtime=runtime)
        payload={'sourceRoot':'C:\\ForgeBoss' if __import__('os').name=='nt' else '/opt/ForgeBoss','baseSha':'a'*40,'runId':'fl1-leak'}
        with self.assertRaises(AuthorityError) as cm:
            svc.handle(req('prepare_self_build',payload),peer_context=CTX)
        self.assertEqual(cm.exception.code,'SECRET_FIELD_DENIED')
        self.assertEqual(self.secrets.github_reads,0)

    def test_self_build_operation_fails_closed_without_runtime(self):
        payload={'sourceRoot':'C:\\ForgeBoss' if __import__('os').name=='nt' else '/opt/ForgeBoss','baseSha':'a'*40,'runId':'fl1-none'}
        with self.assertRaises(AuthorityError) as cm:
            self.service.handle(req('prepare_self_build',payload),peer_context=CTX)
        self.assertEqual(cm.exception.code,'SELF_BUILD_RUNTIME_UNAVAILABLE')

    def _policy_payload(self,reuse=False):
        out={
            'taskId':'task-a',
            'baseSha':'A'*40,
            'objectiveSha256':'B'*64,
            'allowedPaths':['SRC/A.py.','tests\\A.test.py'],
            'ttlSeconds':300,
        }
        if reuse:
            out['subsystem']='terminal-execution';out['reviewSha256']='C'*64
        return out

    def test_policy_approval_requires_explicit_approver_peer(self):
        with self.assertRaises(AuthorityError) as cm:
            self.service.handle(req('approve_small_repair',self._policy_payload()),peer_context=CTX)
        self.assertEqual(cm.exception.code,'POLICY_APPROVER_DENIED')
        self.assertEqual(self.secrets.github_reads,0);self.assertEqual(self.secrets.launch_reads,0);self.assertEqual(self.backend.calls,[])

    def test_small_repair_policy_receipt_is_local_signed_and_exact(self):
        svc=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer,policy_approver_peer_ids={'controller-a'})
        before=__import__('time').time()
        out=svc.handle(req('approve_small_repair',self._policy_payload()),peer_context=CTX)
        self.assertTrue(verify_signed_receipt(out,self.public_b64))
        self.assertEqual(out['receipt']['operation'],'approve_small_repair')
        self.assertEqual(out['result']['policy'],'small-repair-v1')
        self.assertEqual(out['result']['repository'],'owner/repo')
        self.assertEqual(out['result']['baseSha'],'a'*40)
        self.assertEqual(out['result']['objectiveSha256'],'b'*64)
        self.assertEqual(out['result']['allowedPaths'],['src/a.py','tests/a.test.py'])
        self.assertGreaterEqual(out['result']['issuedAt'],int(before)-1)
        self.assertEqual(out['result']['expiresAt']-out['result']['issuedAt'],300)
        self.assertEqual(self.secrets.github_reads,0);self.assertEqual(self.secrets.launch_reads,0);self.assertEqual(self.backend.calls,[])

    def test_reuse_review_policy_receipt_binds_review_digest_and_subsystem(self):
        svc=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer,policy_approver_peer_ids={'controller-a'})
        out=svc.handle(req('approve_reuse_review',self._policy_payload(reuse=True)),peer_context=CTX)
        self.assertTrue(verify_signed_receipt(out,self.public_b64))
        self.assertEqual(out['receipt']['operation'],'approve_reuse_review')
        self.assertEqual(out['result']['policy'],'reuse-review-v1')
        self.assertEqual(out['result']['subsystem'],'terminal-execution')
        self.assertEqual(out['result']['reviewSha256'],'c'*64)
        self.assertEqual(self.secrets.github_reads,0);self.assertEqual(self.backend.calls,[])

    def test_policy_payload_escape_duplicate_and_ttl_fail_closed(self):
        bad=self._policy_payload();bad['allowedPaths']=['../escape.py']
        with self.assertRaises(AuthorityError) as cm:req('approve_small_repair',bad)
        self.assertEqual(cm.exception.code,'POLICY_PATH_INVALID')
        bad=self._policy_payload();bad['allowedPaths']=['SRC/A.py','src/a.py.']
        with self.assertRaises(AuthorityError) as cm:req('approve_small_repair',bad)
        self.assertEqual(cm.exception.code,'POLICY_PATH_DUPLICATE')
        bad=self._policy_payload();bad['ttlSeconds']=3601
        with self.assertRaises(AuthorityError) as cm:req('approve_small_repair',bad)
        self.assertEqual(cm.exception.code,'POLICY_TTL_INVALID')

    def test_policy_request_replay_is_denied_before_second_approval(self):
        svc=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer,policy_approver_peer_ids={'controller-a'})
        rid=str(uuid.uuid4());r=req('approve_reuse_review',self._policy_payload(reuse=True),rid)
        svc.handle(r,peer_context=CTX)
        with self.assertRaises(AuthorityError) as cm:svc.handle(r,peer_context=CTX)
        self.assertEqual(cm.exception.code,'REQUEST_REPLAYED')

    def test_strict_json(self):
        for raw in ('{"x":1,"x":2}','{"x":NaN}','{"x":Infinity}',''):
            with self.subTest(raw=raw),self.assertRaises(AuthorityError):strict_loads(raw)

if __name__=='__main__':unittest.main()