from __future__ import annotations

import tempfile,threading,unittest,uuid
from pathlib import Path

from forgeboss.protected_authority.boundary import PeerContext
from forgeboss.protected_authority.protocol import AuthorityError,build_request,canonical_digest,canonical_json,strict_loads
from forgeboss.protected_authority.service import ProtectedAuthorityService

class Boundary:
    def __init__(self,service_ok=True,peer_ok=True):self.service_ok=service_ok;self.peer_ok=peer_ok
    def assert_service_principal(self,_root):
        if not self.service_ok:raise AuthorityError('SERVICE_PRINCIPAL_DENIED')
        return 'machine:svc'
    def verify_peer(self,peer_id,_digest,_signature,peer_context):return self.peer_ok and peer_id=='controller-a' and peer_context==PeerContext('test','principal-a')
class Secrets:
    private_key='PEM-PRIVATE-DO-NOT-LEAK';trust_root='ED25519-TRUST-DO-NOT-LEAK'
    def github_app_private_key(self):return self.private_key
    def launch_trust_root(self):return self.trust_root
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
    return build_request(operation=op,request_id=request_id or str(uuid.uuid4()),peer_id='controller-a',repository=repo,control_revision=128,payload=payload,signature='sig')
CTX=PeerContext('test','principal-a')

class ProtectedAuthorityServiceV2Tests(unittest.TestCase):
    def setUp(self):self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name);self.boundary=Boundary();self.secrets=Secrets();self.backend=Backend();self.service=ProtectedAuthorityService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend)
    def tearDown(self):self.td.cleanup()
    def test_read_control_binds_and_redacts(self):
        out=self.service.handle(req('read_github_control',{'rootPr':10,'preferredRepairPr':0}),peer_context=CTX);self.assertEqual(out['receipt']['repository'],'owner/repo');self.assertEqual(out['receipt']['peerPrincipal'],'principal-a');self.assertNotIn(self.secrets.private_key,canonical_json(out).decode())
    def test_peer_context_required_and_fake_peer_denied_before_backend(self):
        r=req('read_github_control',{'rootPr':10,'preferredRepairPr':0})
        with self.assertRaises(TypeError):self.service.handle(r)
        with self.assertRaises(AuthorityError) as cm:self.service.handle(r,peer_context=PeerContext('test','wrong'))
        self.assertEqual(cm.exception.code,'PEER_AUTH_DENIED');self.assertEqual(self.backend.calls,[])
    def test_service_principal_fail_closed(self):
        with self.assertRaises(AuthorityError) as cm:ProtectedAuthorityService(protected_root=self.root,boundary=Boundary(False),secrets_provider=self.secrets,backend=self.backend)
        self.assertEqual(cm.exception.code,'SERVICE_PRINCIPAL_DENIED')
    def test_restart_replay_denied(self):
        rid=str(uuid.uuid4());r=req('publish_report_comment',{'issue':11,'body':'report','reportDigest':'a'*64},rid);self.service.handle(r,peer_context=CTX);other=ProtectedAuthorityService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend)
        with self.assertRaises(AuthorityError) as cm:other.handle(r,peer_context=CTX)
        self.assertEqual(cm.exception.code,'REQUEST_REPLAYED')
    def test_two_service_instances_exactly_one_backend_call(self):
        rid=str(uuid.uuid4());r=req('publish_report_comment',{'issue':11,'body':'report','reportDigest':'a'*64},rid);other=ProtectedAuthorityService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend);bar=threading.Barrier(2);out=[]
        def run(s):
            bar.wait()
            try:s.handle(r,peer_context=CTX);out.append('win')
            except AuthorityError as e:out.append(e.code)
        a=threading.Thread(target=run,args=(self.service,));b=threading.Thread(target=run,args=(other,));a.start();b.start();a.join();b.join();self.assertEqual(sorted(out),['REQUEST_REPLAYED','win']);self.assertEqual(self.backend.calls.count('publish_report_comment'),1)
    def test_cross_repo_substitution_breaks_digest(self):
        r=req('read_github_control',{'rootPr':10,'preferredRepairPr':0});r['repository']='other/repo'
        with self.assertRaises(AuthorityError) as cm:self.service.handle(r,peer_context=CTX)
        self.assertEqual(cm.exception.code,'REQUEST_DIGEST_MISMATCH')
    def test_arbitrary_endpoint_rejected(self):
        with self.assertRaises(AuthorityError):req('publish_report_comment',{'issue':11,'body':'x','reportDigest':'a'*64,'endpoint':'/user/tokens'})
    def test_draft_pr_requires_exact_ref_sha_review_shape(self):
        p={'baseSha':'a'*40,'headSha':'b'*40,'baseRef':'main','headRef':'repair/fix','title':'Reviewed fix','body':'evidence','reviewDigest':'c'*64};self.assertTrue(self.service.handle(req('publish_reviewed_draft_pr',p),peer_context=CTX)['result']['ok'])
        bad=dict(p);bad['headRef']='../evil'
        with self.assertRaises(AuthorityError):req('publish_reviewed_draft_pr',bad)
    def test_launch_trust_not_caller_supplied(self):
        signed={'assignmentId':'a1','ownerEpoch':4};d=canonical_digest(signed);env={'signed':signed,'signature':'AA=='};p={'envelope':env,'envelopeDigest':d};self.assertTrue(self.service.handle(req('verify_launch_authority',p),peer_context=CTX)['result']['ok'])
        bad=dict(p);bad['trustRoot']='attacker'
        with self.assertRaises(AuthorityError):req('verify_launch_authority',bad)
    def test_secret_redaction_and_burn_on_backend_failure(self):
        rid=str(uuid.uuid4());r=req('publish_report_comment',{'issue':11,'body':'x','reportDigest':'d'*64},rid);self.backend.fail=True
        with self.assertRaises(AuthorityError) as cm:self.service.handle(r,peer_context=CTX)
        self.assertEqual(cm.exception.code,'BACKEND_OPERATION_FAILED');self.assertNotIn(self.secrets.private_key,str(cm.exception));self.backend.fail=False
        with self.assertRaises(AuthorityError) as replay:self.service.handle(r,peer_context=CTX)
        self.assertEqual(replay.exception.code,'REQUEST_REPLAYED');self.assertEqual(self.backend.calls.count('publish_report_comment'),1)
        self.backend.leak=True
        with self.assertRaises(AuthorityError) as leak:self.service.handle(req('read_github_control',{'rootPr':10,'preferredRepairPr':0}),peer_context=CTX)
        self.assertEqual(leak.exception.code,'SECRET_FIELD_DENIED')
    def test_strict_json(self):
        for raw in ('{"x":1,"x":2}','{"x":NaN}','{"x":Infinity}',''):
            with self.subTest(raw=raw),self.assertRaises(AuthorityError):strict_loads(raw)

if __name__=='__main__':unittest.main()
