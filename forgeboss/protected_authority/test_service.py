from __future__ import annotations

import base64,tempfile,threading,unittest,uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from forgeboss.protected_authority.boundary import PeerContext
from forgeboss.protected_authority.protocol import AuthorityError,OPERATIONS,build_request,canonical_digest,canonical_json,strict_loads
from forgeboss.protected_authority.service import ProtectedAuthorityService,_canonical_peer_policies
from forgeboss.protected_authority.signing import ReceiptSigner,verify_signed_receipt

class Boundary:
    def __init__(self,service_ok=True,peer_ok=True):self.service_ok=service_ok;self.peer_ok=peer_ok
    def assert_service_principal(self,_root):
        if not self.service_ok:raise AuthorityError('SERVICE_PRINCIPAL_DENIED')
        return 'machine:svc'
    def verify_peer(self,peer_id,_digest,_signature,peer_context):return self.peer_ok and peer_id=='controller-a' and peer_context==PeerContext('test','principal-a')
class Secrets:
    private_key='PEM-PRIVATE-DO-NOT-LEAK';trust_root='ED25519-TRUST-DO-NOT-LEAK'
    def __init__(self):self.key_reads=0;self.trust_reads=0
    def github_app_private_key(self):self.key_reads+=1;return self.private_key
    def launch_trust_root(self):self.trust_reads+=1;return self.trust_root
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

def full_policy():
    return {'controller-a':{'operations':sorted(OPERATIONS),'repositories':['owner/repo'],'objects':{op:['*'] for op in OPERATIONS}}}

class TestService(ProtectedAuthorityService):
    def __init__(self,*,protected_root,boundary,secrets_provider,backend,receipt_signer,peer_policies=None):
        self.root=Path(protected_root);self.boundary=boundary;self.secrets_provider=secrets_provider;self.backend=backend;self.receipt_signer=receipt_signer;self.service_principal=boundary.assert_service_principal(self.root);self.allowed_repositories={'owner/repo':'owner/repo'};self.peer_policies=_canonical_peer_policies(peer_policies or full_policy(),self.allowed_repositories)
        from forgeboss.protected_authority.service import ReplayJournal
        self.journal=ReplayJournal(self.root)

class ProtectedAuthorityServiceV3Tests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name);self.boundary=Boundary();self.secrets=Secrets();self.backend=Backend();self.key=Ed25519PrivateKey.generate();self.signer=ReceiptSigner.from_private_key(self.key);self.service=TestService(protected_root=self.root,boundary=self.boundary,secrets_provider=self.secrets,backend=self.backend,receipt_signer=self.signer);raw=self.key.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw);self.public_b64=base64.b64encode(raw).decode()
    def tearDown(self):self.td.cleanup()
    def test_receipt_is_signed_and_forgery_or_result_swap_fails(self):
        out=self.service.handle(req('read_github_control',{'rootPr':10,'preferredRepairPr':0}),peer_context=CTX);self.assertTrue(verify_signed_receipt(out,self.public_b64));forged=dict(out);forged['receipt']=dict(out['receipt']);forged['receipt']['repository']='evil/repo';self.assertFalse(verify_signed_receipt(forged,self.public_b64));swapped=dict(out);swapped['result']={'ok':False};self.assertFalse(verify_signed_receipt(swapped,self.public_b64));self.assertNotIn(self.secrets.private_key,canonical_json(out).decode())
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
    def test_peer_policy_denial_precedes_replay_secret_and_backend(self):
        policy={'controller-a':{'operations':['read_github_control'],'repositories':['owner/repo'],'objects':{'read_github_control':['pr:10']}}}
        self.service.peer_policies=_canonical_peer_policies(policy,self.service.allowed_repositories)
        rid=str(uuid.uuid4());r=req('publish_report_comment',{'issue':11,'body':'report','reportDigest':'a'*64},rid)
        with self.assertRaises(AuthorityError) as cm:self.service.handle(r,peer_context=CTX)
        self.assertEqual(cm.exception.code,'PEER_OPERATION_DENIED');self.assertEqual(self.secrets.key_reads,0);self.assertEqual(self.backend.calls,[])
        self.service.peer_policies=_canonical_peer_policies(full_policy(),self.service.allowed_repositories)
        self.service.handle(r,peer_context=CTX)
        self.assertEqual(self.backend.calls,['publish_report_comment'])
    def test_peer_object_policy_is_fail_closed(self):
        policy={'controller-a':{'operations':['read_github_control'],'repositories':['owner/repo'],'objects':{'read_github_control':['pr:10']}}}
        self.service.peer_policies=_canonical_peer_policies(policy,self.service.allowed_repositories)
        self.service.handle(req('read_github_control',{'rootPr':10,'preferredRepairPr':0}),peer_context=CTX)
        with self.assertRaises(AuthorityError) as cm:self.service.handle(req('read_github_control',{'rootPr':11,'preferredRepairPr':0}),peer_context=CTX)
        self.assertEqual(cm.exception.code,'PEER_OBJECT_DENIED')
    def test_strict_json(self):
        for raw in ('{"x":1,"x":2}','{"x":NaN}','{"x":Infinity}',''):
            with self.subTest(raw=raw),self.assertRaises(AuthorityError):strict_loads(raw)

if __name__=='__main__':unittest.main()
