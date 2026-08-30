from __future__ import annotations
import base64,ctypes,json,os,tempfile,threading,time,unittest,uuid
from ctypes import wintypes
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from forgeboss.protected_authority.boundary import PeerContext
from forgeboss.protected_authority.github_backend import GitHubAppBackend
from forgeboss.protected_authority.lifecycle import FIXED_PIPE_NAME,WindowsNamedPipeServer
from forgeboss.protected_authority.protocol import AuthorityError,build_request,canonical_json
from forgeboss.protected_authority.service import ProtectedAuthorityService,ReplayJournal,_canonical_repository_map
from forgeboss.protected_authority.signing import ReceiptSigner,verify_signed_receipt
from forgeboss.protected_authority.win32_ffi import is_invalid_handle,load_win32

class Boundary:
    def assert_service_principal(self,_root):return 'machine:svc'
    def verify_peer(self,_peer,_digest,_sig,_ctx):return True
class Secrets:
    def github_app_private_key(self):return b'PRIVATE'
    def launch_trust_root(self):return b'TRUST'
class BackendSpy:
    def __init__(self):self.calls=[]
    def read_github_control(self,**kw):self.calls.append(('read',kw['repository']));return {'repository':kw['repository'],'controlRevision':kw['control_revision'],'ok':True}
    def publish_report_comment(self,**kw):self.calls.append(('comment',kw['repository']));return {'repository':kw['repository'],'controlRevision':kw['control_revision'],'ok':True}
    def publish_reviewed_draft_pr(self,**kw):self.calls.append(('pr',kw['repository']));return {'repository':kw['repository'],'controlRevision':kw['control_revision'],'ok':True}
    def verify_launch_authority(self,**kw):self.calls.append(('launch',kw['repository']));return {'repository':kw['repository'],'controlRevision':kw['control_revision'],'verified':True}
class Signer:
    def sign(self,receipt):return {'receipt':dict(receipt),'receiptDigest':'d'*64,'receiptSignature':'signed'}
class TestService(ProtectedAuthorityService):
    def __init__(self,root,allowed=('Owner/Repo',),receipt_signer=None):
        self.root=Path(root);self.boundary=Boundary();self.secrets_provider=Secrets();self.backend=BackendSpy();self.receipt_signer=receipt_signer or Signer();self.allowed_repositories=_canonical_repository_map(allowed);self.service_principal='machine:svc';self.journal=ReplayJournal(self.root)

def request(repo='owner/repo',op='read_github_control'):
    payload={'rootPr':1,'preferredRepairPr':0} if op=='read_github_control' else {'issue':1,'body':'x','reportDigest':'a'*64}
    return build_request(operation=op,request_id=str(uuid.uuid4()),peer_id='controller-a',repository=repo,control_revision=133,payload=payload,signature='sig')

class RepositoryAuthorityTests(unittest.TestCase):
    def test_wrong_repository_denied_before_replay_secret_or_backend(self):
        with tempfile.TemporaryDirectory() as td:
            svc=TestService(td);r=request('other/repo')
            with self.assertRaises(AuthorityError) as cm:svc.handle(r,peer_context=PeerContext('test','p'))
            self.assertEqual(cm.exception.code,'REPOSITORY_DENIED');self.assertEqual(svc.backend.calls,[])
            db=__import__('sqlite3').connect(svc.journal.path);self.assertEqual(db.execute('select count(*) from consumed').fetchone()[0],0);db.close()
    def test_repository_case_is_canonicalized_in_backend_and_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            svc=TestService(td);out=svc.handle(request('owner/repo'),peer_context=PeerContext('test','p'));self.assertEqual(svc.backend.calls,[('read','Owner/Repo')]);self.assertEqual(out['receipt']['repository'],'Owner/Repo');self.assertEqual(out['result']['repository'],'Owner/Repo')
    def test_empty_or_ambiguous_allowlist_denied(self):
        for values in ([],['bad'],['Owner/Repo','owner/repo']):
            with self.subTest(values=values),self.assertRaises(AuthorityError):_canonical_repository_map(values)

class TokenScopeBackend(GitHubAppBackend):
    def __init__(self):super().__init__(app_id=1,installation_id=2);self.requests=[]
    def _jwt(self,_pem):return 'jwt'
    def _request(self,method,path,*,token=None,body=None):self.requests.append((method,path,token,body));return {'token':'opaque'}
class TokenScopeTests(unittest.TestCase):
    def test_operation_tokens_are_exact_repo_and_minimum_permissions(self):
        expected={
            'read_github_control':{'contents':'read','pull_requests':'read'},
            'publish_report_comment':{'issues':'write'},
            'publish_reviewed_draft_pr':{'contents':'read','pull_requests':'write'},
        }
        for op,perms in expected.items():
            with self.subTest(op=op):
                b=TokenScopeBackend();self.assertEqual(b._token(b'k','Owner/Repo',op),'opaque');method,path,token,body=b.requests[-1];self.assertEqual(method,'POST');self.assertEqual(path,'/app/installations/2/access_tokens');self.assertEqual(token,'jwt');self.assertEqual(body,{'repositories':['Repo'],'permissions':perms});self.assertEqual(set(body['permissions']),set(perms))
    def test_unknown_operation_cannot_mint_token(self):
        b=TokenScopeBackend()
        with self.assertRaises(AuthorityError):b._token(b'k','Owner/Repo','arbitrary')
        self.assertEqual(b.requests,[])

@unittest.skipUnless(os.name=='nt','native Windows availability proof')
class WindowsAvailabilityTests(unittest.TestCase):
    class PipeBoundary:
        expected='test'
        def assert_service_principal(self,_root):return 'test'
        def assert_protected_path(self,_path,**_kw):return None
    def _signed_service(self,td):
        key=Ed25519PrivateKey.generate();signer=ReceiptSigner.from_private_key(key);svc=TestService(td,receipt_signer=signer);raw=key.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw);return svc,base64.b64encode(raw).decode()
    def _server(self,td,service,timeout=500):return WindowsNamedPipeServer(service=service,boundary=self.PipeBoundary(),protected_root=Path(td),allowed_peer_sids={'S-1-1-0'},max_instances=4,preauth_timeout_ms=timeout,poll_interval=0.005)
    def _open_client(self):
        api=load_win32();deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            h=api.kernel32.CreateFileW(FIXED_PIPE_NAME,0xC0000000,0,None,3,0,None)
            if not is_invalid_handle(h):return h
            time.sleep(0.01)
        self.fail('client could not open named pipe')
    def _send_recv(self,h,raw:bytes)->bytes:
        api=load_win32();written=wintypes.DWORD(0);self.assertTrue(api.kernel32.WriteFile(h,raw,len(raw),ctypes.byref(written),None));self.assertEqual(written.value,len(raw));buf=ctypes.create_string_buffer(65536);read=wintypes.DWORD(0);deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            ctypes.set_last_error(0);ok=api.kernel32.ReadFile(h,buf,len(buf),ctypes.byref(read),None);err=ctypes.get_last_error()
            if ok and read.value:return buf.raw[:read.value]
            if err in (232,536):time.sleep(0.01);continue
            if read.value:return buf.raw[:read.value]
            time.sleep(0.01)
        self.fail('client response timed out')
    def test_stalled_client_does_not_starve_valid_signed_service_response(self):
        api=load_win32()
        with tempfile.TemporaryDirectory() as td:
            svc,public_b64=self._signed_service(td);srv=self._server(td,svc,timeout=500);srv.start();batch={};t=threading.Thread(target=lambda:batch.setdefault('results',srv.serve_batch()));t.start();stall=self._open_client();valid=self._open_client()
            try:
                raw=canonical_json(request());started=time.monotonic();response=self._send_recv(valid,raw);elapsed=time.monotonic()-started;self.assertLess(elapsed,0.5);obj=json.loads(response.decode());self.assertTrue(verify_signed_receipt(obj,public_b64));self.assertEqual(obj['receipt']['repository'],'Owner/Repo');self.assertEqual(obj['result']['repository'],'Owner/Repo');t.join(2);self.assertFalse(t.is_alive());codes=[x.code for x in batch.get('results',[]) if isinstance(x,AuthorityError)];self.assertIn('IPC_PREAUTH_TIMEOUT',codes)
                second={};t2=threading.Thread(target=lambda:second.setdefault('results',srv.serve_batch()));t2.start();h2=self._open_client()
                try:self.assertTrue(verify_signed_receipt(json.loads(self._send_recv(h2,canonical_json(request())).decode()),public_b64))
                finally:api.kernel32.CloseHandle(h2)
                t2.join(2);self.assertFalse(t2.is_alive())
            finally:
                api.kernel32.CloseHandle(stall);api.kernel32.CloseHandle(valid);srv.close();t.join(1)
    def test_close_unblocks_outstanding_waits(self):
        with tempfile.TemporaryDirectory() as td:
            svc,_=self._signed_service(td);srv=self._server(td,svc,timeout=5000);srv.start();t=threading.Thread(target=srv.serve_batch);t.start();time.sleep(0.1);srv.close();t.join(1.5);self.assertFalse(t.is_alive())

if __name__=='__main__':unittest.main()
