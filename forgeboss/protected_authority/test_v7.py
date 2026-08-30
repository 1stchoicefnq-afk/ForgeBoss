from __future__ import annotations

import base64,json,os,socket,subprocess,tempfile,threading,time,unittest,uuid
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from forgeboss.protected_authority.boundary import PlatformMachineBoundary
from forgeboss.protected_authority.lifecycle import LinuxAuthorityDaemon
from forgeboss.protected_authority.protocol import AuthorityError,canonical_digest,canonical_json
from forgeboss.protected_authority.root_chain import assert_machine_anchored_root
from forgeboss.protected_authority.service import ProtectedAuthorityService,ReplayJournal,_canonical_repository_map
from forgeboss.protected_authority.signing import ReceiptSigner,verify_signed_receipt

class _Secrets:
    def github_app_private_key(self):return b'PRIVATE'
    def launch_trust_root(self):return b'TRUST'
class _Backend:
    def read_github_control(self,**kw):return {'repository':kw['repository'],'controlRevision':kw['control_revision'],'ok':True}
    def publish_report_comment(self,**kw):return {'repository':kw['repository'],'controlRevision':kw['control_revision'],'ok':True}
    def publish_reviewed_draft_pr(self,**kw):return {'repository':kw['repository'],'controlRevision':kw['control_revision'],'ok':True}
    def verify_launch_authority(self,**kw):return {'repository':kw['repository'],'controlRevision':kw['control_revision'],'verified':True}

def _request(peer_key:Ed25519PrivateKey)->bytes:
    u={'schema':2,'operation':'read_github_control','requestId':str(uuid.uuid4()),'peerId':'controller-a','repository':'owner/repo','controlRevision':135,'payload':{'rootPr':1,'preferredRepairPr':0}}
    digest=canonical_digest(u);sig=base64.b64encode(peer_key.sign(bytes.fromhex(digest))).decode();return canonical_json({**u,'requestDigest':digest,'signature':sig})

@unittest.skipIf(os.name=='nt','native Unix proof')
class LinuxAvailabilityV7Tests(unittest.TestCase):
    def _tree(self):
        base=Path(tempfile.mkdtemp(prefix='forgeboss-v7-',dir=str(Path.home())));root=base/'protected';endpoint=base/'run';root.mkdir();endpoint.mkdir();root.chmod(0o700);endpoint.chmod(0o750);return base,root,endpoint
    def _service(self,root):
        uid=os.geteuid();peer=Ed25519PrivateKey.generate();peer_pub=base64.b64encode(peer.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)).decode();boundary=PlatformMachineBoundary(expected_service_principal=f'uid:{uid}',peer_principals={'controller-a':f'uid:{uid}'},peer_public_keys={'controller-a':peer_pub});receipt=Ed25519PrivateKey.generate();signer=ReceiptSigner.from_private_key(receipt);svc=object.__new__(ProtectedAuthorityService);svc.root=root;svc.boundary=boundary;svc.secrets_provider=_Secrets();svc.backend=_Backend();svc.receipt_signer=signer;svc.allowed_repositories=_canonical_repository_map(['Owner/Repo']);svc.service_principal=f'uid:{uid}';svc.journal=ReplayJournal(root);receipt_pub=base64.b64encode(receipt.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)).decode();return svc,boundary,peer,receipt_pub
    def _connect(self,path):
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);deadline=time.monotonic()+3
        while True:
            try:s.connect(str(path));return s
            except (FileNotFoundError,ConnectionRefusedError):
                if time.monotonic()>=deadline:raise
                time.sleep(0.01)
    def _roundtrip(self,path,raw):
        s=self._connect(path)
        try:s.sendall(raw);s.shutdown(socket.SHUT_WR);data=b'';s.settimeout(3)
        except Exception:s.close();raise
        try:
            while True:
                part=s.recv(65536)
                if not part:break
                data+=part
            return data
        finally:s.close()
    def test_stalled_a_does_not_starve_valid_b_and_service_recovers(self):
        base,root,endpoint=self._tree()
        try:
            svc,boundary,peer,receipt_pub=self._service(root);daemon=LinuxAuthorityDaemon(service=svc,boundary=boundary,protected_root=root,endpoint_dir=endpoint,allowed_gid=os.getegid(),max_workers=2,preauth_timeout=0.35,accept_poll=0.05);t=threading.Thread(target=daemon.run_forever);t.start()
            deadline=time.monotonic()+3
            while not daemon.path.exists():
                if time.monotonic()>=deadline:self.fail('daemon socket missing')
                time.sleep(0.01)
            stall=self._connect(daemon.path)
            try:
                started=time.monotonic();response=self._roundtrip(daemon.path,_request(peer));self.assertLess(time.monotonic()-started,0.35);obj=json.loads(response.decode());self.assertTrue(verify_signed_receipt(obj,receipt_pub));self.assertEqual(obj['receipt']['peerPrincipal'],f'uid:{os.geteuid()}')
                time.sleep(0.45)
                with self.assertRaises((BrokenPipeError,ConnectionResetError,OSError)):stall.sendall(b'x')
                second=json.loads(self._roundtrip(daemon.path,_request(peer)).decode());self.assertTrue(verify_signed_receipt(second,receipt_pub))
            finally:
                stall.close();daemon.stop();t.join(2)
            self.assertFalse(t.is_alive())
        finally:__import__('shutil').rmtree(base,ignore_errors=True)
    def test_partial_client_times_out_and_shutdown_breaks_accepted_reads(self):
        base,root,endpoint=self._tree()
        try:
            svc,boundary,peer,_=self._service(root);daemon=LinuxAuthorityDaemon(service=svc,boundary=boundary,protected_root=root,endpoint_dir=endpoint,allowed_gid=os.getegid(),max_workers=2,preauth_timeout=5.0,accept_poll=0.05);t=threading.Thread(target=daemon.run_forever);t.start();deadline=time.monotonic()+3
            while not daemon.path.exists():
                if time.monotonic()>=deadline:self.fail('daemon socket missing')
                time.sleep(0.01)
            a=self._connect(daemon.path);b=self._connect(daemon.path);a.sendall(b'{');b.sendall(b'{');time.sleep(0.1);started=time.monotonic();daemon.stop();t.join(1.5);self.assertLess(time.monotonic()-started,1.5);self.assertFalse(t.is_alive());a.close();b.close()
        finally:__import__('shutil').rmtree(base,ignore_errors=True)

@unittest.skipUnless(os.name=='nt','native Windows root-chain proof')
class WindowsRootChainV7Tests(unittest.TestCase):
    def _boundary(self):
        bootstrap=PlatformMachineBoundary(expected_service_principal='bootstrap',peer_principals={'p':'bootstrap'},peer_public_keys={'p':'AA=='},trusted_storage_principals=set());sid=bootstrap._current_windows_sid();return PlatformMachineBoundary(expected_service_principal=sid,peer_principals={'p':sid},peer_public_keys={'p':'AA=='},trusted_storage_principals=set()),sid
    def _protect(self,path,sid):
        cp=subprocess.run(['icacls',str(path),'/inheritance:r','/grant:r',f'*{sid}:(OI)(CI)F','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F'],capture_output=True,text=True)
        if cp.returncode!=0:self.skipTest('icacls protection unavailable: '+cp.stderr)
    def test_standard_volume_root_allows_genuinely_protected_child(self):
        boundary,sid=self._boundary()
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as td:
            root=Path(td)/'svc';root.mkdir();self._protect(root,sid);self.assertEqual(assert_machine_anchored_root(boundary,root),root.resolve())
    def test_delete_child_authority_on_ancestor_is_denied(self):
        boundary,sid=self._boundary()
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as td:
            parent=Path(td)/'hostile';parent.mkdir();root=parent/'svc';root.mkdir();self._protect(root,sid);self._protect(parent,sid)
            cp=subprocess.run(['icacls',str(parent),'/grant','*S-1-1-0:(DC)'],capture_output=True,text=True)
            if cp.returncode!=0:self.skipTest('icacls delete-child fixture unavailable: '+cp.stderr)
            with self.assertRaises(AuthorityError) as cm:assert_machine_anchored_root(boundary,root)
            self.assertEqual(cm.exception.code,'PROTECTED_ROOT_ANCESTOR_PERMISSIONS')

if __name__=='__main__':unittest.main()
