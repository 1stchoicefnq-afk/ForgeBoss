from __future__ import annotations

import base64,os,tempfile,threading,unittest
from pathlib import Path

from forgeboss.protected_authority.boundary import FileSecretProvider,PeerContext,PlatformMachineBoundary
from forgeboss.protected_authority.github_backend import GitHubAppBackend
from forgeboss.protected_authority.protocol import AuthorityError,SCHEMA,build_request,strict_loads,unsigned_request
from forgeboss.protected_authority.service import ReplayJournal

class ReplayV2Tests(unittest.TestCase):
    def test_two_instances_exactly_one_consume(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);a=ReplayJournal(root);b=ReplayJournal(root);barrier=threading.Barrier(2);out=[]
            def run(j):
                barrier.wait()
                try:j.consume('00000000-0000-4000-8000-000000000001','a'*64);out.append('win')
                except AuthorityError as e:out.append(e.code)
            t1=threading.Thread(target=run,args=(a,));t2=threading.Thread(target=run,args=(b,));t1.start();t2.start();t1.join();t2.join();self.assertEqual(sorted(out),['REQUEST_REPLAYED','win'])
            with self.assertRaises(AuthorityError) as cm:ReplayJournal(root).consume('00000000-0000-4000-8000-000000000001','a'*64)
            self.assertEqual(cm.exception.code,'REQUEST_REPLAYED')
    def test_crash_after_consume_remains_burned(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ReplayJournal(root).consume('00000000-0000-4000-8000-000000000002','b'*64)
            with self.assertRaises(AuthorityError) as cm:ReplayJournal(root).consume('00000000-0000-4000-8000-000000000002','b'*64)
            self.assertEqual(cm.exception.code,'REQUEST_REPLAYED')

class ProtocolV2Tests(unittest.TestCase):
    def _draft(self):
        import uuid
        return build_request(operation='publish_reviewed_draft_pr',request_id=str(uuid.uuid4()),peer_id='worker-a',repository='Owner/Repo',control_revision=7,payload={'baseSha':'A'*40,'headSha':'B'*40,'baseRef':'main','headRef':'repair/x','title':'t','body':'b','reviewDigest':'C'*64},signature='sig')
    def test_draft_pr_requires_ref_and_sha_binding(self):
        import uuid
        r=self._draft()
        self.assertEqual(r['schema'],SCHEMA);self.assertEqual(r['repository'],'owner/repo');self.assertEqual(r['payload']['baseSha'],'a'*40);self.assertEqual(r['payload']['reviewDigest'],'c'*64)
        with self.assertRaises(AuthorityError):build_request(operation='publish_reviewed_draft_pr',request_id=str(uuid.uuid4()),peer_id='worker-a',repository='o/r',control_revision=1,payload={'baseSha':'a'*40,'headSha':'b'*40,'baseRef':'main','headRef':'../evil','title':'t','body':'b','reviewDigest':'c'*64},signature='sig')
    def test_mixed_case_builder_roundtrips_canonical_unsigned_digest(self):
        r=self._draft();self.assertEqual(unsigned_request(dict(r)),r);self.assertEqual(r['repository'],'owner/repo');self.assertEqual(r['payload']['headSha'],'b'*40)
    def test_post_digest_authority_mutations_are_rejected(self):
        r=self._draft()
        mutations=[]
        x=dict(r);x['repository']='owner/other';mutations.append(x)
        x=dict(r);x['payload']=dict(r['payload']);x['payload']['body']='changed';mutations.append(x)
        x=dict(r);x['payload']=dict(r['payload']);x['payload']['headRef']='repair/y';mutations.append(x)
        x=dict(r);x['controlRevision']=8;mutations.append(x)
        x=dict(r);x['requestId']='00000000-0000-4000-8000-000000000001';mutations.append(x)
        for mutated in mutations:
            with self.subTest(mutated=mutated):
                with self.assertRaises(AuthorityError) as cm:unsigned_request(mutated)
                self.assertEqual(cm.exception.code,'REQUEST_DIGEST_MISMATCH')
    def test_duplicate_json_rejected(self):
        with self.assertRaises(AuthorityError):strict_loads('{"x":1,"x":2}')

class BoundaryV2Tests(unittest.TestCase):
    def _boundary(self):
        return PlatformMachineBoundary(expected_service_principal=f'uid:{os.geteuid()}',peer_principals={'worker-a':f'uid:{os.geteuid()}'},peer_public_keys={'worker-a':base64.b64encode(b'0'*32).decode()})
    def test_posix_service_root_requires_private_mode(self):
        if os.name=='nt' or not hasattr(os,'geteuid'):self.skipTest('POSIX only')
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700);b=self._boundary();self.assertEqual(b.assert_service_principal(root),f'uid:{os.geteuid()}');root.chmod(0o755)
            with self.assertRaises(AuthorityError):b.assert_service_principal(root)
    def test_posix_secret_must_be_unreadable_to_other_users(self):
        if os.name=='nt' or not hasattr(os,'geteuid'):self.skipTest('POSIX only')
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700);key=root/'app.pem';trust=root/'launch.pub';key.write_bytes(b'PRIVATE');trust.write_bytes(b'TRUST');key.chmod(0o600);trust.chmod(0o600);b=self._boundary();p=FileSecretProvider(root=root,private_key_path=key,launch_trust_path=trust,boundary=b);self.assertEqual(p.github_app_private_key(),b'PRIVATE');key.chmod(0o644)
            with self.assertRaises(AuthorityError):p.github_app_private_key()
    def test_posix_writable_intermediate_secret_directory_denied(self):
        if os.name=='nt' or not hasattr(os,'geteuid'):self.skipTest('POSIX only')
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700);sub=root/'secrets';sub.mkdir();sub.chmod(0o777);key=sub/'app.pem';key.write_bytes(b'PRIVATE');key.chmod(0o600);trust=root/'launch.pub';trust.write_bytes(b'TRUST');trust.chmod(0o600);b=self._boundary();p=FileSecretProvider(root=root,private_key_path=key,launch_trust_path=trust,boundary=b)
            with self.assertRaises(AuthorityError):p.github_app_private_key()
    def test_peer_context_is_required(self):
        b=PlatformMachineBoundary(expected_service_principal='uid:0',peer_principals={'w':'uid:1'},peer_public_keys={'w':base64.b64encode(b'0'*32).decode()});self.assertFalse(b.verify_peer('w','a'*64,'x',None));self.assertFalse(b.verify_peer('w','a'*64,'x',PeerContext('posix','uid:2')))

class GitHubBackendV2Tests(unittest.TestCase):
    def test_non_github_api_base_denied(self):
        with self.assertRaises(AuthorityError):GitHubAppBackend(app_id=1,installation_id=2,api_base='https://evil.invalid')

if __name__=='__main__':unittest.main()
