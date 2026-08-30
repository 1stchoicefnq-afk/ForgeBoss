from __future__ import annotations

import os, socket, tempfile, threading, time, unittest, uuid
from pathlib import Path

from forgeboss.protected_authority.boundary import PeerContext
from forgeboss.protected_authority.github_backend import GitHubAppBackend
from forgeboss.protected_authority.ipc import serve_unix_once
from forgeboss.protected_authority.lifecycle import LinuxAuthorityDaemon
from forgeboss.protected_authority.protocol import AuthorityError, _ref, build_request
from forgeboss.protected_authority.root_chain import _object_ace_sid_offset
from forgeboss.protected_authority.service import (
    ProtectedAuthorityService, _canonical_repository_map, _compile_peer_policy,
)


class _Boundary:
    peer_principals = {'controller-a': 'uid:1000', 'worker-low': 'uid:1001'}
    def verify_peer(self, _peer, _digest, _signature, _ctx):
        return True


class _Journal:
    def __init__(self): self.calls = []
    def consume(self, request_id, request_digest): self.calls.append((request_id, request_digest))


class _Secrets:
    def __init__(self): self.calls = 0
    def github_app_private_key(self): self.calls += 1; return b'PRIVATE'
    def launch_trust_root(self): self.calls += 1; return b'TRUST'


class _Backend:
    def __init__(self): self.calls = []
    def read_github_control(self, **kw): self.calls.append(('read', kw)); return {'ok': True}
    def publish_report_comment(self, **kw): self.calls.append(('comment', kw)); return {'ok': True}
    def publish_reviewed_draft_pr(self, **kw): self.calls.append(('pr', kw)); return {'ok': True}
    def verify_launch_authority(self, **kw): self.calls.append(('launch', kw)); return {'verified': True}


class _Signer:
    def sign(self, receipt): return {'receipt': dict(receipt), 'receiptDigest': 'd' * 64, 'receiptSignature': 'signed'}


def _service(policy):
    svc = object.__new__(ProtectedAuthorityService)
    svc.root = Path('.')
    svc.boundary = _Boundary()
    svc.secrets_provider = _Secrets()
    svc.backend = _Backend()
    svc.receipt_signer = _Signer()
    svc.allowed_repositories = _canonical_repository_map(['Owner/Repo'])
    svc.peer_policy = _compile_peer_policy(policy, svc.boundary, svc.allowed_repositories)
    svc._peer_policy_required = True
    svc.service_principal = 'uid:999'
    svc.journal = _Journal()
    return svc


def _request(operation, payload, peer='controller-a'):
    return build_request(
        operation=operation,
        request_id=str(uuid.uuid4()),
        peer_id=peer,
        repository='owner/repo',
        control_revision=139,
        payload=payload,
        signature='sig',
    )


class PeerPolicyV8Tests(unittest.TestCase):
    def test_denied_object_is_rejected_before_replay_secret_backend(self):
        policy = {'controller-a': {'Owner/Repo': {'publish_report_comment': {'issues': [5]}}}}
        svc = _service(policy)
        req = _request('publish_report_comment', {'issue': 9, 'body': 'x', 'reportDigest': 'a' * 64})
        with self.assertRaises(AuthorityError) as cm:
            svc.handle(req, peer_context=PeerContext('posix', 'uid:1000'))
        self.assertEqual(cm.exception.code, 'PEER_OBJECT_DENIED')
        self.assertEqual(svc.journal.calls, [])
        self.assertEqual(svc.secrets_provider.calls, 0)
        self.assertEqual(svc.backend.calls, [])

    def test_denied_operation_is_rejected_before_replay(self):
        policy = {'worker-low': {'Owner/Repo': {'read_github_control': {'rootPrs': [10]}}}}
        svc = _service(policy)
        req = _request('publish_report_comment', {'issue': 5, 'body': 'x', 'reportDigest': 'a' * 64}, peer='worker-low')
        with self.assertRaises(AuthorityError) as cm:
            svc.handle(req, peer_context=PeerContext('posix', 'uid:1001'))
        self.assertEqual(cm.exception.code, 'PEER_POLICY_DENIED')
        self.assertEqual(svc.journal.calls, [])

    def test_authorized_read_reaches_replay_then_secret_backend(self):
        policy = {'controller-a': {'Owner/Repo': {'read_github_control': {'rootPrs': [10], 'preferredRepairPrs': [12]}}}}
        svc = _service(policy)
        req = _request('read_github_control', {'rootPr': 10, 'preferredRepairPr': 12})
        out = svc.handle(req, peer_context=PeerContext('posix', 'uid:1000'))
        self.assertEqual(len(svc.journal.calls), 1)
        self.assertEqual(svc.secrets_provider.calls, 1)
        self.assertEqual(svc.backend.calls[0][0], 'read')
        self.assertEqual(out['receipt']['repository'], 'Owner/Repo')

    def test_policy_compiler_rejects_unknown_peer_repo_op_and_unbounded_write(self):
        allowed = _canonical_repository_map(['Owner/Repo'])
        bad = [
            {'ghost': {'Owner/Repo': {'verify_launch_authority': {}}}},
            {'controller-a': {'Other/Repo': {'verify_launch_authority': {}}}},
            {'controller-a': {'Owner/Repo': {'arbitrary': {}}}},
            {'controller-a': {'Owner/Repo': {'publish_report_comment': {}}}},
            {'controller-a': {'Owner/Repo': {'publish_reviewed_draft_pr': {'baseRefs': ['main'], 'headRefPrefixes': ['x/'], 'reviewDigests': []}}}},
        ]
        for policy in bad:
            with self.subTest(policy=policy), self.assertRaises(AuthorityError):
                _compile_peer_policy(policy, _Boundary(), allowed)


class _ControlBackend(GitHubAppBackend):
    def __init__(self, *, root, candidates=(), preferred=None, preferred_error=False):
        super().__init__(app_id=1, installation_id=2)
        self.root = root; self.candidates = list(candidates); self.preferred = preferred; self.preferred_error = preferred_error; self.paths = []
    def _token(self, _pem, _repository, _operation): return 'token'
    def _request(self, method, path, *, token=None, body=None):
        self.paths.append((method, path))
        if '/pulls?' in path:
            return list(self.candidates)
        if path.endswith('/pulls/10'):
            return self.root
        if path.endswith('/pulls/12'):
            if self.preferred_error:
                raise AuthorityError('GITHUB_OPERATION_FAILED')
            return self.preferred
        raise AssertionError(path)


def _pr(number, *, head_sha, head_ref, base_sha, base_ref, repo='Owner/Repo', state='open', title='', body=''):
    return {
        'number': number, 'state': state, 'title': title, 'body': body, 'updated_at': '2026-08-30T00:00:00Z',
        'head': {'sha': head_sha, 'ref': head_ref, 'repo': {'full_name': repo}},
        'base': {'sha': base_sha, 'ref': base_ref},
    }


class ControlReadV8Tests(unittest.TestCase):
    ROOT_HEAD = 'a' * 40
    ROOT_BASE = 'b' * 40
    def root(self, **kw):
        values = dict(number=10, head_sha=self.ROOT_HEAD, head_ref='feature/root', base_sha=self.ROOT_BASE, base_ref='main', title='root')
        values.update(kw); return _pr(**values)
    def child(self, number=20, **kw):
        values = dict(head_sha='c' * 40, head_ref=f'autopilot/repair-pr10-{number}', base_sha=self.ROOT_HEAD, base_ref='feature/root', title='repair #10')
        values.update(kw); return _pr(number, **values)

    def test_single_exact_child_is_bound_and_query_is_encoded(self):
        backend = _ControlBackend(root=self.root(), candidates=[self.child()])
        out = backend.read_github_control(repository='Owner/Repo', control_revision=139, payload={'rootPr': 10, 'preferredRepairPr': 0}, private_key=b'x')
        self.assertEqual(out['binding']['status'], 'EXACT_REPAIR_CHILD_BOUND')
        self.assertTrue(out['binding']['repair_base_equals_root_head'])
        self.assertEqual(out['repair_pr']['number'], 20)
        self.assertTrue(any('base=feature%2Froot' in path for _, path in backend.paths))

    def test_multiple_exact_children_fail_closed(self):
        backend = _ControlBackend(root=self.root(), candidates=[self.child(20), self.child(21)])
        with self.assertRaises(AuthorityError) as cm:
            backend.read_github_control(repository='Owner/Repo', control_revision=139, payload={'rootPr': 10, 'preferredRepairPr': 0}, private_key=b'x')
        self.assertEqual(cm.exception.code, 'CONTROL_REPAIR_AMBIGUOUS')

    def test_stale_preferred_does_not_override_single_exact_child(self):
        stale = self.child(12, base_sha='d' * 40)
        backend = _ControlBackend(root=self.root(), candidates=[self.child(20)], preferred=stale)
        out = backend.read_github_control(repository='Owner/Repo', control_revision=139, payload={'rootPr': 10, 'preferredRepairPr': 12}, private_key=b'x')
        self.assertEqual(out['repair_pr']['number'], 20)
        self.assertEqual(out['binding']['selection_reason'], 'discovered-exact')

    def test_missing_preferred_returns_explicit_no_child(self):
        backend = _ControlBackend(root=self.root(), candidates=[], preferred_error=True)
        out = backend.read_github_control(repository='Owner/Repo', control_revision=139, payload={'rootPr': 10, 'preferredRepairPr': 12}, private_key=b'x')
        self.assertIsNone(out['repair_pr'])
        self.assertEqual(out['binding']['status'], 'NO_CURRENT_EXACT_REPAIR_CHILD')
        self.assertTrue(out['binding']['stale_preferred'])

    def test_root_state_and_repository_are_authority(self):
        for root in (self.root(state='closed'), self.root(repo='Other/Repo')):
            with self.subTest(root=root):
                backend = _ControlBackend(root=root)
                with self.assertRaises(AuthorityError):
                    backend.read_github_control(repository='Owner/Repo', control_revision=139, payload={'rootPr': 10, 'preferredRepairPr': 0}, private_key=b'x')


class FailClosedParserV8Tests(unittest.TestCase):
    def test_unknown_object_ace_flags_fail_closed_before_sid_offset(self):
        for flags in (0x4, 0x8, 0x80000000):
            with self.subTest(flags=flags), self.assertRaises(AuthorityError) as cm:
                _object_ace_sid_offset(flags, 64)
            self.assertEqual(cm.exception.code, 'PROTECTED_ROOT_ANCESTOR_ACL_UNKNOWN')
        self.assertEqual(_object_ace_sid_offset(0, 64), 12)
        self.assertEqual(_object_ace_sid_offset(3, 64), 44)

    def test_noncanonical_git_refs_fail_locally(self):
        for value in ('main//x', 'main/./x', '.hidden/x', 'main/x.lock', 'main/x.'):
            with self.subTest(value=value), self.assertRaises(AuthorityError):
                _ref(value, 'REF_INVALID')
        self.assertEqual(_ref('feature/good-x', 'REF_INVALID'), 'feature/good-x')


@unittest.skipIf(os.name == 'nt', 'native Unix proof')
class UnixPeerPrefilterV8Tests(unittest.TestCase):
    def test_unconfigured_kernel_principal_is_rejected_before_body_wait(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 's.sock'; listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); listener.bind(str(path)); listener.listen(1)
            result = {}
            class Service:
                calls = 0
                def handle_json(self, *_args, **_kwargs): self.calls += 1; return b'{}'
            service = Service()
            def serve():
                try:
                    serve_unix_once(listener, service, accept_timeout=1, preauth_timeout=1, allowed_peer_principals={'uid:999999999'})
                except AuthorityError as exc:
                    result['code'] = exc.code
            thread = threading.Thread(target=serve); thread.start()
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); client.connect(str(path))
            thread.join(0.5)
            client.close(); listener.close()
            self.assertFalse(thread.is_alive())
            self.assertEqual(result.get('code'), 'PEER_CONTEXT_DENIED')
            self.assertEqual(service.calls, 0)


@unittest.skipIf(os.name == 'nt', 'native Unix proof')
class ShutdownV8Tests(unittest.TestCase):
    def test_postauth_stalled_worker_is_retained_and_shutdown_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            daemon = object.__new__(LinuxAuthorityDaemon)
            daemon._close_lock = threading.Lock(); daemon._stop = threading.Event(); daemon.listener = None
            daemon._active_lock = threading.Lock(); daemon._active = set(); daemon.preauth_timeout = 0.05; daemon.accept_poll = 0.01
            daemon.root = Path(td); daemon.path = Path(td) / 'authority.sock'; daemon.path.write_text('occupied')
            daemon.shutdown_failure_path = Path(td) / 'shutdown-failure.json'
            release = threading.Event()
            worker = threading.Thread(target=lambda: release.wait(5), daemon=True); daemon._workers = [worker]; worker.start()
            started = time.monotonic()
            with self.assertRaises(AuthorityError) as cm:
                daemon.close()
            self.assertEqual(cm.exception.code, 'IPC_SHUTDOWN_INCOMPLETE')
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertIn(worker, daemon._workers)
            self.assertTrue(worker.is_alive())
            self.assertTrue(daemon.shutdown_failure_path.is_file())
            self.assertTrue(daemon.path.exists(), 'endpoint identity must remain fenced while old worker survives')
            release.set(); worker.join(1); self.assertFalse(worker.is_alive())
            daemon.close()
            self.assertEqual(daemon._workers, [])
            self.assertFalse(daemon.path.exists())


if __name__ == '__main__':
    unittest.main()
