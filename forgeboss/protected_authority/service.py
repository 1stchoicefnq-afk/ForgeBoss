from __future__ import annotations

import re, sqlite3
from pathlib import Path
from typing import Any, Mapping

from .boundary import FileSecretProvider, PeerContext, PlatformMachineBoundary
from .github_backend import GitHubAppBackend
from .protocol import (
    AuthorityError, OPERATIONS, _ref, assert_public_result, canonical_digest,
    canonical_json, strict_loads, unsigned_request,
)
from .root_chain import assert_machine_anchored_root
from .signing import ReceiptSigner

_REPO_RE = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')


def _canonical_repository_map(values) -> dict[str, str]:
    if not values:
        raise AuthorityError('REPOSITORY_ALLOWLIST_INVALID')
    out = {}
    for value in values:
        if not isinstance(value, str) or not _REPO_RE.fullmatch(value):
            raise AuthorityError('REPOSITORY_ALLOWLIST_INVALID')
        key = value.casefold()
        if key in out and out[key] != value:
            raise AuthorityError('REPOSITORY_ALLOWLIST_INVALID')
        out[key] = value
    if not out:
        raise AuthorityError('REPOSITORY_ALLOWLIST_INVALID')
    return out


def _positive_ints(value, code: str, *, allow_empty: bool = False) -> frozenset[int]:
    if not isinstance(value, (list, tuple, set)) or (not value and not allow_empty):
        raise AuthorityError(code)
    out = set()
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise AuthorityError(code)
        out.add(item)
    if not out and not allow_empty:
        raise AuthorityError(code)
    return frozenset(out)


def _text_set(value, code: str, *, refs: bool = False, prefixes: bool = False) -> frozenset[str]:
    if not isinstance(value, (list, tuple, set)) or not value:
        raise AuthorityError(code)
    out = set()
    for item in value:
        if not isinstance(item, str) or not item or item != item.strip():
            raise AuthorityError(code)
        if refs:
            item = _ref(item, code)
        elif prefixes:
            if item.startswith('/') or item.endswith('/') or '..' in item.split('/') or '@{' in item or '\\' in item:
                raise AuthorityError(code)
        out.add(item)
    return frozenset(out)


def _compile_peer_policy(peer_policy, boundary, allowed_repositories: Mapping[str, str]):
    if not isinstance(peer_policy, Mapping) or not peer_policy:
        raise AuthorityError('PEER_POLICY_INVALID')
    known_peers = set(getattr(boundary, 'peer_principals', {}))
    if not known_peers:
        raise AuthorityError('PEER_POLICY_INVALID')
    compiled = {}
    for peer_id, repo_policy in peer_policy.items():
        if peer_id not in known_peers or not isinstance(repo_policy, Mapping) or not repo_policy:
            raise AuthorityError('PEER_POLICY_INVALID')
        peer_out = {}
        seen_repos = set()
        for repository, operation_policy in repo_policy.items():
            if not isinstance(repository, str):
                raise AuthorityError('PEER_POLICY_INVALID')
            repo_key = repository.casefold()
            canonical_repo = allowed_repositories.get(repo_key)
            if canonical_repo is None or repo_key in seen_repos:
                raise AuthorityError('PEER_POLICY_INVALID')
            seen_repos.add(repo_key)
            if not isinstance(operation_policy, Mapping) or not operation_policy:
                raise AuthorityError('PEER_POLICY_INVALID')
            op_out = {}
            for operation, constraints in operation_policy.items():
                if operation not in OPERATIONS or not isinstance(constraints, Mapping):
                    raise AuthorityError('PEER_POLICY_INVALID')
                c = dict(constraints)
                if operation == 'read_github_control':
                    if set(c) - {'rootPrs', 'preferredRepairPrs'} or 'rootPrs' not in c:
                        raise AuthorityError('PEER_POLICY_INVALID')
                    op_out[operation] = {
                        'rootPrs': _positive_ints(c['rootPrs'], 'PEER_POLICY_INVALID'),
                        'preferredRepairPrs': _positive_ints(c.get('preferredRepairPrs', []), 'PEER_POLICY_INVALID', allow_empty=True),
                    }
                elif operation == 'publish_report_comment':
                    if set(c) != {'issues'}:
                        raise AuthorityError('PEER_POLICY_INVALID')
                    op_out[operation] = {'issues': _positive_ints(c['issues'], 'PEER_POLICY_INVALID')}
                elif operation == 'publish_reviewed_draft_pr':
                    if set(c) != {'baseRefs', 'headRefPrefixes', 'reviewDigests'}:
                        raise AuthorityError('PEER_POLICY_INVALID')
                    digests = _text_set(c['reviewDigests'], 'PEER_POLICY_INVALID')
                    if any(not _HEX64.fullmatch(x.lower()) for x in digests):
                        raise AuthorityError('PEER_POLICY_INVALID')
                    op_out[operation] = {
                        'baseRefs': _text_set(c['baseRefs'], 'PEER_POLICY_INVALID', refs=True),
                        'headRefPrefixes': _text_set(c['headRefPrefixes'], 'PEER_POLICY_INVALID', prefixes=True),
                        'reviewDigests': frozenset(x.lower() for x in digests),
                    }
                elif operation == 'verify_launch_authority':
                    if c:
                        raise AuthorityError('PEER_POLICY_INVALID')
                    op_out[operation] = {}
                else:
                    raise AuthorityError('PEER_POLICY_INVALID')
            peer_out[canonical_repo] = op_out
        compiled[peer_id] = peer_out
    return compiled


def _authorize_peer_request(policy, request: Mapping[str, Any]) -> None:
    peer_policy = policy.get(request['peerId'])
    if peer_policy is None:
        raise AuthorityError('PEER_POLICY_DENIED')
    repo_policy = peer_policy.get(request['repository'])
    if repo_policy is None:
        raise AuthorityError('PEER_POLICY_DENIED')
    constraints = repo_policy.get(request['operation'])
    if constraints is None:
        raise AuthorityError('PEER_POLICY_DENIED')
    payload = request['payload']; operation = request['operation']
    if operation == 'read_github_control':
        if payload['rootPr'] not in constraints['rootPrs']:
            raise AuthorityError('PEER_OBJECT_DENIED')
        preferred = payload['preferredRepairPr']
        if preferred and preferred not in constraints['preferredRepairPrs']:
            raise AuthorityError('PEER_OBJECT_DENIED')
    elif operation == 'publish_report_comment':
        if payload['issue'] not in constraints['issues']:
            raise AuthorityError('PEER_OBJECT_DENIED')
    elif operation == 'publish_reviewed_draft_pr':
        if payload['baseRef'] not in constraints['baseRefs']:
            raise AuthorityError('PEER_OBJECT_DENIED')
        if not any(payload['headRef'].startswith(prefix) for prefix in constraints['headRefPrefixes']):
            raise AuthorityError('PEER_OBJECT_DENIED')
        if payload['reviewDigest'] not in constraints['reviewDigests']:
            raise AuthorityError('PEER_OBJECT_DENIED')
    elif operation == 'verify_launch_authority':
        return
    else:
        raise AuthorityError('PEER_POLICY_DENIED')


class ReplayJournal:
    def __init__(self, root: Path):
        self.path = root / 'replay.sqlite3'
        try:
            db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE IF NOT EXISTS consumed(request_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, consumed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)')
            db.close()
        except Exception as exc:
            raise AuthorityError('REPLAY_STATE_INVALID') from exc

    def consume(self, request_id: str, request_digest: str) -> None:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None); begun = False
        try:
            db.execute('BEGIN IMMEDIATE'); begun = True
            try:
                db.execute('INSERT INTO consumed(request_id,request_digest) VALUES(?,?)', (request_id, request_digest))
            except sqlite3.IntegrityError as exc:
                raise AuthorityError('REQUEST_REPLAYED') from exc
            db.execute('COMMIT'); begun = False
        except AuthorityError:
            if begun:
                db.execute('ROLLBACK')
            raise
        except Exception as exc:
            if begun:
                try:
                    db.execute('ROLLBACK')
                except Exception:
                    pass
            raise AuthorityError('REPLAY_STATE_WRITE_FAILED') from exc
        finally:
            db.close()


class ProtectedAuthorityService:
    def __init__(self, *, protected_root: Path, boundary: PlatformMachineBoundary, secrets_provider: FileSecretProvider, backend: GitHubAppBackend, receipt_signer: ReceiptSigner, allowed_repositories, peer_policy):
        root = Path(protected_root)
        if not root.is_absolute():
            raise AuthorityError('PROTECTED_ROOT_INVALID')
        resolved = assert_machine_anchored_root(boundary, root)
        if receipt_signer is None:
            raise AuthorityError('RECEIPT_SIGNER_REQUIRED')
        self.root = resolved
        self.boundary = boundary
        self.secrets_provider = secrets_provider
        self.backend = backend
        self.receipt_signer = receipt_signer
        self.allowed_repositories = _canonical_repository_map(allowed_repositories)
        self.peer_policy = _compile_peer_policy(peer_policy, boundary, self.allowed_repositories)
        self._peer_policy_required = True
        self.service_principal = boundary.assert_service_principal(resolved)
        self.journal = ReplayJournal(resolved)

    def handle_json(self, raw: str | bytes, *, peer_context: PeerContext) -> bytes:
        return canonical_json(self.handle(unsigned_request(strict_loads(raw)), peer_context=peer_context))

    def handle(self, raw_request: Mapping[str, Any], *, peer_context: PeerContext) -> dict:
        request = unsigned_request(raw_request)
        if not self.boundary.verify_peer(request['peerId'], request['requestDigest'], request['signature'], peer_context):
            raise AuthorityError('PEER_AUTH_DENIED')
        canonical_repo = self.allowed_repositories.get(request['repository'].casefold())
        if canonical_repo is None:
            raise AuthorityError('REPOSITORY_DENIED')
        request = dict(request); request['repository'] = canonical_repo
        policy = getattr(self, 'peer_policy', None)
        if policy is None:
            if getattr(self, '_peer_policy_required', False):
                raise AuthorityError('PEER_POLICY_INVALID')
        else:
            _authorize_peer_request(policy, request)
        self.journal.consume(request['requestId'], request['requestDigest'])
        private = []
        try:
            if request['operation'] == 'verify_launch_authority':
                trust = self.secrets_provider.launch_trust_root(); private.append(trust)
                result = self.backend.verify_launch_authority(repository=request['repository'], control_revision=request['controlRevision'], payload=request['payload'], trust_root=trust)
            else:
                key = self.secrets_provider.github_app_private_key(); private.append(key)
                kwargs = {'repository': request['repository'], 'control_revision': request['controlRevision'], 'payload': request['payload'], 'private_key': key}
                if request['operation'] == 'read_github_control':
                    result = self.backend.read_github_control(**kwargs)
                elif request['operation'] == 'publish_report_comment':
                    result = self.backend.publish_report_comment(**kwargs)
                elif request['operation'] == 'publish_reviewed_draft_pr':
                    result = self.backend.publish_reviewed_draft_pr(**kwargs)
                else:
                    raise AuthorityError('OPERATION_DENIED')
            public = assert_public_result(result, tuple(private))
        except AuthorityError:
            raise
        except Exception as exc:
            raise AuthorityError('BACKEND_OPERATION_FAILED') from exc
        receipt = {
            'schema': 3, 'operation': request['operation'], 'requestId': request['requestId'],
            'peerId': request['peerId'], 'peerPrincipal': peer_context.principal,
            'repository': request['repository'], 'controlRevision': request['controlRevision'],
            'requestDigest': request['requestDigest'], 'resultDigest': canonical_digest(public),
            'servicePrincipal': self.service_principal,
        }
        signed = self.receipt_signer.sign(receipt)
        return {**signed, 'result': public}


def create_production_service(*, protected_root: str, expected_service_principal: str, peer_principals: dict[str, str], peer_public_keys: dict[str, str], github_app_id: int, github_installation_id: int, github_private_key_file: str, launch_trust_file: str, receipt_signing_key_file: str, allowed_repositories, peer_policy, trusted_storage_principals: set[str] | None = None) -> ProtectedAuthorityService:
    root = Path(protected_root)
    boundary = PlatformMachineBoundary(expected_service_principal=expected_service_principal, peer_principals=peer_principals, peer_public_keys=peer_public_keys, trusted_storage_principals=trusted_storage_principals)
    root = assert_machine_anchored_root(boundary, root)
    repos = _canonical_repository_map(allowed_repositories)
    secrets = FileSecretProvider(root=root, private_key_path=Path(github_private_key_file), launch_trust_path=Path(launch_trust_file), boundary=boundary)
    signer = ReceiptSigner.from_file(root=root, path=Path(receipt_signing_key_file), boundary=boundary)
    backend = GitHubAppBackend(app_id=github_app_id, installation_id=github_installation_id)
    return ProtectedAuthorityService(protected_root=root, boundary=boundary, secrets_provider=secrets, backend=backend, receipt_signer=signer, allowed_repositories=repos.values(), peer_policy=peer_policy)
