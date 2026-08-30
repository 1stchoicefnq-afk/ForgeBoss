from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Mapping

from .boundary import FileSecretProvider, PeerContext, PlatformMachineBoundary
from .github_backend import GitHubAppBackend
from .protocol import (
    OPERATIONS,
    AuthorityError,
    assert_public_result,
    canonical_digest,
    canonical_json,
    strict_loads,
    unsigned_request,
)
from .root_chain import assert_machine_anchored_root
from .signing import ReceiptSigner

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_PEER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")


def _canonical_repository_map(values) -> dict[str, str]:
    if not values:
        raise AuthorityError("REPOSITORY_ALLOWLIST_INVALID")
    out: dict[str, str] = {}
    for value in values:
        if not isinstance(value, str) or not _REPO_RE.fullmatch(value):
            raise AuthorityError("REPOSITORY_ALLOWLIST_INVALID")
        key = value.casefold()
        if key in out and out[key] != value:
            raise AuthorityError("REPOSITORY_ALLOWLIST_INVALID")
        out[key] = value
    if not out:
        raise AuthorityError("REPOSITORY_ALLOWLIST_INVALID")
    return out


def _canonical_peer_policies(values, repositories: Mapping[str, str]) -> dict[str, dict[str, Any]]:
    """Validate a fail-closed peer -> operation/repository/object authority map.

    Each peer policy must explicitly authorize every operation, repository and
    protected object it may touch. Object selectors are operation-specific and
    may contain ``*`` only when that peer is intentionally allowed every object
    for that operation. Missing policy is denial, never compatibility fallback.
    """
    if not isinstance(values, Mapping) or not values:
        raise AuthorityError("PEER_POLICY_INVALID")
    out: dict[str, dict[str, Any]] = {}
    for peer_id, raw in values.items():
        if not isinstance(peer_id, str) or not _PEER_RE.fullmatch(peer_id):
            raise AuthorityError("PEER_POLICY_INVALID")
        if not isinstance(raw, Mapping) or set(raw) != {"operations", "repositories", "objects"}:
            raise AuthorityError("PEER_POLICY_INVALID")
        operations = raw["operations"]
        repo_values = raw["repositories"]
        objects = raw["objects"]
        if not isinstance(operations, (list, tuple, set)) or not operations:
            raise AuthorityError("PEER_POLICY_INVALID")
        ops = frozenset(operations)
        if any(not isinstance(op, str) or op not in OPERATIONS for op in ops):
            raise AuthorityError("PEER_POLICY_INVALID")
        if not isinstance(repo_values, (list, tuple, set)) or not repo_values:
            raise AuthorityError("PEER_POLICY_INVALID")
        repos: set[str] = set()
        for repo in repo_values:
            if not isinstance(repo, str):
                raise AuthorityError("PEER_POLICY_INVALID")
            key = repo.casefold()
            if key not in repositories:
                raise AuthorityError("PEER_POLICY_INVALID")
            repos.add(key)
        if not isinstance(objects, Mapping) or set(objects) != set(ops):
            raise AuthorityError("PEER_POLICY_INVALID")
        object_map: dict[str, frozenset[str]] = {}
        for op in ops:
            selectors = objects[op]
            if not isinstance(selectors, (list, tuple, set)) or not selectors:
                raise AuthorityError("PEER_POLICY_INVALID")
            normalized: set[str] = set()
            for selector in selectors:
                if (
                    not isinstance(selector, str)
                    or not selector
                    or selector != selector.strip()
                    or len(selector) > 512
                    or any(ord(c) < 32 or ord(c) == 127 for c in selector)
                ):
                    raise AuthorityError("PEER_POLICY_INVALID")
                normalized.add(selector)
            object_map[op] = frozenset(normalized)
        out[peer_id] = {
            "operations": ops,
            "repositories": frozenset(repos),
            "objects": object_map,
        }
    return out


def _request_objects(request: Mapping[str, Any]) -> frozenset[str]:
    operation = request["operation"]
    payload = request["payload"]
    if operation == "read_github_control":
        objects = {f"pr:{payload['rootPr']}"}
        if payload["preferredRepairPr"]:
            objects.add(f"pr:{payload['preferredRepairPr']}")
        return frozenset(objects)
    if operation == "publish_report_comment":
        return frozenset({f"issue:{payload['issue']}"})
    if operation == "publish_reviewed_draft_pr":
        return frozenset({f"ref:{payload['baseRef']}", f"ref:{payload['headRef']}"})
    if operation == "verify_launch_authority":
        return frozenset({f"envelope:{payload['envelopeDigest']}"})
    raise AuthorityError("OPERATION_DENIED")


class ReplayJournal:
    def __init__(self, root: Path):
        self.path = root / "replay.sqlite3"
        try:
            db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS consumed("
                "request_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, "
                "consumed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )
            db.close()
        except Exception as exc:
            raise AuthorityError("REPLAY_STATE_INVALID") from exc

    def consume(self, request_id: str, request_digest: str) -> None:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        begun = False
        try:
            db.execute("BEGIN IMMEDIATE")
            begun = True
            try:
                db.execute(
                    "INSERT INTO consumed(request_id,request_digest) VALUES(?,?)",
                    (request_id, request_digest),
                )
            except sqlite3.IntegrityError as exc:
                raise AuthorityError("REQUEST_REPLAYED") from exc
            db.execute("COMMIT")
            begun = False
        except AuthorityError:
            if begun:
                db.execute("ROLLBACK")
            raise
        except Exception as exc:
            if begun:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
            raise AuthorityError("REPLAY_STATE_WRITE_FAILED") from exc
        finally:
            db.close()


class ProtectedAuthorityService:
    def __init__(
        self,
        *,
        protected_root: Path,
        boundary: PlatformMachineBoundary,
        secrets_provider: FileSecretProvider,
        backend: GitHubAppBackend,
        receipt_signer: ReceiptSigner,
        allowed_repositories,
        peer_policies,
    ):
        root = Path(protected_root)
        if not root.is_absolute():
            raise AuthorityError("PROTECTED_ROOT_INVALID")
        resolved = assert_machine_anchored_root(boundary, root)
        if receipt_signer is None:
            raise AuthorityError("RECEIPT_SIGNER_REQUIRED")
        repositories = _canonical_repository_map(allowed_repositories)
        self.root = resolved
        self.boundary = boundary
        self.secrets_provider = secrets_provider
        self.backend = backend
        self.receipt_signer = receipt_signer
        self.allowed_repositories = repositories
        self.peer_policies = _canonical_peer_policies(peer_policies, repositories)
        self.service_principal = boundary.assert_service_principal(resolved)
        self.journal = ReplayJournal(resolved)

    def _authorize_peer(self, request: Mapping[str, Any]) -> str:
        peer_id = request["peerId"]
        policy = self.peer_policies.get(peer_id)
        if policy is None:
            raise AuthorityError("PEER_POLICY_DENIED")
        operation = request["operation"]
        if operation not in policy["operations"]:
            raise AuthorityError("PEER_OPERATION_DENIED")
        repo_key = request["repository"].casefold()
        if repo_key not in policy["repositories"]:
            raise AuthorityError("PEER_REPOSITORY_DENIED")
        authorized_objects = policy["objects"].get(operation)
        if not authorized_objects:
            raise AuthorityError("PEER_OBJECT_DENIED")
        requested_objects = _request_objects(request)
        if "*" not in authorized_objects and not requested_objects.issubset(authorized_objects):
            raise AuthorityError("PEER_OBJECT_DENIED")
        canonical_repo = self.allowed_repositories.get(repo_key)
        if canonical_repo is None:
            raise AuthorityError("REPOSITORY_DENIED")
        return canonical_repo

    def handle_json(self, raw: str | bytes, *, peer_context: PeerContext) -> bytes:
        return canonical_json(self.handle(unsigned_request(strict_loads(raw)), peer_context=peer_context))

    def handle(self, raw_request: Mapping[str, Any], *, peer_context: PeerContext) -> dict:
        request = unsigned_request(raw_request)
        if not self.boundary.verify_peer(
            request["peerId"], request["requestDigest"], request["signature"], peer_context
        ):
            raise AuthorityError("PEER_AUTH_DENIED")

        # Authorization must happen before replay mutation, secret access, or any
        # backend call so a valid but over-privileged peer cannot cause durable
        # side effects while probing a denied authority boundary.
        canonical_repo = self._authorize_peer(request)
        request = dict(request)
        request["repository"] = canonical_repo
        self.journal.consume(request["requestId"], request["requestDigest"])

        private = []
        try:
            if request["operation"] == "verify_launch_authority":
                trust = self.secrets_provider.launch_trust_root()
                private.append(trust)
                result = self.backend.verify_launch_authority(
                    repository=request["repository"],
                    control_revision=request["controlRevision"],
                    payload=request["payload"],
                    trust_root=trust,
                )
            else:
                key = self.secrets_provider.github_app_private_key()
                private.append(key)
                kwargs = {
                    "repository": request["repository"],
                    "control_revision": request["controlRevision"],
                    "payload": request["payload"],
                    "private_key": key,
                }
                if request["operation"] == "read_github_control":
                    result = self.backend.read_github_control(**kwargs)
                elif request["operation"] == "publish_report_comment":
                    result = self.backend.publish_report_comment(**kwargs)
                elif request["operation"] == "publish_reviewed_draft_pr":
                    result = self.backend.publish_reviewed_draft_pr(**kwargs)
                else:
                    raise AuthorityError("OPERATION_DENIED")
            public = assert_public_result(result, tuple(private))
        except AuthorityError:
            raise
        except Exception as exc:
            raise AuthorityError("BACKEND_OPERATION_FAILED") from exc

        receipt = {
            "schema": 3,
            "operation": request["operation"],
            "requestId": request["requestId"],
            "peerId": request["peerId"],
            "peerPrincipal": peer_context.principal,
            "repository": request["repository"],
            "controlRevision": request["controlRevision"],
            "requestDigest": request["requestDigest"],
            "resultDigest": canonical_digest(public),
            "servicePrincipal": self.service_principal,
        }
        signed = self.receipt_signer.sign(receipt)
        return {**signed, "result": public}


def create_production_service(
    *,
    protected_root: str,
    expected_service_principal: str,
    peer_principals: dict[str, str],
    peer_public_keys: dict[str, str],
    peer_policies,
    github_app_id: int,
    github_installation_id: int,
    github_private_key_file: str,
    launch_trust_file: str,
    receipt_signing_key_file: str,
    allowed_repositories,
    trusted_storage_principals: set[str] | None = None,
) -> ProtectedAuthorityService:
    root = Path(protected_root)
    boundary = PlatformMachineBoundary(
        expected_service_principal=expected_service_principal,
        peer_principals=peer_principals,
        peer_public_keys=peer_public_keys,
        trusted_storage_principals=trusted_storage_principals,
    )
    root = assert_machine_anchored_root(boundary, root)
    repos = _canonical_repository_map(allowed_repositories)
    secrets = FileSecretProvider(
        root=root,
        private_key_path=Path(github_private_key_file),
        launch_trust_path=Path(launch_trust_file),
        boundary=boundary,
    )
    signer = ReceiptSigner.from_file(
        root=root, path=Path(receipt_signing_key_file), boundary=boundary
    )
    backend = GitHubAppBackend(app_id=github_app_id, installation_id=github_installation_id)
    return ProtectedAuthorityService(
        protected_root=root,
        boundary=boundary,
        secrets_provider=secrets,
        backend=backend,
        receipt_signer=signer,
        allowed_repositories=repos.values(),
        peer_policies=peer_policies,
    )
