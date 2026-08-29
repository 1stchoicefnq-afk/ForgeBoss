from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any, Mapping, Protocol

from .protocol import AuthorityError, assert_public_result, canonical_digest, canonical_json, strict_loads, unsigned_request


class MachineBoundary(Protocol):
    def assert_service_principal(self, protected_root: Path) -> str: ...
    def verify_peer(self, peer_id: str, request_digest: str, signature: str) -> bool: ...


class SecretProvider(Protocol):
    def github_app_private_key(self) -> str | bytes: ...
    def launch_trust_root(self) -> str | bytes: ...


class AuthorityBackend(Protocol):
    def read_github_control(self, *, repository: str, control_revision: int, payload: Mapping[str, Any], private_key: str | bytes) -> Any: ...
    def publish_report_comment(self, *, repository: str, control_revision: int, payload: Mapping[str, Any], private_key: str | bytes) -> Any: ...
    def publish_reviewed_draft_pr(self, *, repository: str, control_revision: int, payload: Mapping[str, Any], private_key: str | bytes) -> Any: ...
    def verify_launch_authority(self, *, repository: str, control_revision: int, payload: Mapping[str, Any], trust_root: str | bytes) -> Any: ...


class ReplayJournal:
    VERSION = 1

    def __init__(self, root: Path):
        self.root = root
        self.path = root / "replay-journal.json"
        self._seen = self._load()

    def _load(self) -> set[str]:
        if not self.path.exists():
            return set()
        try:
            obj = strict_loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise AuthorityError("REPLAY_STATE_INVALID") from exc
        if not isinstance(obj, Mapping) or set(obj) != {"version", "requestIds"} or obj["version"] != self.VERSION or not isinstance(obj["requestIds"], list):
            raise AuthorityError("REPLAY_STATE_INVALID")
        out: set[str] = set()
        for item in obj["requestIds"]:
            if not isinstance(item, str) or item in out:
                raise AuthorityError("REPLAY_STATE_INVALID")
            out.add(item)
        return out

    def contains(self, request_id: str) -> bool:
        return request_id in self._seen

    def commit(self, request_id: str) -> None:
        if request_id in self._seen:
            raise AuthorityError("REQUEST_REPLAYED")
        next_seen = set(self._seen)
        next_seen.add(request_id)
        payload = canonical_json({"version": self.VERSION, "requestIds": sorted(next_seen)})
        temp = self.root / f".replay-{secrets.token_hex(16)}.tmp"
        fd = None
        try:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(temp), flags, 0o600)
            offset = 0
            while offset < len(payload):
                written = os.write(fd, payload[offset:])
                if written <= 0:
                    raise OSError("short replay journal write")
                offset += written
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(temp, self.path)
            try:
                dfd = os.open(str(self.root), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
        except Exception as exc:
            try:
                if fd is not None:
                    os.close(fd)
            except OSError:
                pass
            try:
                temp.unlink()
            except OSError:
                pass
            if isinstance(exc, AuthorityError):
                raise
            raise AuthorityError("REPLAY_STATE_WRITE_FAILED") from exc
        self._seen = next_seen


class ProtectedAuthorityService:
    def __init__(self, *, protected_root: str | os.PathLike[str], boundary: MachineBoundary, secrets_provider: SecretProvider, backend: AuthorityBackend):
        root = Path(protected_root)
        if not root.is_absolute():
            raise AuthorityError("PROTECTED_ROOT_INVALID")
        try:
            if root.is_symlink() or not root.is_dir():
                raise AuthorityError("PROTECTED_ROOT_INVALID")
            resolved = root.resolve(strict=True)
        except AuthorityError:
            raise
        except Exception as exc:
            raise AuthorityError("PROTECTED_ROOT_INVALID") from exc
        principal = boundary.assert_service_principal(resolved)
        if not isinstance(principal, str) or not principal:
            raise AuthorityError("SERVICE_PRINCIPAL_INVALID")
        self.root = resolved
        self.boundary = boundary
        self.secrets_provider = secrets_provider
        self.backend = backend
        self.service_principal = principal
        self.journal = ReplayJournal(resolved)

    def handle_json(self, raw: str | bytes) -> bytes:
        try:
            request = unsigned_request(strict_loads(raw))
            return canonical_json(self.handle(request))
        except AuthorityError:
            raise
        except Exception as exc:
            raise AuthorityError("SERVICE_REQUEST_FAILED") from exc

    def handle(self, raw_request: Mapping[str, Any]) -> dict:
        request = unsigned_request(raw_request)
        request_id = request["requestId"]
        if self.journal.contains(request_id):
            raise AuthorityError("REQUEST_REPLAYED")
        if not self.boundary.verify_peer(request["peerId"], request["requestDigest"], request["signature"]):
            raise AuthorityError("PEER_AUTH_DENIED")

        # Fail closed against mutation replay: once an authenticated privileged request
        # is admitted, its request id is durably consumed before secret-backed work.
        # A backend/crash failure may burn the id, but it cannot duplicate a mutation.
        self.journal.commit(request_id)

        private_values: list[str | bytes] = []
        try:
            if request["operation"] == "verify_launch_authority":
                trust_root = self.secrets_provider.launch_trust_root()
                private_values.append(trust_root)
                result = self.backend.verify_launch_authority(
                    repository=request["repository"], control_revision=request["controlRevision"], payload=request["payload"], trust_root=trust_root
                )
            else:
                private_key = self.secrets_provider.github_app_private_key()
                private_values.append(private_key)
                kwargs = dict(repository=request["repository"], control_revision=request["controlRevision"], payload=request["payload"], private_key=private_key)
                if request["operation"] == "read_github_control":
                    result = self.backend.read_github_control(**kwargs)
                elif request["operation"] == "publish_report_comment":
                    result = self.backend.publish_report_comment(**kwargs)
                elif request["operation"] == "publish_reviewed_draft_pr":
                    result = self.backend.publish_reviewed_draft_pr(**kwargs)
                else:
                    raise AuthorityError("OPERATION_DENIED")
            public_result = assert_public_result(result, tuple(private_values))
        except AuthorityError:
            raise
        except Exception:
            raise AuthorityError("BACKEND_OPERATION_FAILED")

        receipt = {
            "schema": 1,
            "operation": request["operation"],
            "requestId": request_id,
            "peerId": request["peerId"],
            "repository": request["repository"],
            "controlRevision": request["controlRevision"],
            "requestDigest": request["requestDigest"],
            "resultDigest": canonical_digest(public_result),
            "servicePrincipal": self.service_principal,
        }
        response = {"receipt": receipt, "receiptDigest": canonical_digest(receipt), "result": public_result}
        return response
