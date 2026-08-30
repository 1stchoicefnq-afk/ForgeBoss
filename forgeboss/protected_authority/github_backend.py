from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Mapping

from .protocol import AuthorityError, canonical_digest

_TOKEN_PERMISSIONS = {
    "read_github_control": {
        "contents": "read",
        "pull_requests": "read",
        "checks": "read",
        "statuses": "read",
    },
    "publish_report_comment": {"issues": "write"},
    "publish_reviewed_draft_pr": {"contents": "read", "pull_requests": "write"},
}


class GitHubAppBackend:
    def __init__(self, *, app_id: int, installation_id: int, api_base: str = "https://api.github.com"):
        if (
            not isinstance(app_id, int)
            or app_id <= 0
            or not isinstance(installation_id, int)
            or installation_id <= 0
        ):
            raise AuthorityError("GITHUB_APP_CONFIG_INVALID")
        if api_base != "https://api.github.com":
            raise AuthorityError("GITHUB_API_BASE_DENIED")
        self.app_id = app_id
        self.installation_id = installation_id
        self.api_base = api_base

    def _jwt(self, pem: bytes) -> str:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            now = int(time.time())
            header = {"alg": "RS256", "typ": "JWT"}
            payload = {"iat": now - 30, "exp": now + 540, "iss": str(self.app_id)}
            enc = lambda value: base64.urlsafe_b64encode(
                json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
            ).rstrip(b"=")
            unsigned = enc(header) + b"." + enc(payload)
            key = serialization.load_pem_private_key(pem, password=None)
            sig = key.sign(unsigned, padding.PKCS1v15(), hashes.SHA256())
            return (unsigned + b"." + base64.urlsafe_b64encode(sig).rstrip(b"=")).decode()
        except Exception as exc:
            raise AuthorityError("GITHUB_APP_KEY_INVALID") from exc

    def _request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: Mapping[str, Any] | None = None,
    ) -> Any:
        if not path.startswith("/") or "://" in path or ".." in path:
            raise AuthorityError("GITHUB_PATH_DENIED")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ForgeBossAuthority",
        }
        if token:
            headers["Authorization"] = "Bearer " + token
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.api_base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode())
        except (urllib.error.URLError, ValueError) as exc:
            raise AuthorityError("GITHUB_OPERATION_FAILED") from exc

    def _token(self, pem: bytes, repository: str, operation: str) -> str:
        permissions = _TOKEN_PERMISSIONS.get(operation)
        if permissions is None:
            raise AuthorityError("GITHUB_TOKEN_SCOPE_DENIED")
        owner, separator, name = repository.partition("/")
        if not separator or not owner or not name:
            raise AuthorityError("GITHUB_REPOSITORY_INVALID")
        body = {"repositories": [name], "permissions": dict(permissions)}
        obj = self._request(
            "POST",
            f"/app/installations/{self.installation_id}/access_tokens",
            token=self._jwt(pem),
            body=body,
        )
        token = obj.get("token") if isinstance(obj, dict) else None
        if not isinstance(token, str) or not token:
            raise AuthorityError("GITHUB_TOKEN_INVALID")
        return token

    @staticmethod
    def _repo_path(repository: str) -> str:
        return "/repos/" + repository

    @staticmethod
    def _nested(mapping: Mapping[str, Any] | None, *keys: str) -> Any:
        value: Any = mapping
        for key in keys:
            if not isinstance(value, Mapping):
                return None
            value = value.get(key)
        return value

    @classmethod
    def _pr_summary(cls, pr: Mapping[str, Any]) -> dict[str, Any]:
        try:
            number = int(pr["number"])
        except Exception as exc:
            raise AuthorityError("GITHUB_CONTROL_INVALID") from exc
        return {
            "number": number,
            "state": str(pr.get("state") or ""),
            "title": str(pr.get("title") or ""),
            "head_sha": str(cls._nested(pr, "head", "sha") or ""),
            "head_ref": str(cls._nested(pr, "head", "ref") or ""),
            "base_sha": str(cls._nested(pr, "base", "sha") or ""),
            "base_ref": str(cls._nested(pr, "base", "ref") or ""),
            "repo": str(cls._nested(pr, "head", "repo", "full_name") or ""),
            "updated_at": str(pr.get("updated_at") or ""),
        }

    @classmethod
    def _looks_like_repair_child(cls, pr: Mapping[str, Any], parent_number: int) -> bool:
        head_ref = str(cls._nested(pr, "head", "ref") or "")
        title = str(pr.get("title") or "")
        body = str(pr.get("body") or "")
        prefix = f"autopilot/repair-pr{parent_number}-"
        if head_ref.casefold().startswith(prefix.casefold()):
            return True
        parent = re.escape(str(parent_number))
        if re.search(r"(?i)\brepair\b", title) and (
            re.search(rf"#{parent}\b", title) or re.search(rf"#{parent}\b", body)
        ):
            return True
        return bool(
            re.search(
                rf"(?i)(parent|target|integration)\s+PR\s*:?\s*#{parent}\b",
                body,
            )
        )

    def read_github_control(
        self,
        *,
        repository: str,
        control_revision: int,
        payload: Mapping[str, Any],
        private_key: bytes,
    ) -> Any:
        """Return the same fail-closed binding semantics as Read-GitHub-Control.ps1."""
        token = self._token(private_key, repository, "read_github_control")
        root_number = int(payload["rootPr"])
        preferred_number = int(payload["preferredRepairPr"])
        repo_path = self._repo_path(repository)
        root_pr = self._request("GET", f"{repo_path}/pulls/{root_number}", token=token)
        if not isinstance(root_pr, Mapping):
            raise AuthorityError("GITHUB_CONTROL_INVALID")
        if str(root_pr.get("state") or "") != "open":
            raise AuthorityError("ROOT_PR_NOT_OPEN")
        if str(self._nested(root_pr, "head", "repo", "full_name") or "") != repository:
            raise AuthorityError("ROOT_PR_REPOSITORY_MISMATCH")

        root_head_sha = str(self._nested(root_pr, "head", "sha") or "")
        root_head_ref = str(self._nested(root_pr, "head", "ref") or "")
        root_base_sha = str(self._nested(root_pr, "base", "sha") or "")
        root_base_ref = str(self._nested(root_pr, "base", "ref") or "")
        if not root_head_sha or not root_head_ref or not root_base_sha or not root_base_ref:
            raise AuthorityError("GITHUB_CONTROL_INVALID")

        preferred = None
        if preferred_number > 0:
            try:
                candidate = self._request(
                    "GET", f"{repo_path}/pulls/{preferred_number}", token=token
                )
                if isinstance(candidate, Mapping):
                    preferred = candidate
            except AuthorityError as exc:
                if exc.code != "GITHUB_OPERATION_FAILED":
                    raise

        encoded_base = urllib.parse.quote(root_head_ref, safe="")
        open_on_base = self._request(
            "GET",
            f"{repo_path}/pulls?state=open&base={encoded_base}&per_page=100&sort=updated&direction=desc",
            token=token,
        )
        if not isinstance(open_on_base, list):
            raise AuthorityError("GITHUB_CONTROL_INVALID")

        exact_candidates = []
        for pr in open_on_base:
            if not isinstance(pr, Mapping):
                raise AuthorityError("GITHUB_CONTROL_INVALID")
            same_repo = str(self._nested(pr, "head", "repo", "full_name") or "") == repository
            exact_base = str(self._nested(pr, "base", "sha") or "") == root_head_sha
            if same_repo and exact_base and self._looks_like_repair_child(pr, root_number):
                exact_candidates.append(pr)

        selected = None
        selection_reason = ""
        if preferred is not None:
            preferred_valid = (
                str(preferred.get("state") or "") == "open"
                and str(self._nested(preferred, "head", "repo", "full_name") or "")
                == repository
                and str(self._nested(preferred, "base", "sha") or "") == root_head_sha
                and str(self._nested(preferred, "base", "ref") or "") == root_head_ref
            )
            if preferred_valid:
                selected = preferred
                selection_reason = "preferred-exact"

        if selected is None:
            if len(exact_candidates) == 1:
                selected = exact_candidates[0]
                selection_reason = "discovered-exact"
            elif len(exact_candidates) > 1:
                raise AuthorityError("REPAIR_CHILD_AMBIGUOUS")

        owner, _, repo_name = repository.partition("/")
        root_summary = {
            "number": root_number,
            "state": str(root_pr.get("state") or ""),
            "head_sha": root_head_sha,
            "head_ref": root_head_ref,
            "base_sha": root_base_sha,
            "base_ref": root_base_ref,
        }
        preferred_summary = None if preferred is None else self._pr_summary(preferred)
        exact_summaries = [self._pr_summary(pr) for pr in exact_candidates]
        result = {
            "schema": 2,
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "owner": owner,
            "repo": repo_name,
            "root_pr": root_summary,
            "repair_pr": None,
            "preferred_repair_pr": preferred_summary,
            "exact_repair_candidates": exact_summaries,
            "binding": {},
            "controlRevision": control_revision,
        }
        if selected is None:
            result["binding"] = {
                "status": "NO_CURRENT_EXACT_REPAIR_CHILD",
                "repair_base_equals_root_head": False,
                "repository": repository,
                "stale_preferred": preferred is not None,
                "preferred_state": "" if preferred is None else str(preferred.get("state") or ""),
                "preferred_base_sha": ""
                if preferred is None
                else str(self._nested(preferred, "base", "sha") or ""),
            }
            return result

        result["repair_pr"] = self._pr_summary(selected)
        result["binding"] = {
            "status": "EXACT_REPAIR_CHILD_BOUND",
            "repair_base_equals_root_head": True,
            "repository": repository,
            "selection_reason": selection_reason,
        }
        return result

    def publish_report_comment(
        self,
        *,
        repository: str,
        control_revision: int,
        payload: Mapping[str, Any],
        private_key: bytes,
    ) -> Any:
        token = self._token(private_key, repository, "publish_report_comment")
        obj = self._request(
            "POST",
            self._repo_path(repository) + f"/issues/{int(payload['issue'])}/comments",
            token=token,
            body={"body": payload["body"]},
        )
        return {
            "repository": repository,
            "controlRevision": control_revision,
            "commentId": obj.get("id"),
            "reportDigest": payload["reportDigest"],
        }

    def publish_reviewed_draft_pr(
        self,
        *,
        repository: str,
        control_revision: int,
        payload: Mapping[str, Any],
        private_key: bytes,
    ) -> Any:
        token = self._token(private_key, repository, "publish_reviewed_draft_pr")
        base_ref = payload["baseRef"]
        head_ref = payload["headRef"]
        base = self._request(
            "GET", self._repo_path(repository) + f"/git/ref/heads/{base_ref}", token=token
        )
        head = self._request(
            "GET", self._repo_path(repository) + f"/git/ref/heads/{head_ref}", token=token
        )
        if (
            base.get("object", {}).get("sha", "").lower() != payload["baseSha"]
            or head.get("object", {}).get("sha", "").lower() != payload["headSha"]
        ):
            raise AuthorityError("PR_REF_SHA_MISMATCH")
        obj = self._request(
            "POST",
            self._repo_path(repository) + "/pulls",
            token=token,
            body={
                "title": payload["title"],
                "body": payload["body"],
                "head": head_ref,
                "base": base_ref,
                "draft": True,
            },
        )
        return {
            "repository": repository,
            "controlRevision": control_revision,
            "prNumber": obj.get("number"),
            "draft": obj.get("draft") is True,
            "headSha": payload["headSha"],
            "baseSha": payload["baseSha"],
            "reviewDigest": payload["reviewDigest"],
        }

    def verify_launch_authority(
        self,
        *,
        repository: str,
        control_revision: int,
        payload: Mapping[str, Any],
        trust_root: bytes,
    ) -> Any:
        envelope = payload["envelope"]
        signature = envelope.get("signature")
        signed = envelope.get("signed")
        if not isinstance(signature, str) or not isinstance(signed, Mapping):
            raise AuthorityError("LAUNCH_ENVELOPE_INVALID")
        if canonical_digest(signed) != payload["envelopeDigest"]:
            raise AuthorityError("ENVELOPE_DIGEST_MISMATCH")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(trust_root, validate=True))
            key.verify(
                base64.b64decode(signature, validate=True),
                bytes.fromhex(payload["envelopeDigest"]),
            )
        except Exception as exc:
            raise AuthorityError("LAUNCH_AUTHORITY_INVALID") from exc
        return {
            "repository": repository,
            "controlRevision": control_revision,
            "verified": True,
            "envelopeDigest": payload["envelopeDigest"],
        }
