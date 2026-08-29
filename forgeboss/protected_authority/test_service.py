from __future__ import annotations

import tempfile
import unittest
import uuid
from pathlib import Path

from forgeboss.protected_authority.protocol import AuthorityError, build_request, canonical_digest, canonical_json, strict_loads
from forgeboss.protected_authority.service import ProtectedAuthorityService


class Boundary:
    def __init__(self, *, service_ok=True, peer_ok=True):
        self.service_ok = service_ok
        self.peer_ok = peer_ok
        self.peer_calls = []

    def assert_service_principal(self, protected_root):
        if not self.service_ok:
            raise AuthorityError("SERVICE_PRINCIPAL_DENIED")
        return "machine:ForgeBossAuthoritySvc"

    def verify_peer(self, peer_id, request_digest, signature):
        self.peer_calls.append((peer_id, request_digest, signature))
        return self.peer_ok and signature == f"signed:{peer_id}:{request_digest}"


class SecretProvider:
    def __init__(self):
        self.github_reads = 0
        self.launch_reads = 0
        self.private_key = "PEM-PRIVATE-DO-NOT-LEAK"
        self.trust_root = "ED25519-PRIVATE-TRUST-DO-NOT-LEAK"

    def github_app_private_key(self):
        self.github_reads += 1
        return self.private_key

    def launch_trust_root(self):
        self.launch_reads += 1
        return self.trust_root


class Backend:
    def __init__(self):
        self.calls = []
        self.raise_with_secret = False
        self.leak_token = False

    def _result(self, op, repository, control_revision, payload, private):
        self.calls.append((op, repository, control_revision, dict(payload), private))
        if self.raise_with_secret:
            raise RuntimeError(f"provider failed with {private}")
        if self.leak_token:
            return {"token": private}
        return {"ok": True, "operation": op, "repository": repository, "controlRevision": control_revision}

    def read_github_control(self, **kw):
        return self._result("read_github_control", kw["repository"], kw["control_revision"], kw["payload"], kw["private_key"])

    def publish_report_comment(self, **kw):
        return self._result("publish_report_comment", kw["repository"], kw["control_revision"], kw["payload"], kw["private_key"])

    def publish_reviewed_draft_pr(self, **kw):
        return self._result("publish_reviewed_draft_pr", kw["repository"], kw["control_revision"], kw["payload"], kw["private_key"])

    def verify_launch_authority(self, **kw):
        return self._result("verify_launch_authority", kw["repository"], kw["control_revision"], kw["payload"], kw["trust_root"])


def make_request(operation, payload, *, repository="owner/repo", peer="controller-a", revision=127, request_id=None):
    request_id = request_id or str(uuid.uuid4())
    unsigned = {
        "schema": 1,
        "operation": operation,
        "requestId": request_id,
        "peerId": peer,
        "repository": repository,
        "controlRevision": revision,
        "payload": payload,
    }
    digest = canonical_digest(unsigned)
    signature = f"signed:{peer}:{digest}"
    return build_request(operation=operation, request_id=request_id, peer_id=peer, repository=repository, control_revision=revision, payload=payload, signature=signature)


class ProtectedAuthorityServiceTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name).resolve()
        self.boundary = Boundary()
        self.secrets = SecretProvider()
        self.backend = Backend()
        self.service = ProtectedAuthorityService(protected_root=self.root, boundary=self.boundary, secrets_provider=self.secrets, backend=self.backend)

    def tearDown(self):
        self.td.cleanup()

    def test_read_control_binds_repository_revision_and_returns_no_secret(self):
        req = make_request("read_github_control", {"rootPr": 10, "preferredRepairPr": 0})
        out = self.service.handle(req)
        self.assertEqual(out["receipt"]["repository"], "owner/repo")
        self.assertEqual(out["receipt"]["controlRevision"], 127)
        self.assertEqual(self.backend.calls[0][4], self.secrets.private_key)
        self.assertNotIn(self.secrets.private_key, canonical_json(out).decode())

    def test_fake_peer_denied_before_secret_read_or_replay_consumption(self):
        self.boundary.peer_ok = False
        req = make_request("read_github_control", {"rootPr": 10, "preferredRepairPr": 0})
        with self.assertRaises(AuthorityError) as cm:
            self.service.handle(req)
        self.assertEqual(cm.exception.code, "PEER_AUTH_DENIED")
        self.assertEqual(self.secrets.github_reads, 0)
        self.boundary.peer_ok = True
        self.assertTrue(self.service.handle(req)["result"]["ok"])

    def test_service_principal_denial_prevents_secret_provider_use(self):
        secrets_provider = SecretProvider()
        with self.assertRaises(AuthorityError) as cm:
            ProtectedAuthorityService(protected_root=self.root, boundary=Boundary(service_ok=False), secrets_provider=secrets_provider, backend=Backend())
        self.assertEqual(cm.exception.code, "SERVICE_PRINCIPAL_DENIED")
        self.assertEqual(secrets_provider.github_reads + secrets_provider.launch_reads, 0)

    def test_replay_is_durable_across_restart(self):
        request_id = str(uuid.uuid4())
        req = make_request("publish_report_comment", {"issue": 11, "body": "reviewed report", "reportDigest": "a" * 64}, request_id=request_id)
        self.service.handle(req)
        restarted = ProtectedAuthorityService(protected_root=self.root, boundary=self.boundary, secrets_provider=self.secrets, backend=self.backend)
        with self.assertRaises(AuthorityError) as cm:
            restarted.handle(req)
        self.assertEqual(cm.exception.code, "REQUEST_REPLAYED")

    def test_cross_repository_substitution_breaks_digest_binding(self):
        req = make_request("read_github_control", {"rootPr": 10, "preferredRepairPr": 0})
        req["repository"] = "other/repo"
        with self.assertRaises(AuthorityError) as cm:
            self.service.handle(req)
        self.assertEqual(cm.exception.code, "REQUEST_DIGEST_MISMATCH")

    def test_arbitrary_endpoint_or_method_field_is_rejected(self):
        req = make_request("publish_report_comment", {"issue": 11, "body": "x", "reportDigest": "a" * 64})
        req["payload"] = {**req["payload"], "endpoint": "/user/tokens"}
        unsigned = {k: req[k] for k in ("schema", "operation", "requestId", "peerId", "repository", "controlRevision", "payload")}
        req["requestDigest"] = canonical_digest(unsigned)
        req["signature"] = f"signed:{req['peerId']}:{req['requestDigest']}"
        with self.assertRaises(AuthorityError) as cm:
            self.service.handle(req)
        self.assertEqual(cm.exception.code, "PAYLOAD_INVALID")

    def test_draft_pr_is_exact_reviewed_shape_only(self):
        payload = {"baseSha": "a" * 40, "headSha": "b" * 40, "title": "Reviewed correction", "body": "review evidence", "reviewDigest": "c" * 64}
        out = self.service.handle(make_request("publish_reviewed_draft_pr", payload))
        self.assertTrue(out["result"]["ok"])
        bad = dict(payload); bad["method"] = "DELETE"
        with self.assertRaises(AuthorityError):
            make_request("publish_reviewed_draft_pr", bad)

    def test_launch_trust_root_cannot_be_supplied_or_substituted_by_caller(self):
        envelope = {"assignmentId": "a1", "ownerEpoch": 4, "candidateSha": "a" * 40}
        payload = {"envelope": envelope, "envelopeDigest": canonical_digest(envelope)}
        self.service.handle(make_request("verify_launch_authority", payload))
        self.assertEqual(self.backend.calls[-1][4], self.secrets.trust_root)
        bad = dict(payload); bad["trustRoot"] = "attacker"
        with self.assertRaises(AuthorityError):
            make_request("verify_launch_authority", bad)

    def test_secret_redaction_on_backend_exception_and_result(self):
        self.backend.raise_with_secret = True
        req = make_request("read_github_control", {"rootPr": 10, "preferredRepairPr": 0})
        with self.assertRaises(AuthorityError) as cm:
            self.service.handle(req)
        self.assertEqual(cm.exception.code, "BACKEND_OPERATION_FAILED")
        self.assertNotIn(self.secrets.private_key, str(cm.exception))
        self.backend.raise_with_secret = False
        self.backend.leak_token = True
        with self.assertRaises(AuthorityError) as replay:
            self.service.handle(req)
        self.assertEqual(replay.exception.code, "REQUEST_REPLAYED")
        with self.assertRaises(AuthorityError) as cm2:
            self.service.handle(make_request("read_github_control", {"rootPr": 10, "preferredRepairPr": 0}))
        self.assertEqual(cm2.exception.code, "SECRET_FIELD_DENIED")

    def test_malformed_duplicate_nonfinite_and_unknown_fields_rejected(self):
        for raw in ('{"schema":1,"schema":1}', '{"x":NaN}', '{"x":Infinity}', ''):
            with self.subTest(raw=raw), self.assertRaises(AuthorityError):
                strict_loads(raw)
        req = make_request("read_github_control", {"rootPr": 10, "preferredRepairPr": 0})
        req["extra"] = True
        with self.assertRaises(AuthorityError) as cm:
            self.service.handle(req)
        self.assertEqual(cm.exception.code, "REQUEST_FIELDS_INVALID")

    def test_request_id_is_consumed_before_backend_failure(self):
        request_id = str(uuid.uuid4())
        req = make_request("publish_report_comment", {"issue": 11, "body": "x", "reportDigest": "d" * 64}, request_id=request_id)
        self.backend.raise_with_secret = True
        with self.assertRaises(AuthorityError) as first:
            self.service.handle(req)
        self.assertEqual(first.exception.code, "BACKEND_OPERATION_FAILED")
        self.backend.raise_with_secret = False
        with self.assertRaises(AuthorityError) as second:
            self.service.handle(req)
        self.assertEqual(second.exception.code, "REQUEST_REPLAYED")
        self.assertEqual(len(self.backend.calls), 1)


if __name__ == "__main__":
    unittest.main()
