from __future__ import annotations

import concurrent.futures
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from forgeboss.broker import crypto as v2crypto
from forgeboss.broker import server as v2server
from forgeboss.broker import server_v3


class FakeSigner:
    def sign(self, payload):
        return {"signedReceipt": payload, "receiptSignature": "test"}


def authority_request():
    return {
        "envelopeSha256": "e" * 64,
        "taskId": "task-1",
        "runId": "run-1",
        "ownerEpoch": 7,
        "baseSha": "a" * 40,
        "worktreePath": "/repo",
        "budgetUsd": 0.25,
        "expiresAt": 9999999999.0,
        "allowedPaths": ["x.py"],
        "runtime": {"adapter": "mini-swe", "provider": "openai", "model": "openai/gpt-test"},
        "resultRef": "refs/forgeboss/results/task-1/run-1",
        "paidLease": {"schema": 1, "leaseSha256": "1" * 64},
    }


def signed_authority(request, spend="protected-spend-A", attestation="att-A"):
    return {
        **request,
        "spendConsumeId": spend,
        "attestationId": attestation,
        "protected": True,
        "paidConsumed": True,
    }


def paid_payload(spend_attestation="att-A", broker_replay="broker-B", completed=True):
    return {
        "schema": 3,
        "ok": True,
        "paidConsumed": True,
        "completed": completed,
        "reintegrationReceipt": {
            "schema": 3,
            "protectedAuthorityAttestationId": spend_attestation,
            # V2 puts broker-local replay identity here. V3 signer must migrate it before signing.
            "paidConsumeId": broker_replay,
        },
    }


class BrokerServerV3EvidenceTests(unittest.TestCase):
    def test_strict_verifier_accepts_exact_nonempty_string_spend_consume_id(self):
        request = authority_request()
        signed = signed_authority(request)
        with mock.patch.object(v2crypto, "_verify_attestation", return_value=signed):
            got = server_v3.StrictProtectedAuthorityVerifier(exchange=lambda _query: {}, public_key=b"k" * 32).verify(request)
        self.assertEqual(got.spend_consume_id, "protected-spend-A")
        self.assertEqual(got.attestation_id, "att-A")
        self.assertEqual(got.paid_lease, request["paidLease"])

    def test_strict_verifier_rejects_missing_empty_or_wrong_type_spend_consume_id(self):
        request = authority_request()
        for bad in (None, "", "   ", 1, True, {}, []):
            with self.subTest(value=bad):
                signed = signed_authority(request, spend=bad)
                with mock.patch.object(v2crypto, "_verify_attestation", return_value=signed):
                    with self.assertRaisesRegex(v2crypto.BrokerCryptoError, "spendConsumeId"):
                        server_v3.StrictProtectedAuthorityVerifier(exchange=lambda _query: {}, public_key=b"k" * 32).verify(request)

    def test_bad_custom_verifier_stops_before_materializer_runner_or_consume(self):
        class BadVerifier:
            def verify(self, _request):
                return SimpleNamespace(spend_consume_id=123, attestation_id="att-A")

        view = {
            "envelopeSha256": "e" * 64,
            "taskId": "task-1",
            "runId": "run-1",
            "ownerEpoch": 7,
            "baseSha": "a" * 40,
            "worktreePath": "/repo",
            "budgetUsd": 0.25,
            "expiresAt": 9999999999.0,
            "allowedPaths": ["x.py"],
            "runtime": {"adapter": "mini-swe"},
            "resultRef": "refs/forgeboss/results/task-1/run-1",
        }
        materializer = mock.Mock()
        runner = mock.Mock()
        broker = server_v3.BrokerServerV3(
            authority_verifier=BadVerifier(), signer=FakeSigner(), materializer=materializer, runner=runner
        )
        with mock.patch.object(v2server, "_authority_view", return_value=view), mock.patch.object(
            v2server, "_validate_paid_lease", return_value={"schema": 1}
        ), mock.patch.object(v2server, "_consume") as consume:
            with self.assertRaisesRegex(server_v3.BrokerV3Error, "spendConsumeId"):
                broker.handle({"schema": 3})
        consume.assert_not_called()
        materializer.assert_not_called()
        runner.assert_not_called()

    def test_signed_success_receipt_uses_protected_spend_identity_and_separate_broker_replay_identity(self):
        state = threading.local()
        state.protected = SimpleNamespace(spend_consume_id="protected-spend-A", attestation_id="att-A")
        signer = server_v3._EvidenceSigner(FakeSigner(), state)
        envelope = signer.sign(paid_payload(completed=True))
        receipt = envelope["signedReceipt"]["reintegrationReceipt"]
        self.assertEqual(receipt["spendConsumeId"], "protected-spend-A")
        self.assertEqual(receipt["paidConsumeId"], "protected-spend-A")
        self.assertEqual(receipt["brokerReplayConsumeId"], "broker-B")
        self.assertNotEqual(receipt["spendConsumeId"], receipt["brokerReplayConsumeId"])

    def test_signed_paid_failure_receipt_uses_same_protected_spend_identity_contract(self):
        state = threading.local()
        state.protected = SimpleNamespace(spend_consume_id="protected-spend-A", attestation_id="att-A")
        signer = server_v3._EvidenceSigner(FakeSigner(), state)
        envelope = signer.sign(paid_payload(completed=False))
        receipt = envelope["signedReceipt"]["reintegrationReceipt"]
        self.assertEqual(receipt["spendConsumeId"], "protected-spend-A")
        self.assertEqual(receipt["paidConsumeId"], "protected-spend-A")
        self.assertEqual(receipt["brokerReplayConsumeId"], "broker-B")

    def test_signer_rejects_spend_and_broker_replay_identity_collision(self):
        state = threading.local()
        state.protected = SimpleNamespace(spend_consume_id="same-id", attestation_id="att-A")
        signer = server_v3._EvidenceSigner(FakeSigner(), state)
        with self.assertRaisesRegex(server_v3.BrokerV3Error, "must differ"):
            signer.sign(paid_payload(broker_replay="same-id"))

    def test_thread_local_authority_context_prevents_cross_request_evidence_mix(self):
        state = threading.local()

        class ThreadVerifier:
            def verify(self, request):
                return SimpleNamespace(spend_consume_id=request["spend"], attestation_id=request["att"])

        verifier = server_v3._BindingVerifier(ThreadVerifier(), state)
        signer = server_v3._EvidenceSigner(FakeSigner(), state)

        def one(index):
            spend = f"protected-{index}"
            att = f"att-{index}"
            replay = f"broker-{index}"
            verifier.verify({"spend": spend, "att": att})
            receipt = signer.sign(paid_payload(att, replay))["signedReceipt"]["reintegrationReceipt"]
            return receipt["spendConsumeId"], receipt["brokerReplayConsumeId"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(one, range(8)))
        self.assertEqual(results, [(f"protected-{i}", f"broker-{i}") for i in range(8)])

    def test_service_entrypoint_is_v3_not_stale_v2_server(self):
        from forgeboss.broker import __main__ as entry
        self.assertEqual(entry.serve_forever.__module__, "forgeboss.broker.server_v3")


if __name__ == "__main__":
    unittest.main()
