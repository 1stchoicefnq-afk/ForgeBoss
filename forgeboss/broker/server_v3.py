from __future__ import annotations

import os
import threading

from . import crypto as v2crypto
from . import server as v2server


class BrokerV3Error(RuntimeError):
    pass


class StrictProtectedAuthorityVerifier:
    """V3 verifier: preserve V2 paid-lease consume contract, but require a real string spendConsumeId."""

    def __init__(self, exchange=None, public_key=None):
        self.exchange = exchange
        self.public_key = public_key

    def verify(self, request: dict):
        paid_lease = request.get("paidLease")
        if not isinstance(paid_lease, dict):
            raise v2crypto.BrokerCryptoError("protected controller authority missing paid-lease binding")
        query = {
            "schema": 2,
            "operation": "consume-forgeboss-paid-authority",
            "envelopeSha256": request["envelopeSha256"],
            "taskId": request["taskId"],
            "runId": request["runId"],
            "ownerEpoch": request["ownerEpoch"],
            "baseSha": request["baseSha"],
            "worktreePath": request["worktreePath"],
            "budgetUsd": request["budgetUsd"],
            "expiresAt": request["expiresAt"],
            "allowedPaths": request["allowedPaths"],
            "runtime": request["runtime"],
            "resultRef": request["resultRef"],
            "paidLease": paid_lease,
        }
        envelope = self.exchange(query) if self.exchange else (
            v2crypto._windows_exchange(query) if os.name == "nt" else v2crypto._linux_exchange(query)
        )
        signed = v2crypto._verify_attestation(envelope, self.public_key or v2crypto.load_controller_public_key())
        for key, value in query.items():
            if key not in ("schema", "operation") and signed.get(key) != value:
                raise v2crypto.BrokerCryptoError("protected controller authority mismatch: " + key)

        attestation_id = signed.get("attestationId")
        spend_consume_id = signed.get("spendConsumeId")
        if not isinstance(attestation_id, str) or not attestation_id.strip():
            raise v2crypto.BrokerCryptoError("protected paid authority attestationId must be a nonempty string")
        if not isinstance(spend_consume_id, str) or not spend_consume_id.strip():
            raise v2crypto.BrokerCryptoError("protected paid authority spendConsumeId must be a nonempty string")
        if signed.get("protected") is not True or signed.get("paidConsumed") is not True:
            raise v2crypto.BrokerCryptoError("protected paid authority consume prerequisite not satisfied")

        return v2crypto.ProtectedAuthority(
            query["envelopeSha256"], query["taskId"], query["runId"], int(query["ownerEpoch"]),
            query["baseSha"], query["worktreePath"], float(query["budgetUsd"]), float(query["expiresAt"]),
            tuple(query["allowedPaths"]), dict(query["runtime"]), query["resultRef"], dict(query["paidLease"]),
            spend_consume_id, attestation_id,
        )


class _BindingVerifier:
    def __init__(self, inner, state):
        self.inner = inner
        self.state = state

    def verify(self, request):
        protected = self.inner.verify(request)
        spend_consume_id = getattr(protected, "spend_consume_id", None)
        if not isinstance(spend_consume_id, str) or not spend_consume_id.strip():
            raise BrokerV3Error("protected authority returned invalid spendConsumeId")
        attestation_id = getattr(protected, "attestation_id", None)
        if not isinstance(attestation_id, str) or not attestation_id.strip():
            raise BrokerV3Error("protected authority returned invalid attestationId")
        self.state.protected = protected
        return protected


class _EvidenceSigner:
    """Translate V2's broker-local consume field into explicit V3 spend + replay identities before signing."""

    def __init__(self, inner, state):
        self.inner = inner
        self.state = state

    def sign(self, payload):
        protected = getattr(self.state, "protected", None)
        try:
            if isinstance(payload, dict) and payload.get("paidConsumed") is True:
                if protected is None:
                    raise BrokerV3Error("paid receipt has no protected authority context")
                receipt = payload.get("reintegrationReceipt")
                if not isinstance(receipt, dict):
                    raise BrokerV3Error("paid receipt is missing reintegrationReceipt")
                if receipt.get("protectedAuthorityAttestationId") != protected.attestation_id:
                    raise BrokerV3Error("paid receipt protected authority context mismatch")
                broker_replay_id = receipt.get("paidConsumeId")
                spend_consume_id = protected.spend_consume_id
                if not isinstance(broker_replay_id, str) or not broker_replay_id.strip():
                    raise BrokerV3Error("broker replay consume identity is missing")
                if broker_replay_id == spend_consume_id:
                    raise BrokerV3Error("broker replay consume identity must differ from protected spend consume identity")
                for key, expected in (
                    ("spendConsumeId", spend_consume_id),
                    ("brokerReplayConsumeId", broker_replay_id),
                ):
                    existing = receipt.get(key)
                    if existing is not None and existing != expected:
                        raise BrokerV3Error("preexisting paid receipt identity mismatch: " + key)
                receipt = dict(receipt)
                receipt["spendConsumeId"] = spend_consume_id
                receipt["brokerReplayConsumeId"] = broker_replay_id
                # Backward-compatible field is authoritative spend identity in V3, never the broker-local replay ID.
                receipt["paidConsumeId"] = spend_consume_id
                payload = dict(payload)
                payload["reintegrationReceipt"] = receipt
            return self.inner.sign(payload)
        finally:
            if hasattr(self.state, "protected"):
                del self.state.protected


class BrokerServerV3(v2server.BrokerServer):
    def __init__(
        self,
        authority_verifier=None,
        signer=None,
        materializer=v2server.materialize_base,
        runner=v2server.run_mini_swe,
        handoff=v2server.build_and_handoff,
    ):
        state = threading.local()
        verifier = _BindingVerifier(authority_verifier or StrictProtectedAuthorityVerifier(), state)
        evidence_signer = _EvidenceSigner(signer or v2crypto.ReceiptSigner(), state)
        self._v3_state = state
        super().__init__(verifier, evidence_signer, materializer, runner, handoff)


wake_windows_pipe = v2server.wake_windows_pipe


def serve_forever(stop_event=None):
    broker = BrokerServerV3()
    if os.name == "nt":
        v2server.serve_windows(broker, stop_event)
    else:
        v2server.serve_linux(broker, stop_event)
