from __future__ import annotations

import unittest
from unittest import mock

from forgeboss.broker import crypto


class CryptoAuthorityV2Tests(unittest.TestCase):
    def base(self):
        return {
            "envelopeSha256": "e" * 64,
            "taskId": "t",
            "runId": "r",
            "ownerEpoch": 7,
            "baseSha": "a" * 40,
            "worktreePath": r"C:\repo",
            "budgetUsd": 0.25,
            "expiresAt": 9999999999.0,
            "allowedPaths": ["x.py"],
            "runtime": {"adapter": "mini-swe", "provider": "openai", "model": "openai/gpt-test"},
            "resultRef": "refs/forgeboss/results/a/b",
            "paidLease": {
                "schema": 1,
                "leasePath": r"C:\state\lease.json",
                "leaseSha256": "1" * 64,
                "leaseTokenSha256": "2" * 64,
                "leaseExpiresAt": 9999999990.0,
                "packetSha256": "3" * 64,
                "spendAuthority": {
                    "schema": 1,
                    "budgetRunId": "budget-run-1",
                    "workspaceLeaseId": "4" * 64,
                    "taskId": "t",
                    "runId": "r",
                    "ownerEpoch": 7,
                    "worktreePath": r"C:\repo",
                    "currentHead": "a" * 40,
                    "budgetReservedUsd": 0.25,
                    "taskBudgetAllocatedUsd": 1.0,
                    "taskBudgetSpentUsd": 0.25,
                    "budgetRunCapUsd": 10.0,
                    "budgetRunReservedUsd": 1.0,
                    "provider": "openai",
                    "model": "openai/gpt-test",
                    "expiresAt": 9999999990.0,
                    "status": "active",
                    "allowedPathsSha256": "5" * 64,
                    "envelopeSha256": "e" * 64,
                },
            },
        }

    def signed(self, request, **changes):
        return {
            **request,
            "attestationId": "att-1",
            "spendConsumeId": "protected-spend-consume-1",
            "protected": True,
            "paidConsumed": True,
            **changes,
        }

    def test_protected_service_atomically_consumes_and_binds_exact_paid_lease(self):
        request = self.base()
        signed = self.signed(request)
        with mock.patch.object(crypto, "_verify_attestation", return_value=signed):
            got = crypto.ProtectedAuthorityVerifier(exchange=lambda query: {}, public_key=b"k" * 32).verify(request)
        self.assertEqual(got.paid_lease, request["paidLease"])
        self.assertEqual(got.spend_consume_id, "protected-spend-consume-1")
        self.assertEqual(got.result_ref, request["resultRef"])

    def test_query_is_atomic_consume_not_read_only_verify(self):
        request = self.base()
        observed = {}
        signed = self.signed(request)
        def exchange(query):
            observed.update(query)
            return {}
        with mock.patch.object(crypto, "_verify_attestation", return_value=signed):
            crypto.ProtectedAuthorityVerifier(exchange=exchange, public_key=b"k" * 32).verify(request)
        self.assertEqual(observed["operation"], "consume-forgeboss-paid-authority")
        self.assertEqual(observed["paidLease"], request["paidLease"])

    def test_missing_or_unconsumed_protected_spend_authority_fails_closed(self):
        request = self.base()
        for changes in (
            {"spendConsumeId": ""},
            {"paidConsumed": False},
            {"protected": False},
            {"attestationId": ""},
        ):
            signed = self.signed(request, **changes)
            with self.subTest(changes=changes), mock.patch.object(crypto, "_verify_attestation", return_value=signed):
                with self.assertRaisesRegex(crypto.BrokerCryptoError, "consume prerequisite"):
                    crypto.ProtectedAuthorityVerifier(exchange=lambda query: {}, public_key=b"k" * 32).verify(request)

    def test_protected_authority_rejects_paid_lease_or_launch_binding_mismatch(self):
        for field, value in (
            ("worktreePath", r"C:\other"),
            ("resultRef", "refs/evil"),
            ("runtime", {"adapter": "mini-swe", "model": "other"}),
            ("paidLease", {"schema": 1, "leaseSha256": "f" * 64}),
        ):
            request = self.base()
            signed = self.signed(request, **{field: value})
            with self.subTest(field=field), mock.patch.object(crypto, "_verify_attestation", return_value=signed):
                with self.assertRaisesRegex(crypto.BrokerCryptoError, field):
                    crypto.ProtectedAuthorityVerifier(exchange=lambda query: {}, public_key=b"k" * 32).verify(request)

    def test_missing_paid_lease_binding_fails_before_ipc(self):
        request = self.base()
        request.pop("paidLease")
        exchange = mock.Mock()
        with self.assertRaisesRegex(crypto.BrokerCryptoError, "paid-lease"):
            crypto.ProtectedAuthorityVerifier(exchange=exchange, public_key=b"k" * 32).verify(request)
        exchange.assert_not_called()

    def test_receipt_signer_requires_valid_private_material(self):
        with self.assertRaises(crypto.BrokerCryptoError):
            crypto.ReceiptSigner(private_key=b"short").sign({"schema": 3})


if __name__ == "__main__":
    unittest.main()
