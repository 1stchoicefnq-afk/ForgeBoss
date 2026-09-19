from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from forgeboss.protected_authority.protocol import canonical_digest
from forgeboss.protected_authority.signing import ReceiptSigner
from forgeboss.security.executor_guard import SecurityError, _protected_control_authority


class ProtectedPaidStartTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory()
        self.root=Path(self.td.name)
        self.work=self.root/"work"
        self.work.mkdir()
        self.service_key=Ed25519PrivateKey.generate()
        self.signer=ReceiptSigner.from_private_key(self.service_key)
        raw=self.service_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.pin=base64.b64encode(raw).decode("ascii")
        self.packet_sha="1"*64
        self.authority={
            "repository":"1stchoicefnq-afk/ForgeBoss",
            "control_revision":1,
            "task_id":"FL1-A",
            "run_id":"run-a",
            "owner_epoch":1,
            "builder_id":"builder-a",
            "assignment_generation":1,
            "assignment_sha256":"2"*64,
            "branch":"forgeboss/fl1-selfbuild-a-learning-proof",
            "budget_usd":"1.00",
            "global_budget_run_id":"fl1-run",
            "global_budget_reservation_id":"fl1-a",
            "receipt_public_key_b64":self.pin,
        }
        self.lease={
            "allowed_files":["forgeboss/learning/test_fl1_reuse_regression.py"],
            "packet_sha256":self.packet_sha,
        }
        self.packet={"self_build_authority":dict(self.authority)}
        self.signed=self._signed()

    def tearDown(self):
        self.td.cleanup()

    def _signed(self,**overrides):
        value={
            "schema":1,
            "repository":self.authority["repository"],
            "controlRevision":1,
            "taskId":"FL1-A",
            "runId":"run-a",
            "ownerEpoch":1,
            "builderId":"builder-a",
            "assignmentGeneration":1,
            "assignmentSha256":"2"*64,
            "branch":"forgeboss/fl1-selfbuild-a-learning-proof",
            "worktreePath":str(self.work.resolve()),
            "runtimeId":"mini-swe",
            "allowedPaths":["forgeboss/learning/test_fl1_reuse_regression.py"],
            "packetSha256":self.packet_sha,
            "budgetUsd":"1.00",
            "globalBudgetRunId":"fl1-run",
            "globalBudgetReservationId":"fl1-a",
            "expiresAt":time.time()+300,
        }
        value.update(overrides)
        return value

    def _bundle(self,signed=None,*,receipt_key=None):
        signed=dict(self.signed if signed is None else signed)
        digest=canonical_digest(signed)
        result={
            "repository":self.authority["repository"],
            "controlRevision":1,
            "verified":True,
            "envelopeDigest":digest,
        }
        receipt={
            "schema":3,
            "operation":"verify_launch_authority",
            "requestId":"00000000-0000-4000-8000-000000000001",
            "peerId":"controller-a",
            "peerPrincipal":"test",
            "repository":self.authority["repository"],
            "controlRevision":1,
            "requestDigest":"3"*64,
            "resultDigest":canonical_digest(result),
            "servicePrincipal":"service",
        }
        signer=self.signer if receipt_key is None else ReceiptSigner.from_private_key(receipt_key)
        response={**signer.sign(receipt),"result":result}
        p=self.root/("bundle-"+str(time.time_ns())+".json")
        p.write_text(json.dumps({
            "schema":1,
            "envelope":{"signed":signed,"signature":"controller-signature"},
            "authorityResponse":response,
        }),encoding="utf-8")
        return str(p)

    def test_valid_protected_authority_is_bound_to_exact_worker(self):
        out=_protected_control_authority(
            self._bundle(),self.lease,self.packet,self.work,"mini-swe","1.00"
        )
        self.assertTrue(out["protected"])
        self.assertEqual(out["taskId"],"FL1-A")
        self.assertEqual(out["globalBudgetRunId"],"fl1-run")

    def test_service_receipt_signed_by_wrong_key_is_denied(self):
        with self.assertRaisesRegex(SecurityError,"service receipt invalid"):
            _protected_control_authority(
                self._bundle(receipt_key=Ed25519PrivateKey.generate()),
                self.lease,self.packet,self.work,"mini-swe","1.00"
            )

    def test_service_verified_but_wrong_workspace_binding_is_denied(self):
        signed=self._signed(worktreePath=str((self.root/"other").resolve()))
        with self.assertRaisesRegex(SecurityError,"binding mismatch"):
            _protected_control_authority(
                self._bundle(signed),self.lease,self.packet,self.work,"mini-swe","1.00"
            )

    def test_expired_launch_authority_is_denied(self):
        signed=self._signed(expiresAt=time.time()-1)
        with self.assertRaisesRegex(SecurityError,"expired"):
            _protected_control_authority(
                self._bundle(signed),self.lease,self.packet,self.work,"mini-swe","1.00"
            )

    def test_cli_budget_must_equal_protected_budget(self):
        with self.assertRaisesRegex(SecurityError,"runner budget differs"):
            _protected_control_authority(
                self._bundle(),self.lease,self.packet,self.work,"mini-swe","0.50"
            )

    def test_packet_authority_shape_is_closed(self):
        packet={"self_build_authority":{**self.authority,"unexpected":"x"}}
        with self.assertRaisesRegex(SecurityError,"shape invalid"):
            _protected_control_authority(
                self._bundle(),self.lease,packet,self.work,"mini-swe","1.00"
            )

    def test_executor_security_state_can_live_outside_frozen_source_tree(self):
        external=self.root/"runtime-state"
        env=dict(os.environ)
        env["FORGEBOSS_STATE_ROOT"]=str(external)
        cp=subprocess.run(
            [sys.executable,"-c",
             "from forgeboss.security.executor_guard import STATE; print(STATE)"],
            capture_output=True,text=True,env=env,check=True,
        )
        state=Path(cp.stdout.strip()).resolve()
        self.assertEqual(state,(external/"executor-security").resolve())
        self.assertTrue(state.is_dir())


if __name__=="__main__":
    unittest.main()
