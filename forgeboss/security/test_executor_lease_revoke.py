from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import forgeboss.security.executor_guard as guard


class ExecutorLeaseRevokeTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root=Path(self.td.name)
        self.state=self.root/"state"
        self.state.mkdir()
        self.work=self.root/"work"
        self.work.mkdir()
        self.old_state=guard.STATE
        guard.STATE=self.state
        self.addCleanup(self._restore)
        self.token="secret-token"
        self.lease=self.state/"lease-test.json"
        self.lease.write_text(json.dumps({
            "schema":3,
            "executor":"mini-swe",
            "workspace":str(self.work.resolve()),
            "packet_sha256":"0"*64,
            "allowed_files":["src/a.py"],
            "allowed_keys":["src/a.py"],
            "issued_at":1.0,
            "expires_at":9999999999.0,
            "token_sha256":hashlib.sha256(self.token.encode()).hexdigest(),
            "baseline":{},
            "git_metadata":{},
            "isolation_verified":True,
            "paid_consumed":False,
            "paid_authority":None,
            "revoked_at":None,
        }),encoding="utf-8")

    def _restore(self):
        guard.STATE=self.old_state

    def test_revoke_marks_and_removes_exact_lease(self):
        out=guard.revoke_lease(self.lease,self.token,self.work,"mini-swe")
        self.assertTrue(out["revoked"])
        self.assertTrue(out["removed"])
        self.assertFalse(self.lease.exists())

    def test_wrong_token_cannot_revoke(self):
        with self.assertRaisesRegex(guard.SecurityError,"lease token mismatch"):
            guard.revoke_lease(self.lease,"wrong",self.work,"mini-swe")
        self.assertTrue(self.lease.exists())

    def test_outside_state_lease_is_rejected(self):
        outside=self.root/"outside.json"
        outside.write_text(self.lease.read_text(encoding="utf-8"),encoding="utf-8")
        with self.assertRaisesRegex(guard.SecurityError,"outside protected state"):
            guard.revoke_lease(outside,self.token,self.work,"mini-swe")

    def test_revoked_marker_is_rejected_before_packet_verification(self):
        data=json.loads(self.lease.read_text(encoding="utf-8"))
        data["revoked_at"]=123.0
        self.lease.write_text(json.dumps(data),encoding="utf-8")
        with self.assertRaisesRegex(guard.SecurityError,"executor lease revoked"):
            guard._verify_unlocked(
                self.lease,self.token,self.root/"missing-packet.json",self.work,"mini-swe"
            )


if __name__=="__main__":
    unittest.main()
