from __future__ import annotations
import base64,unittest
from forgeboss.control.authority import *

try:
 from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
 from cryptography.hazmat.primitives import serialization
except Exception: Ed25519PrivateKey=None

def sample(key_id="k1"):
 return {"authorityVersion":1,"algorithm":"ed25519","keyId":key_id,"purpose":"worker-launch","authorityId":"a1","taskId":"t1","runId":"r1","ownerEpoch":1,"attempt":1,"repository":"Owner/Repo","baseSha":"a"*64,"branch":"b","worktreePath":"C:/w","runtime":{"adapter":"a","provider":"p","model":"m"},"allowedPaths":["src/a.py"],"deniedPaths":["secrets"],"allowedTools":["python"],"contextBundleHash":"c"*64,"budgetUsd":1.0,"issuedAt":100.0,"expiresAt":200.0,"controllerKnownGood":{"revision":1,"manifestSha256":"d"*64,"identitySha256":"e"*64},"assignmentId":"as1"}

@unittest.skipIf(Ed25519PrivateKey is None,"cryptography unavailable")
class AuthorityTests(unittest.TestCase):
 def setUp(self):
  self.priv=Ed25519PrivateKey.generate();pub=self.priv.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
  self.trust=PinnedAuthorityTrust(2,(AuthorityKey("k1",base64.b64encode(pub).decode(),90,180),),minimum_generation=2)
 def packet(self,a): return {"authority":a,"signature":"ed25519:"+base64.b64encode(self.priv.sign(canonical(a))).decode()}
 def test_valid_and_attempt_tamper(self):
  a=sample();self.assertEqual(ControllerAuthorityVerifier(self.trust).verify(self.packet(a),110)["attempt"],1)
  p=self.packet(a);p["authority"]=dict(a,attempt=2)
  with self.assertRaises(PermissionError):ControllerAuthorityVerifier(self.trust).verify(p,110)
 def test_rotation_cutoff(self):
  p=self.packet(sample())
  with self.assertRaises(PermissionError):ControllerAuthorityVerifier(self.trust).verify(p,181)
 def test_not_before(self):
  with self.assertRaises(PermissionError):ControllerAuthorityVerifier(self.trust).verify(self.packet(sample()),80)
 def test_stale_generation(self):
  t=PinnedAuthorityTrust(1,self.trust.keys,minimum_generation=2)
  with self.assertRaises(PermissionError):ControllerAuthorityVerifier(t).verify(self.packet(sample()),110)
 def test_known_good_structured(self):
  a=sample();a["controllerKnownGood"]="label"
  with self.assertRaises(ValueError):validate_authority(a)
 def test_signer_cannot_change_request(self):
  a=sample()
  c=ControllerAuthoritySignerClient(lambda req:{"authority":dict(req["authority"],attempt=2),"signature":"ed25519:x"},"controller-1")
  with self.assertRaises(PermissionError):c.sign_worker_launch(a)

if __name__=="__main__":unittest.main()
