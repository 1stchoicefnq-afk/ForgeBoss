from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT=Path(__file__).resolve().parent
PROOF_PATH=ROOT/"v28-template"/"Tools"/"prove_authority_operations.py"
spec=importlib.util.spec_from_file_location("forgeboss_stage1_authority_operation_proof",PROOF_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("proof import failed")
proof=importlib.util.module_from_spec(spec);spec.loader.exec_module(proof)


class AuthorityOperationProofTests(unittest.TestCase):
    def test_expected_inventory_is_exact(self):
        self.assertEqual(len(proof.EXPECTED_STAGE1),12)
        self.assertEqual(len(proof.EXPECTED_GITHUB),3)
        out=proof.assert_inventory(proof.EXPECTED_ALL)
        self.assertEqual(out["count"],15)
        with self.assertRaises(RuntimeError) as cm:
            proof.assert_inventory(set(proof.EXPECTED_ALL)|{"decoy_operation"})
        self.assertIn("unexpected",str(cm.exception))
        with self.assertRaises(RuntimeError) as cm:
            proof.assert_inventory(set(proof.EXPECTED_ALL)-{"accept_self_build_candidate"})
        self.assertIn("missing",str(cm.exception))

    def test_every_stage1_operation_has_a_runtime_probe_case(self):
        with tempfile.TemporaryDirectory() as td:
            state={"protectedRoot":td,"engineSha":"a"*40}
            rows=proof.probe_matrix(state)
        operations=[row[0] for row in rows]
        self.assertEqual(len(operations),12)
        self.assertEqual(set(operations),proof.EXPECTED_STAGE1)
        self.assertEqual(len(operations),len(set(operations)))
        success=[row for row in rows if row[2] is None]
        self.assertEqual([row[0] for row in success],["self_build_current_known_good"])
        refusals=[row for row in rows if row[2] is not None]
        self.assertEqual(len(refusals),11)
        self.assertTrue(all(isinstance(row[2],str) and row[2] for row in refusals))


if __name__=="__main__":
    unittest.main()
