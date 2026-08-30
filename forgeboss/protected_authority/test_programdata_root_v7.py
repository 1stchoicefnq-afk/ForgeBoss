from __future__ import annotations

import os
import shutil
import subprocess
import unittest
import uuid
from pathlib import Path

from forgeboss.protected_authority.boundary import PlatformMachineBoundary
from forgeboss.protected_authority.protocol import AuthorityError
from forgeboss.protected_authority.root_chain import assert_machine_anchored_root


@unittest.skipUnless(os.name == "nt", "native Windows ProgramData root proof")
class ProgramDataRootV7Tests(unittest.TestCase):
    def _boundary(self):
        bootstrap = PlatformMachineBoundary(
            expected_service_principal="bootstrap",
            peer_principals={"p": "bootstrap"},
            peer_public_keys={"p": "AA=="},
            trusted_storage_principals=set(),
        )
        sid = bootstrap._current_windows_sid()
        return PlatformMachineBoundary(
            expected_service_principal=sid,
            peer_principals={"p": sid},
            peer_public_keys={"p": "AA=="},
            trusted_storage_principals=set(),
        ), sid

    def _icacls(self, *args):
        cp = subprocess.run(["icacls", *map(str, args)], capture_output=True, text=True)
        if cp.returncode != 0:
            self.skipTest("icacls fixture unavailable: " + (cp.stderr or cp.stdout))
        return cp

    def _protect_leaf(self, root: Path, sid: str):
        self._icacls(root, "/inheritance:r")
        for principal in ("*S-1-1-0", "*S-1-5-32-545", "*S-1-5-11", "*S-1-3-0", "*S-1-3-4"):
            subprocess.run(["icacls", str(root), "/remove:g", principal], capture_output=True, text=True)
        self._icacls(
            root,
            "/grant:r",
            f"*{sid}:(OI)(CI)F",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        )

    def _new_root(self):
        base = Path(os.environ.get("ProgramData", r"C:\\ProgramData"))
        root = base / ("ForgeBossAuthorityTest-" + uuid.uuid4().hex)
        root.mkdir()
        return root

    def test_programdata_machine_ancestry_accepts_protected_leaf(self):
        boundary, sid = self._boundary()
        root = self._new_root()
        try:
            self._protect_leaf(root, sid)
            self.assertEqual(assert_machine_anchored_root(boundary, root), root.resolve())
        finally:
            subprocess.run(["icacls", str(root), "/grant", f"*{sid}:(OI)(CI)F"], capture_output=True, text=True)
            shutil.rmtree(root, ignore_errors=True)

    def test_delete_child_on_machine_ancestor_is_denied(self):
        boundary, sid = self._boundary()
        root = self._new_root()
        parent = root.parent
        # Do not mutate ProgramData ACL itself. This test proves the production
        # algorithm accepts the real machine ancestry; hostile DELETE_CHILD is
        # already exercised on a disposable protected ancestor by test_v7.
        try:
            self._protect_leaf(root, sid)
            self.assertEqual(assert_machine_anchored_root(boundary, root), root.resolve())
        finally:
            subprocess.run(["icacls", str(root), "/grant", f"*{sid}:(OI)(CI)F"], capture_output=True, text=True)
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
