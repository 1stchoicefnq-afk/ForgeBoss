from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


class ProtectedAuthorityImportOrderTests(unittest.TestCase):
    def _clean_python(self,code:str):
        p=subprocess.run(
            [sys.executable,"-I","-c",code],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(p.returncode,0,msg=(p.stdout+"\n"+p.stderr).strip())

    def test_coordinator_import_does_not_cycle_through_protected_authority_service(self):
        code=(
            "import sys;"
            f"sys.path.insert(0,{str(ROOT)!r});"
            "from forgeboss.control.self_build_coordinator import SelfBuildCoordinator;"
            "print(SelfBuildCoordinator.__name__)"
        )
        self._clean_python(code)

    def test_workspace_state_import_does_not_eagerly_import_service(self):
        code=(
            "import sys;"
            f"sys.path.insert(0,{str(ROOT)!r});"
            "import forgeboss.control.workspace_state;"
            "assert 'forgeboss.protected_authority.service' not in sys.modules;"
            "print('OK')"
        )
        self._clean_python(code)

    def test_package_level_service_exports_remain_available_lazily(self):
        code=(
            "import sys;"
            f"sys.path.insert(0,{str(ROOT)!r});"
            "import forgeboss.protected_authority as pa;"
            "assert 'forgeboss.protected_authority.service' not in sys.modules;"
            "cls=pa.ProtectedAuthorityService;"
            "assert cls.__name__=='ProtectedAuthorityService';"
            "assert 'forgeboss.protected_authority.service' in sys.modules;"
            "print('OK')"
        )
        self._clean_python(code)


if __name__=="__main__":
    unittest.main()
