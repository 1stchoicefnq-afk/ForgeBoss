from __future__ import annotations

import os,tempfile,unittest
from pathlib import Path

from forgeboss.protected_authority.lifecycle import FIXED_SERVICE_NAME,FIXED_SOCKET_NAME,LinuxAuthorityDaemon,run_windows_scm_service
from forgeboss.protected_authority.protocol import AuthorityError
from forgeboss.protected_authority.root_chain import assert_machine_anchored_root

@unittest.skipIf(os.name=='nt','POSIX runtime checks')
class RootChainTests(unittest.TestCase):
    def test_writable_tmp_ancestor_denied(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as td:
            root=Path(td)/'svc';root.mkdir(mode=0o700)
            class B:
                expected=f'uid:{os.geteuid()}'
                def assert_service_principal(self,_):return self.expected
            with self.assertRaises(AuthorityError):assert_machine_anchored_root(B(),root)
    def test_linux_fixed_socket_name(self):self.assertEqual(FIXED_SOCKET_NAME,'authority.sock')

class LifecycleShapeTests(unittest.TestCase):
    def test_fixed_windows_service_name(self):self.assertEqual(FIXED_SERVICE_NAME,'ForgeBossAuthoritySvc')
    @unittest.skipIf(os.name=='nt','non-Windows must fail closed')
    def test_windows_dispatcher_not_callable_on_posix(self):
        with self.assertRaises(AuthorityError):run_windows_scm_service(server_factory=lambda:None)

if __name__=='__main__':unittest.main()
