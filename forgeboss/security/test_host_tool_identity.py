from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import forgeboss.security.host_tool_identity as host
from forgeboss.security.executor_guard import SecurityError


class HostToolIdentityTests(unittest.TestCase):
    def test_missing_tool_fails_closed(self):
        with patch.object(host.shutil,"which",return_value=None):
            with self.assertRaisesRegex(host.HostToolIdentityError,"unavailable"):
                host.resolve_trusted_host_executable("docker")

    def test_linklike_tool_fails_closed_before_trust(self):
        if not hasattr(os,"symlink"):
            self.skipTest("symlink unsupported")
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root=Path(td.name)
        target=root/"real"
        target.write_text("x",encoding="utf-8")
        link=root/("docker.exe" if os.name=="nt" else "docker")
        try:
            link.symlink_to(target)
        except OSError as ex:
            self.skipTest(str(ex))
        with patch.object(host.shutil,"which",return_value=str(link)):
            with self.assertRaisesRegex(host.HostToolIdentityError,"linklike"):
                host.resolve_trusted_host_executable("docker")

    def test_identity_drift_fails_closed(self):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        tool=Path(td.name)/("docker.exe" if os.name=="nt" else "docker")
        tool.write_text("one",encoding="utf-8")
        tool.chmod(0o755)
        with (
            patch.object(host.shutil,"which",return_value=str(tool)),
            patch.object(host,"is_linklike",return_value=False),
            patch.object(host,"_trust_chain"),
            patch.object(host,"fhash",side_effect=["a"*64,"b"*64]),
        ):
            with self.assertRaisesRegex(host.HostToolIdentityError,"changed while hashing"):
                host.resolve_trusted_host_executable("docker")

    def test_explicit_path_is_hashed_and_trusted_without_path_lookup(self):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        tool=Path(td.name)/("docker.exe" if os.name=="nt" else "docker")
        tool.write_text("trusted",encoding="utf-8")
        tool.chmod(0o755)
        with (
            patch.object(host,"is_linklike",return_value=False),
            patch.object(host,"_trust_chain"),
            patch.object(host,"fhash",return_value="a"*64),
            patch.object(host.shutil,"which",side_effect=AssertionError("PATH lookup forbidden")),
        ):
            ident=host.trust_explicit_host_executable("docker",tool)
        self.assertEqual(ident.path,str(tool.resolve()))
        self.assertEqual(ident.sha256,"a"*64)

    def test_assert_re_resolves_exact_identity(self):
        first=host.HostToolIdentity("docker","/trusted/docker","a"*64,10)
        second=host.HostToolIdentity("docker","/trusted/docker","a"*64,10)
        with patch.object(host,"resolve_trusted_host_executable",return_value=second):
            self.assertEqual(host.assert_trusted_host_executable(first),second)
        changed=host.HostToolIdentity("docker","/trusted/docker","b"*64,10)
        with patch.object(host,"resolve_trusted_host_executable",return_value=changed):
            with self.assertRaisesRegex(host.HostToolIdentityError,"identity changed"):
                host.assert_trusted_host_executable(first)


if __name__=="__main__":
    unittest.main()
