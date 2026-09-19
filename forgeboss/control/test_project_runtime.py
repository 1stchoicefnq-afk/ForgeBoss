from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from forgeboss.control.project_runtime import (
    FORGEBOSS_ROOT,
    ProjectRuntimeError,
    assert_write_not_live_root,
    inspect_project,
    load_active_project,
    register_project,
)


class ProjectRuntimeTests(unittest.TestCase):
    def test_forgeboss_root_is_detected_as_self(self):
        p = inspect_project(FORGEBOSS_ROOT)
        self.assertTrue(p["is_self_build"])
        self.assertEqual(Path(p["root"]), FORGEBOSS_ROOT.resolve())

    def test_other_project_is_not_self(self):
        with tempfile.TemporaryDirectory() as td:
            p = inspect_project(td)
            self.assertFalse(p["is_self_build"])

    def test_live_root_and_descendants_are_denied(self):
        with self.assertRaises(ProjectRuntimeError):
            assert_write_not_live_root(FORGEBOSS_ROOT)
        with self.assertRaises(ProjectRuntimeError):
            assert_write_not_live_root(FORGEBOSS_ROOT / "dashboard" / "new-file.txt")

    def test_string_prefix_sibling_is_not_falsely_denied(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "ForgeBoss"
            sibling = Path(td) / "ForgeBoss-Evil"
            base.mkdir()
            sibling.mkdir()
            allowed = assert_write_not_live_root(sibling / "x.txt", live_root=base)
            self.assertEqual(allowed.parent, sibling.resolve())

    def test_symlink_alias_into_live_root_is_denied_when_supported(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            live = d / "live"
            live.mkdir()
            alias = d / "alias"
            try:
                alias.symlink_to(live, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks unavailable")
            with self.assertRaises(ProjectRuntimeError):
                assert_write_not_live_root(alias / "candidate.txt", live_root=live)

    def test_registration_writes_state_outside_project_only(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as sd:
            project = Path(td)
            marker = project / "existing.txt"
            marker.write_text("unchanged", encoding="utf-8")
            before = marker.read_bytes()

            result = register_project(project, state_root=Path(sd))
            self.assertFalse(result["is_self_build"])
            self.assertEqual(marker.read_bytes(), before)

            saved = load_active_project(state_root=Path(sd))
            self.assertEqual(saved["root"], str(project.resolve()))
            self.assertEqual(json.loads((Path(sd) / "active.json").read_text())["schema"], 1)


if __name__ == "__main__":
    unittest.main()
