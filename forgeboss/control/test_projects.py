from __future__ import annotations
import unittest
import forgeboss.control.projects as projects_module

class LoadProfilePathTraversalTests(unittest.TestCase):
    # project_id is client-controlled input to the daemon's "project.get" RPC.
    # load_profile() used to build PROJECTS/project_id with no validation, so a
    # value containing ".." could escape the projects/ directory and read
    # project.json/acceptance.json/scope.json from anywhere else on disk that
    # the daemon process can access.

    def test_rejects_dot_dot_traversal(self):
        with self.assertRaises(projects_module.ProjectProfileError):
            projects_module.load_profile("../../../../etc")

    def test_rejects_absolute_path(self):
        with self.assertRaises(projects_module.ProjectProfileError):
            projects_module.load_profile("/etc")

    def test_rejects_embedded_separator(self):
        with self.assertRaises(projects_module.ProjectProfileError):
            projects_module.load_profile("foo/../../bar")

    def test_rejects_non_string(self):
        with self.assertRaises(projects_module.ProjectProfileError):
            projects_module.load_profile(None)

    def test_unknown_but_validly_shaped_id_fails_closed_not_found(self):
        with self.assertRaises(projects_module.ProjectProfileError):
            projects_module.load_profile("definitely-not-a-real-project-id")

    def test_valid_existing_profile_still_loads(self):
        profiles=projects_module.list_profiles()
        if not profiles:
            self.skipTest("no project profiles present in this checkout")
        profile=projects_module.load_profile(profiles[0]["id"])
        self.assertEqual(profile["project"]["id"],profiles[0]["id"])

if __name__=="__main__":unittest.main()
