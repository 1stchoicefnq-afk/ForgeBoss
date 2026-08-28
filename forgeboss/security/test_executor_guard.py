from __future__ import annotations
import unittest
import forgeboss.security.executor_guard as guard

class TrailingDotSpaceBypassTests(unittest.TestCase):
    # Win32's CreateFile silently strips a trailing dot or space from the final
    # path component (e.g. ".env." and ".env " both resolve to ".env" on disk)
    # unless the \\?\ prefix is used. sensitive()/norm() previously did pure
    # string comparison with no awareness of this, so a packet requesting
    # ".env." as an allowed_files entry would pass validate_packet() on any OS
    # and then land on the real ".env" file once actually written on Windows --
    # silently defeating the FORBIDDEN_EXACT denylist for every listed secret
    # file.

    def test_trailing_dot_on_forbidden_file_is_denied(self):
        with self.assertRaises(guard.SecurityError):
            guard.norm(".env.")

    def test_trailing_dot_in_directory_component_is_denied(self):
        with self.assertRaises(guard.SecurityError):
            guard.norm("secrets./config.json")

    def test_trailing_space_in_directory_component_is_denied(self):
        # norm()'s outer .strip() only removes whitespace at the very edges of the
        # whole path string, so a trailing space at the end of the *last* component
        # is caught by that alone; a trailing space on a non-final component (as
        # here) is only caught by the per-component check.
        with self.assertRaises(guard.SecurityError):
            guard.norm("secrets /config.json")

    def test_ordinary_paths_are_unaffected(self):
        self.assertEqual(guard.norm("src/app.js"), "src/app.js")
        self.assertEqual(guard.norm("a.b/c.d.txt"), "a.b/c.d.txt")

    def test_sensitive_still_denies_all_forbidden_exact_names_directly(self):
        for name in (".env", "package.json", "dockerfile"):
            self.assertTrue(guard.sensitive(name))

    def test_validate_packet_rejects_trailing_dot_bypass_attempt(self):
        with self.assertRaises(guard.SecurityError):
            guard.validate_packet({"allowed_files": [".env."]})

if __name__=="__main__":unittest.main()
