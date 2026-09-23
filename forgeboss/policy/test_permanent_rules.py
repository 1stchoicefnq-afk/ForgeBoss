from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from forgeboss.policy.permanent_rules import (
    EXPECTED_RULESET_ID,
    EXPECTED_RULESET_VERSION,
    PermanentRulesError,
    load_permanent_rules,
    require_rule,
)

ROOT = Path(__file__).resolve().parents[2]
CANONICAL = ROOT / "docs" / "bootstrap" / "PERMANENT_RULES.json"


class PermanentRulesTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(CANONICAL.read_text(encoding="utf-8"))

    def write(self, document=None, *, raw=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "rules.json"
        if raw is not None:
            path.write_bytes(raw)
        else:
            path.write_text(json.dumps(self.document if document is None else document), encoding="utf-8")
        return path

    def test_canonical_rules_load_and_are_read_only(self):
        rules = load_permanent_rules(CANONICAL)
        self.assertEqual(rules.ruleset_id, EXPECTED_RULESET_ID)
        self.assertEqual(rules.ruleset_version, EXPECTED_RULESET_VERSION)
        self.assertEqual(len(rules.rules), 25)
        self.assertEqual(len(rules.required_structured_records), 15)
        self.assertEqual(rules.sha256, hashlib.sha256(CANONICAL.read_bytes()).hexdigest())
        self.assertIn("Chief of Staff", require_rule(rules, "FB-PERM-006")["law"])
        with self.assertRaises(TypeError):
            rules.rules["FB-PERM-001"]["law"] = "override"
        with self.assertRaises(TypeError):
            rules.rules["FB-PERM-999"] = {}

    def test_missing_file_fails_closed(self):
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(ROOT / "does-not-exist-rules.json")

    def test_invalid_json_fails_closed(self):
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(self.write(raw=b"{not-json"))

    def test_wrong_schema_id_version_or_status_fails_closed(self):
        for key, value in (
            ("schema", 2),
            ("ruleset_id", "OTHER"),
            ("ruleset_version", "1.0.1"),
            ("status", "DRAFT"),
        ):
            with self.subTest(key=key):
                doc = json.loads(json.dumps(self.document))
                doc[key] = value
                with self.assertRaises(PermanentRulesError):
                    load_permanent_rules(self.write(doc))

    def test_scope_or_precedence_change_fails_closed(self):
        for key in ("applies_to", "precedence"):
            with self.subTest(key=key):
                doc = json.loads(json.dumps(self.document))
                doc[key] = list(reversed(doc[key]))
                with self.assertRaises(PermanentRulesError):
                    load_permanent_rules(self.write(doc))

    def test_duplicate_or_missing_rule_fails_closed(self):
        duplicate = json.loads(json.dumps(self.document))
        duplicate["rules"].append(dict(duplicate["rules"][0]))
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(self.write(duplicate))

        missing = json.loads(json.dumps(self.document))
        missing["rules"] = missing["rules"][:-1]
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(self.write(missing))

    def test_reordered_rules_fail_closed_for_fixed_version(self):
        doc = json.loads(json.dumps(self.document))
        doc["rules"][0], doc["rules"][1] = doc["rules"][1], doc["rules"][0]
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(self.write(doc))

    def test_missing_or_extra_structured_record_fails_closed(self):
        for mutate in ("missing", "extra"):
            with self.subTest(mutate=mutate):
                doc = json.loads(json.dumps(self.document))
                if mutate == "missing":
                    doc["required_structured_records"] = doc["required_structured_records"][:-1]
                else:
                    doc["required_structured_records"].append("UNVERSIONED_EXTRA")
                with self.assertRaises(PermanentRulesError):
                    load_permanent_rules(self.write(doc))

    def test_expected_sha256_binds_exact_bytes(self):
        digest = hashlib.sha256(CANONICAL.read_bytes()).hexdigest()
        rules = load_permanent_rules(CANONICAL, expected_sha256=digest.upper())
        self.assertEqual(rules.sha256, digest)
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(CANONICAL, expected_sha256="0" * 64)
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(CANONICAL, expected_sha256="not-a-digest")

    def test_malformed_rule_fields_fail_closed(self):
        cases = [
            ("id", 7),
            ("name", ""),
            ("law", "bad\ncontrol"),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                doc = json.loads(json.dumps(self.document))
                doc["rules"][0][field] = value
                with self.assertRaises(PermanentRulesError):
                    load_permanent_rules(self.write(doc))

    def test_require_rule_rejects_unknown_or_unvalidated_input(self):
        rules = load_permanent_rules(CANONICAL)
        with self.assertRaises(PermanentRulesError):
            require_rule(rules, "FB-PERM-999")
        with self.assertRaises(PermanentRulesError):
            require_rule({}, "FB-PERM-001")


if __name__ == "__main__":
    unittest.main()
