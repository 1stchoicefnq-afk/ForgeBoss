from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from forgeboss.policy.permanent_rules import (
    EXPECTED_RULESET_ID,
    EXPECTED_RULESET_VERSION,
    PINNED_CANONICAL_SHA256,
    PermanentRulesError,
    load_default_rules,
    load_permanent_rules,
    require_rule,
)

ROOT = Path(__file__).resolve().parents[2]
CANONICAL = ROOT / "docs" / "bootstrap" / "PERMANENT_RULES.json"


class PermanentRulesTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(CANONICAL.read_text(encoding="utf-8"))

    def write(self, document=None, *, raw=None, newline=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "rules.json"
        if raw is not None:
            path.write_bytes(raw)
        else:
            text = json.dumps(
                self.document if document is None else document,
                indent=2,
            )
            if newline is not None:
                text = text.replace("\n", newline)
            path.write_text(text, encoding="utf-8", newline="")
        return path

    def write_default_repo(self, document):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        target = root / "docs" / "bootstrap" / "PERMANENT_RULES.json"
        target.parent.mkdir(parents=True)
        target.write_text(json.dumps(document, indent=2), encoding="utf-8")
        return root

    def test_canonical_rules_load_and_are_read_only(self):
        rules = load_default_rules(ROOT)
        self.assertEqual(rules.ruleset_id, EXPECTED_RULESET_ID)
        self.assertEqual(rules.ruleset_version, EXPECTED_RULESET_VERSION)
        self.assertEqual(len(rules.rules), 48)
        self.assertEqual(len(rules.required_structured_records), 20)
        self.assertEqual(rules.sha256, hashlib.sha256(CANONICAL.read_bytes()).hexdigest())
        self.assertEqual(rules.canonical_sha256, PINNED_CANONICAL_SHA256)
        self.assertIn("Chief of Staff", require_rule(rules, "FB-PERM-006")["law"])
        self.assertIn("cryptographic hash at minimum", require_rule(rules, "FB-PERM-035")["law"])
        self.assertIn("COMPATIBILITY_MATRIX", rules.required_structured_records)
        with self.assertRaises(TypeError):
            rules.rules["FB-PERM-001"]["law"] = "override"
        with self.assertRaises(TypeError):
            rules.rules["FB-PERM-999"] = {}

    def test_missing_file_fails_closed(self):
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(ROOT / "does-not-exist-rules.json")

    def test_invalid_json_duplicate_keys_and_nonstandard_constants_fail_closed(self):
        for raw in (
            b"{not-json",
            b'{"schema":1,"schema":1}',
            b'{"schema":NaN}',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(PermanentRulesError):
                    load_permanent_rules(self.write(raw=raw))

    def test_v1_0_contract_is_rejected_by_v1_1_loader(self):
        doc = json.loads(json.dumps(self.document))
        doc["ruleset_version"] = "1.0.0"
        doc["rules"] = doc["rules"][:25]
        doc["required_structured_records"] = doc["required_structured_records"][:15]
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(self.write(doc))

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

    def test_unknown_top_level_or_rule_fields_fail_closed(self):
        doc = json.loads(json.dumps(self.document))
        doc["override"] = True
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(self.write(doc))

        doc = json.loads(json.dumps(self.document))
        doc["rules"][0]["authority"] = "WRITE"
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

    def test_default_loader_rejects_changed_law_even_when_structure_is_valid(self):
        doc = json.loads(json.dumps(self.document))
        doc["rules"][0]["law"] = "ForgeBoss may ignore this rule."
        root = self.write_default_repo(doc)
        with self.assertRaises(PermanentRulesError):
            load_default_rules(root)

    def test_canonical_identity_tolerates_json_formatting_and_line_endings(self):
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)):
                path = self.write(self.document, newline=newline)
                rules = load_permanent_rules(
                    path,
                    expected_canonical_sha256=PINNED_CANONICAL_SHA256,
                )
                self.assertEqual(rules.canonical_sha256, PINNED_CANONICAL_SHA256)

    def test_expected_canonical_sha256_binds_semantic_content(self):
        rules = load_permanent_rules(
            CANONICAL,
            expected_canonical_sha256=PINNED_CANONICAL_SHA256.upper(),
        )
        self.assertEqual(rules.canonical_sha256, PINNED_CANONICAL_SHA256)
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(
                CANONICAL,
                expected_canonical_sha256="0" * 64,
            )
        with self.assertRaises(PermanentRulesError):
            load_permanent_rules(
                CANONICAL,
                expected_canonical_sha256="not-a-digest",
            )

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
        rules = load_default_rules(ROOT)
        with self.assertRaises(PermanentRulesError):
            require_rule(rules, "FB-PERM-999")
        with self.assertRaises(PermanentRulesError):
            require_rule({}, "FB-PERM-001")


if __name__ == "__main__":
    unittest.main()