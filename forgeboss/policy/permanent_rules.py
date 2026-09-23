from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping


class PermanentRulesError(RuntimeError):
    """Raised when permanent ForgeBoss governance is missing, stale, or invalid."""


EXPECTED_SCHEMA = 1
EXPECTED_RULESET_ID = "FORGEBOSS_PERMANENT_PRODUCT_RULES"
EXPECTED_RULESET_VERSION = "1.1.0"
EXPECTED_STATUS = "PERMANENT_PRODUCT_CONTRACT"
EXPECTED_SCOPES = ("forgeboss", "projects_built_by_forgeboss")
EXPECTED_PRECEDENCE = (
    "runtime_authority",
    "permanent_rules",
    "project_authority",
    "project_decisions",
    "worker_contracts",
    "model_or_tool_output",
)
EXPECTED_RULE_IDS = tuple(f"FB-PERM-{i:03d}" for i in range(1, 49))
EXPECTED_STRUCTURED_RECORDS = (
    "PROJECT_IDEA",
    "REQUIREMENTS",
    "UPSTREAM_REUSE_REVIEW",
    "ARCHITECTURE",
    "AUTHORITY_MODEL",
    "SAFETY_RULES",
    "TEST_MATRIX",
    "DECISIONS",
    "COMPONENT_REGISTRY",
    "WORKER_REGISTRY",
    "ACTIVE_RUNS",
    "EVIDENCE_MANIFEST",
    "KNOWN_ISSUES",
    "STATUS",
    "RELEASE_PROOF",
    "DATA_POLICY",
    "NETWORK_POLICY",
    "BACKUP_MANIFEST",
    "AUDIT_TRAIL",
    "COMPATIBILITY_MATRIX",
)
EXPECTED_TOP_LEVEL_KEYS = frozenset({
    "schema",
    "ruleset_id",
    "ruleset_version",
    "status",
    "applies_to",
    "precedence",
    "rules",
    "required_structured_records",
    "note",
})
EXPECTED_RULE_KEYS = frozenset({"id", "name", "law"})
PINNED_CANONICAL_SHA256 = "ca18162a9a284d01ee3fe6c30839912f34de61c2ef2cc408bc8eec5e2ee0eebd"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class PermanentRuleset:
    schema: int
    ruleset_id: str
    ruleset_version: str
    status: str
    applies_to: tuple[str, ...]
    precedence: tuple[str, ...]
    rules: Mapping[str, Mapping[str, object]]
    required_structured_records: tuple[str, ...]
    note: str
    sha256: str
    canonical_sha256: str
    source_path: str


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise PermanentRulesError(f"{label} must be a string")
    value = value.strip()
    if not value:
        raise PermanentRulesError(f"{label} is required")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise PermanentRulesError(f"{label} contains control characters")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PermanentRulesError(f"{label} must be a JSON array")
    out = tuple(_text(item, label) for item in value)
    if len(set(out)) != len(out):
        raise PermanentRulesError(f"{label} contains duplicate values")
    return out


def _expected_digest(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PermanentRulesError("expected_canonical_sha256 must be a string")
    value = value.strip().lower()
    if not _SHA256.fullmatch(value):
        raise PermanentRulesError(
            "expected_canonical_sha256 must be 64 hexadecimal characters"
        )
    return value


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PermanentRulesError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str):
    raise PermanentRulesError(f"non-standard JSON constant is forbidden: {value}")


def _canonical_bytes(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def load_permanent_rules(
    path: str | Path,
    *,
    expected_canonical_sha256: str | None = None,
) -> PermanentRuleset:
    source = Path(path)
    if not source.is_file():
        raise PermanentRulesError(f"permanent rules file is missing: {source}")

    try:
        raw = source.read_bytes()
    except OSError as ex:
        raise PermanentRulesError(f"cannot read permanent rules: {source}") from ex

    raw_digest = hashlib.sha256(raw).hexdigest()

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except PermanentRulesError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as ex:
        raise PermanentRulesError("permanent rules are not valid UTF-8 JSON") from ex

    if not isinstance(document, dict):
        raise PermanentRulesError("permanent rules root must be an object")

    actual_top_keys = frozenset(document)
    if actual_top_keys != EXPECTED_TOP_LEVEL_KEYS:
        missing = sorted(EXPECTED_TOP_LEVEL_KEYS - actual_top_keys)
        extra = sorted(actual_top_keys - EXPECTED_TOP_LEVEL_KEYS)
        raise PermanentRulesError(
            f"permanent rules top-level contract mismatch: missing={missing!r} extra={extra!r}"
        )

    canonical_digest = hashlib.sha256(_canonical_bytes(document)).hexdigest()
    expected = _expected_digest(expected_canonical_sha256)
    if expected is not None and canonical_digest != expected:
        raise PermanentRulesError(
            "permanent rules canonical SHA-256 mismatch: "
            f"expected {expected}, got {canonical_digest}"
        )

    if type(document.get("schema")) is not int or document["schema"] != EXPECTED_SCHEMA:
        raise PermanentRulesError(
            f"unsupported permanent rules schema: {document.get('schema')!r}"
        )

    ruleset_id = _text(document.get("ruleset_id"), "ruleset_id")
    version = _text(document.get("ruleset_version"), "ruleset_version")
    status = _text(document.get("status"), "status")
    note = _text(document.get("note"), "note")
    if ruleset_id != EXPECTED_RULESET_ID:
        raise PermanentRulesError(f"unexpected ruleset_id: {ruleset_id}")
    if version != EXPECTED_RULESET_VERSION:
        raise PermanentRulesError(f"unsupported ruleset_version: {version}")
    if status != EXPECTED_STATUS:
        raise PermanentRulesError(f"unexpected ruleset status: {status}")

    scopes = _string_tuple(document.get("applies_to"), "applies_to")
    if scopes != EXPECTED_SCOPES:
        raise PermanentRulesError(f"unexpected applies_to contract: {scopes!r}")

    precedence = _string_tuple(document.get("precedence"), "precedence")
    if precedence != EXPECTED_PRECEDENCE:
        raise PermanentRulesError(f"unexpected governance precedence: {precedence!r}")

    raw_rules = document.get("rules")
    if not isinstance(raw_rules, list):
        raise PermanentRulesError("rules must be a JSON array")

    indexed: dict[str, Mapping[str, object]] = {}
    for entry in raw_rules:
        if not isinstance(entry, dict):
            raise PermanentRulesError("each rule must be an object")
        actual_rule_keys = frozenset(entry)
        if actual_rule_keys != EXPECTED_RULE_KEYS:
            missing = sorted(EXPECTED_RULE_KEYS - actual_rule_keys)
            extra = sorted(actual_rule_keys - EXPECTED_RULE_KEYS)
            raise PermanentRulesError(
                f"permanent rule field mismatch: missing={missing!r} extra={extra!r}"
            )
        rule_id = _text(entry.get("id"), "rule.id")
        name = _text(entry.get("name"), f"{rule_id}.name")
        law = _text(entry.get("law"), f"{rule_id}.law")
        if rule_id in indexed:
            raise PermanentRulesError(f"duplicate permanent rule id: {rule_id}")
        indexed[rule_id] = MappingProxyType({"id": rule_id, "name": name, "law": law})

    actual_ids = tuple(indexed)
    if actual_ids != EXPECTED_RULE_IDS:
        missing = [rule_id for rule_id in EXPECTED_RULE_IDS if rule_id not in indexed]
        extra = [rule_id for rule_id in indexed if rule_id not in EXPECTED_RULE_IDS]
        raise PermanentRulesError(
            f"permanent rule contract mismatch: missing={missing!r} "
            f"extra={extra!r} order={actual_ids!r}"
        )

    records = _string_tuple(
        document.get("required_structured_records"),
        "required_structured_records",
    )
    if records != EXPECTED_STRUCTURED_RECORDS:
        missing = [name for name in EXPECTED_STRUCTURED_RECORDS if name not in records]
        extra = [name for name in records if name not in EXPECTED_STRUCTURED_RECORDS]
        raise PermanentRulesError(
            f"structured record contract mismatch: missing={missing!r} extra={extra!r}"
        )

    return PermanentRuleset(
        schema=EXPECTED_SCHEMA,
        ruleset_id=ruleset_id,
        ruleset_version=version,
        status=status,
        applies_to=scopes,
        precedence=precedence,
        rules=MappingProxyType(dict(indexed)),
        required_structured_records=records,
        note=note,
        sha256=raw_digest,
        canonical_sha256=canonical_digest,
        source_path=str(source.resolve()),
    )


def load_default_rules(repo_root: str | Path) -> PermanentRuleset:
    root = Path(repo_root)
    return load_permanent_rules(
        root / "docs" / "bootstrap" / "PERMANENT_RULES.json",
        expected_canonical_sha256=PINNED_CANONICAL_SHA256,
    )


def require_rule(ruleset: PermanentRuleset, rule_id: str) -> Mapping[str, object]:
    if not isinstance(ruleset, PermanentRuleset):
        raise PermanentRulesError("ruleset must be a validated PermanentRuleset")
    clean = _text(rule_id, "rule_id")
    try:
        return ruleset.rules[clean]
    except KeyError as ex:
        raise PermanentRulesError(
            f"required permanent rule is unavailable: {clean}"
        ) from ex