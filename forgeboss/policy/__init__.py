"""ForgeBoss permanent policy contracts."""

from .permanent_rules import (
    PermanentRulesError,
    PermanentRuleset,
    load_default_rules,
    load_permanent_rules,
    require_rule,
)

__all__ = [
    "PermanentRulesError",
    "PermanentRuleset",
    "load_default_rules",
    "load_permanent_rules",
    "require_rule",
]
