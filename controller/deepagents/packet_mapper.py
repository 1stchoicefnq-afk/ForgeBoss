"""Map an untrusted SiteBoss packet dict onto an ImmutablePacket.

Everything in the incoming dict is treated as attacker-influenced: budgets are
clamped to the controller ceilings rather than trusted, and scope entries are
validated by ImmutablePacket.__post_init__ so a malformed packet fails at
construction instead of at first use.
"""

from siteboss_policy import (
    ImmutablePacket,
    SecurityDenial,
    MAX_COMMANDS_CEILING,
    MAX_FILE_MODIFICATIONS_CEILING,
    MAX_SUBAGENTS_CEILING,
    MAX_MODEL_CALLS_CEILING,
    clamp_budget,
)


def _scope(*candidates):
    for c in candidates:
        if c:
            if isinstance(c, str):
                raise SecurityDenial("scope must be a list of paths")
            return tuple(c)
    return ()


def from_siteboss_packet(p):
    if not isinstance(p, dict):
        raise SecurityDenial("packet must be a mapping")
    head = p.get("expected_head_revision") or p.get("expected_head") or p.get("candidate_parent_sha")
    if not head:
        raise SecurityDenial("packet missing expected head revision")
    return ImmutablePacket(
        p["packet_id"],
        head,
        p.get("role", "builder"),
        _scope(p.get("context_files"), p.get("read_scope")),
        _scope(p.get("allowed_files"), p.get("write_scope")),
        _scope(p.get("required_tests")),
        _scope(p.get("review_exclusions")),
        clamp_budget(p.get("max_commands", MAX_COMMANDS_CEILING), MAX_COMMANDS_CEILING, MAX_COMMANDS_CEILING),
        clamp_budget(
            p.get("max_file_modifications", MAX_FILE_MODIFICATIONS_CEILING),
            MAX_FILE_MODIFICATIONS_CEILING,
            MAX_FILE_MODIFICATIONS_CEILING,
        ),
        clamp_budget(p.get("max_subagents", MAX_SUBAGENTS_CEILING), MAX_SUBAGENTS_CEILING, MAX_SUBAGENTS_CEILING),
        clamp_budget(p.get("max_model_calls", MAX_MODEL_CALLS_CEILING), MAX_MODEL_CALLS_CEILING, MAX_MODEL_CALLS_CEILING),
    )
