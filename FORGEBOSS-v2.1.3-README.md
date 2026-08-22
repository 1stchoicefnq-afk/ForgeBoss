# ForgeBoss v2.1.3 - Local Learned First

Run FB-20260821-115249 showed v2.1.2 correctly rejected a bad anchor, but Luna supplied prose as
`anchor_hint` instead of an exact source token.

Changes:
- `anchor_hint` is dynamically schema-constrained to identifier tokens extracted from CURRENT writable source.
- arbitrary prose can no longer satisfy the anchor-hint contract.
- the repeatedly verified Travis SQLSTATE 22P05/NUL repair is promoted into a deterministic local Repair Rat lesson.
- the lesson runs only when matching failure evidence exists and the exact pre-fix source line exists exactly once.
- normal syntax and full acceptance still validate it; a bad local replay is reset before escalation.
- verified local partial/full results flow through the existing retained-foundation machinery.
- dashboard activity can show `REPAIR RAT KNEW THIS` for a zero-API known repair.
- patch cache schema is v11.

This is the first shipped repair that demonstrates the intended learning economics: a repeatedly proven defect is attempted locally before API use.
