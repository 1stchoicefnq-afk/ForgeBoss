# ForgeBoss v2.1.4 - Symbol Anchors

FB-20260821-221919 proved Repair Rat's first zero-API learned repair: cycle 1 fixed the known
Travis 22P05/NUL defect locally and retained it.

Cycle 2 then chose the correct current source symbol `withSerializableRetry` but guessed line 1.
v2.1.4 makes the symbol authoritative and line numbers secondary:
- unique current-source symbol -> ForgeBoss finds the actual line locally;
- repeated symbol -> optional line_start is only a tie-breaker and must match a real occurrence;
- exact source bytes/hash are still materialized locally;
- no fuzzy matching or guessing;
- ambiguous symbols become AMBIGUOUS_SYMBOL_ANCHOR;
- zero-cost learned 22P05 repair remains enabled;
- patch cache schema v12.
