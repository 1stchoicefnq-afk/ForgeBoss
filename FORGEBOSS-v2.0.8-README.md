# ForgeBoss v2.0.8 - Foundation Chain

Run FB-20260820-230242 achieved TWO real partial wins:
1. the Travis JSONB/NUL identity defect;
2. bounded serializable retry coverage for invitation issue/revoke.

Cycle 3 then failed before any API call because the retained foundation generated after cycle 2 was
based on cycle 2's local replay commit instead of the original frozen authoritative base.

v2.0.8 changes retained foundations from a single-step patch into a cumulative verified foundation:
- every new retained patch is `git diff <original-authoritative-base> <newest-verified-commit>`;
- prior foundation metadata carries the original authoritative base forward;
- ancestry is verified before the cumulative patch is written;
- the next cycle always checks out the frozen authoritative base and applies ONE cumulative patch;
- failure feedback carries the root authoritative base;
- foundation metadata schema is v2 and marks `cumulative=true`.

This allows partial wins to accumulate cycle 1 -> cycle 2 -> cycle 3 -> ... without base-SHA drift.
