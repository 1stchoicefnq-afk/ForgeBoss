# ForgeBoss v1.9.3 - Activity Terminology Hotfix

The desktop Activity feed still contained an old fallback:
    ForgeBoss hit a problem.

That bypassed the v1.9.2 canonical Target Ops terminology.

v1.9.3 removes that phrase from the owner-facing activity translator and maps failures to:
- BUDGET BLOCKED - $0 SPENT
- MISSION BLOCKED
- PATCH REJECTED
- FORGEBOSS FAULT

It also preserves TARGET ACQUIRED, ROOT CAUSE FOUND, REPAIR IN PROGRESS,
PARTIAL WIN and NEXT TARGET in activity cards.

Raw diagnostic text remains available in the detail field.
