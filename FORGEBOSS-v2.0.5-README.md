# ForgeBoss v2.0.5 - Budget Reserve Fix

Run FB-20260820-215040 ended at NEXT_TARGET_FOUND after one $0.0230 cycle even though
$0.177 remained from the owner's $0.20 budget.

Root cause:
the dashboard controller had an old hardcoded rule refusing every second repair cycle when
remaining budget was below $0.20. That duplicated Repair Rat's real model-aware budget preflight
and made a $0.20 RUN UNTIL STOPPED session incapable of entering cycle 2.

Fix:
- remove the blunt $0.20 second-cycle reserve;
- keep only a $0.03 controller floor;
- let Repair Rat's Assert-EstimatedCallFitsBudget remain the authoritative paid-call guard;
- if the tiny controller floor is reached, final stage becomes BUDGET_REACHED rather than being
  misleadingly left at NEXT_TARGET_FOUND.

The v2.0.4 contextual-anchor transaction format remains unchanged and should now actually get
exercised on the PostgreSQL 40001 cycle.
