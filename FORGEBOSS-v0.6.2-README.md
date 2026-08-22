# ForgeBoss v0.6.2 — Overall Run Reports + GitHub Findings

Every autonomous session now finishes by generating one full local report with:
- session budget/spend and stop reason;
- every build cycle;
- specialists/provider/model when recorded;
- files changed;
- acceptance/test results and failure tails;
- retained Git diff/code changes;
- fatal failures and safety guarantees.

Dashboard: **Last Run Report → VIEW / COPY ALL**.

ForgeBoss also attempts to post a SANITISED findings summary as a comment on root PR #168 after each run. This is a GitHub write, but it does not push failed candidate code, merge, or deploy. If GitHub publication fails, the local full report remains available and can be manually retried from the dashboard.

Green reviewed code continues to use the existing draft-child-PR publication path.

v0.6.2 also fixes misleading unresolved completion state (`BUDGET_REACHED` instead of `COMPLETE`) and adds a conservative $0.70 reserve before starting another strong-model repair cycle, preventing the obvious v0.6.1 second-cycle overspend pattern. Exact API cost cannot be known before a variable-length model response, so the displayed max remains a spending control/guard rather than a mathematically guaranteed billing ceiling.
