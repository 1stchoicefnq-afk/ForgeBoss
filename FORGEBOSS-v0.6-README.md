# ForgeBoss v0.6 — Autonomous Repair Loop

New session duration option: **UNTIL I PRESS STOP SAFELY**.

A failed live build cycle no longer automatically ends the session. ForgeBoss now:
1. captures the fresh acceptance/report evidence deterministically ($0);
2. classifies the failure (database/auth/backend/frontend/CI);
3. hashes the failure signature;
4. binds the feedback to the exact Git target SHA;
5. supplies that evidence to Repair Rat on the next bounded repair cycle;
6. retries only while time/budget remain and the failure is changing;
7. stops after the same failure signature repeats three times.

The saved zero-cost tournament re-test can seed the first repair cycle, so the known
`22P05`, PostgreSQL persistence and HTTP 500 evidence can be used rather than discarded.

Safety:
- API budget remains a hard session start/continuation gate.
- Maximum 12 build cycles per session.
- Stagnation stops repeated wasted attempts.
- Safe Stop prevents new cycles.
- Draft publication still requires the existing validation/review pipeline.
- Actual merge and deploy execution remain disabled in v0.6, regardless of UI permission toggles.
- After one green draft cycle, ForgeBoss stops rather than duplicate the same authoritative workload while merge is off.
