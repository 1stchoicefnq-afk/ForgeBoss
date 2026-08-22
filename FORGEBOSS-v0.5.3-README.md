# ForgeBoss v0.5.3 — Clickable Activity Drill-down

Candidate re-test events are now clickable.

Clicking `Candidate re-test finished` opens a technical evidence window containing:
- the saved re-test JSON;
- each retained worker's Git diff (actual code changes);
- each worker's validation/test evidence.

The window has COPY ALL and SAVE TXT buttons so the owner can paste the exact technical result into ChatGPT.

This view is read-only: no AI calls and no GitHub writes.
