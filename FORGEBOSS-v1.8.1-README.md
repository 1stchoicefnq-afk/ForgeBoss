# ForgeBoss v1.8.1 — Startup Stall Watchdog

Observed v1.8 symptom: all safety gates passed, but no build-cycle activity appeared for over an hour and
LIVE_WORKLOAD stayed stuck until the owner pressed Stop Safely.

This hotfix:
- logs every startup phase after safety gates;
- makes executor readiness non-fatal;
- bounds/handles bootstrap evidence and focused-packet preparation failures;
- continues with a fresh bounded cycle when reusable evidence is unavailable;
- wraps the worker thread so any unhandled timeout/crash becomes INFRA_ERROR with running=false;
- updates stale UI labels so Strong=Sol and Balanced=Terra.

These recovery paths do not spend model money.
