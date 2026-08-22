# ForgeBoss v1.7.2 — One Call + Deterministic Partial Win

The prior run showed two Luna calls in one Repair Rat invocation. The reason was that the first controller cycle was
not yet a "focused" cycle, so the v1.7.1 one-call guard did not apply.

v1.7.2 fixes that at three levels:
- Repair Rat stops after ANY paid code-producing attempt unless the candidate already passed everything.
- The controller repair adapter always launches Repair Rat with MaxAttempts=1.
- The legacy SiteBoss Builder path also launches Repair Rat with MaxAttempts=1.

Partial-win proof no longer depends on focused-packet metadata. If npm/unit/migrate plus the repeated isolated
business-invitations, production-HTTP and Travis-intake gates are all green while only broad PostgreSQL suite runs
still fail, ForgeBoss treats the code as a verified partial win, commits it locally, teaches Repair Rat, and moves
the next controller cycle to the remaining defect family.

This exactly matches the demonstrated conversation.js repair: isolated regression gates green, 22P05 gone, broad
suite still exposing 40001 serialization conflicts.
