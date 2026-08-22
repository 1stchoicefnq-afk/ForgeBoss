# ForgeBoss v1.7 — Accumulating Repairs

A focused sub-fix is no longer discarded just because the whole PostgreSQL suite still has another defect.

If the primary failed validation step becomes green, Repair Rat commits that sub-fix locally, records it as
`partial_proven`, stores the patch against the authoritative base, and stops the current paid attempt instead of
paying Luna to rediscover the same repair.

Repair Rat's playbook can replay an exact-compatible partial-proven fix locally as a clean baseline, then continue
onto the next failure family. Full-suite acceptance remains the final completion gate.
