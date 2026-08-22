# ForgeBoss v2.2 - Hardening Sweep

This is the first batch hardening release rather than a single-edge-case patch.

The v2.1.9 run exposed a context explosion: per-token exact locator objects multiplied the request
body until the budget preflight estimated a nonsensical $23.032 Luna call. Raising the budget would
have been the wrong fix.

Batch fixes:
- exact locators are now compact line tags: L<line>#<8hex>;
- each numbered source line already carries its locator, so the separate per-token locator catalog is gone;
- anchor_hint is no longer expanded into a huge schema enum;
- ForgeBoss verifies locator line+hash against the exact current line before materializing an edit;
- fresh model evidence contains failed runs only, with bounded failure/output tails;
- retry-trace diagnostics are bounded;
- paid request bodies have a 6 MiB hard ceiling;
- abnormal budget errors report body size and estimated input tokens, explicitly warning against simply raising budget;
- oversized context is classified as ForgeBoss infrastructure;
- patch cache schema v18.

Hardening matrix:
- patch/schema/locator adversarial cases
- context/cost inflation cases
- learning/foundation invariants
- smart-parallel conflict isolation
- multi-project profiles
- validated learning roundtrip

The included Python torture matrix passes locally. Windows PowerShell + Docker/PostgreSQL + real API
execution still require the next live ForgeBoss run; those cannot be truthfully simulated in this build environment.
