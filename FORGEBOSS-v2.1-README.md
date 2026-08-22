# ForgeBoss v2.1 - Project Profiles + Validated Learning

ForgeBoss core now begins separating itself from SiteBoss-specific configuration.

Profiles included:
- SiteBoss
- SiteBoss Connect
- Website Scroll Animation
- reusable new-project template

New foundations:
- generic project profile loader;
- project-specific scope and acceptance definitions;
- conflict-aware smart-parallel batching up to each profile's worker cap;
- durable SQLite learning store for VERIFIED lessons;
- failure-family fingerprints and reusable repair patterns;
- worker/model success, cost and latency statistics for future routing;
- daemon capability discovery for project profiles, smart parallelism and validated learning.

ForgeBoss does not store private model chain-of-thought. It learns from validated engineering
artefacts: failure fingerprints, repair patterns, changed files, test receipts, outcomes, cost,
latency and owner-approved rules. Only validated results may be promoted as reusable lessons.

Still to migrate:
- all third-party agents under forgebossd;
- the main repair loop into true multi-worktree parallel dispatch;
- concrete repos/test commands for SiteBoss Connect and Scroll Animation.
