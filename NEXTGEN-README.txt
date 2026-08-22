SITEBOSS BUILDER v0.6-dev-platform

SEPARATE DEV BRANCH
-------------------
This package does NOT modify or hook into the v0.4 one-click baseline.

NextGen remains:
- model calls = 0
- GitHub reads = 0
- GitHub writes = 0
- pushes = 0
- merges = 0
- deploys = 0

New in v0.6
-----------
- Provenance / exact-head inventory
- Impact analysis per issue
- Resumable local job queue
- NextGen-specific selftest
- Readiness score
- Merge-readiness report
- Richer local dashboard
- Explicit merge thresholds in NEXTGEN-POLICY.json

Run:
  SELFTEST-NEXTGEN.cmd
  RUN-NEXTGEN-DIAGNOSTICS.cmd

Outputs:
  state\nextgen\selftest.json
  state\nextgen\provenance.json
  state\nextgen\product-plan.json
  state\nextgen\issue-graph.json
  state\nextgen\impact.json
  state\nextgen\acceptance-contracts.json
  state\nextgen\security.json
  state\nextgen\job-queue.json
  state\nextgen\readiness.json
  state\nextgen\merge-readiness.json
  state\nextgen\dashboard.html

The merge-readiness report does not merge anything.
It only says whether this branch is mature enough to be considered for integration after v0.4 is proven.
