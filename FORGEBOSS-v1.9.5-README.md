# ForgeBoss v1.9.5 - Validation Terminology Hotfix

Ordinary SiteBoss test failures are no longer mislabeled as FORGEBOSS FAULT.

Owner-facing Activity now maps:
- [FAIL] broad/known regression-family checks -> NEXT TARGET FOUND
- [FAIL] other tests -> VALIDATION HIT BACK
- controller/workspace/runtime exceptions -> FORGEBOSS FAULT

This preserves the v1.9.4 security hardening and all prior Target Ops terminology.
