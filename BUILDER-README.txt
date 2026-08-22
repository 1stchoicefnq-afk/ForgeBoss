SITEBOSS BUILDER v0.4-oneclick

NORMAL USE
----------
Double-click START-SITEBOSS.cmd

It runs:
CHECK -> BREAKER -> DIAGNOSE -> FULL BUILDER

If CHECK, BREAKER or DIAGNOSE fails, FULL BUILDER does not run.

CHECK/BREAKER/DIAGNOSE are local/no-model stages.
FULL BUILDER may make paid API calls according to BUILDER-POLICY.json.

The launcher writes state\builder\oneclick-<timestamp>.json.

Safety:
automatic merge = OFF
deployment = OFF
force push = OFF
