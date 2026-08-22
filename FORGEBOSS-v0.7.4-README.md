# ForgeBoss v0.7.4 — Self-test Contract Hotfix

The v0.7.3 startup failure was a stale self-test, not a runtime cost-funnel failure.

v0.7.3 deliberately reduced the focused OpenAI output cap from 6,000 to 3,000 tokens,
but `selftest-cost-funnel.py` still asserted the old 6,000-token contract. The safety
gate therefore stopped before any SiteBoss work or paid model call.

v0.7.4 updates the self-test to the real 3,000-token focused contract. Both the
cost-funnel self-test and v0.7.3 safety self-test pass in this package.
