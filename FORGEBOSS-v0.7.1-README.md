# ForgeBoss v0.7.1 — Startup Self-test Path Hotfix

v0.7 referenced a removed startup self-test:
`forgeboss/tests/selftest.js`

That caused the exact `Cannot find module ... forgeboss\tests\selftest` error before any paid repair work.

v0.7.1 runs only shipped gates, including `controller/selftest-agency-core-team.js`, and adds a package-path preflight.
