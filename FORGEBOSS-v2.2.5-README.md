# ForgeBoss v2.2.5 - Locator + Spend Guard
FB-20260822-075411 exposed two ForgeBoss defects together. Locator tags were generated from a regex-split
source representation but verified against ReadAllLines, and locator mismatch was absent from the controller's
terminal paid-patch rejection tuple. The same deterministic failure was therefore bought repeatedly until
$0.1854 of the $0.20 session was consumed.

v2.2.5 uses one LF-normalized canonical line model for both locator generation and verification, reports
expected/actual hashes on mismatch, makes locator invalid/mismatch terminal after one paid response, and adds
a generic repeated-fatal fingerprint spend breaker. Cache schema v22. All prior v2.2.x hardening remains.
