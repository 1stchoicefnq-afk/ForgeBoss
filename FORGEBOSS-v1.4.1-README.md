# ForgeBoss v1.4.1 — Funnel Self-test Sync

The v1.4 startup failure was caused by a stale inherited self-test, not by the funnel itself.

The actual debug funnel has intentionally used the tighter 24,000-character total cap since the focused-evidence changes, but `selftest-cost-funnel.py` was still asserting the old 42,000-character contract.

v1.4.1 updates that assertion to the real 24,000-character contract. Unified executor security from v1.4 is unchanged.
