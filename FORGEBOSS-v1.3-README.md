# ForgeBoss v1.3 — Security Foundation + Desktop Load Hotfix

Fixes the reviewed localhost RPC/CSRF issue with a per-process token, Host/Origin checks and JSON-only POSTs.
Enforces a real $10 server-side session ceiling, caches executor probes, uses an atomic exclusive-create
controller lock, derives GitHub report PRs from authoritative state instead of hard-coding #168, adds explicit
publication gating, clean request errors, VBS/CMD extraction guards and removes shipped .pyc files.

The v1.2 black desktop window is addressed by loading pro.html through a canonical file:// URI via Path.as_uri().
The rematerialize/reset/clean/NUL-safe Repair-PR pristine gate was already present in this branch and is preserved.
