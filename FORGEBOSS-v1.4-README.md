# ForgeBoss v1.4 — Unified Executor Security

Fixes the Windows Script Host 800A0408 launcher error by writing START-FORGEBOSS.vbs as strict ASCII with no UTF-8 BOM.

All live third-party executors now require a one-time ForgeBoss lease bound to executor identity, packet hash,
workspace, expiry and allowed writes. The common postflight rejects out-of-scope changes, symlink changes,
Git remotes and packet mutation.

mini-SWE keeps Docker --network none and now passes unified pre/post policy.
OpenHands has TerminalTool removed and runs editor-only with unified pre/post policy.
OpenCode is quarantined by default because its host-shell execution is not OS-isolated; the league now routes
it through the ForgeBoss runner instead of invoking opencode directly.
Tournament and league issue executor leases themselves, preventing direct runner bypass.

Security chooses BLOCKED over pretending an executor is safe when isolation is not proven.
