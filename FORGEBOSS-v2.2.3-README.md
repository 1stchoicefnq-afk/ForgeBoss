# ForgeBoss v2.2.3 - Evidence Scope Expansion

FB-20260822-072506 was a legitimate safe refusal: current evidence pointed at a PostgreSQL
quote-safeguard transaction path, but the implementation/call-site was omitted from the focused
source packet. postgres.js already had the safe whole-transaction retry boundary, so widening the
generic transaction primitive would have violated replay safety.

v2.2.3 fixes the missing-evidence class without weakening write authority:
- authoritative failed stack frames add referenced src files to read context;
- exact failing test files are inspected for local src imports;
- one bounded dependency hop is followed from those files;
- a small bounded semantic grep can add source files matching meaningful failing-test terms;
- expansion is capped at 8 files / 140k source characters;
- source context may expand automatically;
- write permission is restored ONLY when the discovered file was already present in the controller's
  original write allowlist before the focused packet narrowed it;
- no path outside controller-approved scope becomes writable;
- every context/write restoration is logged and included in repair-context hashing;
- patch cache schema v20.

This should let the next paid cycle see the missing quote/application transaction call-site instead
of paying for a safe refusal caused purely by an over-narrow focused packet.
