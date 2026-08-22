# ForgeBoss v1.1 — Productive Repair Contract

The v1.0 run showed Luna repeatedly safe-refusing because it believed it needed its
own disposable workspace and execution tools. That was a role-contract bug: ForgeBoss
already creates the exact-head workspace, applies returned files, and runs Docker/PostgreSQL
acceptance itself.

v1.1 explicitly tells Repair Rat's model:
- the local workspace already exists;
- ForgeBoss owns patch application and testing;
- lack of direct shell/git/Docker access is NOT a valid refusal reason;
- safe=false is reserved for genuinely missing source/evidence or governance conflicts;
- a refusal must name the exact missing fact/file/error.

The debug funnel now prioritizes the evidence surfaced by the real run
(`receiveAnswer`, `saveIntakeSession`, `22P05`, NUL, production HTTP) and can discover
files by local git grep, including `src/travis/conversation.js`. Focused context is
tightened to at most 4 files / 24,000 source characters.

The $0 evidence collector now proves the retained workspace exists and includes code
excerpts around relevant matches rather than only a list of grep hits.
