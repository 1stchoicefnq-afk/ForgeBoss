# ForgeBoss v2.0.3 - Patch Schema Guard

Run FB-20260820-113702 proved the v2.0.1 spend guard works: after a successful partial win,
cycle 2 reached the PostgreSQL 40001 target and stopped after ONE malformed paid patch instead of
burning repeated format-repair calls.

v2.0.3 moves that malformed delete failure earlier into the structured-output contract:
- edit operations require non-empty old_text in the JSON schema;
- create operations require empty old_text and non-empty new_text;
- delete remains supported, but can never use an empty anchor;
- local normalization enforces the same invariants for every provider;
- patch cache schema bumped to v4 so the old malformed response cannot replay;
- prompt explicitly tells the model how to delete bounded code safely.

No safety relaxation was added: ForgeBoss still refuses to guess an empty or ambiguous edit anchor.
All v2.0.2 elapsed-timer, v2.0.1 patch-recovery, and v2.0 control-plane changes remain included.
