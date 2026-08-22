# ForgeBoss v2.0.4 - Contextual Anchors

Run FB-20260820-214626 reached the real PostgreSQL 40001 target but Luna returned an `old_text`
fragment that existed more than once in `src/auth/businessInvitations.js`. v2.0.3 correctly stopped
after one paid response rather than guessing or buying another format retry.

v2.0.4 makes repeated source fragments representable safely:
- every edit operation now carries exact `context_before` and `context_after`;
- if `old_text` is unique, ForgeBoss behaves exactly as before;
- if `old_text` repeats, ForgeBoss filters occurrences using immediately-adjacent exact context;
- exactly one contextual match is accepted;
- zero matches => PATCH_CONTEXT_MISMATCH;
- multiple contextual matches => AMBIGUOUS_EDIT_ANCHOR;
- ForgeBoss never chooses an occurrence heuristically;
- patch cache schema bumped to v5, so old responses without contextual anchors cannot replay.

This is deterministic transaction plumbing, not a relaxation of the write-scope/staleness protections.
All v2.0.3, v2.0.2, v2.0.1 and v2.0 control-plane changes remain included.
