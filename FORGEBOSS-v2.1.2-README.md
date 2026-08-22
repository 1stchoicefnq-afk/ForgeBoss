# ForgeBoss v2.1.2 - Anchor Intent + Fast Candidate Guard

Run FB-20260821-112644 showed that v2.1.1 removed stale text anchors, but the model selected the wrong
CURRENT line range and inserted a second `const identity`, causing a SyntaxError.

Changes:
- edit operations require `anchor_hint`, an exact distinctive token that must exist inside the selected current lines;
- existing-file operations are bounded to at most 8 lines;
- JavaScript candidates run `node --check` immediately after patch application and before expensive acceptance;
- syntax-invalid candidates are reset and become PATCH_CANDIDATE_INVALID;
- model source context is no longer duplicated as both raw and numbered full content: only metadata + numbered current source is sent;
- patch cache schema v10.

Validated learning remains enabled, and invalid candidates cannot be promoted.
