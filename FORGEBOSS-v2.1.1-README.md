# ForgeBoss v2.1.1 - Exact Source Anchors + Validated Learning

Run FB-20260821-064233 proved the cumulative foundation handoff works, but cycle 2 paid for a patch
whose text anchor no longer existed in the replayed current `businessInvitations.js`.

v2.1.1 removes model-authored source anchors from the transaction contract:
- the model selects `path`, 1-based `line_start`, `line_end`, mode and new_text from numbered CURRENT source;
- ForgeBoss materializes old_text, adjacent context and exact SHA256 directly from the replayed workspace;
- historical/debug-funnel snippets can diagnose the defect but cannot supply an edit anchor;
- stale text can therefore no longer become a paid PATCH_PRECONDITION_FAILED merely because it was quoted from old context;
- no fuzzy matching or guessing was added;
- patch cache schema is v9.

Validated learning is also wired into the real run loop:
- every full green or verified partial win may be promoted to `state/learning/forgeboss-learning.db`;
- lessons contain failure evidence, repair pattern/diff, changed files and validation outcome;
- private model chain-of-thought is never stored;
- only validation-approved results are reusable.

The v2.1 multi-project profiles and smart-parallel scheduler foundation remain included.
