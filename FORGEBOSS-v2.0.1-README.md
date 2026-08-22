# ForgeBoss v2.0.1 - Patch Contract Recovery

This release responds to run FB-20260820-103800, where ForgeBoss successfully accumulated into cycle 2 but then
spent three additional paid calls on malformed/ambiguous patch-transaction outputs.

Changes:
- The model no longer supplies transaction_id, base_sha or expected_file_hash. ForgeBoss deterministically adds them.
- Patch paths are constrained by the strict response schema to the actual write allowlist.
- If a path is missing and there is exactly one writable file, ForgeBoss can recover it locally at $0.
- File hashes are always generated from the exact local file by ForgeBoss, never trusted from model output.
- Patch cache schema is bumped so malformed old transaction caches cannot replay.
- Unique-anchor requirements are explicit in the prompt.
- Any remaining paid PATCH_CONTRACT_INVALID / PATCH_PRECONDITION_FAILED / AMBIGUOUS_EDIT_ANCHOR /
  STALE_FILE / PATH_OUTSIDE_SCOPE response becomes PATCH REJECTED and stops immediately. No paid format-retry loop.
- Reports no longer mislabel these model transaction-contract failures as ForgeBoss infrastructure faults.
- The v2.0 forgebossd control-plane foundation remains included.

The safety rule remains: ForgeBoss never guesses which duplicate source occurrence an ambiguous edit intended.
