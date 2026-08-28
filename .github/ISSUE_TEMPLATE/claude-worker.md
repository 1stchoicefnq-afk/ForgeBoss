---
name: Claude isolated worker
aabout: Run one Claude worker in a non-overlapping file lane
title: "CLAUDE WORKER — [LANE] — [TASK]"
labels: ""
assignees: ""
---

@claude perform the task below as an isolated ForgeBoss worker.

LANE: REPLACE_WITH_ONE_LANE

ALLOWED PATHS:
- REPLACE_WITH_EXACT_PATH/**

FORBIDDEN PATHS:
- .github/workflows/**
- CLAUDE.md
- every path not listed under ALLOWED PATHS

SHARED FILES:
- NONE

TASK:
Describe the exact audit/fix objective here.

PARALLEL WORKER RULES:
- Read root CLAUDE.md before editing.
- Treat ALLOWED PATHS as an exclusive write allowlist.
- You may read outside the lane for context but must not write outside it.
- Do not make drive-by cleanup or unrelated refactors.
- If a required fix crosses into another lane, leave that file unchanged and report the finding with severity and intended owner lane.
- Do not merge, rebase, cherry-pick, or copy changes from another active Claude branch.
- Do not modify main directly.
- Work only on the branch created for this issue.
- Run all relevant tests available for this lane.
- Add regression tests for confirmed defects where practical, but only inside ALLOWED PATHS.
- Fail closed if ownership/overlap is uncertain.
- Before finishing, check that every changed file is inside ALLOWED PATHS.

AT THE END:
- Push completed fixes to your Claude branch.
- List every changed file.
- List tests actually run and results.
- List unresolved findings and intended owner lane.
- Report any overlap/conflict risk.
- Provide the PR creation link.
- Do not claim tests you did not actually run.