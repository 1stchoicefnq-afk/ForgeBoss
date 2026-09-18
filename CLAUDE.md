# ForgeBoss Claude Worker Rules

## GitHub compliance HARD LAW

Before any GitHub API call, automated clone/fetch/push, issue/PR/comment mutation, workflow dispatch or GitHub-backed polling, read and obey `GITHUB-COMPLIANCE-LAW.md`.

- No worker may bypass the shared GitHub governor.
- No worker may raise/disable the hard governor ceilings or reduce the minimum spacing.
- No worker may use extra tokens/accounts/processes to evade limits or cooldowns.
- 403/429/rate-limit/abuse signals fail closed.
- GitHub issues/comments are not a high-frequency worker message bus.
- New GitHub automation is blocked until the compliance checker and bypass audit cover it.

If speed conflicts with GitHub compliance, **compliance wins and the worker stops**.

These rules apply to every Claude Code worker in this repository.

## Parallel-worker safety is mandatory

Multiple Claude workers may run at the same time. Every worker must behave as an isolated lane and must not make opportunistic edits outside its assigned scope.

### 1. The issue body defines ownership

Before editing any file, read the triggering issue/comment and identify these fields when present:

- `LANE:`
- `ALLOWED PATHS:`
- `FORBIDDEN PATHS:`
- `SHARED FILES:`

`ALLOWED PATHS` is an exclusive write allowlist for that worker. Read access may extend outside the lane when needed for understanding, but writes may not.

If an implementation request does not define `ALLOWED PATHS`, do not make broad cross-repository changes. Limit changes to the smallest clearly relevant subsystem and explicitly list every file changed in the final report.

### 2. Never cross into another worker's lane

Do not edit a file merely because a related defect is discovered there. If the required fix is outside `ALLOWED PATHS`:

1. Leave the file unchanged.
2. Record the finding as a follow-up with severity.
3. Explain which lane/path should own the fix.

Do not copy, cherry-pick, merge, rebase, or otherwise incorporate another active Claude branch into your branch.

### 3. Shared/high-conflict files are integration-lane only

Unless the issue explicitly assigns `LANE: integration`, normal workers must not edit these shared files or areas:

- `.github/workflows/**`
- `CLAUDE.md`
- repository-wide dependency/lock manifests
- root-level release/version metadata
- central controller/dispatcher registries shared by multiple subsystems
- global generated ledgers/indexes

If one of these files must change, report it for the integration lane instead.

### 4. One subsystem per worker

A worker should prefer cohesive changes inside one subsystem. Do not perform drive-by cleanup, formatting, renaming, dependency upgrades, or unrelated refactors.

Tests added for a fix should live with the owned subsystem where practical.

### 5. Stale-main protection

Workers start from a snapshot of `main`. Before pushing final changes:

- inspect the files being changed for evidence that upstream/main has materially moved;
- if the task can no longer be completed safely without reconciling overlapping upstream changes, stop and report a conflict instead of force-pushing or rewriting other work;
- never force-push over unrelated changes.

### 6. Fail closed on overlap

If there is uncertainty about file ownership or likely concurrent edits, choose no edit over a conflicting edit. Report the finding for the controller/integration lane.

### 7. Required final report

Every worker that changes code must report:

- lane name;
- files changed;
- tests actually run and results;
- unresolved findings and their intended owner/lane;
- any possible overlap/conflict noticed;
- branch and PR link.

Never claim a test passed unless it actually ran.

## Suggested lane map

Use these default ownership boundaries when creating parallel work:

- `security`: `forgeboss/security/**` plus directly owned security tests
- `windows`: Windows/PowerShell-specific components and their tests
- `concurrency`: concurrency/locking/state-transaction modules and their tests
- `process`: process/subprocess supervision modules and their tests
- `git`: git/worktree/branch handling modules and their tests
- `spend`: budget/cost/paid-call control modules and their tests
- `paths`: filesystem/path-validation modules and their tests
- `tests`: test infrastructure only; do not change production behavior unless explicitly assigned
- `integration`: shared/global files and cross-lane reconciliation

The triggering issue's explicit `ALLOWED PATHS` always overrides this suggested map.