SITEBOSS REPAIR RAT v0.5-smokescreen
========================

Purpose
-------
Repair Rat consumes the successful repeated PostgreSQL repair-lab evidence for PR #525,
makes bounded AI repair attempts in a disposable LOCAL branch, and repeatedly tests the
whole defect family before allowing even a local commit.

Default bounds
--------------
Provider: OpenAI (SITEBOSS_REPAIR_PROVIDER=openai|anthropic)
Max paid repair attempts: 3
Repeat count for each isolated PostgreSQL regression: 3
Stops early if the failure fingerprint repeats unchanged.

Acceptance gates
----------------
- npm test
- initial PostgreSQL migration
- business invitations x3
- production HTTP x3
- Travis intake x3
- full tests/postgres*.integration.test.js x2
- rollback
- migrate again

Safety
------
Repair Rat DOES NOT:
- push
- create/update GitHub PRs
- update refs
- merge
- deploy

It only:
- clones/fetches PR #525
- verifies exact head against bundled lab evidence
- asks one model per attempt for complete contents of allowlisted files
- writes those files in a disposable local workspace
- runs Docker/PostgreSQL acceptance
- optionally creates a LOCAL git commit only after every acceptance gate passes

Cost control
------------
At most 3 model calls by default, max configurable to 5.
Stops immediately when all acceptance gates pass.
Stops early when the same failure fingerprint repeats, to avoid paying for identical retries.

Run
---
1. CHECK-SITEBOSS.cmd
2. RUN-REPAIR-RAT.cmd

Reports:
state\repair-rat\repair-rat-<timestamp>.json
state\repair-rat\repair-rat-<timestamp>.log


REPAIR RAT v0.5-smokescreen — CASE-SENSITIVE + COST HARDENING
=================================================
v0.1 made one paid model call, then Git reported `.github/PULL_REQUEST_TEMPLATE.md`
as changed even though the model was not allowed to touch it. The repository contains
both uppercase and lowercase pull-request-template paths, so a normal Windows working
tree cannot represent the Git tree safely.

v0.2 fixes the class:
- uses the proven case-sensitive SiteBoss workspace root
- hard reset + clean + `git status --porcelain -z` must be pristine BEFORE any model call
- inventories case-colliding Git paths for evidence
- every attempt starts from the exact frozen PR #525 head
- patch outputs are cached to `state\repair-rat\patch-cache` BEFORE file application
- cache identity binds PR, exact head, provider, repair-lab evidence SHA256 and attempt number
- rerunning an exact cached attempt makes NO new paid model call
- failed attempts are not stacked indefinitely; each attempt returns to the exact frozen head
  and receives the previous acceptance failures as evidence

The v0.1 model output was not cached, so that already-spent call cannot be recovered.
v0.2 prevents the same waste class going forward.

GitHub publication remains forbidden.


REPAIR RAT v0.5-smokescreen — BOUNDED DEPENDENCY DISCOVERY
==============================================
v0.2 safely refused to guess. The cached model response specifically said the source packet
did not include enough invitation-service / withTransaction callers to prove that a generic
SERIALIZABLE retry would be replay-safe.

v0.3 widens evidence, not trust:
- automatically discovers relevant exact-head files with read-only `git grep`
- searches transaction retry, invitation, qualification/fencing and SERIALIZABLE call sites
- caps the source packet at 42 files / 520,000 chars
- derives the write allowlist from discovered existing src/*.js and postgres integration tests
- still rejects any changed path outside that derived bounded allowlist
- patch cache identity now includes the discovered source-scope hash
- therefore the old v0.2 refusal is NOT reused after legitimate evidence expansion
- safe=false is recorded as a normal model refusal and stops without wasting attempts 2/3

Also fixes the v0.2 CHECK-SITEBOSS regex bug that expanded `$env:USERPROFILE` into a regex.

GitHub publication remains forbidden.


REPAIR RAT v0.5-smokescreen — REFERENCE-GUIDED CLEAN-FEEDBACK LOOP
=======================================================

The v0.3 candidate passed its local run but failed both full PostgreSQL-suite runs when
Rat Review reconstructed it cleanly.

v0.4 adds:
- curated PostgreSQL/node-postgres/Slonik transaction architecture invariants
- automatic ingestion of the latest failed clean Rat Review report for PR #525
- a cache identity that changes when reference/clean-feedback evidence changes
- five full PostgreSQL-suite runs per validation round
- two independent PostgreSQL/container validation rounds before a local commit is allowed

Reference file:
  references\postgres-transaction-reference-pack.json

No implementation source is copied from open-source projects. Repair Rat uses their
documented transaction architecture as constraints and must write SiteBoss-native code.

Transaction constraints include:
- whole-transaction retry for safe 40001/40P01 cases
- same checked-out node-postgres client for one transaction
- bounded retries
- no retry for cancellation/abort or unknown/ambiguous completion
- no duplicated external side effects
- preserve SERIALIZABLE, idempotency, exact-once semantics and tenant isolation

Still LOCAL ONLY: no push, PR/ref update, merge or deploy.


REPAIR RAT v0.5-SMOKESCREEN
===========================

Pre-handoff sequence:
  1. CHECK-SITEBOSS.cmd
  2. BREAK-REPAIR-RAT.cmd
  3. RUN-REPAIR-RAT.cmd

BREAK-REPAIR-RAT performs zero model calls and zero GitHub API calls.

It adversarially checks:
- all PowerShell/module files parse
- no publication primitives exist in Repair Rat
- case-sensitive workspace guard exists
- pristine Git baseline is enforced before paid model calls
- patch cache is written before patch application
- cache context changes with feedback/reference/source evidence
- reference pack contains 40001/40P01/40003 and single-client/bounded retry invariants
- clean Rat Review failure feedback is wired in
- strong x5 full-suite / x2 validation-round acceptance is present
- safe=false stops without burning attempts
- failure reporting trap exists
- CHECK avoids USERPROFILE-in-regex expansion
- temporary Git fixture detects clean vs dirty worktree state
- malformed JSON is rejected
- stale-head fixture invalidates cache identity
- Docker engine/images are present
- a no-network Node container smoke test works

The breaker writes:
  state\repair-rat\breaker-last.json
