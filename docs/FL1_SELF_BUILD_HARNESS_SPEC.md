# ForgeBoss Finish Line 1 — Final Self-Build Harness Spec

## Purpose

This is the executable acceptance specification for the final ForgeBoss-on-ForgeBoss Finish Line 1 run.

It is preparation only until all required production components are independently accepted and integrated on fresh `main`.

The harness must fail closed. A single missing identity, stale authority, failed review, budget ambiguity, collision, unverified process, or promotion/rollback ambiguity means FL1 is NOT complete.

## Preconditions

Before running the final harness, freeze and record:

- `known_good_sha`: currently running verified known-good ForgeBoss controller revision.
- `candidate_base_sha`: exact fresh current `main` used by every builder assignment.
- `repository`: exact canonical repository identity.
- `global_budget_usd`: finite exact run cap.
- `builder_count`: initially exactly 2 for FL1.
- `reviewer_id`: independent from both builders.
- `controller_id`: independent acceptance authority.
- protected execution/broker identity.

Required integrated components must already have terminal independent acceptance:

1. Store Authority with canonical Store-produced assignment digest.
2. Receipts/candidate freeze using that exact assignment authority.
3. Workspace isolation/provisioning with generation-bound cleanup/reconciliation.
4. Collision/scope scheduler.
5. Global + per-worker spend enforcement.
6. Process supervisor stop/reassign/stale-generation fencing.
7. Protected execution boundary.
8. Known-good identity + activation/promotion/rollback.

## Run layout

Create a unique run root:

`state/fl1-self-build/<run_id>/`

Required durable subrecords:

- `run.json`
- `assignments/`
- `workers/`
- `candidates/`
- `reviews/`
- `acceptance/`
- `promotion/`
- `events.jsonl`
- `final-report.json`

No mutable caller-supplied path may escape the run root.

## Builder tasks

Use two small, real ForgeBoss changes that are useful but deliberately non-overlapping.

Example shape only; exact files must be chosen against current fresh main at execution time:

- Builder A: one narrowly-scoped diagnostic/test-helper improvement.
- Builder B: one different narrowly-scoped diagnostic/test-helper improvement.

Requirements:

- both tasks originate from the same exact `candidate_base_sha`;
- exact writable scopes are disjoint under ForgeBoss path-collision policy;
- both receive Store-issued canonical assignment identities;
- both have independent workspace + private Git authority;
- both have individual finite budgets;
- the sum of reservations is bounded by `global_budget_usd`;
- neither can mutate the peer workspace/ref/authority.

Do not use deterministic fake builder scripts for the terminal FL1 run. The terminal run must use an actually available coding engine through the protected execution path.

## Phase 1 — Controller identity and known-good freeze

PASS only if all are true:

- running controller proves exact known-good manifest/revision/tree identity;
- candidate activation cannot mutate the current known-good pointer;
- old known-good artefact remains available for rollback;
- controller records immutable `known_good_sha` and `candidate_base_sha` before worker launch;
- current `main` still equals `candidate_base_sha` immediately before assignment issuance.

## Phase 2 — Store-issued assignments

Issue Builder A and Builder B assignments from Store Authority.

Each canonical assignment record must bind at minimum:

- assignment ID
- Store-produced canonical assignment digest
- task ID
- run ID
- attempt
- owner epoch
- authoritative builder ID
- assignment generation
- repository
- base SHA
- branch
- workspace generation/content identity
- allowed writable scope
- required tests
- reserved per-worker budget
- global budget/run identity where applicable

PASS only if:

- caller cannot replace the assignment digest;
- a one-field mutation changes/invalidates authority;
- builder IDs differ;
- assignment generations are non-zero and exact;
- both assignments share exact base but have disjoint scopes.

## Phase 3 — Provision two isolated workers

Provision both workspaces through the production workspace factory.

PASS only if:

- private Git dirs/common authority differ;
- no worker has a writable remote to production authority;
- no alternates/shared mutable common refs undermine isolation;
- each workspace verifies exact assigned base/branch/generation;
- physical worktree identities differ;
- restart discovery can identify both durable workspace generations.

## Phase 4 — Concurrent protected engine launch

Launch both builders through the production protected execution path.

PASS only if:

- both are concurrently alive for a measurable overlap window;
- paid/start authority is consumed only after final protected validation;
- protected broker/executor identity is verified;
- workers cannot mutate host controller Git authority;
- workers cannot mutate each other;
- per-worker and global reservation state exists before spend can occur;
- unknown cost is never silently treated as zero.

Capture:

- PIDs/process identity
- start timestamps
- engine/provider/model
- reservation IDs
- assignment digests
- protected-execution receipts

## Phase 5 — Deliberate stop/reassign failure injection

While both workers are active, deliberately stop Builder B using the production controller.

Then reassign Builder B's slot to a fresh replacement assignment/generation.

Required hostile checks:

1. old worker attempts heartbeat -> rejected.
2. old worker attempts release -> rejected.
3. old worker attempts candidate submission -> rejected.
4. old worker attempts write/authority continuation -> rejected.
5. replacement receives fresh generation/assignment digest.
6. Builder A continues unaffected.

PASS only if the stop is evidenced against exact process identity and stale B authority cannot resurrect.

## Phase 6 — Candidate freeze

When each surviving builder finishes:

- verify workspace exact head/branch/generation;
- compute exact diff against assigned base;
- verify changed paths equal authorised scope subset;
- run required focused tests;
- run applicable regression tests;
- settle/record measured cost truthfully;
- freeze candidate SHA and candidate tree SHA;
- create handoff receipt bound to Store assignment digest.

PASS only if:

- candidate is immutable after handoff;
- later workspace mutation cannot change accepted handoff evidence;
- over-scope change fails the entire handoff;
- stale assignment fails the handoff;
- measured cost cannot exceed reserved authority without rejection/escalation;
- every candidate has distinct authoritative builder/run identity.

## Phase 7 — Independent exact-SHA review

The reviewer must not be either builder.

Reviewer receives only frozen candidate evidence and exact SHA.

For each candidate, reviewer independently verifies:

- exact assignment digest
- exact candidate SHA/tree
- exact changed files
- exact scope
- required tests
- regression evidence
- spend receipt
- no self-review
- no stale base/head
- no post-freeze mutation

A PASS review must create a durable review receipt bound to exact assignment + handoff + candidate SHA.

FAIL or BLOCKED means no integration.

## Phase 8 — Controller acceptance and integration

Controller may accept only independently PASS-reviewed candidates.

Before integration:

- re-check live main equals expected integration base;
- re-check candidate SHA remains frozen;
- re-check review receipt binds exact candidate;
- re-check controller identity is independent from builder/reviewer where required by policy.

Integrate through protected PR/merge path with expected-head fencing.

Then run fresh integrated-main regressions.

PASS only if both accepted non-overlapping changes coexist and all required regressions pass.

## Phase 9 — Candidate ForgeBoss activation

Build/stage the newly integrated ForgeBoss candidate without replacing current known-good in place.

Required checks:

- staged candidate identity is complete and verified;
- startup selftests pass;
- required control tests pass;
- process identity/liveness is verified;
- old controller retains authority until explicit handoff boundary;
- new controller cannot become known-good before health confirmation.

## Phase 10 — Forced rollback proof

A forced failure must be injected during one activation attempt.

Examples: failed health probe or deliberately invalid candidate start condition.

PASS only if:

- failed candidate is proven dead/fenced before rollback;
- known-good pointer never advances to failed candidate;
- previous known-good restarts/restores successfully;
- previous manifest/revision/tree identity verifies after rollback;
- stale failed candidate loses mutation/control authority.

Then perform a clean second activation attempt.

## Phase 11 — Successful promotion proof

On the clean activation:

- candidate starts;
- health/control/selftests pass;
- authority handoff completes;
- prior controller loses mutation authority at the defined boundary;
- new revision is durably promoted to known-good;
- promotion receipt binds exact integrated candidate revision/tree/build identity.

PASS only if the promoted controller is the exact reviewed/integrated revision.

## Global budget terminal checks

The final report must show:

- exact global cap;
- each worker reservation;
- actual measured settlement where known;
- remaining/closed global authority;
- no double reservation;
- no reservation reuse after release unless explicitly authorised by invariant;
- concurrent start could not exceed cap;
- stop/reassign did not refund/reuse spent authority incorrectly;
- unknown/failed provider cost state is explicit.

## Required final report fields

`final-report.json` must include at minimum:

- run ID
- started/finished timestamps
- original known-good SHA
- candidate base SHA
- final integrated SHA
- promoted known-good SHA
- builder A/B assignment IDs + canonical digests
- builder A/B candidate SHAs
- reviewer identity
- review receipt digests
- controller acceptance receipt digests
- process stop/reassign evidence
- stale-worker rejection evidence
- workspace identities/generations
- global/per-worker budget evidence
- test commands + exit codes
- protected execution evidence
- rollback attempt result
- promotion result
- unresolved uncertainty array
- `finish_line_1_passed: true|false`

## Automatic FAIL conditions

Set `finish_line_1_passed=false` if ANY occur:

- builder scopes overlap;
- shared mutable Git authority exists;
- caller-generated assignment digest is accepted as authoritative;
- self-review occurs;
- candidate changes after freeze;
- stale worker can act after reassignment;
- spend can exceed authority or becomes unknowingly zero;
- protected execution proof is missing;
- review is not exact-SHA bound;
- integration uses stale main;
- failed candidate becomes known-good;
- rollback cannot restore prior known-good;
- promoted revision differs from reviewed/integrated exact revision;
- required runtime evidence is missing.

## Terminal success statement

Only after every phase passes may the controller emit exactly:

`READY / FINISH LINE 1 COMPLETE`

Then immediately open/activate Issue #88 as ForgeBoss' first self-improvement task: scale the proven worker pool from 2 builders toward 10 through 2->4->6->10 staged gates.
