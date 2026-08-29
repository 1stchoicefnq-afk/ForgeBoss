# ForgeBoss Finish Line 1 Closeout Runbook

Prepared on live main `8d36be20cfb3f29e315363e290818f4c370f5b03`.

This document is preparation only. It does not waive any review or runtime gate.

## Objective

Finish Line 1 is complete only after ForgeBoss performs a real ForgeBoss-on-ForgeBoss self-build with at least two concurrent builders, isolated authority, exact non-overlap writable scopes, bounded spend, stop/reassign, independent exact-SHA review, known-good protection, and successful promotion or safe rollback.

## Current dependency chain

1. Store Authority V3
   - authoritative durable assignment identity
   - Store-produced canonical assignment digest
   - builder principal + task/run/attempt/ownerEpoch + repo/base/workspace/scope/spend identity
   - stale/retry/revoke fencing
   - preserve legacy never-assignment-bound compatibility

2. Receipts R3
   - consume Store-produced assignment digest; never caller-recompute it
   - frozen candidate SHA/tree/scope/tests/spend
   - reviewer identity bound independently from builder
   - controller acceptance bound to exact candidate

3. Workspace V6
   - generation-bound private Git/workspace authority
   - Windows-safe read-only Git cleanup
   - no pathname reopen / reparse-swap cleanup race
   - crash/restart quarantine/reconciliation remains fail-closed

4. Protected execution authority / FB-026 closure
   - actual paid-start authority protected from uncooperative host mutation
   - exact task/run/epoch/envelope/workspace/runtime/scope/budget binding
   - no paid start when required isolation cannot be established

5. Process supervisor / FB-052 terminal acceptance
   - observed process identity
   - bounded stop + escalation
   - generation CAS
   - stop/reassign and stale-generation rejection

6. Known-good / activation terminal acceptance
   - running controller stays on frozen known-good while candidate is built
   - exact manifest/tree identity
   - failed activation proves candidate dead before rollback
   - previous known-good remains recoverable

7. Spend closure
   - per-worker exact cap
   - authoritative global self-build cap
   - concurrent reserve/start cannot oversubscribe global cap
   - measured cost settlement remains truthful

## Integration rule

Never merge an old candidate merely because it passed unit tests. For every component:

1. identify the latest authoritative candidate and latest terminal review;
2. confirm live main SHA;
3. replay/integrate onto fresh live main if required;
4. freeze exact integration SHA;
5. run focused tests and broad control regression;
6. run Linux + Windows CI where applicable;
7. merge only after exact-SHA acceptance.

## Pre-self-build integration test

After required components are accepted and integrated, run one fresh-main local rehearsal that proves:

- two builders start from identical exact base;
- separate workspaces/private Git authority;
- exact disjoint writable scopes;
- both active concurrently;
- distinct candidate SHAs;
- peer branch/HEAD unaffected;
- candidate diff remains in assigned scope;
- one worker is stopped and replaced;
- replacement gets a new generation/assignment identity;
- old generation heartbeat/write/release is rejected;
- global + worker budget simulation cannot oversubscribe;
- known-good activation and rollback tests pass;
- full Python discovery passes.

## Real FL1 self-build run

### Controller

- Pin/freeze current known-good controller SHA before starting.
- Create one immutable self-build run identity and hard global budget.
- Decompose two or more useful ForgeBoss changes with exact non-overlap scopes.
- Generate Store assignments for builders.
- Provision isolated workspaces.
- Start builders through protected execution authority.

### Builders

Minimum two builders must be concurrently active.

Each must have unique:
- builderId
- taskId
- runId
- attempt
- ownerEpoch
- assignmentGeneration
- assignment digest
- workspace generation
- branch
- writable scope
- budget

### Deliberate failure

During the run:
- stop one active builder using ProcessSupervisor;
- prove exact process/tree termination;
- reassign its task or replacement task using a fresh generation;
- attempt stale authority operation from the old generation and require rejection;
- continue without disturbing peer builder.

### Candidate finalization

For each builder candidate:
- verify current head equals authoritative expected head;
- verify exact scope diff;
- run required focused tests;
- freeze candidate SHA;
- generate candidate handoff receipt from Store authority;
- prohibit author from reviewing own candidate.

### Independent review

Reviewer must verify exact frozen SHA and return PASS / FAIL / BLOCKED with durable evidence.

On FAIL:
- candidate cannot integrate;
- builder receives a new assignment/generation if rework is needed.

On PASS:
- controller may integrate only the reviewed exact candidate or a fresh-main integration SHA whose ancestry/source is revalidated and regression tested.

### Promotion / rollback

After integration candidate is assembled:
- stage candidate controller without replacing current known-good;
- run startup/control/selftests and required multi-agent checks;
- if healthy, promote and record new known-good identity;
- if unhealthy, prove candidate dead and roll back to previous known-good;
- failed candidate must never become known-good.

## FL1 terminal evidence packet

One final durable packet must record:
- original known-good SHA
- self-build base SHA
- self-build run ID
- global cap and measured spend
- all builder assignments/digests
- workspace identities
- process identities
- candidate SHAs
- changed paths
- required tests/results
- stop/reassign evidence
- stale-authority rejection evidence
- reviewer identities/verdicts
- integration SHA
- activation result
- promoted known-good SHA OR rollback target/result
- Linux/Windows CI references

## Completion statement

`READY / FINISH LINE 1 COMPLETE` may only be posted if the real engine-backed self-build above passes. Local rehearsal or green unit tests alone are not sufficient.

## Immediate post-FL1 task

Proceed to Issue #88: scale the proven worker-slot architecture from 2 builders to 10 using the same control-plane invariants, configuration-driven pool size, and staged 2→4→6→10 proof.