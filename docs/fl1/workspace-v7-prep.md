# Workspace V7 prep — protected quarantine authority

Status: PREP ONLY. Do not merge as production Workspace code. This file exists to remove design/test delay once Protected Authority V7 has an independently accepted exact SHA.

## Dependency
Workspace V6 FINAL2 closed the prior Windows pathname-chmod cleanup race but failed independent review because `.forgeboss-quarantine` remained ordinary same-principal mutable filesystem authority. Under the FL1 hostile-worker model, a coding worker may share the controller OS principal; therefore a same-user directory, JSON file, chmod/ACL tweak, path-based open, or moved directory is not sufficient as the authority boundary.

Workspace V7 must consume an accepted protected authority/service boundary. It must not invent a second protected-service design inside `workspace.py`.

## Required architecture

### 1. Protected quarantine store
All destructive-cleanup authority records live behind the protected authority service/broker, not in worker-writable workspace state.

The protected record must bind at minimum:
- repository identity
- taskId
- runId
- ownerEpoch
- builderId
- assignmentGeneration
- workspaceGeneration
- workspace root canonical identity
- target canonical identity
- staging/quarantine canonical identity
- immutable/native file identity needed for cleanup
- base/head/branch identity when relevant
- record generation/version
- state (`preparing`, `provisioning`, `finalizing`, `quarantined`, `reconciled` or accepted equivalent)
- digest/signature/service receipt binding the complete canonical projection

Caller-controlled path text alone must never authorize destructive cleanup.

### 2. Protected service owns state transitions
Workspace code may request transitions, but the protected service must validate and authorize them from protected durable state.

Expected operations are conceptually:
- begin workspace generation
- bind provisioned target identity
- mark finalizing
- quarantine failed generation
- read authoritative quarantine state
- authorize reconcile/cleanup for one exact generation
- mark reconciled only after absence/identity proof

Exact API names are not prescribed here; reuse the accepted Protected Authority interface.

### 3. Generation-bound destructive cleanup
Before deleting any target/stage tree:
1. obtain protected authoritative record/receipt;
2. prove task/run/builder/assignment/workspace generation matches current authority;
3. open/inspect the target without following reparse/symlink aliases;
4. bind observed native identity to protected record;
5. perform handle-bound/no-follow cleanup where the platform supports it;
6. fail closed if identity changes before/during cleanup;
7. mark the protected record reconciled only after target + stage are proven absent.

A stale generation must never clean a newer generation even if paths are reused.

### 4. Worker isolation
A worker must not be able to:
- delete/replace/edit the protected quarantine record;
- redirect protected state via parent junction/symlink/reparse swap;
- choose a sibling/peer workspace as cleanup target;
- downgrade a quarantined generation to clean by deleting local metadata;
- forge a service receipt/digest;
- replay an old protected record after reassignment;
- use stale assignment authority to reconcile a workspace.

### 5. Crash/restart behavior
After controller/service restart:
- protected records remain authoritative;
- in-flight generations are recovered deterministically;
- stale local workspace files do not override protected state;
- orphan workspace/staging directories are reported as untrusted until explicitly matched to protected authority;
- cleanup remains generation-bound after restart.

## Hostile test packet

### Protected-state attacks
1. Worker deletes local `.forgeboss-quarantine` tree while protected record exists -> workspace remains quarantined.
2. Worker creates forged local record saying `reconciled` -> ignored/denied.
3. Worker alters target/stage path in local copy -> ignored/denied.
4. Worker supplies valid-looking record with forged digest/signature -> denied.
5. Replay old protected receipt after assignmentGeneration increment -> denied.
6. Replay old workspaceGeneration after new workspace is provisioned at same path -> denied.

### Parent/path swap attacks
7. Replace quarantine-state parent with junction/reparse/symlink between validation and use -> cannot redirect protected state.
8. Replace workspace parent/target with sibling junction before cleanup -> cleanup denied; sibling preserved.
9. Replace child directory during recursive cleanup -> fail closed or remain contained to originally bound handle identity.
10. Case/8.3/reserved-device/UNC/device path aliases cannot redirect authority on Windows.

### Cross-worker attacks
11. Builder A attempts to reconcile Builder B workspace using A token/assignment -> denied.
12. Builder A obtains stale record for its old generation, then slot is reassigned to Builder C -> A cannot reconcile C generation.
13. Two concurrent reconcile requests for same generation -> at most one succeeds; result is idempotent/durable.
14. Concurrent provision of next generation cannot race with old-generation cleanup into deleting new workspace.

### Crash/restart attacks
15. Crash after protected quarantine record durable but before local rename/delete -> restart discovers exact state and does not silently clear it.
16. Crash after destructive cleanup but before protected `reconciled` write -> restart verifies absence + identity before finalizing; no unsafe blind retry.
17. Crash during generation rollover -> exactly one generation remains authoritative.

### Regression proof
18. Normal workspace provision still creates private Git authority with no shared peer refs/remotes.
19. Wrong base/head/branch/detached workspace remains rejected.
20. Read-only Git pack/index cleanup remains working on native Windows.
21. Existing exact isolation tests remain green on Linux and Windows.
22. Full relevant control/workspace regression passes.

## Independent review packet
Reviewer must verify exact frozen SHA only and must not edit candidate.

Required terminal evidence:
- exact base/parent and topology
- exact changed files
- protected authority dependency is the independently accepted version, not a rejected ancestor
- protected state cannot be modified by worker principal under the declared runtime model
- hostile tests above or equivalent committed proof
- native Windows proof for handle/reparse/readonly cleanup
- Linux proof for symlink/no-follow/generation/restart behavior
- no broad regression

Terminal: REVIEW PASS, REVIEW FAIL, or REVIEW BLOCKED tied to exact candidate SHA.

## Integration rule
Do not integrate Workspace V7 before:
1. Protected Authority V7 (or superseding version) has terminal independent PASS;
2. Workspace V7 is built from current accepted main or fresh-main replayed;
3. independent exact-SHA Workspace review passes;
4. fresh-main combined control/workspace tests pass.

## FL1 relationship
Workspace V7 is not Finish Line 1 by itself. After acceptance it feeds the final real 2-builder ForgeBoss-on-ForgeBoss self-build, which must still prove isolated concurrent builders, stop/reassign, stale authority rejection, exact candidate freeze/review, bounded spend, known-good protection, and promotion or rollback.