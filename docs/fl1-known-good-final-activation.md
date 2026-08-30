# FL1 Known-Good Final Activation / Rollback Packet

Purpose: pre-stage the final known-good activation gate so FL1 can close quickly once Store V3, Receipts R3, Protected Authority V7, Workspace V7, spend and process-supervisor requirements are accepted.

## Rule
The controller running the self-build must remain on a frozen known-good revision until the candidate is independently accepted. Candidate code must never become the active controller merely because it built or tested successfully.

## Required identity binding
A promotable ForgeBoss package must bind, at minimum:
- exact Git commit SHA
- complete package/tree identity
- repository identity
- expected executable/module entrypoint
- config/schema version expected by the controller
- activation generation
- prior known-good revision
- promotion receipt / controller acceptance identity
- required Store assignment/candidate/review receipt identities where applicable

Any mismatch fails closed before activation.

## Activation sequence
1. Start from the current frozen known-good controller.
2. Freeze the proposed candidate SHA/tree.
3. Verify independent exact-SHA review PASS and controller acceptance.
4. Verify all required FL1 component gates are green on current authoritative ancestry.
5. Materialize candidate in isolated activation location; do not overwrite prior known-good in place.
6. Run startup sanity checks from the candidate without switching the durable known-good pointer.
7. Run control selftests and required multi-agent checks.
8. Deliberately inject one activation failure before final promotion and prove rollback restores the prior known-good controller/state.
9. Repeat with a clean candidate activation.
10. Atomically move the durable known-good pointer only after all post-start checks pass.
11. Record old revision, new revision, activation generation, exact test evidence and rollback evidence.

## Mandatory hostile tests
- candidate SHA differs from accepted reviewed SHA -> reject
- package/tree differs while commit label is reused -> reject
- missing/partial package file -> reject
- activation process starts but health/selftest fails -> terminate candidate and keep prior known-good
- candidate exits during activation window -> rollback
- controller restart during promotion -> reconcile to exactly one known-good revision, never half-promoted state
- stale promotion receipt/generation -> reject
- retry same activation request -> idempotent/no duplicate promotion
- prior known-good package missing/corrupt before activation -> fail closed rather than destroy recoverability
- malicious/incorrect activation root/path -> containment/identity reject
- candidate attempts to mutate known-good metadata directly -> reject/protected authority only
- successful promotion followed by deliberate next-candidate failure -> rollback must target the newly promoted known-good revision

## Acceptance evidence
A terminal PASS must include:
- exact prior known-good SHA/tree
- exact candidate SHA/tree
- candidate review PASS identity
- controller acceptance identity
- activation generation
- startup/selftest results
- deliberate failed activation evidence
- rollback target/result
- successful promotion evidence
- restart/reconciliation result
- Windows result and Linux result where platform-specific activation/process code differs

## Integration rule
Historical known-good branches are reference evidence only. Do not merge/promote a historical candidate merely because it previously passed. Re-evaluate/replay the accepted implementation on the then-current main and run this packet against the exact final candidate.

## FL1 linkage
This gate is complete only when the final ForgeBoss-on-ForgeBoss self-build can keep the running controller protected, reject a bad candidate, roll back safely, then promote a good independently accepted candidate as the next known-good revision.
