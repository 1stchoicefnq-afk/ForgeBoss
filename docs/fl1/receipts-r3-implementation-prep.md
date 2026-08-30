# Receipts R3 implementation prep

Status: PREP ONLY. Do not merge to production before Store Authority V3 has an independently accepted canonical assignment contract.

## Goal
Receipts R3 must consume one Store-produced authoritative assignment record and its Store-computed digest. Receipts must not define a second assignment hashing scheme or accept a caller-selected assignment digest.

## Expected Store contract
The accepted Store API must expose one immutable assignment projection with authoritative values for at least:

- taskId
- runId
- attempt
- ownerEpoch
- builderId
- assignmentGeneration
- repository
- objectFormat
- baseSha
- workspaceGeneration
- workspaceContentSha256
- runtime/model identity where Store binds it
- allowed path/tool authority where Store binds it
- worker budget authority
- global run/reservation identity
- assignmentSha256 computed by Store from the authoritative canonical projection

Receipts R3 should parse that projection only after verifying it through the accepted Store contract. A caller-provided object that merely looks like the Store projection is not authority.

## Proposed boundary
Use an adapter shaped conceptually like:

```python
store_assignment = store.get_assignment_identity(task_id, run_id, assignment_generation)
# returns canonical projection + Store-computed assignmentSha256
handoff = CandidateHandoff.from_store_assignment(store_assignment, candidate_evidence)
review = ReviewerReceipt.create(store_assignment, handoff, reviewer_id, evidence)
acceptance = ControllerAcceptance.create(store_assignment, handoff, review, controller_id)
```

The exact function names must follow the accepted Store V3 API rather than inventing parallel authority.

## Required receipt invariants

1. Assignment equality means exact authoritative Store identity, not matching caller fields.
2. Candidate handoff binds exact candidate SHA/tree, exact changed paths, required test receipts, scope diff digest and reserved/measured spend.
3. Reviewer receipt binds the exact handoff digest and exact candidate SHA/tree.
4. `reviewerId == authoritative builderId` is denied case-insensitively regardless of contributors metadata.
5. Controller acceptance requires an exact PASS review and an independent controller principal.
6. FAIL/BLOCKED review cannot become acceptance.
7. Assignment revoke/reassign/generation advance makes prior handoffs/reviews unacceptable.
8. Path policy remains fail-closed for Windows aliases, rooted paths, ADS, traversal, duplicate exact paths and policy-key collisions.
9. Measured spend may not exceed reserved authority.
10. Unknown keys, duplicate JSON keys, non-finite numbers and non-canonical identity values fail closed.

## Hostile test vectors to implement immediately after Store V3 PASS

### Assignment authority
- valid fresh Store assignment -> PASS
- change builderId, keep old digest -> FAIL
- change assignmentGeneration, keep old digest -> FAIL
- change ownerEpoch/runId/attempt, keep old digest -> FAIL
- change repository/baseSha/workspace generation/content identity, keep old digest -> FAIL
- arbitrary 64-hex assignmentSha256 -> FAIL
- stale Store assignment after revoke/reassign -> FAIL
- persisted/reloaded fresh Store assignment -> PASS

### Reviewer independence
- authoritative builder is omitted from contributors; reviewer uses builderId -> FAIL
- reviewer differs from builder only by case -> FAIL
- unrelated reviewer -> PASS
- reviewer swaps assignment object while retaining handoff digest -> FAIL

### Candidate binding
- candidate SHA swap -> FAIL
- tree SHA swap -> FAIL
- scope diff digest swap -> FAIL
- required test receipt swap -> FAIL
- changed path case/alias collision -> FAIL
- duplicate exact path -> FAIL
- path-policy version mismatch -> FAIL

### Spend
- measured < reserved -> PASS
- measured == reserved -> PASS
- measured > reserved -> FAIL
- NaN/Infinity/exponent/negative/non-canonical money -> FAIL

### Acceptance
- exact PASS review + independent controller -> PASS
- FAIL review -> FAIL
- BLOCKED review -> FAIL
- controller == builder -> FAIL
- controller == reviewer -> FAIL
- review/handoff digest mismatch -> FAIL

## Review execution packet

When Store V3 is accepted:

1. Create Receipts R3 from current authoritative main.
2. Touch only `forgeboss/control/receipts.py` and direct receipt tests unless controller explicitly widens scope.
3. Preserve V2/V3 security fixes that are still compatible.
4. Remove any caller-trusted assignment digest construction.
5. Add hostile tests above before freezing.
6. Run focused receipt tests.
7. Run Store Authority focused tests to prove integration compatibility.
8. Run full `forgeboss/control` discovery.
9. Freeze one exact SHA.
10. Route to a non-author reviewer using Issue #90 packet.

## No-go conditions

Do not freeze/accept Receipts R3 if:

- Store V3 has no independent terminal PASS;
- Receipts recomputes assignment identity with its own canonical schema instead of consuming Store authority;
- caller can provide or replace `assignmentSha256`;
- self-review can be hidden by contributors metadata;
- stale assignments remain valid after reassignment/revoke;
- the test suite proves only internal receipt consistency rather than Store-to-Receipt authority binding.
