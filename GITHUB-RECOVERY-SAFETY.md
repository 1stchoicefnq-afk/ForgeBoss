# GitHub Recovery Write Safety

ForgeBoss GitHub automation resumed only after account access was restored. Automated GitHub mutation must use `forgeboss/github/write-gate.js`; direct worker writes are not an approved path.

## Enforced controls

- Cross-process single-writer lock serializes GitHub write requests.
- Minimum 2 seconds between writes and hard ceiling of 30 writes per rolling minute.
- Identical report comments are suppressed for 5 minutes by content digest.
- HTTP 403/429 and transient 5xx responses back off instead of retrying aggressively.
- `Retry-After` is authoritative; exhausted primary limits also honor `X-RateLimit-Reset`.
- Remaining retries use capped exponential backoff with jitter.
- Request status, throttles, duplicate suppression and backoff events are appended to `.forgeboss-github-write-state.jsonl` for diagnosis.
- The PowerShell report publisher delegates to the guarded Node writer so there is one mutation implementation rather than two concurrent writers.
- Safe batching/coalescing is performed by duplicate suppression; operations with different semantics are not combined.

## Worker rule

Workers may prepare GitHub mutations concurrently, but they must not execute GitHub writes directly. Queue/serialize them through the guarded writer. New GitHub mutation features must use the same gate or an audited successor with equivalent controls.

## Remaining risk

This gate controls ForgeBoss code paths that use it. A worker or historical script that invokes `git push`, `gh`, `curl`, `Invoke-RestMethod`, or GitHub's API directly can bypass it. Before broad autonomous worker activity, audit new/historical mutation entrypoints and keep repository credentials unavailable to workers that do not need write authority.
