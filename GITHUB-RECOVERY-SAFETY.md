# GitHub Recovery Request Safety

ForgeBoss/SiteBoss GitHub automation resumed only after account access was restored. **No software can guarantee that GitHub will never restrict or suspend an account.** The required strategy is conservative traffic, fail-closed rate-limit handling, least privilege, and no runtime bypass around the shared governor.

## Shared governor

All audited runtime GitHub REST traffic, GitHub-backed clone/fetch operations and automated pushes must route through:

- `forgeboss/github/request-governor.js`
- `forgeboss/github/github-gate-cli.js`
- `forgeboss/github/GitHub-Governor.psm1`

`write-gate.js` remains only as a compatibility wrapper around the shared governor.

Default local ceilings are deliberately conservative:

- one cross-process GitHub request/network operation at a time;
- 30 total GitHub requests/network operations per rolling minute;
- 6 mutations per rolling minute;
- 60 mutations per rolling hour;
- at least 500 ms between ordinary requests;
- at least 2.5 seconds between mutations;
- 5-minute exact-mutation deduplication;
- ETag/Last-Modified conditional GET support;
- short optional GET caching;
- 5-minute repeated-404 suppression.

These are ForgeBoss safety ceilings, not GitHub entitlement limits. They must not be raised merely to increase throughput.

## Rate-limit circuit breaker

A GitHub HTTP 429 always opens the shared circuit. A 403 opens it only when GitHub supplies rate-limit evidence such as `Retry-After`, exhausted `X-RateLimit-Remaining`, or an explicit rate/abuse message.

When the circuit opens:

1. stop new governed GitHub activity on this machine;
2. honor `Retry-After` when present;
3. otherwise honor `X-RateLimit-Reset` for an exhausted primary limit;
4. otherwise wait at least one minute;
5. increase cooldown exponentially for repeated limit/abuse signals;
6. do not hammer the same operation until it succeeds.

A plain permission/authentication 403 is returned as an error and is **not** retried as a rate-limit event.

## Reads and polling

- Prefer event/webhook-driven state over polling.
- Critical exact-head reads use conditional requests rather than a stale local success cache.
- Repeated missing-resource polling is suppressed.
- Worker lanes should consume already-fetched controller state where possible rather than independently refetching the same GitHub objects.
- Do not use GitHub issues/comments as a high-frequency message bus.
- Batch evidence into meaningful updates instead of streaming tiny comments.

## Mutations and Git transport

- Workers may prepare changes concurrently; actual GitHub mutations are serialized.
- Automated `git push` uses the same mutation budget and lock.
- Audited GitHub-backed `clone`/`fetch`/mirror refreshes use the same request queue.
- Local-only Git operations are not throttled by the GitHub governor.
- New runtime GitHub code must use the shared gate or an independently reviewed successor.
- Workers that do not need write authority must not receive write credentials.

## Logging

Governor metrics may include method, redacted path, status, duration, local throttling, circuit state and remaining-rate headers.

Never log:
- Authorization values;
- installation tokens;
- private keys;
- request bodies;
- customer data;
- URL query strings containing sensitive values.

## Verification

Portable checks:

```powershell
node forgeboss\github\test-request-governor.js
node forgeboss\github\audit-governor-bypasses.js
```

The bypass audit covers the known executable controller, worker, reviewer, repair, diagnostic and repository-mirror paths. Adding a new GitHub runtime entrypoint requires extending that audit.

## Native acceptance still required

Portable/static checks do not prove Windows PowerShell, Git for Windows, credential-helper, process-lock or shutdown behavior. Those paths require native Windows execution before this hardening can be called fully accepted.

## Remaining risk

GitHub may change or apply unpublished abuse/secondary limits. Human activity, browser use, GitHub Desktop, other Apps/tokens, CI and unrelated software can consume account/repository resources outside this local governor. A governor reduces automation risk; it cannot guarantee that GitHub will never take account action.
