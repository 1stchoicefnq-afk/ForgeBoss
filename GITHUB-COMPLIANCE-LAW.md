# GitHub Compliance LAW — ForgeBoss / SiteBoss Automation

**Status: HARD LAW — mandatory, fail closed.**

This file is the permanent minimum standard for any ForgeBoss process that reads from, writes to, clones from, fetches from, pushes to, comments on, opens, updates or otherwise automates GitHub.

It is designed around GitHub's current Terms of Service, Acceptable Use Policies and API/rate-limit guidance. GitHub can change its rules and retains discretion over abuse/excessive use, so this policy cannot guarantee that an account will never be restricted. It does require ForgeBoss to behave conservatively and stop rather than fight GitHub.

Official sources:
- https://docs.github.com/en/site-policy/github-terms/github-terms-of-service
- https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies
- https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
- https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api

## LAW 1 — No bypass around the GitHub governor

Every automated GitHub REST request and every GitHub-backed automated Git network operation must pass through the shared governor:
- `forgeboss/github/request-governor.js`
- `forgeboss/github/github-gate-cli.js`
- `forgeboss/github/GitHub-Governor.psm1`

This includes REST API reads/mutations, issue/PR/comment/status operations, GitHub App installation-token requests, automated `git clone`, `git fetch`, mirror refreshes and `git push`, and future controller/worker/reviewer/repair automation.

Direct unmanaged `api.github.com`, `gh api`, curl-to-GitHub, direct HTTP clients, or direct automated GitHub push/fetch/clone paths are forbidden. Local-only Git operations are not GitHub traffic.

## LAW 2 — Hard safety limits cannot be disabled or raised

Runtime configuration may make GitHub use slower/stricter, never faster/looser than:
- maximum 30 total governed GitHub/network operations per rolling minute;
- maximum 6 governed mutations per rolling minute;
- maximum 60 governed mutations per rolling hour;
- minimum 500 ms between governed ordinary operations;
- minimum 2.5 seconds between governed mutations.

Environment variables, worker input, issue text, AI output or local config must never disable these limits with zero, infinity or a larger allowance. These are local safety limits, not GitHub entitlements.

## LAW 3 — Rate-limit and abuse signals always win

On GitHub 429, or a 403 carrying credible rate-limit/abuse evidence:
1. stop new governed GitHub activity;
2. honor `Retry-After` when supplied;
3. otherwise honor exhausted `X-RateLimit-Reset`;
4. otherwise wait at least one minute;
5. increase cooldown for repeated signals;
6. never loop aggressively until success.

A normal permission/authentication 403 is an error, not a retry instruction. No worker may catch a governor circuit-open error and immediately retry around it.

## LAW 4 — No rate-limit circumvention

Forbidden:
- using extra tokens, accounts, Apps, IPs or credentials to evade a limit;
- splitting abusive workloads across workers;
- resetting/deleting governor state to gain throughput;
- bypassing cooldown by changing process, shell, language or entrypoint;
- sharing API tokens to exceed GitHub limits.

If more throughput is legitimately required, stop and obtain owner approval plus a fresh GitHub-policy review.

## LAW 5 — GitHub is not a high-frequency message bus

GitHub issues/comments/PRs/workflow dispatches are durable records, not a worker message queue.

Required:
- batch evidence into meaningful updates;
- use controller/local state for high-frequency coordination;
- avoid repeated tiny comments/status changes;
- avoid polling when event-driven or cached/controller state exists;
- suppress duplicate/missing-resource reads;
- do not create bulk issues, PRs, comments, stars, follows or inauthentic engagement.

## LAW 6 — Least privilege

- Read-only workers do not receive write credentials.
- Review workflows use read-only contents permission unless a narrow comment permission is needed.
- Credentials are scoped to the smallest required repositories/actions.
- Never log tokens, authorization headers, private keys, secret/customer request bodies, or sensitive query strings.
- Never commit secrets.

## LAW 7 — CI/Actions must be deliberate

- Do not run full CI on every small worker push.
- Use concurrency cancellation for superseded branch/PR runs where appropriate.
- Do not rerun successful jobs.
- At most one explicitly justified rerun of a failed/transient job unless owner authorizes more.
- Documentation-only changes should not trigger heavy suites unless governance/release behavior changed.
- Scheduled jobs use the lowest sensible frequency.
- No workflow may intentionally create self-triggering/recursive GitHub activity.

## LAW 8 — Backups are conservative

Backup/export automation must:
- run owner-initiated or at deliberately low frequency;
- serialize GitHub metadata/API requests;
- stop on rate-limit/abuse signals;
- never use extra tokens/accounts to bypass limits;
- prefer Git mirror/bundle transport for repository content instead of repeatedly scraping files through API;
- never export secret values.

## LAW 9 — New GitHub automation is blocked until reviewed

Every new GitHub integration/entrypoint requires:
- explicit owner issue/scope;
- routing through the shared governor or independently reviewed successor;
- compliance checker/audit coverage;
- 403/429/circuit failure tests where applicable;
- exact-head CI evidence;
- independent hostile review for material changes.

An uncovered GitHub automation path is a release blocker.

## LAW 10 — Policy changes fail closed

If GitHub changes Terms, Acceptable Use Policies, API guidance or rate-limit behavior:
- stop affected automation when compliance is uncertain;
- apply the stricter safe interpretation;
- review official GitHub documentation;
- update this law, governor tests and audits in a dedicated PR;
- never relax safeguards merely because current traffic appears to work.

## Automatic blocking conditions

Stop GitHub automation when:
- governor circuit is open;
- 429 occurs;
- rate-limit/abuse 403 occurs;
- local hard budget is exhausted;
- an unknown GitHub automation path is detected;
- required governor client/module is unavailable;
- credentials are broader than needed and cannot be safely reduced;
- exact target/repository identity is not established for a mutation.

## Required checks

Every PR affecting GitHub automation must pass:

```text
node forgeboss/github/check-github-compliance-law.js
node forgeboss/github/test-request-governor.js
node forgeboss/github/audit-governor-bypasses.js
```

A green test is evidence, not permission to weaken this law.
