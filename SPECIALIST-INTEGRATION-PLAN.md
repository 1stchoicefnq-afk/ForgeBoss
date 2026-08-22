# SiteBoss Specialist Intelligence Integration — evidence-based first slice

## Current SiteBoss worker architecture inspected

1. Controller entry point: `controller/siteboss-autopilot.js`.
2. Packet building: `controller/lib/packet.js`; exact-head scope: `controller/lib/scope.js`.
3. OpenAI repair invocation: `SiteBoss-Repair-Rat.ps1` (`Invoke-OpenAI` / `Get-OrCreatePatch`).
4. Repair prompt construction: Repair Rat builds immutable repair instructions plus a structured payload containing exact head, evidence, allowed paths, source files and acceptance gates.
5. Worker lifecycle: controller -> exact control/mirror/scope -> Repair Rat disposable case-sensitive workspace -> patch cache -> apply -> repeated Docker/PostgreSQL validation.
6. Repair mode: bounded attempts, exact-head reset per attempt, write allowlist enforcement, cached paid responses.
7. Reviewer lifecycle: `SiteBoss-Rat-Review.ps1` reconstructs candidate, repeats acceptance, rechecks target head, invokes independent structured reviewer, and is forced to `-NoPublish` by the controller.
8. Configuration: `controller/config.default.json`, `PROVIDER-POLICY.json`, Repair Rat configuration.
9. GitHub state: read-only adapter `controller/adapters/Read-GitHub-Control.ps1`, dynamic exact-child/parent-head target selection.
10. Evidence/logging: controller JSON state/events plus `state/repair-rat`, `state/rat-review`, patch/review caches.
11. Tests: controller selftests, target/scope/scope-contract/scope-priority fixtures and legacy breaker/validation suites.

## Upstream Agency Agents evidence inspected

Pinned reviewed upstream: `msitarzewski/agency-agents@c89557f`.

Useful patterns:
- agent Markdown frontmatter + focused specialist persona;
- divisions as a machine-readable catalog concept (`divisions.json`);
- specialist roles in engineering, database, IAM, AI, DevOps, frontend and review;
- installer/converter/lint separation.

Not imported:
- Agency scheduling/orchestration authority;
- Agency installer behavior;
- any swarm/controller semantics;
- tool/permission assumptions;
- the full agent catalog.

## Highest-priority gap

SiteBoss's worker/reviewer prompts are strong but domain-hardcoded. The controller has no reusable, deterministic domain-specialist routing layer. The first slice adds specialist intelligence without changing controller authority, scope, writer caps, leases, exact-head binding or publication rules.

## First slice

- 10 concise Agency-derived specialist profiles with provenance.
- deterministic max-2 router;
- safe fallback;
- prompt composer with immutable governance first;
- Repair Rat builder integration;
- independent reviewer routing with builder-specialist exclusion;
- specialist IDs recorded in evidence;
- licensing/third-party notice;
- deterministic tests and no-model benchmark.

No merge/deploy/publication capability is added.
