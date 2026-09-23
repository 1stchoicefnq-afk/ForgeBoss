# ForgeBoss Core Project Engineering Rules

Status: product-level rules for future project mode  
Tracking issue: #169

These rules describe the minimum project-engineering behavior ForgeBoss should automatically apply when operating on user projects and when building ForgeBoss itself.

## Permanent rules

1. Inspect before editing.
2. Reuse proven components before rebuilding them. This is a permanent, non-optional ForgeBoss rule.
3. Plan before substantial implementation.
4. Review the plan adversarially before execution.
5. Split work into bounded, reviewable units.
6. Separate builder and reviewer roles.
7. Do not let a worker approve its own material changes.
8. Require tests and evidence before acceptance.
9. Treat green tests as provisional until independent review.
10. Check alternate, historical and underlying execution paths.
11. Put important permission checks at the true action/mutation boundary.
12. Prefer one authoritative implementation for important state.
13. Fail closed when safety, identity, evidence or authority is unknown.
14. Require human approval for high-risk actions unless the owner explicitly delegated that exact authority.
15. Preview destructive actions where practical.
16. Record material assumptions as durable decisions.
17. Do not silently invent missing requirements, evidence, metrics or causes.
18. Test both successful and failure paths.
19. Test concurrency, stale state, retries, restart and partial failure where the domain requires it.
20. Do not call portable proof native-platform proof.
21. Do not claim tests that were not actually run.
22. Do not claim FIXED, VERIFIED, SECURE, RELEASE READY or PRODUCTION READY without supporting exact evidence.
23. Keep project documentation concise, authoritative and machine-loadable.
24. Keep secrets out of source control, prompts, logs and evidence exports.
25. Keep model providers replaceable; provider chat history must not be the only project memory.
26. Preserve exact evidence sufficient for another worker/reviewer to reproduce important claims.
27. Prefer reversible changes and known-good rollback paths.
28. Make risky authority explicit rather than implicit.
29. If a requirement materially affects money, security, privacy, permissions, data, platform support or irreversible architecture, record and surface the decision.
30. The final objective is not simply code generation. It is a product whose important behavior can be tested, reviewed and proven.
31. Every material worker/task/run must have durable identity and provenance.
32. Expected work with no evidence is SILENT; unexpected work must be surfaced rather than ignored.
33. A paused worker/routine that still executes is unexpected activity and must be surfaced.
34. Learned/self-improving state cannot rewrite base rules, permissions, canonical evidence or acceptance state.
35. Only independently proven repair lessons may be automatically replayed, and only when authoritative preconditions still match.
36. Do not perform blind model/paid retries. A retry must be justified by new evidence, a corrected precondition, or a materially different bounded strategy.
37. Prefer deterministic/local/free validation before buying another model call when it can answer the question reliably.
38. Evidence from an older artifact/snapshot/run cannot prove a newer one.
39. Final release proof must be bound to the exact final artifact/snapshot and exact evidence set.
40. UI status must be derived from canonical stored state/evidence, not model-generated prose.
41. Long-running work must be resumable/reconcilable from durable state after ordinary process/worker interruption.
42. Providers, worker engines, gateways, workflow engines, sandboxes, browsers, memory engines, integrations and other commodity infrastructure should remain replaceable behind ForgeBoss-owned interfaces where practical.
43. Installed workers, packs, plugins, skills or dependencies cannot grant themselves broader capabilities or authority.
44. Chief of Staff is observer/reporting only and cannot become a mutation/approval authority.
45. Routine worker notifications should be consolidated into an owner brief where practical; urgent safety/authority failures may interrupt immediately.
46. Worker Pack installation/upgrades must preserve provenance and owner/project modifications and must not silently overwrite conflicts.
47. Desktop, mobile and web surfaces must consume the same canonical ForgeBoss project/run truth.
48. The end user should not need a separate AI chat, Git client, PowerShell/terminal workflow or coding-agent UI to use ForgeBoss's normal product path.
49. Release proving must produce an explicit outcome such as READY, NEEDS_REPAIR, BLOCKED or PROOF_INCOMPLETE.
50. Missing or unverifiable evidence must never be translated into READY.
51. The user owns their project/source and must have a practical export/import path.
52. Uninstall or account changes must not silently destroy user project source/data.
53. Authoritative project/runtime state must have a tested backup/restore strategy appropriate to its deployment mode.
54. Data retention/deletion and telemetry behavior must be explicit; hidden telemetry/collection is forbidden.
55. Worker/tool network egress must be policy-controlled and least-necessary for the approved task.
56. Secrets must use an appropriate secure store, least-privilege scoping and log/evidence masking.
57. Releases/projects must maintain sufficient third-party provenance for an SBOM or equivalent dependency inventory.
58. Authority/security-critical dependencies must be pinned to reviewed versions/identities.
59. Dependency upgrades must be reviewed and tested; do not silently follow an unreviewed latest version.
60. Executable Worker Packs/plugins/extensions must be identity/version/hash/signature verified where the distribution model supports it.
61. Installing a plugin/extension/pack never grants capabilities automatically; declared capabilities remain subject to ForgeBoss authority.
62. ForgeBoss application updates must be authenticated/versioned and have known-good rollback/recovery behavior.
63. Projects must be isolated from one another for private context, secrets, workspace and evidence unless explicit sharing is authorised.
64. Cloud/team features must enforce tenant/account/team isolation server-side.
65. Material actions/approvals/authority changes/releases/destructive operations belong in a canonical audit trail.
66. Cancellation/stop revokes future stale authority; a cancelled/superseded worker cannot later resume mutation without fresh authority.
67. Schema/state migrations require forward validation and a rollback/recovery strategy appropriate to the risk.
68. ForgeBoss itself maintains an accessibility baseline for normal user workflows.
69. Local/degraded operation should continue where practical when optional cloud/provider services are unavailable.
70. Before destructive project-state migrations, create or verify an appropriate backup/export where practical.
71. Rulesets/projects/Worker Packs/adapters/state schemas must declare compatibility/version expectations.
72. Cost estimates/bounds should be shown before materially expensive work where practical, and actual recorded spend shown afterward.
73. Hard owner/project/run spend ceilings cannot be bypassed by models, workers, tools or providers.

## Permanent reuse-before-build rule

Before designing or implementing any substantial subsystem, ForgeBoss must perform an upstream reuse review.

The review must:

1. search for existing maintained components, libraries, frameworks, SDKs, tools or reference implementations that already solve all or part of the problem;
2. prefer permissively licensed, actively maintained components when they satisfy the engineering and safety requirements;
3. verify the exact license, relevant enterprise carve-outs, provenance, maintenance state, platform fit, transitive dependencies and security implications before adoption;
4. prefer a thin ForgeBoss-owned adapter around a proven component over reimplementing commodity functionality;
5. preserve ForgeBoss ownership of authority, approvals, canonical project state, evidence binding, hostile-review gates and user-facing workflow;
6. keep adopted components replaceable behind ForgeBoss-owned interfaces where practical;
7. record the candidates considered, the selected component or the reason no suitable component exists;
8. build from scratch only when the reuse review shows a real gap, unacceptable risk, incompatible license, excessive complexity or a requirement unique to ForgeBoss.

For substantial work, the implementation plan must contain an explicit `UPSTREAM_REUSE_REVIEW` (or equivalent structured record). If that review is missing, ForgeBoss must not treat the work as ready to build.

This rule applies to ForgeBoss itself and to software projects ForgeBoss builds.

## Retry and spend rule

A retry is not a plan.

Before another paid/model attempt after a failure, ForgeBoss must identify at least one of:

- new evidence;
- corrected/missing context;
- corrected authority/precondition;
- a smaller/focused target;
- a materially different strategy;
- a different worker/tool chosen for a recorded reason.

If none exists, another paid/model attempt is a blind retry and must be blocked.

Deterministic validators, existing tests, local indexes, parsers, static analysis, stored evidence and other non-model checks should be used first when they can answer the question reliably.

## Evidence-finality rule

All acceptance/proof claims must identify the exact subject they prove.

Important evidence should bind, as applicable, to:

- project;
- task;
- run;
- worker identity;
- artifact/snapshot/commit/hash;
- test/reviewer/prover identity;
- timestamp/version;
- authoritative rule/policy version.

If the subject changes, prior proof becomes historical evidence and cannot automatically prove the new subject.

## Self-improvement rule

ForgeBoss may accumulate proven repair lessons, skills, routing knowledge and performance history.

Self-improvement is subordinate to immutable governance.

Learned state must never:

- modify its own acceptance criteria after seeing a result merely to make it pass;
- widen authority, scope, tools, spend or permissions;
- weaken builder/reviewer separation;
- alter canonical evidence/history;
- silently edit permanent rules;
- bypass required owner approval;
- promote itself or its own work.

## Worker Pack rule

Reusable worker capability should be packaged as versioned Worker Packs where practical.

Packs must declare identity/version/capabilities/routines/compatibility and remain descriptive rather than authoritative.

Installation/upgrades must:

- record upstream/provenance/license/version/hash;
- preserve owner/project modifications;
- preview conflicts;
- avoid silent overwrite;
- run pack self-tests before activation where practical;
- require normal ForgeBoss authority for any capability actually exercised.

## Required questions for every substantial feature

ForgeBoss should be able to answer:

- What exactly is being built?
- Why is it required?
- Which authority owns the decision/action?
- What existing component can be reused?
- What can fail?
- How will failure behave?
- How will we test it?
- How could the intended path be bypassed?
- What evidence proves the result?
- What exact artifact/snapshot does that evidence prove?
- How will the work resume after interruption?
- What remains uncertain?
- Does the owner need to approve anything before proceeding?

If ForgeBoss cannot answer a material question, it must resolve or explicitly record the gap before treating the feature as complete.