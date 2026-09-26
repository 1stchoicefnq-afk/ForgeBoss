# ForgeBoss Project Bootstrap Contract

Status: product contract / not yet runtime proof  
Tracking issue: #169

## Purpose

A project must never depend on a user remembering to paste a giant prompt into a model.

ForgeBoss itself must deterministically load the required engineering rules and current project truth before substantial project work starts.

A Markdown file may explain the contract to humans, but prompt text alone is not authority. The runtime must load authoritative, versioned project/bootstrap state.

## Startup rule

Before any substantial project action, ForgeBoss must:

1. load the authoritative ForgeBoss permanent-rules/bootstrap manifest;
2. verify its version and identity;
3. load required core engineering/safety/review rules;
4. inspect the selected project/workspace;
5. classify the project as NEW, EXISTING, or REPAIR_REVIEW;
6. load or initialize authoritative project records;
7. load/reconcile any durable active task/run state;
8. identify missing material decisions;
9. complete required upstream reuse review;
10. create a reviewed plan before substantial implementation.

If required authority, rules, identity, project truth or evidence is missing, ambiguous or unverifiable, ForgeBoss must report the gap and fail closed for affected actions.

## New project flow

For a NEW project:

1. capture the user's idea in ordinary language;
2. preserve the original intent;
3. derive explicit functional requirements;
4. derive non-functional requirements;
5. identify users/roles;
6. identify important user flows;
7. identify data and retention needs;
8. identify permissions and authority boundaries;
9. identify security/privacy constraints;
10. identify supported platforms;
11. complete the permanent upstream reuse review before inventing a substantial subsystem;
12. propose architecture;
13. identify failure/restart modes;
14. create acceptance criteria and test strategy;
15. record assumptions as explicit decisions;
16. identify questions that genuinely require owner input;
17. independently review the plan;
18. present a plain-English proposal to the owner;
19. only after required approvals, create bounded implementation work.

## Existing project flow

For an EXISTING project:

1. inspect the repository/workspace first;
2. identify canonical entry points;
3. identify build/test/start commands;
4. map architecture and dependencies;
5. discover existing requirements and documentation;
6. identify duplicate or historical execution paths;
7. identify authority-bearing components;
8. identify current tests and gaps;
9. identify reusable existing/upstream components before adding a new subsystem;
10. do not assume repository documentation is complete or correct;
11. record verified findings before planning changes.

## Repair/review flow

For REPAIR_REVIEW work:

1. reproduce the reported problem where practical;
2. identify the exact affected path and authority boundary;
3. inspect prior proven/failed repair memory without treating it as authority;
4. create a bounded repair plan;
5. add or identify a regression test;
6. implement through an isolated builder;
7. freeze the candidate;
8. independently review the exact candidate;
9. attack adjacent and alternate paths;
10. prove the regression test protects the fix;
11. bind acceptance evidence to the exact repaired candidate;
12. accept only through controller/release authority.

A failed attempt must not trigger a blind paid/model retry. ForgeBoss must gather new evidence or select a materially different bounded strategy first.

## Required project truth

ForgeBoss should maintain authoritative records equivalent to:

- PROJECT_IDEA
- REQUIREMENTS
- UPSTREAM_REUSE_REVIEW
- ARCHITECTURE
- AUTHORITY_MODEL
- SAFETY_RULES
- TEST_MATRIX
- DECISIONS
- COMPONENT_REGISTRY
- WORKER_REGISTRY
- ACTIVE_RUNS
- EVIDENCE_MANIFEST
- KNOWN_ISSUES
- STATUS
- RELEASE_PROOF
- DATA_POLICY
- NETWORK_POLICY
- BACKUP_MANIFEST
- AUDIT_TRAIL
- COMPATIBILITY_MATRIX

Exact filenames and storage formats may evolve.

The runtime must know which records are authoritative and their current version/identity.

## Permanent upstream reuse gate

The reuse-before-build rule is mandatory for ForgeBoss itself and every substantial project it builds.

Before substantial implementation, ForgeBoss must create an `UPSTREAM_REUSE_REVIEW` or equivalent structured record containing:

- the capability/subsystem being considered;
- repositories/packages/components searched;
- exact candidate versions or commits where relevant;
- license and carve-out checks;
- maintenance/platform/security fit;
- what can be reused unchanged;
- what requires an adapter or modification;
- what must remain ForgeBoss/project-owned;
- the selected component(s), or the explicit reason custom implementation is required.

A substantial subsystem is **not ready to build** if this review is absent.

The reuse gate never grants runtime authority to an upstream component. External code remains subordinate to ForgeBoss/project permissions, canonical state, approval, evidence and review rules.

## Worker/run identity contract

Every material task/run must carry durable identity sufficient to bind:

- project;
- task;
- role;
- worker identity;
- provider/model/tool route;
- authority/write scope;
- input/context version;
- source artifact/snapshot;
- start/end/status;
- output artifact/snapshot;
- evidence references;
- supersession/retry lineage.

Duplicate/conflicting identity or evidence must fail closed rather than being silently reconciled by a model.

## Durable resume contract

ForgeBoss must persist enough authoritative state to resume/reconcile long-running work after ordinary interruption.

On restart, ForgeBoss must not assume an in-flight action succeeded or failed solely from UI state or model narrative. It must reconcile persisted run state, process/tool state where available, artifacts and evidence.

Unsafe ambiguity becomes BLOCKED/NEEDS_OWNER/PROOF_INCOMPLETE rather than guessed completion.

## Chief of Staff contract

Chief of Staff reads authoritative run/task/evidence/approval state and creates an owner brief.

It must surface expected-vs-actual discrepancies, including SILENT and UNEXPECTED_RUN conditions.

Chief of Staff has no independent mutation, approval, merge, deploy, spend or permission authority.

## Worker Pack contract

Versioned Worker Packs may describe reusable roles/capabilities/routines.

A pack:

- cannot grant itself authority;
- cannot change permanent rules;
- cannot widen its own write/tool/spend scope;
- must preserve provenance/license/version identity;
- should self-test before activation;
- must preserve owner/project modifications during upgrade and surface conflicts.

## User ownership / export contract

A project must have a practical export path for user-owned source and authoritative project records required for continued work.

ForgeBoss must not make one provider/cloud service the only path to recover project truth.

Uninstall/delete flows must distinguish removing the application from deleting user projects/data. Destructive data deletion requires explicit owner intent.

## Data/privacy contract

Authoritative project policy must define relevant retention/deletion behavior and whether any telemetry is collected.

Hidden project/code telemetry is forbidden.

External model/tool calls must be treated as data egress and must be governed by the approved provider/tool/network policy.

## Secrets/network contract

Secrets belong in an appropriate secure credential store, not ordinary project truth files.

Secret access must be scoped to the smallest worker/tool/action that requires it, and ordinary logs/evidence must redact or omit secret values.

Network access for workers/tools must be policy-controlled. A worker does not gain unrestricted egress merely because it can execute code.

## Supply-chain contract

Adopted executable dependencies/components/packs/plugins must have recorded provenance sufficient to identify what code/version/license was trusted.

Authority/security-critical dependencies must be pinned.

Upgrades require a reviewed identity/version change and relevant regression/security tests.

Executable extension distribution must pin an exact identity/version and verify a cryptographic hash at minimum; signatures are additionally verified where supported. Installation is not an authority grant.

## Backup/recovery/update contract

Authoritative state must have a backup/restore strategy appropriate to deployment.

Risky/destructive migrations should verify a usable recovery point before mutation.

Application update flows must authenticate/identify the update and preserve a safe known-good recovery/rollback path.

## Isolation/audit contract

Projects are isolated by default for workspace, private context, credentials and evidence.

Cloud/team deployments must enforce tenant/account/team boundaries on the server side.

Material actions/approvals/authority changes/releases/destructive operations must be representable in a canonical audit trail.

Cancellation/supersession invalidates stale future authority and must be revalidated at the true mutation boundary.

## Cost contract

ForgeBoss should provide useful cost estimates/bounds before materially expensive work where practical and record actual spend afterward.

Hard owner/project/run ceilings are authority and cannot be widened by a provider/model/tool request.

## Compatibility/accessibility contract

Rulesets, projects, Worker Packs, adapters and state schemas must declare compatibility/version expectations.

ForgeBoss normal user workflows must maintain an accessibility baseline, including keyboard-operable material controls and readable status/approval information.

## Core engineering rules

ForgeBoss project work must preserve these principles:

- inspect and reuse proven components first;
- build only missing glue, control and safety where possible;
- plan before coding;
- adversarially review the plan;
- split work into small gated units;
- keep builder and reviewer logically separate;
- require tests and evidence before acceptance;
- preview before destructive actions;
- require human approval for risky actions unless explicitly delegated;
- prefer orchestration, context and verification over reinventing mature tools;
- use one clear authority path for important state mutation;
- fail closed when important authority cannot be established;
- validate at real trust boundaries, not only in the UI;
- test concurrency, retries, stale state, restart and partial failure where relevant;
- never call source inspection runtime proof;
- never call a green builder test independent verification;
- record uncertainty instead of inventing certainty.

## Hostile review standard

Treat every green test as provisional.

For important changes, reviewers should attempt relevant attacks such as:

- bypassing wrappers/frontends;
- calling underlying engines directly;
- using old/duplicate entry points;
- substituting stale state;
- concurrency and race conditions;
- crash/restart interruption;
- malformed or duplicate inputs;
- stale operations and replay;
- permission/authority loss;
- mutation/removal of safeguards;
- platform-specific failures;
- shutdown/startup races;
- partial persistence.

After one defect is fixed, continue checking adjacent paths.

## Regression proof

For an important fix:

1. reproduce the defect;
2. create a test that fails because of it;
3. implement the fix;
4. prove the test passes;
5. deliberately weaken/remove the protection where practical;
6. prove the test fails again;
7. restore the fix;
8. rerun relevant suites.

This distinguishes a real regression guard from a test that merely happens to pass.

## AI/provider/tool rule

Model output is a proposal, not authority.

The safe pattern is:

MODEL/TOOL PROPOSAL  
-> STRUCTURED VALIDATION  
-> POLICY/AUTHORITY CHECK  
-> HUMAN APPROVAL WHERE REQUIRED  
-> ACTION  
-> EVIDENCE

No model, worker engine, tool, plugin, pack, dependency or external service should receive broader permission merely because it requested it.

Model providers and commodity infrastructure should remain replaceable behind ForgeBoss-owned interfaces where practical.

## User question and notification rule

The user should not need to understand software engineering terminology to start a project.

ForgeBoss should make safe ordinary defaults where appropriate and ask the owner only when a material decision cannot safely be inferred.

Questions should be plain-language and decision-oriented.

Routine updates should be consolidated into the owner/Chief-of-Staff brief where practical. Urgent authority/safety failures may interrupt immediately.

## Status/UI rule

A UI label such as PASS, COMPLETE, FIXED, READY or SECURE must be derived from authoritative stored state/evidence.

A model-generated sentence is not status authority.

Desktop, mobile and web surfaces must show the same canonical project/run state, subject only to presentation differences.

## Release proof rule

The final release prover must operate on the exact final artifact/snapshot and exact evidence set.

Earlier proof does not automatically roll forward after a candidate changes.

Allowed high-level outcomes include:

- READY
- NEEDS_REPAIR
- BLOCKED
- PROOF_INCOMPLETE

Missing/unverifiable evidence cannot become READY.

## Definition of ready-to-build

Substantial implementation should not begin until the project has enough evidence for:

- explicit core requirements;
- known users/roles;
- chosen or bounded platforms;
- architecture direction;
- authority/security boundaries;
- test strategy;
- recorded material assumptions;
- unresolved owner decisions surfaced;
- independent plan review completed;
- upstream reuse review completed for each substantial subsystem;
- required worker/component identity/provenance defined;
- durable run/resume expectations defined where relevant.

If these are incomplete, status should say NOT YET PROVEN / NEEDS OWNER / BLOCKED as appropriate rather than pretending the project is ready.

## Future runtime requirement

ForgeBoss runtime must enforce this contract through a machine-readable permanent-rules/bootstrap manifest.

The manifest must identify required records, schema/version, identity/hash or equivalent, precedence and fail-closed behavior.

Do not rely on a language model voluntarily reading every Markdown file.