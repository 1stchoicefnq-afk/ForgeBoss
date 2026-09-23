# ForgeBoss End-User Product Vision

Status: post-Finish-Line-1 target  
Source tracking issue: #169  
Current FL1 authority remains Issues #4 and #15.

## Product statement

ForgeBoss is the user-facing engineering application.

The end user talks to ForgeBoss directly. They should not need to separately operate ChatGPT, Claude, Git, PowerShell, terminals, test runners, branches, worktrees, or coding-agent interfaces.

External and local AI models are replaceable worker engines behind ForgeBoss. ForgeBoss owns the project truth, workflow, permissions, evidence, decisions, state, safety gates, spend authority, and release process.

## Permanent product form

ForgeBoss has three coordinated surfaces with one canonical backend/project truth:

1. **Desktop app = primary engineering workshop.** This is where local files, code, terminals, Git, tests, sandboxes, local models and other heavy engineering work live.
2. **Mobile = companion remote control.** Mobile is for progress, notifications, owner decisions, approvals, failures, pause/stop actions and proof/status while the owner is away from the computer. It is not a second independent project authority.
3. **Web = account/cloud dashboard.** Web owns account, subscription/billing, cloud/project access, teams, backup/sync administration and remote monitoring.

Build order is desktop first, responsive phone web/PWA second, and native iOS/Android only when the product value justifies it.

All surfaces must read the same canonical ForgeBoss project/run state. A mobile/web display must never invent or maintain a competing project truth.

## Canonical user journey

A non-technical user should be able to:

1. install ForgeBoss;
2. open it;
3. connect one or more model providers or local engines;
4. click **New Project**;
5. describe an idea in ordinary language;
6. review a plain-English project proposal;
7. answer only material owner decisions;
8. approve the plan;
9. watch ForgeBoss plan, build, test, review, repair and prove the project;
10. preview and release the resulting product.

The user supplies the idea. ForgeBoss supplies the engineering system.

## Example

Jane types:

> I want an app for parents where they can give children chores, award points and let the children trade points for rewards.

ForgeBoss should turn that into explicit users, requirements, user flows, data model, platform assumptions, permissions, security rules, architecture, milestones, acceptance tests and owner decisions before substantial implementation starts.

Jane should not need to know how to write software requirements.

## ForgeBoss ownership boundary

ForgeBoss owns:

- the user-facing conversation;
- durable project context;
- authoritative requirements;
- recorded decisions and assumptions;
- architecture;
- authority and permissions model;
- safety rules;
- provider/model/tool routing;
- task decomposition;
- builder/reviewer separation;
- worker/run identity;
- budgets and spend authority;
- human approval gates;
- tests and evidence;
- project status;
- known issues;
- release-readiness proof.

AI providers, worker frameworks, tools, gateways, sandboxes, browsers, memory engines and plugins must not become the sole project memory or source of truth.

## Worker model

ForgeBoss may route different jobs to different engines.

Examples:

- planning -> one model;
- implementation -> another model;
- independent review -> separate worker/model identity;
- cheap repetitive work -> smaller or local model;
- deterministic validation -> non-model tools.

Provider selection must never weaken builder/reviewer separation or ForgeBoss authority.

Every material worker/run must have a durable identity sufficient to answer:

- which project/task/run it belonged to;
- which worker role performed it;
- which provider/model/tooling was used;
- which exact input/context/snapshot it operated on;
- which authority/write scope applied;
- what output/evidence it produced;
- whether the run completed, failed, blocked, paused or was superseded.

## Worker Pack model

Reusable workers should be distributed as versioned **Worker Packs** rather than ad-hoc prompts.

A Worker Pack may declare:

- role;
- version;
- capabilities;
- routines;
- required tools/routes;
- limits;
- evidence expectations;
- compatibility requirements.

A Worker Pack is descriptive. Installing or upgrading a pack must never grant itself runtime authority.

Pack upgrades must preserve owner/project modifications, record provenance and version/hash information, preview conflicts, and avoid silently overwriting locally modified content.

## Chief of Staff

Chief of Staff is a permanent ForgeBoss oversight role.

Its purpose is to reconcile what should have happened with what actually happened and give the owner one concise brief.

It should surface, at minimum:

- healthy work;
- partial work;
- blocked work;
- failed work;
- silent work that was expected but produced no evidence;
- paused work;
- work needing approval;
- unexpected work that ran when it was not expected or while paused.

Chief of Staff is **not** the controller, builder, reviewer, repair worker, approver, merger, deployer or source of authority. It reads authoritative state and reports it.

Where practical, ForgeBoss should consolidate routine worker notifications into the Chief of Staff/owner brief rather than interrupting the owner independently from every worker.

## Self-improvement boundary

ForgeBoss may learn from proven outcomes, but learning is never permission escalation.

Self-improvement, repair memory, learned skills, generated Worker Packs or model-authored configuration must never:

- rewrite or bypass immutable/base safety rules;
- grant broader tools, write scope, spend, merge, deploy, secret or approval authority;
- mark its own work accepted;
- change canonical evidence to make a result look successful;
- silently replace an authoritative rule/record with learned state.

Only independently proven lessons may be replayed automatically, and only when their preconditions still match authoritative current state.

## User experience target

The default UI should speak plain English.

Example:

- Project progress: 42%
- User accounts: complete
- Chore system: building
- Tests: 284 passed, 0 failed
- Review: current stage passed
- Needs owner: nothing

Technical evidence should remain available through a details/advanced view.

Displayed status must be derived from canonical stored state/evidence. Model-generated prose is not allowed to manufacture a PASS, FIXED, READY, SECURE or completed state.

## Owner interruption rule

ForgeBoss should not repeatedly ask the user questions that can be safely resolved by ordinary defaults.

It must ask for explicit owner decisions when they materially affect areas such as:

- money;
- security;
- permissions;
- privacy;
- external communications;
- data retention;
- irreversible architecture;
- platform support;
- destructive operations;
- publishing or deployment.

Material assumptions must be recorded as project decisions. They must not become hidden architecture.

Routine status should be consolidated into an owner brief where practical. Urgent safety/authority failures may interrupt immediately.

## Core delivery loop

ForgeBoss should operate through gated stages:

IDEA  
-> REQUIREMENTS  
-> UPSTREAM REUSE REVIEW  
-> ARCHITECTURE  
-> PLAN  
-> INDEPENDENT PLAN REVIEW  
-> OWNER APPROVAL WHERE REQUIRED  
-> BUILD  
-> TEST  
-> INDEPENDENT HOSTILE REVIEW  
-> REPAIR  
-> RETEST  
-> PROVE  
-> RELEASE CANDIDATE

A passing builder test is evidence, not final acceptance.

## Durable execution

Long-running work must survive ordinary interruption.

ForgeBoss should be able to recover/reconcile after:

- ForgeBoss process restart;
- desktop UI restart;
- worker/provider disconnect;
- computer sleep/reconnect where feasible;
- temporary network/API failure;
- worker crash;
- partial stage completion.

Resume must come from authoritative persisted run/task/evidence state, not from a model guessing what happened previously.

## Proof and release

Evidence is bound to the exact artifact/snapshot/run it proves.

Evidence from an earlier candidate cannot prove a later candidate merely because the later candidate looks similar.

Release proof must identify the exact final artifact/snapshot and derive its claims from stored evidence.

The release prover must use explicit outcomes such as:

- `READY`
- `NEEDS_REPAIR`
- `BLOCKED`
- `PROOF_INCOMPLETE`

Unknown/missing evidence cannot be converted into READY.

## User ownership and portability

The user's project belongs to the user.

ForgeBoss must support a documented export path that preserves, as applicable:

- source files;
- requirements and architecture;
- decisions;
- project configuration;
- Worker Pack/component provenance;
- relevant evidence/release records;
- other portable project metadata required to continue work elsewhere.

Export/import must not require continued access to one AI provider or proprietary ForgeBoss cloud service merely to recover the user's own source/project records.

Uninstalling ForgeBoss must not silently delete user project source or cloud/project data. Destructive deletion requires an explicit owner choice.

## Privacy, secrets and network boundary

ForgeBoss must make data movement visible and policy-controlled.

Permanent expectations:

- no hidden telemetry or undisclosed project/code collection;
- retention and deletion behavior is explicit;
- secrets are stored through an appropriate secure credential/vault mechanism rather than ordinary project files;
- secrets are scoped to the smallest worker/tool/action that needs them and masked from ordinary logs/evidence;
- worker/tool network egress is policy-controlled rather than unlimited by default;
- external services receive only the minimum context required for the approved task.

## Supply-chain and extension safety

ForgeBoss must know what executable third-party code it is trusting.

Releases/projects should maintain sufficient component provenance to produce an SBOM or equivalent dependency inventory.

Authority/security-critical dependencies should be pinned to reviewed versions. Dependency updates must be reviewed/tested rather than silently rolling to an unknown latest version.

Executable Worker Packs/plugins/extensions should be versioned and hash/signature verified where the distribution mechanism supports it. Installation never grants runtime capability automatically.

## Backup, recovery and updates

Important project/state transformations require a recovery path.

ForgeBoss must support tested backup/restore for authoritative project/runtime state appropriate to the deployment mode.

Before destructive migrations or irreversible state transformations, create or verify an appropriate backup/export where practical.

ForgeBoss application updates must be authenticated/versioned and support safe rollback or recovery to known-good when an update fails.

## Isolation and audit

Separate projects must not silently share private project context, secrets, workspaces or evidence.

Cloud/team features must enforce tenant/account/team boundaries server-side.

Material actions, approvals, authority changes, releases and destructive operations should be represented in one canonical audit trail sufficient to answer who/what/when/which authority/which artifact.

Cancellation/stop is an authority event: cancelled or superseded workers must not later resume and mutate state using stale authority.

## Cost and degraded operation

Before materially expensive work, ForgeBoss should show a useful estimate/bound where practical; after work, it should show actual recorded spend.

Hard owner/project/run spend ceilings remain authoritative even if a provider or worker requests more.

Local/degraded operation should continue where feasible when a provider/cloud service is unavailable. Loss of one replaceable external service must not destroy canonical project truth.

## Compatibility and accessibility

Rulesets, projects, Worker Packs, adapters and state schemas should declare compatibility/version expectations rather than fail mysteriously.

ForgeBoss itself should maintain an accessibility baseline for normal workflows, including keyboard-operable core actions and readable status/approval information.

## Definition of success

This vision is not complete merely because the UI exists or a prompt imitates it.

The end-to-end product must prove that:

- the user can work entirely through ForgeBoss;
- project and active-run truth survive process and model restarts;
- model providers, worker engines and commodity infrastructure can be replaced behind ForgeBoss-owned interfaces;
- bootstrap rules are loaded deterministically;
- requirements and important decisions are durable;
- builders cannot self-approve;
- safety does not depend only on prompt obedience;
- learned/self-improving state cannot rewrite authority;
- ForgeBoss can turn a rough idea into a tested, reviewed project;
- final proof is bound to the exact final artifact;
- technical evidence remains inspectable;
- desktop, mobile and web surfaces show the same canonical state;
- the non-technical user flow works without a separate chat application.

## Relationship to current ForgeBoss

This target extends the existing ForgeBoss controller, bounded worker, reviewer, isolation, evidence and known-good principles.

It must not bypass Finish Line 1.

Implementation begins only through normal ForgeBoss governance after the prerequisite finish line is legitimately complete.