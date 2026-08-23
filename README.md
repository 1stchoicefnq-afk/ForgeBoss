# ForgeBoss

ForgeBoss is a controlled AI-assisted software build and repair system designed to work on SiteBoss through bounded tasks, isolated branches/worktrees, automated checks, independent review, and explicit controller approval.

> **Current status:** active development and hardening. ForgeBoss is **not yet fully production-ready**. A restricted MVP mode exists for low-risk SiteBoss work while deeper hardening continues in parallel.

## What ForgeBoss is trying to solve

A normal coding agent can edit files. ForgeBoss adds the control layer needed to make that process safer and repeatable:

- bounded task packets with explicit writable paths;
- separate builder and reviewer roles;
- branch/worktree isolation;
- stale-head and scope validation;
- test and evidence collection;
- spend/cost controls;
- controller-managed task assignment;
- crash/restart and lease handling;
- specialist routing for different engineering tasks;
- structured findings and review evidence in GitHub Issues;
- gradual multi-worker operation rather than uncontrolled agent swarms.

The long-term goal is for ForgeBoss to coordinate multiple engineering workers that can safely build and maintain SiteBoss with strong evidence, review, spend and isolation controls.

## Current operating model

ForgeBoss currently runs two tracks at the same time.

### Track A — Controlled SiteBoss MVP use

ForgeBoss may be used for tightly bounded, low-risk SiteBoss tasks under Issue **#15 — MVP TRACK — Controlled SiteBoss Build Mode**.

Initial MVP rules include:

- maximum **1 active ForgeBoss builder** on SiteBoss at a time unless the controller explicitly raises it;
- separate branch/worktree required;
- exact writable paths declared before work begins;
- no direct writes to SiteBoss `main`;
- no automatic merge;
- mandatory independent review on the exact candidate SHA;
- focused tests required;
- stale-head revalidation before handoff/acceptance;
- no first-run database migrations, auth/permission changes, payment/billing work, deployment, destructive data operations, secret handling, or infrastructure changes.

Good first MVP jobs are deterministic tests, isolated business-logic fixes, small UI fixes, dead-code cleanup, narrow bug fixes, and documentation/build-tooling changes.

### Track B — ForgeBoss hardening

The hardening queue continues in parallel. Current work covers areas such as:

- spend and hard-cap correctness;
- durable transaction and lease behavior;
- Windows release-gate execution proof;
- Git metadata mutation visibility;
- restart/idempotency behavior;
- scope/provenance validation;
- multi-worker collision and recovery testing.

Hardening findings block any claim that ForgeBoss is fully ready, but they do not automatically block a low-risk MVP SiteBoss task that is outside the affected capability and satisfies the MVP contract.

## Safety and review model

ForgeBoss follows one core rule:

**Finding a problem is not permission to fix it. Controller assignment is permission to fix it. Independent review is permission to accept it.**

Additional rules:

- no worker may approve code it authored or materially changed;
- every production write needs an explicit non-overlapping scope;
- reviewers evaluate the exact candidate SHA;
- a source review does not become a runtime PASS unless the required runtime test actually executed;
- no self-merge;
- merge/deployment authority remains separate from build authority;
- when evidence is unavailable, ForgeBoss records the result as blocked instead of fabricating PASS evidence.

## GitHub control structure

The GitHub Issues in this repository are the durable source of truth for active work:

- **Issue #4** — authoritative CONTROL board;
- **Issue #5** — findings and review-evidence ledger;
- **Issue #6** — longer-term roadmap / architecture ideas;
- **Issue #8** — Worker A / Chat 1 lane;
- **Issue #11** — Worker B / Chat 2 lane;
- **Issue #10** — Controller / Integration / Assist lane;
- **Issue #13** — Worker C / Chat 4 lane;
- **Issue #14** — Worker D / Chat 5 lane;
- **Issue #15** — controlled SiteBoss MVP operating mode.

Before acting on a task, workers should verify live `main` and read the latest relevant issue comments. Older issue bodies or comments may contain stale SHAs or superseded assignments.

## Requirements

ForgeBoss is primarily developed for Windows and currently expects the local environment used by its launchers and tests to provide:

- Windows 10/11;
- Git;
- PowerShell / `pwsh`;
- Python;
- Node.js + npm;
- Docker for the SiteBoss repair/test paths that require it;
- provider API credentials only when a paid model path is intentionally enabled.

Do not store API keys, daemon secrets, private keys, runtime databases or other local state in Git.

## Setup

From an extracted ForgeBoss folder, run:

```text
SETUP-FORGEBOSS-ENGINES.cmd
```

This creates the isolated ForgeBoss Python runtime and installs the supported open-source executor dependencies.

The current setup script installs pinned OpenHands, mini-SWE-agent and Deep Agents versions. OpenCode setup is also present; its version-pinning/reproducibility behavior is part of the active hardening backlog.

## Launchers

Several launchers currently exist because ForgeBoss evolved through multiple development stages. Some are aliases and some are legacy paths. Do not assume that similarly named files have different behavior without checking the current source.

Useful current entry points include:

- `START-FORGEBOSS.vbs` — desktop/dashboard launcher after the runtime is installed;
- `FORGEBOSSD-HEALTH.cmd` — daemon/control-plane health check;
- `AUTOPILOT-STATUS.cmd` — controller status;
- `AUTOPILOT-PLAN.cmd` — planning/control path;
- `AUTOPILOT-DOCTOR.cmd` — diagnostics;
- `AUTOPILOT-STOP.cmd` — stop request;
- `AUTOPILOT-RESUME.cmd` — resume path;
- `START-HYBRID-TESTS.cmd` — zero-model-spend hybrid validation path;
- `BUILD-SITEBOSS.cmd` / `BUILD-SITEBOSS-WITH-FORGEBOSS.cmd` — bounded SiteBoss build launchers, still subject to the active safety gates and current controller state.

Some launcher duplication and naming cleanup is still tracked as maintenance work.

## Tests and evidence

ForgeBoss uses a mix of Python, Node.js, PowerShell and Windows-specific checks. Important principles:

- a test marked PASS must correspond to an actual assertion or successful required behavior;
- compile/static checks are not substitutes for behavioral runtime checks;
- Windows-specific PowerShell behavior must be verified on Windows where required;
- source-only review must be labelled as source-only;
- exact candidate SHA and exact changed files are part of the review evidence;
- runtime blockers are recorded instead of being silently downgraded.

The active findings ledger in Issue #5 contains the exact defect, severity, reproduction/evidence, fix SHA, reviewer and acceptance state for tracked findings.

## Multi-worker operation

ForgeBoss supports multiple engineering lanes, but full parallel SiteBoss operation is intentionally gated.

Current policy:

1. drain independent reviews first;
2. otherwise build explicitly assigned non-overlapping work;
3. otherwise perform read-only defensive QA on an unclaimed subsystem;
4. never self-review;
5. never let two builders own the same write scope.

Full parallel readiness is not claimed until the dedicated transaction/isolation work and an end-to-end multi-worker collision/recovery proof pass.

## Repository state and secrets

Local runtime state belongs outside committed source. Examples include:

```text
state/
.env
.env.*
*.db
*.bin
*.pem
*.key
venv/
node_modules/
```

The repository is actively tightening ignore rules and historical secret/state checks. If any secret is ever proven to have entered Git history, ignoring it later is not sufficient; the credential must be rotated and history handled appropriately.

## Development workflow

A normal ForgeBoss finding moves through this lifecycle:

```text
AUDIT / REPRODUCE
        ↓
CONTROLLER ASSIGNMENT
        ↓
BUILDER BRANCH + EXACT SCOPE
        ↓
FOCUSED TESTS
        ↓
CANDIDATE SHA FROZEN
        ↓
INDEPENDENT REVIEW
        ↓
CONTROLLER ACCEPT / REJECT
        ↓
INTEGRATION
```

A failed review returns the exact candidate for rework. A builder does not modify a frozen candidate while another worker is reviewing it.

## Project direction

The immediate goal is practical rather than theoretical:

**Get ForgeBoss safely doing useful SiteBoss work now under a narrow MVP envelope, while continuing to harden the system toward reliable multi-worker autonomous engineering.**

For the live state, do not rely on this README alone. Read **Issue #4 (CONTROL)** and **Issue #5 (LEDGER)** before making release, readiness or active-assignment decisions.
