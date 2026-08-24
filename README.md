# ForgeBoss

ForgeBoss is a controlled multi-agent software engineering system for building, repairing, testing, reviewing, and maintaining **any software project or repository** through bounded tasks, isolated branches/worktrees, automated checks, independent review, spend controls, and explicit controller approval.

It is **not a SiteBoss-specific tool**. SiteBoss is the first major real-world project ForgeBoss is being used to prove against, and ForgeBoss is also being designed to build and improve ForgeBoss itself.

> **Current status:** active development and hardening. ForgeBoss is not yet fully production-ready. Finish Line 1 is the proof that ForgeBoss can safely build ForgeBoss itself with multiple concurrent agents. SiteBoss comes after that proof.

## What ForgeBoss is for

A normal coding agent can edit files. ForgeBoss adds the orchestration and control layer needed to turn several coding agents into a safer, repeatable engineering system.

ForgeBoss is intended to work on projects such as:

- web applications;
- mobile applications;
- APIs and backend services;
- desktop software;
- internal business systems;
- automation tools;
- libraries and frameworks;
- infrastructure and developer tooling;
- existing legacy codebases;
- brand-new repositories;
- ForgeBoss itself.

The target repository is a project configuration choice, not part of ForgeBoss's identity.

## Core idea

ForgeBoss coordinates builders, reviewers, tests, repository isolation, budgets, evidence, and controller decisions around one or more target repositories.

Core capabilities include:

- bounded task packets with explicit writable paths;
- multiple builders working in parallel;
- separate builder and reviewer roles;
- one branch/worktree per worker;
- exact non-overlapping write scopes;
- stale-head/base validation;
- test and evidence collection;
- per-worker and global API spend controls;
- controller-managed assignment and collision prevention;
- stop/reassign handling;
- crash/restart and lease handling;
- exact-SHA independent review;
- controlled integration;
- known-good version promotion and rollback;
- specialist routing where useful;
- structured findings and review evidence in GitHub Issues;
- project switching without redesigning the orchestration layer.

The long-term goal is a general-purpose engineering control plane that can safely coordinate many AI-assisted workers across arbitrary software projects.

## Current Finish Line 1

The current first finish line is deliberately narrow:

**ForgeBoss must successfully build ForgeBoss itself using 2–4 concurrent builders.**

That proof requires:

- isolated branches/worktrees;
- exact non-overlapping writable scopes;
- controller-owned task assignment and collision prevention;
- stale-state protection;
- hard per-worker and global spend authority;
- focused tests and exact scope/diff evidence;
- independent exact-SHA review;
- stop/reassign proof;
- a frozen known-good controller while self-build workers modify ForgeBoss;
- promotion of a successful new ForgeBoss version only after required checks;
- rollback to the previous known-good ForgeBoss version if activation fails.

New findings do not automatically expand Finish Line 1. A new problem joins the critical path only if it directly breaks one of those already-defined requirements. Everything else goes to backlog.

## Project targets

ForgeBoss should treat the active project as an explicit target.

Planned operating model:

```text
Project Mode
    |
    +--> ForgeBoss
    |
    +--> SiteBoss
    |
    +--> Any other configured repository
```

A project target should define at minimum:

- repository identity;
- base/default branch;
- build/test commands;
- project-specific environment requirements;
- allowed and forbidden paths where needed;
- integration rules;
- deployment rules if deployment is enabled later.

The multi-agent safety model remains the same regardless of which project is selected.

## ForgeBoss self-build

ForgeBoss is explicitly designed to improve itself.

Self-build uses an extra known-good boundary:

1. the active controller runs from a frozen known-good ForgeBoss version;
2. builders edit only isolated ForgeBoss branches/worktrees;
3. builders cannot replace the running controller in place;
4. candidates freeze before review;
5. a different worker independently reviews the exact SHA;
6. controller acceptance requires scope, tests, review, spend and base/head checks;
7. the resulting ForgeBoss version must pass startup/control/selftests and required multi-agent checks before promotion;
8. failed activation rolls back to the previous known-good version.

Once this is proven, the same fleet can be pointed at other repositories.

## SiteBoss

SiteBoss is the first major target application for ForgeBoss, not the definition of ForgeBoss.

After ForgeBoss proves self-build and scales its worker fleet safely, SiteBoss will be used as the first large external product target for high-throughput parallel development.

Any SiteBoss-specific launchers, repair scripts, references or compatibility code currently in the repository should be treated as project adapters or historical implementation paths. Over time, project-specific behavior should move behind generic ForgeBoss project interfaces rather than define the core architecture.

## Safety and review model

ForgeBoss follows one core rule:

**Finding a problem is not permission to fix it. Controller assignment is permission to fix it. Independent review is permission to accept it.**

Additional rules:

- no worker may approve code it authored or materially changed;
- every write needs an explicit non-overlapping scope;
- reviewers evaluate the exact candidate SHA;
- source review does not become runtime PASS unless the required runtime test actually executed;
- builders and reviewers do not directly write the target project's protected main branch;
- merge/deployment authority remains separate from build authority;
- unavailable evidence is reported as blocked, never fabricated as PASS;
- live repository state wins over stale issue text or old SHAs.

## Root-cause-first repair protocol

ForgeBoss workers should diagnose before rewriting code.

For a reported failure:

1. reconstruct the exact history, candidate SHA and environment;
2. identify which candidate actually failed;
3. distinguish old rejected fixes from the current candidate;
4. reproduce the real behavior where possible;
5. determine why previous tests missed it;
6. trace the production root cause;
7. check whether a newer existing fix already solves it;
8. make the smallest real correction only when needed;
9. run focused and adjacent regressions;
10. freeze the exact candidate SHA;
11. send it to an independent reviewer;
12. revalidate live base/topology before integration.

This prevents repeated speculative rewrites and false confidence from weak tests.

## GitHub control structure

GitHub Issues are the durable source of truth for active ForgeBoss development:

- **Issue #4** — authoritative CONTROL board;
- **Issue #5** — findings and review-evidence ledger;
- **Issue #6** — longer-term roadmap / architecture ideas;
- **Issue #8** — Worker A / Chat 1 lane;
- **Issue #11** — Worker B / Chat 2 lane;
- **Issue #10** — Controller / Integration / Assist lane;
- **Issue #13** — Worker C / Chat 4 lane;
- **Issue #14** — Worker D / Chat 5 lane;
- **Issue #15** — Finish Line 1: multi-agent ForgeBoss builds ForgeBoss;
- **Issue #17** — Project Mode, self-build scale-up and later target switching.

Before acting on a task, workers should verify live `main` and read the latest relevant issue comments. Older issue bodies or comments may contain stale SHAs or superseded assignments.

## Requirements

ForgeBoss is primarily developed and tested on Windows today and currently expects the local environment used by its launchers and tests to provide:

- Windows 10/11;
- Git;
- PowerShell / `pwsh`;
- Python;
- Node.js + npm;
- Docker for project paths that require containerized execution;
- provider API credentials only when a paid model path is intentionally enabled.

Future project adapters may add project-specific requirements.

Do not store API keys, daemon secrets, private keys, runtime databases or other local state in Git.

## Setup

From an extracted ForgeBoss folder, run:

```text
SETUP-FORGEBOSS-ENGINES.cmd
```

This creates the isolated ForgeBoss Python runtime and installs supported executor dependencies.

The setup currently includes integrations for engines such as mini-SWE-agent, OpenHands, Deep Agents and OpenCode. ForgeBoss should prefer maintained upstream execution engines where practical while keeping ForgeBoss responsible for controller policy, isolation, scope, review, spend and evidence.

## Launchers

ForgeBoss evolved through several development stages, so some current launchers still contain SiteBoss-specific names.

Useful entry points include:

- `START-FORGEBOSS.vbs` — ForgeBoss launcher/dashboard;
- `FORGEBOSSD-HEALTH.cmd` — daemon/control-plane health;
- `AUTOPILOT-STATUS.cmd` — controller status;
- `AUTOPILOT-PLAN.cmd` — planning/control path;
- `AUTOPILOT-DOCTOR.cmd` — diagnostics;
- `AUTOPILOT-STOP.cmd` — stop request;
- `AUTOPILOT-RESUME.cmd` — resume path;
- `START-HYBRID-TESTS.cmd` — zero-model-spend validation path.

Existing `BUILD-SITEBOSS...` and SiteBoss Repair Rat scripts are project-specific integrations. They should not be interpreted as limiting ForgeBoss to SiteBoss.

## Tests and evidence

ForgeBoss uses Python, Node.js, PowerShell and Windows-specific checks.

Important principles:

- PASS must correspond to real assertions or successful required behavior;
- source-marker checks are not substitutes for behavioral execution;
- compile/static checks are not substitutes for runtime checks;
- Windows-specific behavior must be verified on Windows when required;
- source-only review is labelled source-only;
- exact candidate SHA and changed files are part of the evidence;
- runtime blockers are recorded explicitly;
- tests should prove the behavior that matters, not merely that expected text exists in a file.

The findings ledger in Issue #5 records defects, evidence, fix candidates, review results and controller acceptance state.

## Multi-worker operation

ForgeBoss is intended to scale beyond a single coding agent.

The operating model is:

1. controller loads the target project and current known-good/base state;
2. controller assigns non-overlapping tasks;
3. each builder receives its own branch/worktree and bounded packet;
4. workers build and test independently;
5. completed candidate SHAs freeze;
6. independent reviewers inspect exact SHAs;
7. controller integrates only reviewed candidates after fresh topology/base checks;
8. failed/hung work can be revoked and safely reassigned;
9. concurrency increases only after evidence shows the previous level is stable.

Workers should continue consuming safe Finish-Line work within a turn instead of stopping after one trivial task, while still preserving separate commit/test/review boundaries for each logical change.

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

If a secret is ever proven to have entered Git history, ignoring it later is not sufficient; the credential must be rotated and history handled appropriately.

## Development workflow

A normal ForgeBoss change moves through this lifecycle:

```text
REPRODUCE / DIAGNOSE
        ↓
ROOT CAUSE
        ↓
CONTROLLER ASSIGNMENT
        ↓
BUILDER BRANCH + EXACT SCOPE
        ↓
FOCUSED + ADJACENT TESTS
        ↓
CANDIDATE SHA FROZEN
        ↓
INDEPENDENT REVIEW
        ↓
CONTROLLER ACCEPT / REJECT
        ↓
INTEGRATION
```

A failed review returns the exact candidate for narrow rework. A builder does not modify a frozen candidate while another worker is reviewing it.

## Project direction

The product direction is:

**Build a general-purpose multi-agent software engineering control system that can safely work on ForgeBoss, SiteBoss, and arbitrary future repositories without redesigning the core orchestration layer for every project.**

Immediate sequence:

```text
Finish Line 1: ForgeBoss builds ForgeBoss
        ↓
Project Mode / target switching
        ↓
Scale ForgeBoss self-build worker count
        ↓
Switch target to SiteBoss
        ↓
Apply the proven fleet to SiteBoss
        ↓
Support additional projects/repositories
```

For live readiness or assignment decisions, do not rely on this README alone. Read **Issue #4 (CONTROL)** and **Issue #5 (LEDGER)** first.
