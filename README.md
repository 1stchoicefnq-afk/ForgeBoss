# ForgeBoss

**Open-source multi-agent AI software engineering supervisor. Help us build it.**

ForgeBoss coordinates multiple coding agents so they can work on the same software project without turning into an uncontrolled swarm. It is designed to give each worker a bounded task, isolated workspace, explicit write scope, budget authority, test requirements and independent review before code is accepted.

> **Status:** active development. ForgeBoss is not yet production-ready. The current milestone is proving that ForgeBoss can safely build ForgeBoss itself with multiple agents in parallel.

## Why ForgeBoss exists

Coding agents are already good at editing files. The harder problem is safely coordinating several of them at once.

ForgeBoss focuses on the cross-agent control layer:

- multiple builders working in parallel;
- isolated branches/worktrees;
- exact non-overlapping writable scopes;
- stale-head and scope validation;
- per-worker and global spend controls;
- frozen candidate SHAs;
- independent builder/reviewer separation;
- test and evidence collection;
- stop/reassign and recovery handling;
- known-good promotion and rollback;
- support for multiple upstream coding engines.

The architecture follows a **reuse-before-build** rule: ForgeBoss should wrap strong upstream coding engines rather than rebuild their reasoning loops, editors, shell tooling or model integrations.

Current/upcoming worker engines include Claude Code, mini-SWE-agent, OpenHands, OpenCode and other maintained systems where they fit the safety contract.

## The current finish line

**Finish Line 1: ForgeBoss builds ForgeBoss.**

A successful proof requires at least two builders operating concurrently on ForgeBoss itself with:

- separate branches/worktrees;
- non-overlapping write scopes;
- bounded worker/global spend;
- focused tests;
- scope/diff checks;
- frozen candidate SHAs;
- independent review;
- controller acceptance;
- stop/reassign behavior;
- known-good promotion or safe rollback.

See **Issue #15** for the full self-build contract and **Issue #4** for the live controller state.

## We want contributors

ForgeBoss is an open-source community project under the MIT License.

You do **not** need to understand the whole codebase to help. Good contributions include:

- reproducing bugs;
- improving Windows setup;
- writing tests;
- improving docs;
- reviewing isolated modules;
- hardening concurrency and recovery behavior;
- improving cross-platform support;
- adding thin adapters for upstream coding engines;
- improving developer experience;
- testing clean installs and failure paths.

Start with issues labelled **`good first issue`** or **`help wanted`**.

Before contributing, read `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `SECURITY.md`.

## Quick start

ForgeBoss is currently developed primarily on Windows 10/11.

Expected local tools include:

- Git;
- PowerShell / `pwsh`;
- Python;
- Node.js + npm;
- Docker for paths that require containerized testing.

From an extracted or cloned ForgeBoss folder:

```text
SETUP-FORGEBOSS-ENGINES.cmd
```

Then useful entry points include:

```text
START-FORGEBOSS.vbs
FORGEBOSSD-HEALTH.cmd
AUTOPILOT-STATUS.cmd
AUTOPILOT-DOCTOR.cmd
START-HYBRID-TESTS.cmd
```

The setup path is still being hardened. If a clean install fails or the instructions are unclear, please open an issue or pick up the clean-Windows setup task.

## Safety model

ForgeBoss uses a simple rule:

**Finding a problem is not permission to fix it. Assignment is permission to fix it. Independent review is permission to accept it.**

Core rules:

- no direct unreviewed production writes to `main`;
- no self-review or self-approval;
- exact writable scope before implementation;
- exact candidate SHA for review;
- runtime PASS requires actual runtime evidence;
- unknown or unavailable evidence is recorded as blocked, not invented;
- secrets, credentials and private runtime state do not belong in Git.

## Project control and roadmap

Important repository issues:

- **#4** — authoritative ForgeBoss control board;
- **#5** — findings and review-evidence ledger;
- **#6** — longer-term roadmap / architecture ideas;
- **#15** — Finish Line 1: multi-agent ForgeBoss builds ForgeBoss;
- **#16** — upstream-first / reuse-before-build architecture mandate;
- **#19** — Claude Code worker/reviewer integration.

Active worker-lane issues are internal engineering coordination. Community contributors should normally start from public `good first issue` / `help wanted` tasks instead of claiming controller-owned production lanes.

## Development workflow

Typical contribution flow:

```text
ISSUE / REPRODUCTION
        ↓
FORK + BRANCH
        ↓
SMALL FOCUSED CHANGE
        ↓
TESTS
        ↓
PULL REQUEST
        ↓
REVIEW
        ↓
MERGE
```

For controller-managed ForgeBoss production work, the stricter internal workflow also requires exact assignment scope, candidate freezing and independent acceptance evidence.

## Repository hygiene

Do not commit local runtime state or credentials. Examples that belong outside source control include:

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

If a real credential is ever committed, removing the file later is not enough. Rotate the credential and handle the history appropriately.

## Contributing

Want to help?

1. Pick a `good first issue` or `help wanted` task.
2. Comment that you are working on it.
3. Fork the repository and create a focused branch.
4. Make the smallest useful change.
5. Run the relevant tests.
6. Open a pull request using the repository template.

See `CONTRIBUTING.md` for the full process.

## License

ForgeBoss is licensed under the **MIT License**. See `LICENSE`.
