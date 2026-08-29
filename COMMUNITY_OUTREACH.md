# ForgeBoss Community Outreach Kit

Use this copy when introducing ForgeBoss to developer communities. Keep posts factual: ForgeBoss is under active development and is not production-ready yet.

## Short post

**ForgeBoss is an open-source multi-agent AI software engineering supervisor.**

The goal is to coordinate multiple coding agents safely: isolated workspaces, non-overlapping write scopes, spend controls, frozen candidate SHAs, independent review, stop/reassign handling and known-good rollback.

The current milestone is deliberately hard: ForgeBoss must prove it can build ForgeBoss itself with multiple agents working in parallel before we call the core supervisor ready.

We are looking for contributors. You do not need to understand the entire project. There are `good first issue` and `help wanted` tasks for Windows setup, smoke tests, docs, Linux compatibility, path handling, validation tests, restart/cancellation behavior and coding-engine adapters.

Repo: https://github.com/1stchoicefnq-afk/ForgeBoss

## Reddit / forum post

### Title
Open-source project: coordinating multiple coding agents safely — contributors wanted

### Body
I am building **ForgeBoss**, an MIT-licensed open-source supervisor for multi-agent software engineering.

Instead of trying to build another coding-agent reasoning loop, ForgeBoss sits above existing engines and focuses on the coordination problems that appear when several agents work on one repository at once:

- isolated branches/worktrees;
- exact non-overlapping writable scopes;
- stale-head and scope checks;
- per-worker and global spend authority;
- frozen candidate SHAs;
- independent builder/reviewer separation;
- test/evidence collection;
- stop/reassign behavior;
- known-good promotion and rollback.

The current finish line is a real self-build proof: at least two workers modifying ForgeBoss concurrently on isolated scopes, independently reviewed and safely integrated.

It is still in active development, so I am specifically looking for people who enjoy testing, breaking assumptions, improving setup/docs, cross-platform work, concurrency/recovery testing, or thin integrations with existing coding-agent engines.

There are beginner-friendly and `help wanted` issues ready now.

Repo: https://github.com/1stchoicefnq-afk/ForgeBoss

Feedback and PRs are welcome.

## Hacker News / Show HN draft

### Title
Show HN: ForgeBoss – open-source supervisor for multiple coding agents

### Text
ForgeBoss is an MIT-licensed project exploring the control layer around multiple coding agents working on the same repository.

The project is intentionally upstream-first: coding intelligence stays in tools such as Claude Code, mini-SWE-agent, OpenHands, OpenCode and future engines. ForgeBoss focuses on cross-worker authority: isolated workspaces, write-scope allocation, collision prevention, spend controls, frozen candidates, independent review, stop/reassign and rollback.

The current milestone is to prove the system by having ForgeBoss safely build ForgeBoss itself with multiple workers in parallel.

It is not production-ready yet. I am opening it up early because clean-install testing, Windows/Linux compatibility, recovery/concurrency tests and outside architectural criticism are useful right now.

Repo: https://github.com/1stchoicefnq-afk/ForgeBoss

## Discord / chat post

Working on an open-source project called **ForgeBoss**: a supervisor for multiple AI coding agents working safely on one codebase. It handles isolated workspaces, non-overlapping scopes, spend controls, independent review and rollback rather than rebuilding the coding agents themselves.

It is early and not production-ready. We have `good first issue` and `help wanted` tasks open for setup, testing, docs, Linux support, path handling and engine adapters.

https://github.com/1stchoicefnq-afk/ForgeBoss

## Before posting

- make sure the README still accurately reflects the live milestone;
- link directly to the repository;
- do not claim production readiness;
- answer technical criticism openly;
- point newcomers toward `good first issue` and `help wanted` labels;
- never post API keys, private logs, customer information or private SiteBoss material.
