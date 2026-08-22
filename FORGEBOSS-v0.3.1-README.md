# ForgeBoss v0.3.1 — Case Collision + Executor Adapter Hotfix

Canonical SiteBoss pull-request template path is now **`.github/pull_request_template.md`**.

GitHub's documentation uses this lowercase path for the single default template. The existing uppercase duplicate is treated as a legacy case-collision candidate and is never whitelisted into application repair scope.

This version:
- provides mini-SWE's required system/instance templates;
- isolates OpenHands runtime/home state outside the repository;
- uses case-sensitive Windows tournament workspaces;
- refuses a dirty exact-head baseline before either worker runs;
- parses `git status --porcelain=v1 -z`;
- attributes only worker delta relative to baseline;
- provides a zero-cost dashboard action that prepares a local cleanup patch deleting only `.github/PULL_REQUEST_TEMPLATE.md` while retaining `.github/pull_request_template.md`;
- does **not** publish that hygiene patch automatically.

The hygiene cleanup is deliberately separate from application repairs so a repository metadata cleanup never contaminates a SiteBoss feature/bugfix candidate.
