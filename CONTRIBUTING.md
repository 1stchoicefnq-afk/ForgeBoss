# Contributing to ForgeBoss

Thanks for helping build ForgeBoss.

ForgeBoss is an open-source control layer for safer AI-assisted software engineering. Contributions are welcome from developers, testers, security reviewers, documentation writers and people who can break things in useful ways.

## Before you start

1. Read `README.md`.
2. Check existing Issues and Pull Requests so work is not duplicated.
3. For anything larger than a small fix, open or claim an Issue first.
4. Never include API keys, credentials, customer data, private repositories, runtime databases or other secrets.

## Good ways to contribute

- reproduce and fix bugs;
- improve Windows reliability;
- add tests and failure cases;
- harden security and path/process handling;
- improve crash recovery and concurrency behavior;
- improve provider/executor integrations;
- reduce unnecessary model spend;
- improve documentation and setup;
- add deterministic test fixtures;
- review Pull Requests independently.

Look for Issues labelled `good first issue` or `help wanted`.

## Development workflow

1. Fork the repository.
2. Create a focused branch from current `main`.
3. Make one logical change per Pull Request where practical.
4. Add or update tests for behavior changes.
5. Run the relevant checks locally.
6. Open a Pull Request and complete the template.
7. Respond to review findings with code or evidence.

Do not push directly to `main` unless you are a maintainer specifically performing repository administration.

## Pull Request expectations

A useful PR should state:

- what problem it solves;
- what files changed;
- how it was tested;
- operating-system assumptions;
- security or spend implications;
- known limitations.

A source inspection is not the same as a runtime test. Do not claim a runtime PASS unless that behavior actually ran.

## Scope and safety

ForgeBoss is specifically designed around bounded work. Contributors should follow the same principle:

- keep changes scoped;
- avoid unrelated refactors;
- do not weaken validation or safety gates merely to make tests pass;
- fail closed for security-sensitive behavior;
- preserve independent review boundaries;
- document behavior that cannot be tested in your environment.

## Commit style

Use short, descriptive commit messages. Examples:

```text
fix: reject stale candidate sha

test: add windows subprocess regression

docs: clarify local setup
```

## Reporting security problems

Do not publish exploitable secrets or sensitive vulnerabilities in a public Issue. Follow `SECURITY.md`.

## Code of conduct

Participation in this project requires following `CODE_OF_CONDUCT.md`.
