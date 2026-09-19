# ForgeBoss Project Bootstrap Contract

Status: product contract / not yet runtime proof  
Tracking issue: #169

## Purpose

A project must never depend on a user remembering to paste a giant prompt into a model.

ForgeBoss itself must deterministically load the required engineering rules and current project truth before substantial project work starts.

A Markdown file may explain the contract to humans, but prompt text alone is not authority. The runtime must load authoritative, versioned project/bootstrap state.

## Startup rule

Before any substantial project action, ForgeBoss must:

1. load the authoritative ForgeBoss bootstrap manifest/policy;
2. verify its version and identity;
3. load required core engineering/safety/review rules;
4. inspect the selected project/workspace;
5. classify the project as NEW, EXISTING, or REPAIR_REVIEW;
6. load or initialize authoritative project records;
7. identify missing material decisions;
8. create a reviewed plan before substantial implementation.

If required authority or project truth is missing, ambiguous or unverifiable, ForgeBoss must report the gap and fail closed for affected high-risk actions.

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
11. search for proven components/dependencies before reinventing them;
12. propose architecture;
13. identify failure modes;
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
9. do not assume the repository documentation is complete or correct;
10. record verified findings before planning changes.

## Repair/review flow

For REPAIR_REVIEW work:

1. reproduce the reported problem where practical;
2. identify the exact affected path and authority boundary;
3. create a bounded repair plan;
4. add or identify a regression test;
5. implement through an isolated builder;
6. freeze the candidate;
7. independently review the exact candidate;
8. attack adjacent and alternate paths;
9. prove the regression test protects the fix;
10. accept only through controller/release authority.

## Required project truth

ForgeBoss should maintain authoritative records equivalent to:

- PROJECT_IDEA
- REQUIREMENTS
- ARCHITECTURE
- AUTHORITY_MODEL
- SAFETY_RULES
- TEST_MATRIX
- DECISIONS
- KNOWN_ISSUES
- STATUS

Exact filenames and storage formats may evolve.

The runtime must know which records are authoritative and their current version/identity.

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
- test concurrency, retries, stale state and partial failure where relevant;
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

## AI provider rule

Model output is a proposal, not authority.

The safe pattern is:

MODEL PROPOSAL  
-> STRUCTURED VALIDATION  
-> POLICY/AUTHORITY CHECK  
-> HUMAN APPROVAL WHERE REQUIRED  
-> ACTION  
-> EVIDENCE

No model should receive broader permission merely because it requested it.

## User question rule

The user should not need to understand software engineering terminology to start a project.

ForgeBoss should make safe ordinary defaults where appropriate and ask the owner only when a material decision cannot safely be inferred.

Questions should be plain-language and decision-oriented.

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
- independent plan review completed.

If these are incomplete, status should say NOT YET PROVEN / NEEDS OWNER / BLOCKED as appropriate rather than pretending the project is ready.

## Future runtime requirement

A future ForgeBoss runtime should enforce this contract through a machine-readable bootstrap manifest.

The manifest should identify required records, schema/version, hashes or equivalent identity, precedence and fail-closed behavior.

Do not rely on a language model voluntarily reading every Markdown file.
