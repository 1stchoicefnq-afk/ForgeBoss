# ForgeBoss Community Growth Playbook

ForgeBoss should grow by making real engineering progress visible, reproducible and easy to contribute to.

## Core loop

`build -> publish proof -> contributors reproduce -> issues/ideas -> bounded assignments -> independent review -> ship -> credit contributors -> repeat`

## Principles

1. **Release useful proof early.** Do not wait for a giant finished launch. Publish small, concrete milestones when they are genuinely proven.
2. **Show evidence, not hype.** Exact SHAs, reproducible commands, supported platforms and known limitations are part of the product story.
3. **Make the first contribution small.** New contributors should be able to take one bounded task without understanding the entire control plane.
4. **Credit people visibly.** Release notes and changelogs should name contributors where appropriate.
5. **Turn failures into work.** Reproducible setup failures, engine incompatibilities and reliability defects should become well-scoped public issues.
6. **Reuse before build.** Community growth must reinforce the upstream-first architecture mandate rather than encourage duplicate local frameworks.
7. **Never weaken control for speed.** Contributor work touching controlled production scope still follows exact assignment, frozen candidate, independent review and evidence rules.

## Current launch gate

Finish Line 1 remains the immediate product proof: ForgeBoss safely builds ForgeBoss with multiple builders, independent review, finite spend, isolated workspaces, known-good promotion and rollback.

Until that proof is complete, community work should focus on non-colliding documentation, setup, compatibility, reproducible tests and bounded upstream adapter work approved through the normal controller process.

## Post-FL1 launch sequence

1. Publish the exact self-build proof and known limitations.
2. Provide the shortest reproducible demo path possible.
3. Invite a small technical founding group to reproduce the proof.
4. Convert every reproducible failure into a bounded issue.
5. Ship fixes frequently and publish a visible changelog.
6. Expand supported engines/platforms based on evidence.
7. Publish capability comparisons only from repeatable tests.

## Contributor funnel

A new contributor should be able to move through:

`README -> quick start -> successful smoke test -> good first issue -> branch -> tests -> PR -> independent review -> merged contribution`

Track where people drop out. Setup failures and unclear instructions are product defects for an open-source developer tool.

## Community-created value

High-value contribution categories include:

- upstream engine adapters;
- cross-platform compatibility fixes;
- deterministic reliability regressions;
- setup and diagnostics improvements;
- sample target repositories and demos;
- architecture/documentation improvements;
- evidence collection and reproducibility tooling;
- safe cross-engine policies that belong in the ForgeBoss supervisor layer.

## Visible development

For meaningful accepted milestones, publish concise notes containing:

- what became possible;
- exact accepted SHA/release;
- how to reproduce it;
- supported environments;
- important limitations;
- contributors involved;
- next bounded milestone.

Do not describe planned or source-inspected behavior as runtime-proven.

## Metrics

Useful community/product metrics:

- clean-install success rate;
- median time to first successful run;
- clone-to-first-PR conversion;
- external contributors with merged work;
- repeat contributors;
- open vs resolved setup failures;
- Windows/Linux reproducibility coverage;
- supported upstream engines with proven adapters;
- percentage of worker capability reused from upstream instead of duplicated locally.

## Anti-patterns

Do not use:

- artificial stars/followers;
- spam promotion;
- fake benchmarks;
- exaggerated capability claims;
- giant unreviewable community PRs;
- direct main writes that bypass the controller model;
- private repository/customer data in public examples;
- secret or credential material in demos or issue evidence.

## Durable tracking

Community growth backlog and launch work is tracked in Issue #135. Finish Line 1 and the authoritative control board continue to take precedence over this playbook whenever scopes conflict.
