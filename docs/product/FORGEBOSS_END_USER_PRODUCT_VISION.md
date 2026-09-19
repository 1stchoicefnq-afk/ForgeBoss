# ForgeBoss End-User Product Vision

Status: post-Finish-Line-1 target  
Source tracking issue: #169  
Current FL1 authority remains Issues #4 and #15.

## Product statement

ForgeBoss is the user-facing engineering application.

The end user talks to ForgeBoss directly. They should not need to separately operate ChatGPT, Claude, Git, PowerShell, terminals, test runners, branches, worktrees, or coding-agent interfaces.

External and local AI models are replaceable worker engines behind ForgeBoss. ForgeBoss owns the project truth, workflow, permissions, evidence, decisions, state, safety gates, spend authority, and release process.

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
- provider/model routing;
- task decomposition;
- builder/reviewer separation;
- budgets and spend authority;
- human approval gates;
- tests and evidence;
- project status;
- known issues;
- release-readiness proof.

AI providers must not become the sole project memory or source of truth.

## Worker model

ForgeBoss may route different jobs to different engines.

Examples:

- planning -> one model;
- implementation -> another model;
- independent review -> separate worker/model identity;
- cheap repetitive work -> smaller or local model;
- deterministic validation -> non-model tools.

Provider selection must never weaken builder/reviewer separation or ForgeBoss authority.

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

## Core delivery loop

ForgeBoss should operate through gated stages:

IDEA  
-> REQUIREMENTS  
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

## Definition of success

This vision is not complete merely because the UI exists or a prompt imitates it.

The end-to-end product must prove that:

- the user can work entirely through ForgeBoss;
- project truth survives process and model restarts;
- model providers can be replaced;
- bootstrap rules are loaded deterministically;
- requirements and important decisions are durable;
- builders cannot self-approve;
- safety does not depend only on prompt obedience;
- ForgeBoss can turn a rough idea into a tested, reviewed project;
- technical evidence remains inspectable;
- the non-technical user flow works without a separate chat application.

## Relationship to current ForgeBoss

This target extends the existing ForgeBoss controller, bounded worker, reviewer, isolation, evidence and known-good principles.

It must not bypass Finish Line 1.

Implementation begins only through normal ForgeBoss governance after the prerequisite finish line is legitimately complete.
