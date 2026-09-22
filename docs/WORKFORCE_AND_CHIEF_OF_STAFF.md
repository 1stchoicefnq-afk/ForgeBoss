# Workforce contracts and Chief of Staff

## Purpose

ForgeBoss can use multiple AI/provider workers, but ForgeBoss remains the authority. A worker description never grants permission to write files, spend money, push code, merge, approve or deploy.

This package adapts useful operating ideas from the MIT-licensed markfulton/ai-employees project without copying its markdown-kit runtime model.

## Adopted patterns

- Versioned worker and routine contracts.
- Named capabilities are separate from concrete provider/tool routes.
- Scheduled work uses an exact worker + routine + period key so retries do not silently duplicate completed work.
- Outbound actions are held by default. A release is not authority: the independent ForgeBoss runtime authority gate must also allow the action.
- Run evidence records identify the exact period and evidence reference.
- A Chief of Staff compares expected work with actual run evidence so a missing run becomes visible as silent.
- The Chief of Staff produces a brief and does not edit another worker's state.

## Chief of Staff boundary

The first Chief of Staff contract has two observer-only routines:

1. fleet-reconcile — reads control/evidence state and identifies healthy, partial, blocked, failed, silent, paused and needs-approval work.
2. owner-brief — reads control/evidence/approval state and builds one concise owner-facing summary.

Its contract has authority_grant NONE and declares no outbound actions.

The Chief of Staff is not a controller, builder, reviewer, repair worker, merger, approver or deployer. It cannot turn a report into execution authority.

## What was deliberately not copied

The upstream project intentionally uses local markdown kits and small Node scripts rather than a central runtime. ForgeBoss needs stronger authority, immutable evidence, controlled write scopes, independent review and local/cloud execution boundaries, so text files are never treated as enforcement authority.

Likewise, a local release file is not enough to permit an outbound ForgeBoss action. The code requires both an explicit release and independent runtime authority.

## Integration path

This first slice is deliberately isolated. Later wiring should:

- source expected routines from the authoritative ForgeBoss scheduler/control store;
- source run records from immutable receipts/evidence;
- source approvals from the existing approval/authority layer;
- expose the owner brief to desktop and mobile dashboards;
- keep Chief of Staff read-only even when other worker roles gain execution authority.

Do not wire this module directly to provider credentials, GitHub mutation APIs or shell execution.
