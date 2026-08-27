# OSS App-Builder Acceleration

## Purpose

ForgeBoss should become a controlled prompt-to-app software factory without turning into a fork of one existing app builder.

This packet reuses open-source projects in two different ways:

1. **Runtime dependencies/adapters** where an upstream tool can perform a bounded ForgeBoss job.
2. **Reference architecture** where importing a whole product would create unnecessary coupling or licensing/security risk.

## Selected upstreams

### Cline — actual optional executor

- Source: `cline/cline`
- License: Apache-2.0
- Why it helps: headless CLI, JSON output, selectable provider/model, project rules, and multi-agent/worktree patterns.
- ForgeBoss use: optional coding executor behind the existing lease/scope/postflight boundary.
- Safety state: quarantined by default. It requires the paid-executor gate, explicit Cline enable gate, and `FORGEBOSS_OS_ISOLATION_VERIFIED=YES`.
- Install: `SETUP-FORGEBOSS-CLINE.cmd`.
- Important: installing Cline does not promote it to the default executor.

### bolt.diy — reference architecture, not vendored

- Source: `stackblitz-labs/bolt.diy`
- License: MIT.
- Useful patterns: prompt-to-artifact flow, provider abstraction, starter templates, preview/revert workflow, file locking/diff ideas, web/mobile starter selection.
- ForgeBoss adaptation: deterministic app blueprints + later preview/change UX.
- Why not vendor it: Bolt is a complete product with WebContainer assumptions. ForgeBoss needs its own controller, security model, workspaces and multi-agent build pipeline.

### Dyad — Apache-only reference architecture

- Source: `dyad-sh/dyad`
- License boundary: code outside `src/pro` is Apache-2.0; `src/pro` is FSL-1.1-ALv2.
- Useful patterns: local-first app builder UX, Electron renderer/main-process separation, local project lifecycle.
- Hard rule: ForgeBoss must not copy/import/use Dyad `src/pro` code under this packet.

### Existing upstreams retained

ForgeBoss already tracks OpenHands Software Agent SDK, mini-SWE-agent, Deep Agents, OpenCode and Agency Agents. Those remain part of the executor/durability/specialist bakeoff rather than being replaced.

## New app-builder boundary

`forgeboss.appbuilder` is the deterministic boundary between a user's app idea and the controller.

Input:

```text
"Build me SiteBoss, a SaaS for fencing businesses with CRM, scheduling,
AI receptionist, Stripe billing, login and an owner dashboard."
```

Output:

- stable blueprint ID and SHA-256 fingerprint;
- inferred app template;
- explicit technology stack;
- detected/requested capabilities;
- build workstreams with dependencies;
- preview command/type;
- controller safety contract.

The compiler performs **no model call**. A model can improve the user's request before this boundary, but the controller receives deterministic JSON that can be stored, diffed, reviewed and reproduced.

## Build flow

```text
USER IDEA
   |
PROMPT ENHANCEMENT (optional model)
   |
DETERMINISTIC APP BLUEPRINT
   |
ARCHITECT / CONTROLLER
   |
EXACT FILE-SCOPE TASK PACKETS
   |
ISOLATED EXECUTORS
   |-- Repair Rat
   |-- OpenHands
   |-- mini-SWE
   |-- OpenCode
   `-- Cline (new, quarantined)
   |
TEST / REVIEW / REPAIR
   |
FROZEN CANDIDATE
   |
INDEPENDENT REVIEW
   |
PREVIEW / RELEASE READINESS
```

## What this deliberately does not do

- no automatic deployment;
- no direct-main writes;
- no whole-repository vendoring of Bolt or Dyad;
- no use of Dyad `src/pro`;
- no bypass of ForgeBoss spend, isolation, scope, review or candidate-freeze controls;
- no promotion of a new executor without the existing frozen-task bakeoff.

## Next high-value stages

1. Connect blueprint output to controller task-packet materialization after the active Finish Line 1 authority/workspace work lands.
2. Add app template repositories with pinned commit SHAs and license receipts.
3. Add preview lifecycle management (start, health, stop, snapshot, revert).
4. Add conversational change requests that compile into blueprint deltas instead of rewriting the whole app.
5. Benchmark Repair Rat, OpenHands, OpenCode and Cline on the same frozen app-building packets.
