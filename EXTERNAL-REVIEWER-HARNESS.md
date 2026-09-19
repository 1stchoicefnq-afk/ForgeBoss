# External Reviewer Harness

**Status:** architecture/design capture  
**Owner issue:** #171  
**Product:** ForgeBoss  
**Applies to:** ForgeBoss projects, including SiteBoss review workflows

## Purpose

ForgeBoss should be able to coordinate an independent external reviewer through an approved local computer-use/UI path without making that reviewer part of the trusted release authority.

The target use case is:

```text
ForgeBoss
  -> freeze exact candidate
  -> generate review packet
  -> open external reviewer UI
  -> submit read-only hostile-review task
  -> capture reviewer output
  -> normalize findings
  -> feed findings to Repair Rat / regression work
  -> run ForgeBoss acceptance gates
  -> human/authority gate decides what happens next
```

Examples of external reviewers may include Claude Desktop/web, ChatGPT/Codex or future providers. The architecture must remain provider-neutral.

## Core rule

**External reviewer output is evidence, never authority.**

```text
Reviewer says PASS
        !=
ForgeBoss accepted
```

A candidate may only move forward when the authoritative ForgeBoss gates independently establish the required evidence.

## Target architecture

```text
                  FORGEBOSS
                      |
              Build / Repair lane
                      |
              Freeze exact candidate
                      |
              Review packet builder
                      |
            External Reviewer Harness
          /            |              \
   Claude UI      ChatGPT/Codex     Future UI/API
          \            |              /
               Normalized findings
                      |
                 Repair Rat
                      |
         Regression + mutation tests
                      |
          Native/platform evidence
                      |
             Authority / release gate
```

The harness is an orchestration boundary. It does not grant the reviewer authority over Git, GitHub, releases, merges, deployments or project policy.

## Local ReviewQueue

Preferred local layout:

```text
C:\ForgeBoss\ReviewQueue\
  <review-id>\
    REVIEW-START-HERE.md
    CANDIDATE.zip
    CANDIDATE-SHA256.txt
    BASELINE.json
    CHANGE-SCOPE.json
    RUNTIME-MAP.json
    AUTHORITY-MAP.md
    THREAT-MODEL.md
    CLAIM-LEDGER.json
    KNOWN-FINDINGS.json
    FALSE-GREEN-MATRIX.md
    WINDOWS-ACCEPTANCE.md
    EVIDENCE-INDEX.json
    REVIEW-RESULT.schema.json
    reviewer-output\
```

The exact candidate hash recorded in the packet is authoritative for the review task.

## Review packet contract

Every external-review request must include:

- review ID;
- project/repository identity;
- exact frozen candidate SHA/hash;
- exact base/baseline identity;
- allowed review scope;
- read-only instruction;
- explicit prohibition on edits, pushes, comments, workflow triggers, merges and settings changes;
- relevant permanent laws/rules;
- known claims to verify;
- known prior findings where appropriate;
- required hostile-review standard;
- requested output schema;
- statement that supplied PASS results are provisional.

The harness must refuse to claim an exact review if it cannot prove the reviewer was given the intended candidate.

## Read-only reviewer LAW

An external hostile reviewer may:

- read local review-packet files;
- inspect exact candidate source;
- inspect public or authorized read-only repository evidence;
- inspect test reports and workflow logs;
- reason about hypothetical mutations;
- return findings in chat/output.

It must not be given authority to:

- edit the candidate;
- commit;
- push;
- merge;
- approve;
- request changes on GitHub as authority;
- comment on GitHub unless a separate owner-approved review integration explicitly requires it;
- trigger/re-run workflows;
- change repository settings;
- alter branch protection;
- change secrets;
- deploy;
- update known-good state;
- mark its own result accepted.

For UI-driven hostile review, the default is **no GitHub write credentials**.

## GitHub compliance LAW integration

The harness must obey `GITHUB-COMPLIANCE-LAW.md` once that law is accepted/merged.

UI automation is not a loophole around GitHub rules.

The harness must never:

- use multiple accounts/tokens/windows/machines to evade GitHub limits;
- create high-frequency comments/issues/PR activity;
- turn GitHub into a worker message bus;
- bypass the shared GitHub governor for automated GitHub traffic;
- retry around 403/429/cooldown protections.

Where repository access is needed, prefer already-frozen local candidate/evidence packets over repeated GitHub reads.

## Provider/account compliance

The harness must not use computer-use/UI automation to evade a provider restriction, disabled organization, suspended account, paywall, authentication boundary or other provider control.

If a provider/API organization is unavailable but a separately legitimate user product/session is available, that UI may be used only within its normal permitted access and terms.

A disabled/restricted account is a stop condition, not a challenge to route around.

## Independence rules

A reviewer is independent only when:

- it did not author the candidate under review in the same review role;
- it receives a frozen exact candidate;
- it cannot edit the candidate;
- it cannot update acceptance state;
- it cannot mark itself accepted;
- its output is stored separately from authoritative acceptance evidence.

Where practical, builder and reviewer should use different roles, sessions and/or model providers.

## Reviewer prompt baseline

Minimum instruction:

```text
READ ONLY.

Review exact candidate:
<exact SHA/hash>

Do not edit the candidate.
Do not push to GitHub.
Do not trigger workflows.
Do not trust supplied PASS results.
Independently attack the claimed protections.
Return findings only.
```

Provider-specific prompts may add context but cannot weaken these rules.

## Hostile-review standard

The harness must carry ForgeBoss's permanent review standard:

- every green test is provisional;
- reproduce claimed fixes independently;
- keep attacking adjacent and alternate paths;
- bypass wrappers/frontends and inspect underlying engines;
- mutate/remove protections in disposable copies and prove tests are sensitive where practical;
- inspect historical/duplicate/dead entrypoints;
- distinguish integrity from authority;
- distinguish portable evidence from Windows-native evidence;
- attack stale state, crash/restart, concurrency and double-launch behavior;
- search for false PASS/READY/VERIFIED/ACCEPTED/HEALTHY/COMPLETE states;
- never stop merely because supplied tests pass.

## Result normalization

Reviewer output should be normalized to structured findings such as:

```json
{
  "review_id": "...",
  "candidate_sha256": "...",
  "reviewer": {
    "provider": "...",
    "surface": "desktop-ui|web-ui|api|local-model",
    "session_id": "..."
  },
  "target_proven": true,
  "findings": [
    {
      "id": "ERH-001",
      "severity": "HIGH",
      "path": "...",
      "problem": "...",
      "reproduction": "...",
      "impact": "...",
      "required_repair": "...",
      "required_regression": "..."
    }
  ],
  "verdict": "ACCEPT|REPAIR_REQUIRED|TARGET_UNPROVEN",
  "limitations": []
}
```

The normalized result should be ingestible by Repair Rat as review memory/evidence.

## Repair Rat relationship

External-review findings may become:

- ATTEMPT evidence;
- PROVEN_FIX evidence after repair/retest/review;
- KNOWN_REPAIR_PATTERN input after repeated proof.

Reviewer output alone must never create a PROVEN_FIX or release-authoritative state.

## Acceptance boundary

A candidate is not accepted merely because an external reviewer returns ACCEPT.

Expected final chain:

```text
exact candidate identity
+ deterministic tests
+ independent external review evidence
+ regression tests
+ mutation/sensitivity tests
+ native/platform evidence where required
+ authority/root-of-trust checks
+ project-specific gates
= candidate may become eligible for acceptance
```

The authoritative acceptance decision remains inside ForgeBoss governance.

## Failure modes

The harness must fail closed or report UNKNOWN/TARGET_UNPROVEN when:

- candidate hash cannot be proved;
- wrong file/version was opened;
- reviewer output is truncated/unavailable;
- reviewer session edits the candidate;
- reviewer requests write authority;
- provider/account is restricted;
- UI automation cannot reliably identify the target;
- reviewer output cannot be associated with the exact review ID;
- evidence references are missing;
- GitHub/provider compliance becomes uncertain.

A UI timeout or missing output is not PASS.

## Human-visible fallback

The harness must support a manual mode:

1. ForgeBoss creates the frozen review packet.
2. User opens the external reviewer.
3. User pastes the generated read-only prompt.
4. User copies the reviewer response back to ForgeBoss.
5. ForgeBoss validates review ID/candidate identity and normalizes the result.

This is the immediate fallback while automated computer-use orchestration is not yet implemented.

## Security/privacy

By default, do not send:

- secrets;
- API keys;
- private keys;
- credentials;
- customer personal data;
- unrelated repository files;
- private business data.

The packet builder should minimize context to the exact material necessary for review.

## Provider-neutral adapter contract

A future adapter should expose capabilities such as:

```text
prepare_session()
open_reviewer()
submit_packet()
wait_for_output()
capture_output()
verify_target_binding()
normalize_result()
close_session()
```

Provider adapters must not own acceptance authority.

Possible transports:

- local desktop UI through approved computer use;
- browser UI through approved computer use;
- direct provider API;
- local model process.

All transports feed the same review-result schema.

## Evidence requirements

Record where practical:

- review ID;
- exact candidate hash;
- baseline hash;
- packet hash;
- reviewer/provider/surface;
- prompt hash;
- start/end timestamps;
- returned output hash;
- whether target binding was proven;
- provider/session limitations;
- normalized findings;
- raw reviewer output location.

Do not record secrets.

## Implementation phases

### Phase 0 — architecture capture
This document only.

### Phase 1 — manual ReviewQueue
- packet generator;
- exact SHA/hash binding;
- generated read-only reviewer prompt;
- manual copy/paste result ingestion;
- schema validation;
- no UI automation.

### Phase 2 — reviewer adapters
- provider-neutral adapter interface;
- local/browser computer-use adapters;
- read-only capability checks;
- session evidence.

### Phase 3 — adversarial hardening
- wrong-file/wrong-SHA tests;
- reviewer self-acceptance attacks;
- write-authority attacks;
- stale-output attacks;
- duplicate review/session confusion;
- provider failure/restart behavior;
- privacy/secret leakage tests.

### Phase 4 — controlled orchestration
- ForgeBoss opens reviewer;
- submits exact packet;
- collects output;
- normalizes findings;
- Repair Rat can consume findings;
- still no reviewer release authority.

### Phase 5 — multi-reviewer comparison
- send the same frozen candidate to multiple independent reviewers when policy requires;
- compare findings;
- retain disagreements;
- never convert majority vote into authority.

## SiteBoss use

SiteBoss is a prime ForgeBoss project for this harness.

Typical flow:

```text
SiteBoss change
 -> ForgeBoss builds/tests
 -> exact SiteBoss candidate frozen
 -> external hostile reviewer receives local packet
 -> reviewer findings returned
 -> ForgeBoss Repair Rat / builder handles repairs
 -> exact candidate rebuilt/retested
 -> final SiteBoss acceptance gates
```

SiteBoss itself should not need to embed external reviewer credentials or UI-control logic.

## Non-goals

This architecture does not:

- make Claude/ChatGPT/Codex a release authority;
- permit review providers to merge;
- replace deterministic testing;
- replace Windows-native acceptance;
- replace the GitHub compliance governor;
- bypass provider restrictions;
- prove a candidate simply because multiple models agree;
- require one permanent AI provider.

## Product principle

**ForgeBoss owns the workflow, evidence, rules and authority. AI providers are replaceable reviewer/worker engines behind ForgeBoss.**
