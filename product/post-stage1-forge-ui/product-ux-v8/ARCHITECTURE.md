# ForgeBoss Product Architecture — Memory, Bible, Vault and Autonomous Project Flow

## 1. Product contract

A normal user should be able to:

1. Install / sign into ForgeBoss.
2. Choose **New Project**, **Existing Folder**, or **Remote Repository**.
3. For a new project, describe the idea in ordinary language.
4. Answer only questions that materially change the product or permissions.
5. Approve the generated Project Bible foundation.
6. Allow ForgeBoss to plan, build, test, hostile-review, repair and prove autonomously.
7. Return later and continue with conversation + project memory intact.

The user should not need to understand prompting, Git internals, test frameworks, model routing, or agent orchestration.

## 2. Memory model

### A. Conversation History
Append-only project chat transcript.

Recommended fields:
- project_id
- conversation_id
- message_id
- role
- timestamp
- content
- attachments
- source / tool metadata
- redaction metadata

### B. Project Memory
Distilled reusable facts from conversations and runs:
- decisions
- preferences
- known constraints
- rejected approaches and why
- verified repairs
- previous failures
- operational lessons
- unresolved questions

This is not automatically authoritative.

### C. Project Bible
Authoritative project specification:
- START_HERE
- PROJECT_IDEA
- REQUIREMENTS
- ARCHITECTURE
- RULES
- SAFETY
- WORKFLOW
- REVIEW_STANDARD
- ACCEPTANCE
- DECISIONS
- CHANGELOG

Promotion rule:
Conversation -> proposed memory -> explicit/validated decision -> Bible update.

A random old chat line must never silently override the Bible.

## 3. New-project creation

Input: free-form project idea.

ForgeBoss creates an initial interrogation plan and asks only decision-grade questions such as:
- who the product is for,
- critical first outcome,
- non-negotiable constraints,
- data/security requirements,
- deployment/operating environment,
- integrations that materially change architecture,
- budget/risk boundaries.

Then ForgeBoss creates a local project folder and Bible foundation.

Example:
```
MyProject/
  .forgeboss/
    START_HERE.md
    PROJECT_IDEA.md
    REQUIREMENTS.md
    ARCHITECTURE.md
    RULES.md
    SAFETY.md
    WORKFLOW.md
    REVIEW_STANDARD.md
    ACCEPTANCE.md
    DECISIONS.md
    CHANGELOG.md
    memory/
    evidence/
    runs/
```

## 4. Forge modes

### Repair Rat
Local/proven bounded repair path only.

### Low Heat
Repair Rat first; allow only the cheapest approved paid model if required.

### Working Heat
Cost/capability balanced.

### High Heat
Escalate to stronger reasoning/models sooner for difficult work.

### Full Forge
Strongest approved engines are available when justified.

### Auto Forge (default)
Evidence-driven escalation:
1. Repair Rat / local deterministic tooling.
2. Cheapest suitable paid model.
3. Mid-tier reasoning.
4. Strongest approved model.

Escalation is not automatic just because a lower tier failed once. It should require classified evidence such as:
- context insufficiency,
- repeated same-signature failure,
- planning complexity,
- model capability ceiling,
- hostile review defect that lower tier cannot resolve.

Fuel cap is always hard.

## 5. Forge Vault

### Normal-user default: ForgeBoss Managed
The ForgeBoss service provides model access. The user sees plan/usage rather than API keys.

### Advanced option: Bring Your Own Fuel
Users may connect provider accounts.

Preferred authentication order:
1. OAuth / provider app flow.
2. Provider-specific secure account connection.
3. API key/token fallback.

### Secret storage requirements

Never store raw secrets in:
- browser localStorage,
- project JSON,
- SQLite project DB,
- Git,
- Bible,
- chat transcript,
- logs,
- crash reports,
- evidence.

For Windows local mode:
- use Windows DPAPI / Credential Manager,
- bind secret access to the signed-in user or ForgeBoss service identity,
- keep only secret references/IDs in project state.

For cloud-managed mode:
- use a dedicated secrets manager,
- envelope encryption,
- per-customer separation,
- rotation,
- revocation,
- access audit.

### Secret broker

Workers should not receive a user's entire vault.

ForgeBoss controller issues a short-lived credential lease only to the worker that needs it:
- provider
- scope
- project/run ID
- allowed operation
- expiry
- spend ceiling

The worker gets the minimum required credential or proxy capability.

## 6. Git provider connections

Support:
- GitHub
- GitLab
- Bitbucket
- Azure DevOps
- generic Git / self-hosted

For GitHub, prefer a GitHub App/OAuth flow over personal access tokens for ordinary users.

Remote-repo start procedure:
1. Detect provider.
2. Confirm authentication.
3. Fetch metadata read-only.
4. Resolve exact branch + commit.
5. Create isolated working copy/worktree.
6. Record authority in run manifest.
7. Work only in the isolated copy.
8. Publishing/PR creation remains separately permission-gated.

## 7. Conversation search

Project chat should support:
- full-text search,
- date filters,
- decision-only filter,
- "why did we choose this?" tracing,
- links from Bible decisions back to source conversations/evidence.

The answer to a project question should prefer:
1. Bible,
2. validated project memory,
3. current conversation,
4. historical chat,
with conflicts surfaced instead of silently resolved.

## 8. UX state language

Primary user-visible states:
- FORGE READY
- FORGING
- TEMPERING
- INSPECTING
- NEEDS YOU
- BLOCKED
- QUENCHED
- PROVEN

Always pair forge language with plain meaning.

Example:
`TEMPERING — Running acceptance tests`

## 9. Progress semantics

The main progress bar must represent workflow progress, not money.

Suggested stages:
- Plan
- Forge
- Temper
- Inspect
- Prove

Fuel/API spend gets its own separate bar.

## 10. Forge Log

Newest event first.

Events should be plain English and severity classified:
- informational,
- active,
- success,
- warning,
- needs-owner,
- failure.

Raw technical logs live under "Under the Hood."

## 11. User interruption policy

Autonomy continues until one of these is true:
- a product decision materially changes the output,
- permission is required,
- spend cap would be exceeded,
- safety rule blocks progress,
- authoritative inputs conflict,
- evidence cannot establish a safe next step.

Ordinary implementation choices should not stop the user.

## 12. Stage 1 isolation

This UX/product work must remain outside the current Stage 1 finish-line target until the exact green Stage 1 target is complete and independently proven.

No product-UX work should mutate:
- Stage 1 exact checkout,
- Stage 1 root-of-trust,
- live Stage 1 controller,
- acceptance evidence,
- branch authority,
unless explicitly integrated after the finish-line gate.
