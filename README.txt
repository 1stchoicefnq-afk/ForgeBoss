SITEBOSS AUTOPILOT Repair Rat v0.5-smokescreen

ONE-LAUNCHER GOAL
-----------------
Double-click START-SITEBOSS.cmd.

This alpha connects the proven SiteBoss API worker lineage into the first real autonomous repair cycle:
  exact-head independent review
  -> cache exact review result
  -> if FAIL, plan ONE bounded repair slice
  -> isolated repair branch from the reviewed PR head
  -> Docker npm ci
  -> focused tests + npm test with network disabled during tests
  -> exact changed-path verification
  -> DRAFT child repair PR targeting the parent PR branch
  -> STOP

It does NOT merge or deploy anything.

WHY A CHILD REPAIR PR?
----------------------
The existing v0.4 executor is intentionally main-based. PR #168 already owns the files that need repair,
so creating another main-based PR would collide with it. Alpha1 instead branches from the exact frozen PR head
and creates a child PR whose base is the parent PR's branch. This preserves review lineage and avoids modifying
the parent branch directly.

COST CONTROL
------------
- Review results are cached in state\review-pr<N>.json and reused only while the live PR head/base still match.
- Deterministic GitHub/Git/Docker gates run before repair API coding.
- Only ONE coherent repair slice is attempted per launcher cycle.
- Max repair plan: 6 existing files.
- Full test suite always runs.
- No idle API polling.
- No background 24/7 loop yet.

SAFETY
------
- No AHK/browser automation.
- No consumer ChatGPT scraping.
- No self-merge.
- No deployment.
- No settings/secrets/permissions mutations.
- No direct write to the reviewed parent PR branch.
- No repair from stale review evidence.
- No repair if the parent PR head moves.
- No file outside the model-planned existing allowlist may change.
- Docker test commands have networking disabled.
- OPENAI_API_KEY/GitHub token are not passed to test containers.

RUN
---
1. Extract the ZIP fully.
2. Double-click CHECK-SITEBOSS.cmd.
3. If PASS, double-click START-SITEBOSS.cmd.

CURRENT TARGET
--------------
Default: PR #168.
Advanced PowerShell invocation:
  pwsh -File .\SiteBoss-Autopilot.ps1 -TargetPullRequest 168

WHAT HAPPENS AFTER A REPAIR PR
------------------------------
Alpha1 intentionally stops after creating (or detecting) one DRAFT child repair PR.
The next iteration will add automatic independent review of that child repair PR, then an explicit-authority
integration step back into the parent branch, followed by automatic re-review of the parent PR.

BUNDLED LINEAGE
---------------
components\Controller-v0.5.10.ps1  - proven controller preserved for general main-based packets
components\Executor-v0.4.ps1       - proven main-based coding executor preserved
components\Review-PR.ps1           - v0.6.4-derived independent reviewer with exact-head cache/output
components\Repair-PR.ps1           - new bounded child repair executor

CLAUDE
------
The provider boundary is not enabled in alpha1. It is intentionally left for the stable v1.x reviewer layer,
where Anthropic can be added as an independent second reviewer without browser automation.

ALPHA2 PATCH
------------
- Fixes the Repair-PR.ps1 parser failure caused by compact foreach syntax.
- CHECK-SITEBOSS.ps1 now recursively parses every PowerShell script in the package before a live run.
- The exact-head review cache remains reusable: if you copy state\review-pr168.json from alpha1 into alpha2's state folder, the same unchanged PR head/base will not be re-reviewed.
- No merge, deployment, authority, path, Docker, or GitHub write-safety rules changed.

ALPHA3 COST-GUARD PATCH
-----------------------
- Docker engine readiness is checked BEFORE any independent-review/OpenAI call.
- CHECK-SITEBOSS.cmd now fails if Docker Desktop is installed but the daemon is not running.
- START-SITEBOSS.cmd also performs the same no-cost Docker preflight before reviewer execution.
- This prevents paying for a fresh review only to discover later that the repair worker cannot run.
- Existing exact-head review evidence remains reusable. Copy `state\review-pr168.json` from alpha2 into alpha3's `state` folder before starting.
- No merge, deployment, authority, path, test-isolation, or GitHub write-safety rule changed.

ALPHA4 GITHUB PR-SHAPE PATCH
----------------------------
- Fixes StrictMode crashes caused by direct `.head` / `.base` access in the repair worker.
- Target PR detail now validates `state`, `head`, `head.sha`, `head.ref`, `base`, and `base.sha` explicitly.
- Duplicate child-PR scans validate each list item's `head`/`head.ref` before use.
- Publication recheck is also shape-safe.
- Adds stage diagnostics so a future GitHub response-shape failure identifies the exact read stage.
- Existing exact-head review cache remains reusable; no paid re-review is needed while PR #168 head/base are unchanged.
- No merge, deployment, authority, test-isolation, path, or GitHub write-safety rule changed.

ALPHA5 DETERMINISTIC DUPLICATE-CHECK PATCH
------------------------------------------
- Replaces the broad "all PRs targeting the parent branch" scan with GitHub's exact `head=owner:branch` PR filter.
- Explicitly normalizes one-item/array response shapes across PowerShell versions.
- If one exact-head PR exists, fetches its canonical PR detail before deciding it is the existing repair PR.
- Refuses ambiguous duplicate state if more than one PR uses the deterministic repair head.
- This check happens before any repair-planning/coding OpenAI call, so duplicate work is still prevented without extra spend.
- Existing review cache remains reusable; no paid re-review is needed while PR #168 head/base are unchanged.
- No merge, deployment, authority, path, Docker, test-isolation, or GitHub write-safety rule changed.

ALPHA6 EXPLICIT GIT-BINDING PATCH
---------------------------------
- Fixes the local repair-worker failure where `--no-checkout` was interpreted as the Git helper working-directory argument.
- Renames Git helper parameters to `CommandArgs` / `WorkingDir`.
- Every repair-worker Git call now uses explicit named parameter binding.
- CHECK-SITEBOSS also rejects positional Git helper calls in Repair-PR.ps1.
- Review cache remains reusable, so no paid re-review is needed while PR #168 head/base are unchanged.
- No merge, deployment, authority, path, Docker, test-isolation, or GitHub write-safety rule changed.

ALPHA7 SYSTEMATIC HARDENING PASS
--------------------------------
This release is intentionally broader than a one-line patch.

Audited active path:
- SiteBoss-Autopilot.ps1
- components\Review-PR.ps1
- components\Repair-PR.ps1

Hardening:
- All active Git-helper calls build a typed string[] variable before binding it to -CommandArgs.
- Repair worker runs a harmless local Git-helper semantic self-test before live GitHub/OpenAI work.
- Reviewer PR head/base reads are now StrictMode shape-safe as well as the repair worker's.
- Compact parser-sensitive foreach/operator syntax is normalized.
- SELFTEST-SITEBOSS.cmd performs parser/static/local-Git regression checks with zero GitHub/OpenAI calls.
- CHECK-SITEBOSS.cmd invokes the regression self-test automatically.
- Static packaging audit rejects the exact bug classes already seen: inline helper arrays, compact foreach/in@, and direct PR head/base dereferences on active paths.

COST:
Copy the unchanged exact-head `state\review-pr168.json` cache forward. Alpha7 should not pay for another PR #168 review while that head/base remain unchanged.

This still does not merge, deploy, change owner settings, or grant itself authority.

ALPHA8 ROOT-CAUSE FIX
---------------------
This release fixes the actual reason alpha6/alpha7 Git calls failed.

PowerShell command names are case-insensitive. The repair worker had a helper named `Git`
whose body executed `& git ...`. That recursively invoked the helper itself instead of
the external Git executable, producing misleading positional-parameter errors.

Fixes:
- Renames the repair helper from `Git` to `Invoke-GitProcess`.
- The helper explicitly invokes `git.exe`.
- All repair call sites use `Invoke-GitProcess`.
- Local self-test rejects any future function named `Git`.
- Local self-test rejects bare `& git` calls in the repair worker.
- Local semantic Git checks use `git.exe` explicitly.
- Existing parser, StrictMode PR-shape, Docker, and cost-guard checks remain.

COST:
Copy the unchanged exact-head `state\review-pr168.json` into alpha8. No paid re-review
is needed while PR #168 head/base remain unchanged.

No merge, deployment, authority, settings, secret, or permission behavior changed.

ALPHA9 PROCESS-OUTPUT HARDENING
-------------------------------
This is a root-level process-runner fix, not a warning-specific exception.

Observed failure:
Git successfully changed only an allowlisted file, but `git diff --name-only`
also emitted a Windows LF/CRLF warning to stderr. Alpha8 merged stderr into stdout,
so the verifier interpreted the warning sentence as another changed path.

Fix:
- Repair Git runner uses ProcessStartInfo and `git.exe`.
- Reviewer Git runner uses the same stdout/stderr separation.
- Machine-readable Git results receive stdout only.
- Successful stderr is diagnostic-only.
- Nonzero Git exits still include stderr in the error.
- Regression selftest rejects `2>&1` in every active script.
- Existing parser, StrictMode, Docker, cost, duplicate-work and path-scope guards remain.

The line-ending warning itself is harmless and will no longer be parsed as a filename.

COST:
Copy the unchanged exact-head `state\review-pr168.json` into alpha9. The cached
review remains reusable and avoids another paid four-chunk review.

No merge, deployment, authority, settings, secrets, permissions, or scope rules changed.

ALPHA10 CROSS-MODEL HARDENING
-----------------------------
This release combines the strongest parts of the OpenAI and Claude reviews.

Kept from alpha9:
- ProcessStartInfo-based Git runners.
- stdout/stderr are captured separately.
- machine-readable Git output receives stdout only.
- no `2>&1` contamination.
- explicit `git.exe` invocation.
- existing StrictMode/parser/Docker/cost/duplicate-work/path guards.

Added from Claude's review:
- Disposable repair clones set repo-local `core.autocrlf=false`.
- Disposable repair clones set repo-local `core.safecrlf=false`.
- This prevents Git from rewriting line endings or emitting avoidable CRLF warnings in the repair workspace.

Strengthened regression gate:
- SELFTEST requires separate stdout/stderr redirection.
- SELFTEST rejects any `2>&1` merged capture.
- SELFTEST requires BOTH `core.autocrlf=false` and `core.safecrlf=false`.
- These settings are local to the throwaway repair clone and do not change global/user Git settings.

COST:
Carry forward `state\review-pr168.json`. The unchanged exact-head review remains reusable.

No merge, deployment, owner authority, settings, secrets, permissions, or path-scope rules changed.

ALPHA11 PRE-WRITE BASELINE DRIFT CHECK
---------------------------------------
Alpha10 fixed the CRLF-warning contamination bug but a related failure surfaced on the
next live run: the post-write allowlist check (`git diff --name-only` after the model's
edits) flagged a path the model never touched (e.g. `.github/PULL_REQUEST_TEMPLATE.md`)
as "outside the repair allowlist."

Root cause: that file was already showing as modified in the working tree immediately
after `checkout`/`switch -c`, before the repair model made any edit at all. This is
environmental drift — almost always `.gitattributes` line-ending normalization (`text=auto`
or an explicit `eol=` rule) disagreeing with how the blob was actually committed — not a
repair-model defect. The old check couldn't tell the two apart, so it misattributed
pre-existing drift to the model and failed closed with a misleading message.

Fix:
- Immediately after `checkout --detach` + `switch -c`, and before any OpenAI call, the
  repair worker now runs `git diff --name-only` as a baseline check. If the working tree
  is not byte-clean at that point, the run fails closed immediately with an accurate
  diagnosis (naming the drifted paths and the likely `.gitattributes` cause) instead of
  paying for a plan + patch OpenAI call that would fail anyway.
- This also improves cost control: a repo/PR combination with this kind of drift now
  fails before any paid API call rather than after two.
- SELFTEST-SITEBOSS.ps1 requires this baseline check to be present in Repair-PR.ps1.

This does not loosen the allowlist invariant — it only fixes attribution. A path that
becomes dirty *after* the model's write, and isn't in the planned allowlist, still fails
closed exactly as before.

COST:
Carry forward `state\review-pr168.json`. The unchanged exact-head review remains reusable.
Note: if PR #168 itself has this `.gitattributes` drift, alpha11 will now fail fast and
clearly on that PR specifically — that's expected until the drift is resolved upstream in
the repo (e.g. `git add --renormalize .` committed separately), not something this
launcher can safely resolve on your behalf.

No merge, deployment, owner authority, settings, secrets, permissions, or path-scope rules changed.


ALPHA12 — PRESERVED CLAUDE SCAFFOLD + OPENAI PEER-PROVIDER CONTRACT
-------------------------------------------------------------------
Baseline:
This package is built from the Claude-edited alpha11 files supplied by the owner.
Claude/provider additions are preserved rather than overwritten.

Provider architecture:
- Repair worker supports `openai` and `anthropic` behind the same structured contract.
- Reviewer now supports the same two providers.
- Defaults remain OPENAI for both paths.
- `SITEBOSS_REPAIR_PROVIDER=anthropic` can later select Claude for repair generation.
- `SITEBOSS_REVIEW_PROVIDER=anthropic` can later select Claude for independent review.
- No Anthropic key is required unless Anthropic is explicitly selected.
- `ANTHROPIC_API_KEY` is never passed to Docker test containers.
- `claude-sonnet-5` is the default Anthropic model and can be overridden by `SITEBOSS_ANTHROPIC_MODEL`.

Dual-review:
NOT enabled in alpha12. The future policy is recorded in PROVIDER-POLICY.json.
When enabled after the mechanics are stable:
- an authoring provider must not be its sole independent reviewer;
- FAIL from either required reviewer blocks;
- NEEDS_EVIDENCE prevents PASS;
- dual review should be reserved for release/security/data-integrity/high-risk work or disagreement escalation;
- exact-head provider-specific review caches and hard cost ceilings should be required.

Workspace integrity:
- repo-local `core.autocrlf=false` and `core.safecrlf=false` are preserved;
- disposable repair workspace is reset/cleaned after checkout;
- NUL-safe `git status --porcelain=v1 -z` must prove a pristine baseline before any paid repair call;
- post-write changed paths use NUL-safe `git diff --name-only -z`.

This keeps Claude's future integration hooks while retaining the OpenAI-side safety and cost model.
No merge/deploy/owner-authority behavior is expanded by this scaffold.

ALPHA13 WINDOWS CASE-COLLISION HARDENING
----------------------------------------
The repeated template-path drift appeared with two spellings:
- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/pull_request_template.md`

That is a strong signal of a Git tree containing case-colliding paths on Windows.
Normal NTFS directories are case-insensitive, so those Git paths can map to one
physical file and remain dirty even after reset/clean.

Alpha13:
- preserves the OpenAI + Anthropic provider scaffolding from alpha12
- moves disposable repair clones into:
  `%USERPROFILE%\.siteboss\autopilot\case-sensitive-repair-workspaces`
- requires that dedicated root to have the NTFS case-sensitive directory flag
- detects case-fold collisions in the exact frozen Git tree before checkout/model calls
- still runs pristine reset/clean/status gates
- still uses stdout/stderr separation, local autocrlf/safecrlf controls, NUL-safe diff parsing
- does not whitelist or ignore template files

ONE-TIME SETUP
--------------
Run `PREPARE-SITEBOSS-WORKSPACE.cmd` once.
It asks for Windows Administrator approval and marks ONLY the new empty disposable
repair-workspace root as case-sensitive. It does not modify global Git settings or
make your Downloads/repository folders case-sensitive.

Microsoft documents that Windows directories are normally case-insensitive, that
per-directory case sensitivity is supported, requires elevation to change, must be
set on an empty directory, and is inherited by newly-created child directories.

COST
----
The workspace/collision checks occur before repair planning/coding API calls.
Carry forward `state\review-pr168.json` to avoid another exact-head review.

No merge, deploy, owner-authority, settings, secrets, or provider policy was loosened.

ALPHA14 SELFTEST REGEX HARDENING
--------------------------------
- Fixes the PowerShell regex interpolation failure in SELFTEST-SITEBOSS.ps1.
- Regex patterns containing literal `$true` / `$branch` now use single-quoted PowerShell strings.
- Added a packaging-time audit that rejects any double-quoted `-match` / `-notmatch` regex
  containing `$`, preventing PowerShell variable interpolation from corrupting the regex.
- No live GitHub/OpenAI behavior, provider abstraction, repair scope, Docker isolation,
  merge authority, or case-sensitive workspace behavior changed.

ALPHA15 STABILIZATION RELEASE
-----------------------------
This release is intentionally a broader system hardening pass, not a one-line fix.

Docker/test architecture:
- Removed the invalid nested mount:
    read-only bind /workspace + volume /workspace/node_modules
- Source is now mounted read-only at /source.
- A fresh Docker-managed volume is mounted at /workspace.
- The exact repaired tree is copied /source -> /workspace.
- `npm ci --ignore-scripts` runs inside that Docker-managed workspace.
- Tests mount ONLY the Docker workspace volume, never the host repository.
- Test containers run with `--network none`, `no-new-privileges`, pids limit, and tmpfs /tmp.
- No OpenAI/GitHub/Anthropic secrets are passed into containers.
- Volumes use unique per-run names and are removed in finally blocks.

Cost/preflight:
- START-SITEBOSS runs the exact Docker mount topology probe BEFORE the reviewer.
- Missing node image is pulled before any paid API call.
- The repair worker repeats the topology assertion before plan/patch calls.
- This catches Docker/storage failures without paying for model work first.

Git/publication hardening:
- Disposable repo gets explicit local commit user.name/user.email.
- Existing case-sensitive workspace, pristine baseline, stdout/stderr separation,
  NUL-safe changed-path checks, head revalidation, draft-PR-only publication remain.

Provider hardening:
- OpenAI + Anthropic scaffolding is preserved.
- New review results record provider/model.
- Legacy review caches are reusable only when current reviewer is OpenAI.
- Repair branch identity includes both review-provider identity and repair provider,
  avoiding future OpenAI/Claude branch collisions.
- Dual review remains disabled until the single-provider mechanics are stable.

KNOWN-FAILURE REGRESSION COVERAGE
---------------------------------
The self-test/check layer now explicitly guards against the classes already seen:
PowerShell parser/interpolation errors, Git helper recursion/binding, stdout/stderr
contamination, Windows case collisions, dirty checkout baseline, CRLF conversion,
Docker daemon absence, invalid nested mounts, stale review cache/provider identity,
unexpected changed paths, and missing local Git commit identity.

No merge/deploy/self-approval authority is added.

ALPHA16 POWERSHELL AUTOMATIC-VARIABLE HARDENING
-----------------------------------------------
Alpha15 introduced typed `$args` locals for Docker command arrays. `$args` is a
PowerShell automatic variable and cannot safely be repurposed.

Alpha16 fixes the class across the entire package, including the bundled legacy executor:
- no PowerShell file assigns or declares `$args` as its own variable
- Repair Docker command arrays use `$dockerArgs`
- Test-Sandbox uses `$dockerArgs`
- legacy Executor-v0.4 uses a non-reserved local name
- SELFTEST now performs AST-level checks for assignments/parameters using reserved
  automatic variables such as `$args`, `$input`, `$error`, `$pid`, `$pwd`,
  `$matches`, `$foreach`, and related PowerShell-reserved names

All alpha15 stabilized Docker topology, case-sensitive workspace, provider abstraction,
review cache, Git safety, and cost guards are preserved.

ALPHA18 REPAIR-CHAIN LOOP
-------------------------
This build starts from the alpha16 lineage that successfully created repair PR #525.

New behavior when a repair PR already exists:
- Discover the exact open repair-child chain from the parent PR head.
- Follow at most 4 levels; multiple children at one level fail closed as ambiguous.
- Act only on the deepest repair leaf.
- Independently review that exact child head against its exact parent-branch head.
- Child review cache is provider/mode/parent/head/base bound.
- If child review FAILS: create at most one bounded repair child of that failed child, then stop.
- If child review NEEDS_EVIDENCE: stop with no mutation.
- If child review PASSES: re-read both PRs, verify exact SHAs/base refs, verify the child is a clean fast-forward,
  then advance ONLY the direct parent PR head branch to the reviewed child commit.
- `main`, master, develop, production, and release are refused as repair-integration targets.
- The Git ref update uses `force=false`.
- The child PR receives an audit comment and is closed if still open.
- Integration evidence is written to state\child-integration-pr<child>-into-pr<parent>.json.
- The cycle stops immediately after one reviewed integration. The now-changed parent PR must receive a fresh
  exact-head review on the next launcher cycle.

COST CONTROL
------------
Existing parent and child reviews are cached by exact provider/mode/head/base.
A pre-existing repair PR no longer causes another coding call merely because the launcher was restarted.
Only the leaf requiring work is reviewed/repaired.

PROVIDER INDEPENDENCE
---------------------
`SITEBOSS_CHILD_REVIEW_PROVIDER` may be `openai` or `anthropic`.
Default remains the normal review provider (OpenAI unless configured otherwise).
Set `SITEBOSS_REQUIRE_CROSS_PROVIDER_CHILD_REVIEW=1` later if you want to require the child reviewer to differ
from the provider inferred from the repair branch. It is not forced by default yet to avoid unexpected double spend.

This still never merges the parent PR into main and never deploys.

ALPHA19 CHILD-LOOP STABILIZATION
--------------------------------
Alpha18 found the existing repair chain (#168 -> #525) but the new child reviewer exited
before producing useful diagnostics.

Alpha19 hardens the entire child-review/integration path:
- materializes parent head ref/SHA into scalar strings before subprocess invocation
- passes reviewer arguments through ProcessStartInfo.ArgumentList rather than PowerShell
  expression/argument-mode binding
- captures and surfaces child reviewer stdout/stderr on failure
- adds a zero-API child-review argument-binding harness to CHECK-SITEBOSS
- child review no longer requires GitHub mergeable=true while mergeability is unknown;
  it still refuses a concrete merge conflict
- nested repair subprocesses use the same diagnostic process runner
- parent-branch ref lookup/update now handles slash-containing branch names explicitly
- exact Git ref is re-read immediately before and after a non-forced update
- existing exact-head/base/provider/mode checks and main/protected-branch refusal remain

No merge to main, deployment, owner-setting mutation, or dual-provider requirement is enabled.


ALPHA20 DIAGNOSTIC / OFF-LIVE MODE
----------------------------------
This package deliberately takes SiteBoss out of live operation while the repair-chain mechanics are stabilized.

DEFAULT:
- START-SITEBOSS.cmd refuses live execution unless SITEBOSS_ALLOW_LIVE=1 is explicitly set.
- Run DIAGNOSE-SITEBOSS.cmd.
- Diagnostic mode makes ZERO OpenAI calls and ZERO Anthropic calls.
- Diagnostic mode makes ZERO GitHub repository writes.
- No pushes, PR creation/update, ref updates, merge, deploy, or settings mutation.

BATCH DIAGNOSTICS:
The diagnostic harness continues across independent failures, marking each stage PASS / FAIL / BLOCKED.
It inspects parser issues, providers, Git/Docker, case-sensitive workspace, live read-only GitHub PR state,
#168/#525 binding, failing check runs and annotations, fast-forward ancestry, repair diff inventory,
child-review argument binding, child-cycle safety contracts, exact repair-head clone, case collisions,
pristine checkout, Docker sandbox topology, isolated npm ci, focused-test skip-evidence policy,
and the common structured failure-reporting contract.

OUTPUT:
  state\diagnostics\diagnostic-<timestamp>.json
  state\diagnostics\diagnostic-<timestamp>.txt

The report is designed to be sent to both OpenAI and Claude so multiple problems can be repaired together.

CURRENT KNOWN LIVE FAILURE:
PR #525 currently reports:
  postgres-integration [failure]

Diagnostic mode reads that failure and tries to collect its annotations/details without modifying GitHub.

STRUCTURED LIVE FAILURE CONTRACT:
components\Failure-Reporting.psm1 defines the format to wire into the next live build:
stage, component, reason, command, exit code, stdout, stderr, PR/SHA/ref context,
API call count, GitHub mutation count, and a state\failures JSON record.


ALPHA21 BATCH DIAGNOSTIC FIXES
------------------------------
Built from the first alpha20 batch report (23 PASS / 3 FAIL).

Fixes both harness defects from that report:
1. diagnostic self-inspection no longer relies on `$MyInvocation.MyCommand.Path` from inside a nested check scriptblock;
   it resolves SiteBoss-Diagnostics.ps1 from the stable package root.
2. focused repair tests now classify a Node TAP run with total>0 and skipped==total and pass==fail==0 as
   `SKIPPED_EVIDENCE` and fail closed instead of treating "all skipped" as repair proof.
   A zero-API local regression harness checks this behavior.

Deeper read-only CI diagnostics:
- For failed GitHub check runs, diagnostic mode extracts the Actions job id from details_url.
- It downloads the failed workflow job log through GitHub's read-only Actions job-log endpoint.
- Raw logs are saved under state\diagnostics\diagnostic-<timestamp>-artifacts\.
- A bounded failure excerpt is embedded in the JSON report.
- The exact repair-head .github/workflows files are inspected for PostgreSQL-related workflow/test commands.

This is still OFF-LIVE by default:
- zero OpenAI calls
- zero Anthropic calls
- zero GitHub repository writes
- no push, PR/ref update, merge, deploy, or settings mutation


ALPHA23 SAFE SCOPED-VARIABLE FIX
--------------------------------
Alpha22's global `$Name:` rewrite was too aggressive and corrupted valid scoped PowerShell
variables such as `$script:Results`, `$script:Token`, and `$script:Counters`.

Alpha23 is rebuilt from the undamaged alpha21 baseline.

It:
- fixes only the original ambiguous `$JobId:` expandable-string case using `$($JobId):`
- never rewrites scoped variables
- recognizes valid PowerShell scope prefixes (`script:`, `global:`, `local:`, `private:`,
  `env:`, `function:`, `variable:`)
- runs the real PowerShell parser before any heuristic source audit
- preserves alpha21's read-only diagnostic mode, failed job-log collection, and focused-test
  all-skipped evidence rule

Live mode remains guarded. Diagnostic mode still makes zero OpenAI/Anthropic calls and zero
GitHub repository writes.


ALPHA24 DEEP POSTGRESQL DIAGNOSTICS
-----------------------------------
The alpha23 batch report reached 28 PASS / 1 FAIL. The sole real blocker is PR #525's
`postgres-integration` GitHub check.

Alpha24 deepens diagnostics without turning live mode back on:

1. GitHub failed-job log reader
   - replaced the brittle redirected Invoke-WebRequest handling with HttpClient auto-redirect
   - reads the Actions job log in-memory
   - stores the raw log and bounded failure excerpt in the diagnostic artifacts/report

2. Local PostgreSQL CI reproduction
   - starts disposable `postgres:17-alpine`
   - uses a private disposable Docker network
   - stages the exact frozen repair head into a Docker-managed workspace
   - runs the workflow-equivalent sequence:
       npm test
       npm run db:migrate
       RUN_POSTGRES_INTEGRATION=1 node --test tests/postgres*.integration.test.js
       npm run db:rollback
       npm run db:migrate
   - continues through all steps and reports every failing step in one batch
   - destroys the DB container, workspace volume, and network afterward

Diagnostic mode still makes zero OpenAI calls, zero Anthropic calls, and zero GitHub repository writes.


ALPHA25 GITHUB ACTIONS LOG HEADER FIX
-------------------------------------
The alpha24 diagnostic report showed the failed-job log endpoint returning HTTP 403 because
the HttpClient request did not include a User-Agent.

Alpha25 adds:
  User-Agent: SiteBoss-Autopilot-Diagnostics/1.0

to the read-only GitHub Actions job-log request, and CHECK-SITEBOSS verifies that contract.

The local PostgreSQL CI reproduction still requires the free Docker image:
  docker pull postgres:17-alpine

Live mode remains guarded. Diagnostic mode still makes zero OpenAI/Anthropic calls and zero
GitHub repository writes.


ALPHA26 MULTI-FAILURE REPAIR LAB
--------------------------------
Built from alpha25 evidence. It does NOT repair or publish anything yet.

RUN-REPAIR-LAB.cmd:
- fetches exact PR #525 head read-only
- starts disposable PostgreSQL 17
- runs each of the three observed failing integration files repeatedly (default 5 each)
- runs the complete PostgreSQL integration suite twice
- verifies rollback -> migrate after testing
- records every run, exit code, failure lines and output tail
- writes one JSON packet under state\repair-lab\
- destroys its DB container, workspace volume and network
- makes zero OpenAI calls, zero Anthropic calls and zero GitHub writes

This establishes repeatability and interaction evidence before an AI repair is allowed to modify PR #525.


ALPHA27 REPAIR-LAB DB ENVIRONMENT + ALWAYS-REPORT FIX
------------------------------------------------------
Alpha26 failed before its test loop because workspace setup ran `npm run db:migrate`
without DATABASE_URL. Because that throw happened before the normal report footer, the
state\repair-lab directory remained empty.

Alpha27 fixes both issues:
- workspace setup now performs only `npm ci`
- the initial migration runs separately with DATABASE_URL and NODE_ENV=test
- every later PostgreSQL test/migration container continues to receive DATABASE_URL
- a script-level trap writes a schema-2 JSON report on ANY terminating runtime/setup failure
- early-failure reports include completed=false, fatal_failure, exact head if known, and
  any partial test evidence already collected
- successful reports include completed=true

The repeated three-failure lab plan remains unchanged and still performs no model calls
or GitHub writes.
