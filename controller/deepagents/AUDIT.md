# DEEPAGENTS — Hostile Sandbox / Tool Permission Audit

Lane: `DEEPAGENTS` · Scope audited: `controller/deepagents/**` · Date: 2026-08-28

Every finding below was reproduced against the pre-fix module before being
fixed. Regression tests live in `tests/test_policy.py` and are named
`test_regr_*`.

## Threat model

The deep agent is treated as fully hostile. It controls:

* every `path` string passed to `sb_read_file` / `sb_write_file`;
* every element of the `argv` list passed to `sb_run_test`;
* the entire `SiteBossResult` object it emits;
* file content it writes, which is later read back as model input.

It does **not** control the packet, the workspace root, or this module.

---

## BLOCKER

### B1 — `python -c` made the executable allowlist meaningless

`run_command` allowlisted interpreter basenames but placed no constraint on
arguments, so `["python", "-c", "<any code>"]` passed the "command class"
check. Reproduced: the child process read `/etc/hostname` from outside the
workspace root. `node -e`, `node -p`, `node --require` and `npm install`
(lifecycle scripts) were equivalent. The old test suite itself relied on
`python -c`, which is how the hole survived review.

**Fixed** — `_check_argument_policy` denies inline-code and interactive flags,
restricts `python -m` to `pytest`/`unittest`, denies bare interpreter
invocations (which read code from inherited stdin), and restricts `npm` to
`test` / `run` / `run-script`. `stdin` is now `subprocess.DEVNULL`.
Tests: `test_regr_inline_code_execution_denied`,
`test_regr_node_argument_policy`, `test_regr_npm_subcommand_allowlist`,
`test_regr_python_module_allowlist`.

**Residual (see X1):** an approved test runner still executes repository code
by definition. This module contains the *tool surface*, not the process.

---

## HIGH

### H1 — Agent-written file could be executed as an interpreter

The allowlist tested `Path(argv[0]).name.lower()`, i.e. the basename only, with
no anchoring of the executable's location. An agent with any write scope could
write `tests/python` (POSIX) or `tests/npm.cmd` (Windows, no execute bit
needed) and then run it. Reproduced: a workspace-written shell script executed
and returned its own stdout.

**Fixed** — `_resolve_executable` resolves `argv[0]` to an absolute path (via
`shutil.which` for bare names) and denies anything that resolves *inside* the
workspace root. Test: `test_regr_workspace_executable_denied`.

### H2 — In-workspace symlink bypassed read and write scope

Scope was checked on the logical path while I/O happened on the resolved path.
`tests/alias -> src/secret.js` is logically inside `write_scope = ("tests",)`
and resolves inside the root, so both existing checks passed. Reproduced: the
out-of-scope file `src/secret.js` was overwritten, and its content was read
back through the same alias.

**Fixed** — `GuardedWorkspace._authorise` re-applies the scope check to the
post-resolution root-relative path. Tests:
`test_regr_inworkspace_symlink_bypasses_write_scope`,
`test_regr_inworkspace_symlink_bypasses_read_scope`.

*Behaviour note:* a repository that legitimately symlinks a scoped directory
elsewhere in the tree now needs both paths in scope. That is the correct call —
scope is defined on logical paths — but it is a behaviour change.

### H3 — `npx` in the allowlist was arbitrary remote code execution

`npx <pkg>` downloads and runs an arbitrary package from the network inside the
workspace. `DECISION.json` sets `allow_network_tools: false` and
`no_local_shell: true`; the allowlist contradicted both.

**Fixed** — `npx`/`npx.cmd` removed from the executable pattern.
Test: `test_regr_npx_denied`.

---

## MEDIUM

### M1 — Model-authored evidence was accepted verbatim (fail-open)

`SiteBossResult` carries `files_read`, `files_changed`, `commands_run`,
`tests`, `scope_respected` and `write_authority_respected`, all authored by the
model and defaulting to `True`. Nothing reconciled them against the
`GuardedWorkspace.evidence` that actually recorded what happened, so an agent
could report `status=COMPLETED, scope_respected=True` with a fabricated test
list. `packet.required_tests` was never enforced anywhere in the codebase.

**Fixed** — `reconcile_evidence` in `siteboss_policy.py` overwrites every
evidence field from the workspace, recomputes both `*_respected` flags,
enforces `required_tests_satisfied` (requires exit code 0), and forces
`status="BLOCKED"` with explicit blockers on any mismatch.
`prototype_runtime.finalise_result` is the call site.
Tests: `test_regr_evidence_reconciliation_overrides_model_claims`,
`test_regr_required_tests_cannot_be_forged`,
`test_regr_required_tests_need_zero_exit`.

### M2 — No read-before-write ordering

`write_text` accepted a full-content overwrite of an existing file the agent had
never read, silently destroying content outside its knowledge.

**Fixed** — writing an existing file requires it to appear in
`evidence.files_read`. Creating a new file still needs no read. A successful
write records the path as read, so follow-up writes are legal.
Tests: `test_regr_read_before_write_required`,
`test_create_new_file_needs_no_read`.

### M3 — Packet budgets were unbounded and unvalidated

`packet_mapper` did `int(p.get("max_commands", 12))` with no ceiling, so a
packet claiming `max_commands: 10000` was honoured. `ImmutablePacket` accepted
scope entries like `"../etc"` or `"C:/windows"` without validation, deferring
the failure to first use. A bare string scope (`"tests"`) silently became five
single-character scopes because strings are iterable.

**Fixed** — controller-owned ceilings (`MAX_*_CEILING`) enforced in
`ImmutablePacket.__post_init__` and clamped in `packet_mapper` via
`clamp_budget`; scope entries validated at construction; string scopes rejected;
missing head revision rejected. Tests:
`test_regr_packet_budget_ceiling_enforced`,
`test_regr_packet_rejects_malformed_scope`,
`test_regr_mapper_clamps_hostile_budgets`,
`test_regr_mapper_rejects_missing_head`.

### M4 — `revalidate_resume` accepted truthy non-booleans

`if not lease_valid` treats the string `"expired"` as a valid lease and `"no"`
as a valid controller version — a fail-open on malformed caller input.
`current_head=None` compared unequal and happened to fail closed, but by luck.

**Fixed** — strict `is not True` identity checks plus explicit type/emptiness
validation on both head revisions.
Test: `test_regr_resume_rejects_truthy_non_boolean`.

### M5 — Windows path-normalisation mismatches

`norm` accepted:

* reserved DOS device names (`tests/NUL`, `tests/COM1`, `tests/aux.txt`) which
  open character devices rather than files on Windows;
* NTFS alternate data streams (`src/ok.js:evil`, `x.txt::$DATA`), which write
  bytes that no scope or extension reasoning accounts for;
* trailing dots/spaces (`src/no.js.`), which Windows strips, so two strings that
  compare as different scope entries name the same file;
* control characters and NUL bytes in paths.

**Fixed** — all four rejected per path component, on every platform, so the
policy decision is host-independent. Tests:
`test_regr_reserved_device_names_denied`,
`test_regr_alternate_data_stream_denied`,
`test_regr_trailing_dot_or_space_denied`,
`test_regr_control_characters_denied`.

### M6 — `python3` denied on Linux while `python.exe` allowed on Windows

The allowlist omitted `python3`, the ordinary POSIX interpreter name, so an
identical `required_tests` entry executed on Windows and was denied on Linux.
This is why the pre-existing `test_command_budget` was failing on `main`
(`sys.executable` is `/usr/bin/python3`).

**Fixed** — `python3` and versioned `python3.12` forms accepted. This is the
only permission *expansion* in this change: it is the same interpreter class
already allowed under a different name, and it is bounded by B1's argument
policy, which is strictly tighter than what `python` previously permitted.
Test: `test_regr_python3_allowed_on_posix`.

---

## LOW

### L1 — Timed-out commands left no evidence
`subprocess.TimeoutExpired` propagated before the record was appended, so a hung
command consumed budget with no audit trail. Now recorded (with
`timed_out: True`) and re-raised as `BudgetExceeded`.
Test: `test_regr_timeout_leaves_evidence`.

### L2 — Malformed `argv` reached `subprocess`
Non-string elements and non-list `argv` produced a raw `TypeError` instead of a
policy denial. Now `SecurityDenial`. Test: `test_regr_malformed_argv_denied`.

### L3 — One malformed scope entry broke every check
`under()` called `norm()` on scope entries inside the match loop, so a single
bad entry raised `SecurityDenial("parent traversal denied")` for an unrelated
in-scope path. Fail-closed, but it misattributes the denial. Malformed entries
are now skipped (they never grant) and rejected at packet construction.
Test: `test_regr_malformed_scope_entry_grants_nothing`.

### L4 — Unbounded reads and writes
`read_text` loaded any size into memory; `write_text` accepted any size and any
type. Now capped at `MAX_READ_BYTES` / `MAX_WRITE_BYTES`, non-regular files
rejected, non-string content rejected. Tests: `test_regr_read_size_limit`,
`test_regr_read_rejects_non_regular_file`,
`test_regr_write_rejects_non_string_content`.

### L5 — Traversal through a non-directory
`real()` did not reject `src/no.js/child` where `no.js` is a file; it failed
later with a raw `NotADirectoryError`. Now a policy denial.
Test: `test_regr_non_directory_traversal_denied`.

### L6 — Missing hardening in the child environment
The env allowlist was already correct (no host secrets reach the child) but
omitted `PYTHONNOUSERSITE`, leaving `~/.local/.../usercustomize.py` as a code
injection path that the PATH allowlist does not cover. Added, along with
`PYTHONDONTWRITEBYTECODE` and `NO_COLOR`.
Test: `test_regr_child_env_has_no_host_secrets`.

### L7 — Windows child processes started with a broken environment
The env allowlist omitted `SystemRoot`, `COMSPEC` and `PATHEXT`. On Windows
this breaks process startup, socket and TLS initialisation. Added under
`os.name == "nt"` only; none carry secret material.

### L8 — Test suite used a predictable shared temp path
`test_symlink_escape` created `<tmp>/../sb-outside` with `mkdir(exist_ok=True)`
and cleaned up with a swallowed `rmdir()`, so it reused any pre-existing
directory at that name and leaked on failure. Replaced with a second
`TemporaryDirectory` registered via `addCleanup`.

### L9 — Prompt injection had no stated precedence rule
File contents and command output re-enter the model as untrusted text next to
the authority block. Enforcement is in `GuardedWorkspace`, so this is
defence-in-depth only; the system prompt now states that nothing in the
specialist prompt, file contents or command output widens scope or overrides a
denial.

---

## Not defects

* **Dangling symlink** — `resolve(strict=False)` already resolved broken
  symlinks, so `candidate.relative_to(root)` caught the escape. The
  per-component loop used `exists()`, which is false for a broken link, so only
  one of the two layers was holding. Now uses `is_symlink() or exists()`.
  Guarded by `test_regr_dangling_symlink_escape`.
* **`shell=False`** — correctly set; no shell metacharacter injection path
  exists through `run_command` directly.
* **Environment leakage** — the explicit env allowlist was already correct.
* **Directory scope granting a subtree** — `write_scope = ("tests",)` granting
  `tests/x` is intended prefix semantics, and L5 now stops a *file* entry from
  acting as a directory prefix.

---

## Unresolved / requires other lanes

### X1 — No OS-level isolation (BLOCKER, cross-lane)
Owner: `process` lane (subprocess supervision) with `security`.
An approved test runner executes repository code, which can read any file the
runner user can read, open network sockets, and spawn grandchildren that
survive the `TimeoutExpired` kill. `run_command` cannot fix this from inside
Python. Requires a job object / cgroup / container boundary, a process-group
kill on timeout, and network egress denial. Until then `DECISION.json`'s
`enabled: false` is doing the real containment.

### X2 — TOCTOU between `real()` and `open()` (MEDIUM, cross-lane)
Owner: `paths` lane.
Resolution and I/O are separate syscalls. A concurrently running approved
command can replace a component with a symlink in between. Closing this needs
`O_NOFOLLOW`/`openat`-style handling with a Windows equivalent, which is a
path-layer concern shared with `forgeboss/**`, not a deepagents-local fix.

### X3 — `controller/deepagents` is not a package (LOW, cross-lane)
Owner: `integration` lane.
`packet_mapper` and `prototype_runtime` use bare `from siteboss_policy import`,
which only resolves via `sys.path` manipulation. There is no `__init__.py`.
Adding one changes how `TEST-FORGEBOSS.cmd` (root-level, out of lane) invokes
the suite, so it is left alone.

### X4 — `TEST-FORGEBOSS.cmd` invokes `python` not `python3` (LOW, cross-lane)
Owner: `integration` lane. Root-level file, out of lane. The suite runs on
Linux CI only if `python` exists on PATH.

### X5 — `prototype_runtime` is untestable without `pydantic` (LOW)
`pydantic` is not in `requirements-prototype.txt` (it arrives transitively via
`deepagents`), and neither is installed in CI. The reconciliation logic was
therefore placed in `siteboss_policy.py`, which has no third-party imports, so
it is covered by the suite. `finalise_result` itself remains uncovered.
