# ForgeBoss Windows control-service native acceptance

Target stack: PR #325 -> #328 -> #331 -> #335 -> #338 -> issue #333 harness.

This is **native acceptance**, not a portable test. Run it only on a disposable native Windows VM/test host. It installs and starts the real `ForgeBossControl` service, creates test state under `%PROGRAMDATA%\ForgeBoss`, performs a controlled stop race, creates `ACTIVE-STATE.json`, restarts the service and deliberately tampers with the selected test state.

The harness never deletes the old source fixture and never cleans up automatically. Preserve the host/evidence until review is complete.

## Preconditions

Use an **elevated PowerShell** in a clean checkout of the exact review head.

Install the exact runtime dependencies into the same Python installation that will host `pythonservice.exe`:

```powershell
py -3 -m pip install -e .
py -3 -m pip install pywin32==312
```

Set the frozen review head by copying it from the PR/review target. Do **not** derive this value from the checkout:

```powershell
$HEAD = "<EXACT_40_CHARACTER_REVIEW_HEAD>"
$env:FORGEBOSS_WINDOWS_CONTROL_ACCEPTANCE = "YES-I-AM-ON-A-DISPOSABLE-WINDOWS-HOST"
```

Every harness command independently checks:
- native Windows;
- the exact 40-character Git head;
- a completely clean working tree;
- the explicit disposable-host opt-in.

## 1. Install the SCM service

Still in elevated PowerShell:

```powershell
py -3 -c "import sys; from forgeboss.control.windows_control_service import service_command_line; sys.argv=['forgeboss-control-service','--startup','manual','install']; raise SystemExit(service_command_line())"
```

Do not start it yet.

## 2. Provision disposable control state

```powershell
py -3 -m forgeboss.control.windows_control_native_acceptance --expected-head $HEAD provision | Tee-Object -FilePath .\WINDOWS-CONTROL-ACCEPTANCE.jsonl -Append
```

This phase:
- configures the real `ForgeBossControl` service SID as UNRESTRICTED;
- resolves the current desktop SID;
- creates/verifies the exact protected service-private DACL;
- creates a disposable source DB and fake test secrets;
- writes the protected `allowed-client-sid.txt` and `bootstrap-source-root.txt`;
- refuses any pre-existing candidate or active state.

It does not create `ACTIVE-STATE.json`.

## 3. Prove install/import/SID/registry identity

```powershell
py -3 -m forgeboss.control.windows_control_native_acceptance --expected-head $HEAD preflight | Tee-Object -FilePath .\WINDOWS-CONTROL-ACCEPTANCE.jsonl -Append
```

This must prove the installed registry `PythonClass` is exactly:

```text
forgeboss.control.windows_control_service.ForgeBossControlService
```

and that it resolves back to the exact candidate class. It also proves the service SID is UNRESTRICTED.

## 4. Start from SCM

```powershell
sc.exe start ForgeBossControl
```

Wait for `STATE: RUNNING`. A start failure is a native acceptance failure; do not substitute debug-mode execution.

## 5. Prove stop-during-copy withholding

Run this **before normal bootstrap**:

```powershell
py -3 -m forgeboss.control.windows_control_native_acceptance --expected-head $HEAD stop-race | Tee-Object -FilePath .\WINDOWS-CONTROL-ACCEPTANCE.jsonl -Append
```

The fixture contains a large SQLite payload. The harness starts `bootstrap.activate`, waits until a real `.migration-stage-*` directory is observed, then asks SCM to stop the service.

Required result:
- migration staging was actually observed;
- no `ACTIVE-STATE.json` commit exists after stop;
- a completed candidate, if present, independently verifies;
- SCM restart returns to bootstrap health;
- the next bootstrap may safely reuse a verified interrupted candidate.

If the copy finishes before staging can be observed, the phase fails and the host is not valid evidence.

## 6. Perform the real one-time bootstrap

```powershell
py -3 -m forgeboss.control.windows_control_native_acceptance --expected-head $HEAD bootstrap | Tee-Object -FilePath .\WINDOWS-CONTROL-ACCEPTANCE.jsonl -Append
```

Required result:
- pre-bootstrap health works;
- capabilities expose only `health` and `capabilities`;
- `bootstrap.activate` returns `ACTIVATED_RESTART_REQUIRED`;
- response contains no secret metadata;
- the same running process remains R0-only and does not hot-load authority.

## 7. Restart and verify persistence

```powershell
py -3 -m forgeboss.control.windows_control_native_acceptance --expected-head $HEAD restart-verify | Tee-Object -FilePath .\WINDOWS-CONTROL-ACCEPTANCE.jsonl -Append
```

This stops/starts through SCM, proves pipe health after restart, verifies the selected candidate against the migration manifest and confirms the old source fixture still exists.

## 8. Prove desktop access is denied

Open a **new NON-ELEVATED PowerShell** as the same configured desktop user. Do not use an Administrator/elevated token.

From the same clean exact-head checkout:

```powershell
$HEAD = "<SAME_EXACT_40_CHARACTER_REVIEW_HEAD>"
$env:FORGEBOSS_WINDOWS_CONTROL_ACCEPTANCE = "YES-I-AM-ON-A-DISPOSABLE-WINDOWS-HOST"

py -3 -m forgeboss.control.windows_control_native_acceptance --expected-head $HEAD desktop-denial | Tee-Object -FilePath .\WINDOWS-CONTROL-ACCEPTANCE-DESKTOP.jsonl -Append
```

Required result:
- the configured desktop SID can call the local health pipe;
- the non-elevated desktop token receives ACCESS DENIED for every candidate authority-bearing secret file.

The harness refuses this phase if the PowerShell process is elevated.

## 9. Tamper matrix

Return to the original **elevated PowerShell** and run:

```powershell
py -3 -m forgeboss.control.windows_control_native_acceptance --expected-head $HEAD tamper-matrix | Tee-Object -FilePath .\WINDOWS-CONTROL-ACCEPTANCE.jsonl -Append
```

The harness tests, one at a time:
- `ACTIVE-STATE.json`;
- migration manifest;
- candidate SQLite DB;
- one candidate secret.

For each target it:
1. stops the service;
2. changes the selected test-state bytes;
3. proves the service cannot provide normal health from that tampered state;
4. restores the original bytes;
5. restarts the service and proves health recovers.

Failure to reject any tampered target is a release blocker.

## 10. Preserve evidence

Do not remove the service, candidate, source fixture or acceptance JSONL until an independent reviewer has inspected the result.

The two evidence files are:
- `WINDOWS-CONTROL-ACCEPTANCE.jsonl` from the elevated phases;
- `WINDOWS-CONTROL-ACCEPTANCE-DESKTOP.jsonl` from the non-elevated denial phase.

The harness intentionally emits no secret bytes, credentials or secret hashes.

## Acceptance rule

The existence of this harness is **not** Windows acceptance.

The stack can claim native acceptance only when all required phases above have been run on the exact frozen candidate head and their observed JSONL evidence passes independent review.
