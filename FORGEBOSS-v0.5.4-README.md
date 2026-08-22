# ForgeBoss v0.5.4 — Validator Native STDERR Hotfix

The previous re-test did not run any candidate tests. Docker/npm emitted harmless
`npm notice` text on STDERR, and Windows PowerShell converted that native STDERR
stream into a terminating `NativeCommandError` because ForgeBoss globally uses
`$ErrorActionPreference='Stop'`.

v0.5.4 fixes the Docker wrapper by temporarily disabling PowerShell native-command
stderr promotion while each Docker process runs, while still treating Docker's
real `$LASTEXITCODE` as authoritative.

The dashboard also no longer labels `failure_count=999` + zero validation runs as
a worker FAIL. It displays `VALIDATOR ERROR`, because no candidate tests actually
ran.

Next action: click `RETEST LAST CANDIDATES · $0` again. This reuses the existing
mini-SWE and OpenHands workspaces and makes zero new model calls.
