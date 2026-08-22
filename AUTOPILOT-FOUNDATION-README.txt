SITEBOSS AUTOPILOT v0.8-foundation

NORMAL LAUNCH:
  SITEBOSS-AUTOPILOT.cmd

FOUNDATION COMMANDS:
  AUTOPILOT-DOCTOR.cmd
  AUTOPILOT-DRY-RUN.cmd
  AUTOPILOT-STATUS.cmd
  AUTOPILOT-RESUME.cmd
  AUTOPILOT-LOGS.cmd
  AUTOPILOT-COSTS.cmd
  AUTOPILOT-STOP.cmd
  AUTOPILOT-SELFTEST.cmd

PROVES:
- proper Node controller behind CMD
- persistent atomic state
- controller lock + heartbeat
- stale lock recovery
- interrupted run reconciliation
- explicit state machine
- structured logs
- fail-closed errors
- dry-run

SAFETY:
live execution OFF
model calls OFF
GitHub writes OFF
merge OFF
deploy OFF

Next milestone: M3 authoritative control-state retrieval and validation.
