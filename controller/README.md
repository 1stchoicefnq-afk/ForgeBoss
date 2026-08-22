# SiteBoss Autopilot Controller v0.8-foundation

This is the controller foundation behind the Windows CMD launchers.

Implemented:
- real CLI entrypoint
- atomic persistent run state
- exclusive controller lock
- heartbeat and stale-lock recovery
- interrupted-run reconciliation
- structured JSONL logging
- configuration validation
- doctor/status/dry-run/run/resume/logs/costs/stop/selftest
- local preflight adapters
- fail-closed state machine

Not enabled yet:
- model calls
- GitHub writes
- commit/push
- merge
- deploy
