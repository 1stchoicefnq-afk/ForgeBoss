# ForgeBoss v2.0 - Control Plane Foundation

This release begins the durable control-plane architecture recommended by the OpenClaw audit.

Implemented:
- `forgebossd`: one long-running local daemon foundation, loopback-only by default.
- SQLite/WAL task + event store with schema versioning.
- durable tasks, runs, events, workspace leases, worker records, validation receipts, artefacts and provider usage tables.
- owner-epoch fencing: every writer must present taskId + runId + ownerEpoch and optionally expected head.
- signed WorkerLaunchEnvelope using a locally generated HMAC-SHA256 secret.
- strict request framing with connect-first, protocol version negotiation, 256 KiB frame limit, request IDs,
  stable protocol errors, idempotency keys for mutation methods, event sequence/state-version fields.
- workspace claim/heartbeat/assert/release operations.
- worker admission verifies envelope signature, expiry, workspace and current lease epoch.
- dashboard snapshot reports forgebossd health when the daemon is running.
- START-FORGEBOSSD.cmd and FORGEBOSSD-HEALTH.cmd.

Deliberately NOT claimed yet:
- The old dashboard/Repair Rat controller is not yet fully migrated to make forgebossd the sole scheduler.
- Transport is authenticated loopback JSONL TCP today; Windows named-pipe/WebSocket transport is a later hardening step.
- Runtime harnesses, LOST reconciliation, isolated worktree manager and full Patch Transaction Engine epoch checks are next.

The existing v1.9.8 repair/security behavior is retained.
