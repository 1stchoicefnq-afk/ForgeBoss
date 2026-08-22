# SiteBoss v1.3 Hybrid Worker — Testable First Slice

## Final decision
- Agency Agents: **ADOPT_SELECTED_COMPONENTS**
- Deep Agents: **ADOPT_SELECTED_COMPONENTS**
- OpenCode: **ADOPT_SELECTED_COMPONENTS**
- SiteBoss remains the only control/security plane.

## What this build adds
1. Deterministic model-router abstraction: local only for low-risk bounded work; OpenAI escalation for high-risk/complex work.
2. OpenCode-inspired `read`, bounded `grep`, and exact-edit workflow behind SiteBoss path scopes.
3. Windows absolute-path, traversal, UNC/symlink-aware guard logic.
4. Disposable end-to-end bridge smoke fixture.
5. Capability matrix and architecture decision record.

## What this build does NOT do
- It does not install OpenCode.
- It does not replace Repair Rat.
- It does not enable Deep Agents as the live executor.
- It does not make paid model calls.
- It does not make GitHub writes.
- It does not merge or deploy.
- It does not install a local model.

## Test order
1. `HYBRID-SELFTEST.cmd`
2. `HYBRID-BRIDGE-SMOKE.cmd`
3. `AGENCY-CORE-TEAM-SELFTEST.cmd` if present
4. `START-SITEBOSS.cmd`

The bridge smoke is intentionally deterministic and local.
