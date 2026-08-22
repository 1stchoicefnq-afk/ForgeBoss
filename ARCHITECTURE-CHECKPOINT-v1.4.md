# SiteBoss Architecture Checkpoint v1.4

The architecture expansion is frozen while executor candidates are benchmarked.

Current decision:
- **SiteBoss control plane — KEEP CUSTOM.**
- **Agency Agents — ADOPT_SELECTED_COMPONENTS** for specialist intelligence.
- **OpenHands Software Agent SDK — PROTOTYPE NEXT / leading executor candidate.** It already exposes agent, terminal, file-editor, task-tracker and local/ephemeral workspace APIs; do not replace Repair Rat until a bounded benchmark wins.
- **OpenCode — ADAPT SELECTED PATTERNS** for LSP/search/edit/provider/session ergonomics. Do not use its permission UI as SiteBoss's sandbox.
- **Deep Agents — ADOPT_SELECTED_COMPONENTS / DEFER LIVE EXECUTOR** for durable context/checkpoint/resume only after a proven gap.
- **mini-SWE-agent — REFERENCE_ARCHITECTURE_ONLY** as the complexity benchmark: keep the worker loop small.

v1.4 therefore does not introduce another framework. It makes the already-proven SiteBoss + Repair Rat path actually perform one bounded live build cycle and, only after clean independent review, publish a draft child PR.

`BUILD-SITEBOSS.cmd` is the owner-facing launcher.
