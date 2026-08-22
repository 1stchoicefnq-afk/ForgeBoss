# SiteBoss Specialist Integration Report

## WHAT CHANGED
Added an Agency-derived specialist intelligence layer beneath the existing SiteBoss controller. The controller still owns exact-head control, packet scope, writer caps and execution authority. It now selects a maximum of two builder profiles and later selects independent reviewers from the actual changed domain.

## FILES CHANGED / ADDED
- `controller/lib/specialists.js`
- `controller/specialists/registry.json`
- `controller/specialists/profiles/*.json` (10 profiles)
- `controller/specialists/PROVENANCE.json`
- `controller/specialists-cli.js`
- `controller/siteboss-autopilot.js`
- `controller/lib/repair-adapter.js`
- `controller/config.default.json`
- `SiteBoss-Repair-Rat.ps1`
- `SiteBoss-Rat-Review.ps1`
- `controller/selftest-specialists.js`
- `controller/benchmark-specialists.js`
- `SPECIALIST-SELFTEST.cmd`
- `SPECIALIST-BENCHMARK.cmd`
- `THIRD_PARTY_NOTICES.md`
- `SPECIALIST-INTEGRATION-PLAN.md`
- `SPECIALISTS-README.md`
- `SPECIALIST-BUILD-AUDIT.json`

## AGENCY COMPONENTS REUSED
Concepts from the upstream specialist roster, frontmatter role structure, focused engineering personas, division/catalog organization and validation/install separation.

## AGENCY COMPONENTS ADAPTED
The ten profiles are concise SiteBoss-specific adaptations. Upstream tool permissions, orchestration authority and generic autonomy are intentionally removed.

## UPSTREAM COMMIT
`msitarzewski/agency-agents@c89557f`

## LICENSING / ATTRIBUTION
MIT attribution and permission notice are retained in `THIRD_PARTY_NOTICES.md`; per-profile provenance is recorded in JSON.

## SPECIALISTS AVAILABLE
1. Database Optimizer
2. Database Reliability Engineer
3. Identity & Access Engineer
4. Multi-Agent Systems Architect
5. AI Engineer
6. Prompt Engineer
7. Minimal Change Engineer
8. Code Reviewer
9. DevOps Automator
10. Frontend Developer

## ROUTING RULES
Deterministic term/domain scoring; maximum two profiles; safe minimal-change fallback; domain reviewer plus code reviewer where relevant; builder profiles are excluded from reviewer selection.

## TESTS RUN
- specialist router/adversarial selftest;
- six-case zero-model benchmark;
- Node syntax checks;
- existing controller selftest;
- target-selection selftest;
- scope-contract selftest;
- scope-priority selftest;
- static PowerShell structural/automatic-variable checks;
- licensing/provenance and authority-boundary audit.

## TEST RESULTS
Specialist selftest: 26 PASS / 0 FAIL.
Build/adversarial audit: 47 PASS / 0 FAIL.
Benchmark routing: 6/6 expected domains selected, zero model calls.
Existing controller and scope fixtures remain green.

## TOKEN / COST IMPACT
Routing itself costs $0 and makes no model call. Representative composed specialist prompts add about 1.6k–2.1k characters, averaging about 2.0k characters in the deterministic benchmark. Only one or two selected profiles are loaded; the upstream catalog is never dumped into a model request. Existing repair/review response caches are invalidated when specialist routing identity changes.

## KNOWN LIMITATIONS
- No paid A/B model-quality benchmark was run; quality/latency/failure-rate improvement is explicitly not claimed yet.
- The first slice has 10 profiles, not the full Agency catalog.
- Routing is deterministic keyword/domain scoring, not semantic model classification.
- PowerShell parser execution was unavailable in the build container; scripts received structural and automatic-variable checks, while Windows-side CHECK remains authoritative for PowerShell parsing.
- No GitHub publication, merge or deployment capability was added.

## NEXT RECOMMENDED SLICE
Run the zero-cost specialist selftest/benchmark on Windows, then run one bounded paid PostgreSQL repair. Compare the specialist-assisted candidate against the previous generic Repair Rat evidence. Only after evidence shows equal/better scope adherence and review quality should additional profiles or automatic draft-child publication be considered.
