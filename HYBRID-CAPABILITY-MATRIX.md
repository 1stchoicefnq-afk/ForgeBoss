# SiteBoss Hybrid Capability Matrix

| Capability | Current SiteBoss | Agency | Deep Agents | OpenCode | Best Choice | Reason |
|---|---|---|---|---|---|---|
| controller | SiteBoss | profiles only | runtime only | runtime only | KEEP SiteBoss | Unique governance authority |
| scheduler | SiteBoss | Orchestrator advice | subagent runtime | agent/session runtime | KEEP SiteBoss | Leases and assignments are authority |
| task packets | immutable | metadata only | state input | session input | KEEP SiteBoss | Security contract |
| leases | implemented | none | none | none | KEEP SiteBoss | No framework may self-lease |
| permissions | hard wrappers | none | wrap | allow/ask/deny | KEEP SiteBoss | Prompt/permission UI is not sandbox |
| workspace isolation | implemented | none | backend ideas | local workspace | KEEP SiteBoss | Hard boundary |
| file read/search/edit | basic | none | filesystem tools | mature tools | ADAPT OpenCode patterns | High-value coding ergonomics |
| LSP | missing | none | none | mature | ADOPT selected OpenCode capability | Largest executor gap |
| planning | packet | Orchestrator | agent planning | plan/build | SiteBoss packet + optional planning | Planning never grants authority |
| subagents | limited | specialist concepts | strong isolated contexts | custom agents | DEFER | Benchmark first |
| specialist selection | working | strong catalog | none | custom agents | Agency + SiteBoss | Already proven |
| prompt construction | working | specialist prompts | system/state | agent prompts | KEEP SiteBoss composer | Governance precedence |
| context management | custom cache | none | strong | compaction/session | Deep/OpenCode selected | Avoid reinvention |
| checkpoint/resume | basic | none | LangGraph | sessions | Deep Agents + SiteBoss revalidation | Durable work |
| memory | cache only | none | memory | session | DEFER | Never authority |
| model routing | OpenAI-centric | none | provider abstraction | provider abstraction/local | SiteBoss router + adapters | Reduce lock-in/cost |
| repair loops | Repair Rat | none | agent loop | agent loop | KEEP then benchmark | Existing evidence is strong |
| testing | strong | QA profiles | tool execution | tools | KEEP SiteBoss | Deterministic acceptance |
| Git/GitHub | authority-aware | none | possible tools | tools/plugins | KEEP SiteBoss | Live truth |
| review | independent | reviewers | subagents | agents | SiteBoss + Agency | Author/reviewer independence |
| logging/evidence | structured | none | events/state | sessions/events | KEEP SiteBoss + event ideas | Single audit trail |
| cost control | hard budgets | profile cap | not authority | provider choice | KEEP SiteBoss | Controller-owned |
| failure recovery | bounded | none | checkpointing | sessions | Deep Agents selected | Resume after revalidation |
| Windows | proven CMD/PS | n/a | wrapper care | supported | KEEP SiteBoss wrappers | Virtual paths + breaker tests |