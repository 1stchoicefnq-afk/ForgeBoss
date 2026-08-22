# Deep Agents assessment

**Decision: ADOPT_SELECTED_COMPONENTS_ONLY**

Use Deep Agents for the agent loop, context management, structured output, streaming and later LangGraph checkpoint/resume. Keep SiteBoss as the control/security plane. The prototype is disabled by default and exposes no GitHub, MCP, network, LocalShellBackend, merge or deploy capability. Repository I/O and tests cross SiteBoss-owned wrappers only.
