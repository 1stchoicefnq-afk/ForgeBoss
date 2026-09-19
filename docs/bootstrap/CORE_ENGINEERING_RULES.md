# ForgeBoss Core Project Engineering Rules

Status: product-level rules for future project mode  
Tracking issue: #169

These rules describe the minimum project-engineering behavior ForgeBoss should automatically apply when operating on user projects.

## Rules

1. Inspect before editing.
2. Reuse proven components before rebuilding them.
3. Plan before substantial implementation.
4. Review the plan adversarially before execution.
5. Split work into bounded, reviewable units.
6. Separate builder and reviewer roles.
7. Do not let a worker approve its own material changes.
8. Require tests and evidence before acceptance.
9. Treat green tests as provisional until independent review.
10. Check alternate, historical and underlying execution paths.
11. Put important permission checks at the true action/mutation boundary.
12. Prefer one authoritative implementation for important state.
13. Fail closed when safety or authority is unknown.
14. Require human approval for high-risk actions unless the owner explicitly delegated that exact authority.
15. Preview destructive actions where practical.
16. Record material assumptions as durable decisions.
17. Do not silently invent missing requirements.
18. Test both successful and failure paths.
19. Test concurrency, stale state, retries and partial failure where the domain requires it.
20. Do not call portable proof native-platform proof.
21. Do not claim tests that were not actually run.
22. Do not claim FIXED, VERIFIED, SECURE, RELEASE READY or PRODUCTION READY without supporting evidence.
23. Keep project documentation concise, authoritative and machine-loadable.
24. Keep secrets out of source control.
25. Keep model providers replaceable; provider chat history must not be the only project memory.
26. Preserve exact evidence sufficient for another worker/reviewer to reproduce important claims.
27. Prefer reversible changes and known-good rollback paths.
28. Make risky authority explicit rather than implicit.
29. If a requirement materially affects money, security, privacy, permissions, data, platform support or irreversible architecture, record and surface the decision.
30. The final objective is not simply code generation. It is a product whose important behavior can be tested, reviewed and proven.

## Required questions for every substantial feature

ForgeBoss should be able to answer:

- What exactly is being built?
- Why is it required?
- Which authority owns the decision/action?
- What existing component can be reused?
- What can fail?
- How will failure behave?
- How will we test it?
- How could the intended path be bypassed?
- What evidence proves the result?
- What remains uncertain?
- Does the owner need to approve anything before proceeding?

If ForgeBoss cannot answer a material question, it must resolve or explicitly record the gap before treating the feature as complete.
