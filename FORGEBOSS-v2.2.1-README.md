# ForgeBoss v2.2.1 - Locator-First Hardening

The v2.2 live run proved the context/cost hardening worked: Luna received a normal ~111k-token request
for about $0.024 instead of the bogus $23 context explosion. The next rejection came from model contract
semantics: Luna put a prose repair description into `anchor_hint`.

This release fixes that whole class, not just the exact string:
- anchor_hint is schema-constrained to ONE JavaScript-style identifier token;
- a second local contract check rejects prose before normalization;
- anchor_locator is now authoritative and resolved FIRST;
- ForgeBoss verifies locator line/hash, then checks the identifier actually occurs on that exact current line;
- global symbol ambiguity no longer matters when an exact locator is supplied;
- semantic role is validated against the located line;
- class/object method declarations such as `async issue(...)` are recognized as definitions;
- the accidental literal PowerShell prompt `` `n `` is removed;
- cache schema v19 prevents replay of v2.2 responses.

Hardening expansion:
- original v2.2 torture matrix plus prose-anchor, locator-first, method-definition and prompt-format attacks;
- dedicated v2.2.1 model-contract matrix.

The learned $0 Travis repair, compact evidence, context ceiling, retry tracing, retained foundations,
runtime guards, project profiles, validated learning and smart-parallel scheduler foundation remain.
