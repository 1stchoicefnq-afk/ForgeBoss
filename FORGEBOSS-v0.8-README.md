# ForgeBoss v0.8 — Cheap-First Model Router

The main cost problem was not two specialists making two calls. Repair Rat makes one OpenAI repair call with a composed specialist prompt. The expensive default was the unsuffixed `gpt-5.6`, which routes to the Sol tier.

v0.8 adds explicit model lanes:
- Cost optimized: GPT-5.6 Luna only, reasoning low.
- Balanced: Luna first; Terra only after a failed cycle.
- Strong: Luna first, Terra second, Sol only from the third cycle.

Repair Rat now prices the preflight using the actual selected model instead of always assuming Sol rates. Process-environment rate overrides remain available.

The existing focused packet, hard budget preflight, local validation, review gates, stagnation guard, merge-off and deploy-off protections remain in place.
