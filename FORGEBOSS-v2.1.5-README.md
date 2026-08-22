# ForgeBoss v2.1.5 - Strict Schema Preflight

Fixes FB-20260821-222823. OpenAI strict structured outputs require every property in an object schema
to also appear in required[]. v2.1.4 made line hints optional by removing them from required, so the
provider rejected the schema before inference.

v2.1.5 keeps line_start/line_end required with 0/0 as the explicit no-hint sentinel, validates
required/property coverage locally before HTTP, and immediately stops invalid_json_schema as an
INFRA_ERROR rather than repeating it. Symbol-first anchors and the zero-API learned 22P05 repair remain.
