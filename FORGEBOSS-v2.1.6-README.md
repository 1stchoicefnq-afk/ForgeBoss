# ForgeBoss v2.1.6 - Schema Walker Hardening

FB-20260822-033132 showed v2.1.5 stopped before any paid API call, but the local strict-schema walker
crashed while traversing a dictionary node with no `type` property.

Fixes:
- schema walker now uses IDictionary.Contains(...) and indexer access;
- property-map nodes without `type` are traversed safely;
- object schemas still enforce required/property parity;
- unknown required entries are rejected too;
- preflight failures are wrapped as FORGEBOSS_SCHEMA_PREFLIGHT_FAILED;
- controller stops immediately on that infra fault;
- symbol anchors and the zero-API learned Travis 22P05 repair remain intact;
- patch cache schema v14.
