# ForgeBoss v2.0.7 - Retained Evidence Handoff

Run FB-20260820-222628 proved cycle 1 was healthy and the accumulating loop reached cycle 2,
but cycle 2 safe-refused because the focused 40001 packet was rejected after replaying the retained
foundation: its target_sha referred to the authoritative base, while the replay created a new local
commit SHA. A single fresh baseline then happened to pass, so Luna saw failure_count=0 and correctly
refused speculative work.

Fix:
- focused packets are accepted after verified foundation replay when their authoritative_base_sha
  matches the frozen base;
- failure feedback gets the same provenance rule;
- the payload exposes retained_foundation_evidence separately from historical lab evidence;
- repeated 40001/40P01 evidence from immediately preceding validation remains current even when one
  stochastic rerun passes;
- current source_files from the replayed workspace outrank older debug-funnel snippets;
- debug funnel records evidence provenance explicitly;
- patch cache schema bumped to v7.

This does not make stale evidence authoritative: the retained patch must be replayed successfully and
the packet must bind to the same authoritative base SHA.
