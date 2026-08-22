# ForgeBoss v1.9.7 - Accumulating Handoff Fix

Fixes the repeated retained-partial-win handoff stop. Authoritative HEAD remains the trust anchor while the retained
workspace may advance to a local commit. The debug funnel now accepts that workspace when the authoritative HEAD is
an ancestor. If the normal funnel still cannot build the next packet, ForgeBoss derives a minimal next-target packet
directly from the just-finished failing validation runs, including a dedicated PostgreSQL 40001 serialization family.
