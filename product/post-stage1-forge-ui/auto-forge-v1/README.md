# ForgeBoss Auto Forge Candidate v1

Status: **finished isolated candidate — NOT applied to Stage 1**.

Exact GitHub base: `9669583bd10af91d52e3647a5f5c85e0cec975b7`

This wires the existing cheap-first cost controls into a real evidence-driven ladder:

**Repair Rat orchestration + Luna → Terra → Sol**

Rules:
- first bounded attempt stays Luna;
- the same failure signature repeating after focused retry permits Terra;
- if that same signature survives Terra, permit Sol;
- if it persists at maximum approved heat, stop;
- a new failure signature drops back to Luna;
- a verified partial win / new defect family drops back to Luna;
- cycle count by itself never increases spend;
- the existing session cap, daily cap, focused-context funnel, one-paid-call contract and pre-call budget estimate stay in force.

Backward compatibility: existing `cost-optimized` becomes the Auto Forge alias, so the current dashboard can use smart routing without waiting for the redesigned UI.

`apply_auto_forge.py` is fail-closed. It refuses unless HEAD, reviewed file blobs and clean working tree exactly match the pinned base. It performs no commit, push, merge, PR, workflow or remote write. On self-test failure it restores the original files.

Do **not** run this against the live Stage 1 exact-green engine.
