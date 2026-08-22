# ForgeBoss v0.9 — Repair Rat Playbook

Repair Rat now learns structured engineering outcomes from every completed attempt.

It stores failure signatures, affected files, exact pre-fix file hashes, specialists,
tests, concise model summaries/reasoning summaries, failure fingerprints and outcomes.
Only fixes that actually passed acceptance are stored with a reusable patch.

Before paying an AI model, Repair Rat checks the playbook. A proven patch is replayed
only if every affected file exactly matches the pre-fix hashes from the learned case.
The patch must pass `git apply --check` and the normal full acceptance suite. If it
passes, the repair costs $0 in model calls. If it fails, the workspace is reset to the
exact target and Repair Rat escalates normally.

Failed strategies are retained as negative evidence and are never automatically replayed.
