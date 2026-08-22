# ForgeBoss v1.9 — Patch Transaction Engine

ForgeBoss now treats AI output as an intended change transaction, not as file transport.

Each operation carries:
- path
- expected_file_hash
- mode: replace / insert_before / insert_after / delete / create
- old_text
- new_text
- replace_all

The transaction also carries transaction_id, exact base_sha and a validation_plan.

Deterministic ForgeBoss code verifies:
- exact repository HEAD;
- path allowlist;
- prior full read by this task;
- current SHA-256 against the model-visible file hash;
- unique edit anchors unless replace_all is explicit;
- no-op rejection;
- resulting size ceiling;
- changed-path ceiling.

Writes are made through a temporary file + replace, a recovery copy is retained, and a transaction receipt records
the diff hash and validation plan.

v1.9 also commits a replayed retained foundation locally before the next transaction so accumulation stays pristine.
