# ForgeBoss v2.1.8 - Retry Trace Evidence

FB-20260822-040321 showed the infrastructure path is now healthy enough to reach a meaningful safe refusal.
Cycle 1 again used the learned Travis 22P05/NUL repair for $0. Cycle 2 correctly refused to make a generic
serialization change because the packet proved 40001 failures but did not prove what happened across each
retry attempt.

v2.1.8 adds execution evidence instead of weakening the safety policy:
- when normal acceptance observes SQLSTATE 40001, ForgeBoss instruments ONLY the disposable Docker copy
  of src/persistence/postgres.js;
- an extra diagnostic full-suite run records each withSerializableRetry attempt/decision:
  attempt number, timestamp, PostgreSQL code, transaction outcome, same-error identity, retryable flag,
  and abort state;
- the retained/source worktree is never modified by diagnostic instrumentation;
- diagnostics do not affect acceptance pass/fail;
- Repair Rat may support bounded backoff only when trace evidence proves consecutive trusted rolled-back
  retryable 40001/40P01 attempts re-enter almost immediately;
- it is still forbidden to increase retry count, weaken SERIALIZABLE isolation, or retry ambiguous commits;
- all v2.1.7 symbol-role/runtime guards and the $0 learned repair remain;
- patch cache schema v16.
