# ForgeBoss v2.2.2 - Control Plane Hardening

Addresses the unauthenticated second authorization plane before real workers consume it.

Batch fixes:
- HMAC-authenticated initial connect with timestamp + one-use nonce replay protection.
- Windows secret protection uses explicit icacls DACLs; chmod is no longer treated as a Windows ACL.
- forgebossd DB and validated-learning DB directories/files use the same private ACL policy.
- worktreePath must be an absolute local path inside FORGEBOSS_WORKTREE_ROOT; UNC/device/escape paths are denied.
- task.create/workspace.claim reuse executor_guard sensitive-path policy.
- claim allowedPaths cannot exceed the task's original allowedPaths.
- repository and baseSha are bound back to the task before signing an envelope.
- allowedTools are selected from a server-side whitelist, not arbitrary caller input.
- state/forgebossd/ and state/learning/ are executor-denied write prefixes.
- signed envelopes use canonical lease path + validated allowed paths.

Additional finding fixed during torture testing:
executor_guard.norm() used lstrip("./"), which stripped the leading dot from `.git/...` and `.env` style
paths before policy matching. Hidden-dot paths are now preserved exactly; the new matrix explicitly tests
`.git/hooks/pre-commit`.

Boundary: this protects against unauthenticated local clients and other Windows accounts lacking access to
the owner-restricted secret. It does not claim to contain malware already executing as the same Windows user;
host-untrusted workers still require an OS sandbox/service-account boundary before admission.
