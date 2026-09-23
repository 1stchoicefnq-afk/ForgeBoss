# ForgeBoss post-Stage1 backend prototype v1

This is an isolated product-side prototype. It must not be wired into the frozen Stage 1 engine until Stage 1 is independently proven and the integration is re-reviewed.

Implemented here:

- SQLite project conversation history.
- Automatic redaction of common API/token shapes before chat persistence.
- Candidate -> validated project memory lifecycle.
- Project Bible proposals separated from canonical activation.
- Canonical Bible activation requires explicit `human-owner` approval.
- Context precedence: active Bible -> validated memory -> recent conversation.
- New-project scaffold generation with hashed Bible manifest.
- Windows DPAPI Vault with no insecure non-Windows fallback.
- Vault metadata shows provider + last four only.
- Scoped, expiring in-memory secret leases for individual project/run use.
- Safe project snapshot explicitly excludes Vault content.

## Security boundary

Raw secrets must never be stored in Git, project folders, Bible files, chat exports, logs or evidence. The Windows vault defaults to `%LOCALAPPDATA%/ForgeBoss/Vault`, outside project repositories, and stores DPAPI-encrypted blobs only.

The implementation intentionally refuses to create a plaintext/non-Windows fallback.

## Test

`python tests/test_backend.py`

Windows-native DPAPI round-trip remains an acceptance requirement because this build environment is not Windows.
