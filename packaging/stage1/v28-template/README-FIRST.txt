FORGEBOSS STAGE 1 V28 - SELF-VERIFYING CANDIDATE

1. Extract this ZIP to a fresh folder.
2. Run TURN-ON-FORGEBOSS.cmd.
3. Approve the one UAC prompt. It is only for the protected C:\ForgeBossAuthorityStage1-v28 root/ACL step.
4. Run VERIFY-FORGEBOSS.cmd.
5. Do NOT press START BUILD until this exact ZIP has passed independent hostile review.

Security changes:
- package manifest hashes and exact file-set are enforced before Install-Stage1.ps1 runs;
- PACKAGE-VERIFICATION.json is not used or shipped;
- package Python is behavior-scanned for forbidden process-wide os.mkdir/subprocess.Popen monkeypatches;
- exact engine selection comes from stage1-installed.json and a mismatched FORGEBOSS_ENGINE_ROOT is rejected;
- runtime dependencies install from a fully hashed Windows lock with --require-hashes --no-deps --only-binary :all:;
- VERIFY exercises the engine's own self-build budget policy and hidden-child no-console mechanism;
- VERIFY executes the protected-root identity/denylist table before readiness and TURN-ON executes it before UAC;\n- VERIFY proves the current self_build_* authority API and requires a signed self_build_current_known_good receipt;\n- builder image is digest-pinned;
- only the protected machine-root/ACL step is elevated;
- VERIFY does not clean or delete engine evidence;
- the protected authority returns the trust grade shown by the dashboard;
- Stage 1 uses a version-specific named pipe so old authority hosts do not collide with v28;
- Forge Vault is visible but does not collect secrets until a protected lease-only broker exists.

The advanced ForgeBoss dashboard remains the product shell. Projects, Forge Chat, Bible, Evidence and Forge Vault status are integrated directly into the engine UI rather than monkeypatched by a package wrapper.

Package authenticity boundary:
This is an OWNER-DELIVERED UNSIGNED PACKAGE. The manifest proves internal consistency, not publisher identity. Compare the SHA-256 of the ZIP with the value supplied through the delivery channel before running it.
