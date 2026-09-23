# Forge Vault Security Contract

1. Raw secrets never enter project content.
2. Raw secrets never enter prompts or model context unless an explicitly scoped provider call requires a delegated credential.
3. Raw secrets never enter logs, crash reports or evidence.
4. Secret values are write-only in normal UI. After save, show provider + status + optional last four characters only.
5. Prefer OAuth / provider app authentication to manually copied tokens.
6. Windows local mode uses OS-protected credential storage.
7. Cloud mode uses a dedicated encrypted secrets manager.
8. Workers receive short-lived least-privilege leases, not vault access.
9. Every lease is tied to project_id, run_id, provider, allowed scope, expiry and spend ceiling.
10. Revocation must invalidate future worker access immediately.
11. Project export excludes secrets.
12. Backup/restore excludes raw secrets unless a separate encrypted secret-backup flow is explicitly implemented.
