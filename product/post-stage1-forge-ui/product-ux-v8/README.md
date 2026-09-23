# ForgeBoss Product UX v8

This is a **standalone product prototype** and implementation specification. It does not modify the live ForgeBoss repository, Stage 1 checkout, branches, CI, or Windows services.

## What is represented

- New Project flow driven by a project **idea**, not repair prompts.
- Essential-question gate before the first Project Bible is created.
- Existing local folder and remote Git repository entry paths.
- Project-scoped Forge Chat memory.
- Three memory layers:
  1. conversation history,
  2. distilled project memory,
  3. authoritative Project Bible.
- Forge run screen with:
  - actual workflow progress,
  - newest activity first,
  - forge time,
  - fuel cap / API spend,
  - current worker/model,
  - Auto Forge escalation.
- Bible and Evidence sections.
- Forge Vault with:
  - ForgeBoss Managed AI,
  - Bring Your Own Fuel,
  - OpenAI / Anthropic,
  - GitHub / GitLab / Bitbucket / Azure DevOps,
  - local model connections.
- Settings for default time, spend cap, mode, memory and Bible-promotion behaviour.

## Important security note

The prototype intentionally does **not** persist raw API keys. Production ForgeBoss must use an OS-protected secret store (Windows DPAPI / Credential Manager or equivalent service-side vault) or OAuth/App authentication.

Raw credentials must never appear in:
- project folders,
- Git repositories,
- Project Bible files,
- chat memory,
- logs,
- evidence bundles,
- model prompts.

See `ARCHITECTURE.md` for the production design requirements.
