# ForgeBoss v1.9.4 - Security Hardening

Fixes from the latest security review:
- Windows path-policy comparisons are casefolded, closing `.GIT` / `.ENV` style bypasses.
- High-impact execution surfaces are denied to third-party writers by default, including `.github/actions`,
  package.json, Docker/Compose files and common CI configuration.
- Baseline symlinks/junctions are rejected before a lease is issued, and allowed/context paths must resolve inside
  the leased workspace.
- OpenHands and OpenCode write-capable execution are quarantined until an OS/network-isolation adapter is explicitly
  verified. mini-SWE keeps Docker `--network none` for its shell.
- GitHub report publication can no longer bypass `SITEBOSS_ALLOW_DRAFT_PUBLISH=YES` through `owner_confirmed=True`.
- Dashboard safety text no longer claims independent review while provider policy is still single-provider.
- Legacy `index.html` is rethemed to the mint ForgeBoss palette used by `pro.html`.

Important limitation:
A file guard cannot retroactively prevent data exfiltration. v1.9.4 therefore fails closed for write-capable
executors without proven process/network isolation rather than claiming postflight inspection is a sandbox.
