# ai-employees upstream snapshot

This directory is a quarantined, pinned source snapshot retained for review and selective adaptation.

- Upstream repository: markfulton/ai-employees
- Upstream commit: edffe8f4afea467818988ce3ce9332e6d832e5ed
- License: MIT
- Vendored for ForgeBoss issue: #189

## Included upstream files

| Upstream path | Local path | Upstream Git blob |
| --- | --- | --- |
| `LICENSE` | `LICENSE` | `b60449ab76b836c35fa1887b9404de6da2e5f45b` |
| `installer/upgrade.mjs` | `installer/upgrade.mjs` | `fc028ffadde1b8c570f01aadca379598e636218e` |
| `employees/chief-of-staff/scripts/guard.mjs` | `scripts/guard.mjs` | `7b6a2c3df125449fb91cf16fbd649a1ee9fc96a2` |
| `employees/chief-of-staff/scripts/runlog.mjs` | `scripts/runlog.mjs` | `2f624015a6726ac97573dff4964ddd1eac601102` |
| `employees/chief-of-staff/scripts/copy-check.mjs` | `scripts/copy-check.mjs` | `457b63e151dda689913226d7ff89628cee142d8b` |

## Boundary

These files are stored unchanged except for their repository path. They are not imported by ForgeBoss, are not an authority source, and are not part of the runtime.

Any production adaptation must be implemented in a separate reviewed packet behind ForgeBoss authority, evidence, approval and execution controls. Do not edit the vendored copies to create local behavior; adapt into first-party modules and keep this snapshot as provenance/reference.
