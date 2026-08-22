# ForgeBoss v1.9.8 - Secure Publish + UI Hardening

Security/correctness changes:
- Manual PUBLISH FINDINGS works again, but only after BOTH the server env gate and a native Windows Yes/No confirmation.
  A web/pywebview script cannot silently turn owner_confirmed on without triggering the native OS dialog.
- Automatic end-of-session publication is separate and requires both SITEBOSS_ALLOW_DRAFT_PUBLISH=YES and
  SITEBOSS_ALLOW_AUTO_DRAFT_PUBLISH=YES.
- Third-party write guard now also denies requirements files, pyproject.toml, setup.py/setup.cfg, tox.ini,
  Makefiles, Pipfile/Poetry/Cargo/Go manifests and .vscode/.
- pro.html no longer inserts activity/task/worker strings into privileged DOM without escaping/textContent.
- index.html keeps the same IDs/API functions but gets the mint grid, hierarchy, split action rows and status pulse.

The v1.9.7 accumulating handoff fix remains intact.
