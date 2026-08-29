# Security Policy

ForgeBoss coordinates code-writing tools, subprocesses, repositories and optional paid model providers. Treat security defects as first-class engineering defects.

## Supported code

Security fixes target the current `main` branch unless maintainers explicitly identify a supported release branch.

## Do not publish sensitive exploit details first

If a vulnerability could expose credentials, execute unintended commands, escape path/scope controls, bypass spend controls, corrupt repositories or compromise a host machine, do not begin with a public Issue containing weaponized details.

Use GitHub's private vulnerability reporting feature if it is enabled for this repository. If private reporting is unavailable, open a minimal public Issue stating that you have a security report and need a private contact channel. Do not include secrets, tokens, private customer data or a working exploit in that public Issue.

## Useful reports include

- affected version or commit SHA;
- operating system and runtime versions;
- exact component affected;
- impact;
- safe reproduction steps;
- logs with secrets removed;
- suggested mitigation if known.

## Security-sensitive areas

Extra care is expected around:

- shell and subprocess execution;
- path traversal and writable-scope enforcement;
- Git ref/SHA validation;
- credentials and environment variables;
- provider/API spend controls;
- webhook or external-input validation;
- database transactions and leases;
- process supervision and restart behavior;
- automatic patching or merge authority.

## Disclosure

Please allow maintainers reasonable time to reproduce, patch and validate a vulnerability before publishing detailed exploit information.
