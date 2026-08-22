# ForgeBoss v0.4.2 — Polished Desktop + $0 Candidate Retest

Fixes the tournament validator root cause: the PowerShell function used `$Args`, which collides case-insensitively with PowerShell's automatic `$args` variable. It now uses `$DockerArgs`.

The native desktop dashboard now:
- uses the supplied SiteBoss logo;
- uses mint/teal with restrained SiteBoss orange accents;
- translates raw logs into plain-English activity events;
- keeps technical logs internal;
- adds **RETEST LAST CANDIDATES $0**.

That retest scans the retained case-sensitive mini-SWE/OpenHands tournament workspaces and runs the repaired deterministic validator without making another model call. This preserves the value of the work already paid for.
