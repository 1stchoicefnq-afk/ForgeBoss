# ForgeBoss v0.3 — Better Worker Tournament

The dashboard now has **RUN $1 BETTER-WORKER TOURNAMENT**.

What it does:
1. performs one authoritative SiteBoss read/plan;
2. freezes the exact current SiteBoss HEAD and packet;
3. creates two disposable Git workspaces from the same local mirror;
4. removes Git remotes from both;
5. runs mini-SWE-agent and OpenHands on the same packet using GPT-5.6 Luna;
6. mini-SWE shell execution is Docker-isolated with `--network none`;
7. OpenHands has API/GitHub credentials removed before terminal tools run;
8. rejects any changed path outside the packet allowlist;
9. runs the same deterministic PostgreSQL quick-acceptance suite on each candidate;
10. records cost/time/test/scope evidence and picks only a **provisional** winner.

No tournament candidate can push, create a PR, merge, or deploy. A winner is not promoted to live SiteBoss work after one experiment; it must win again or pass a full independent ForgeBoss gate.

Repair Rat remains the live default executor until that proof exists.
