# ForgeBoss v0.7.2 — Cost Cap + Focused First Call

The v0.7.1 run exposed two cost-control defects:
- the $0.50 run budget was being read from the Windows USER environment while ForgeBoss supplied it in the child PROCESS environment;
- the debug funnel used the wrong packet key and an assumed mirror path, so it could create zero focused files and Repair Rat silently fell back to its large packet.

v0.7.2 fixes both. Cost-optimized mode now requires a real non-empty focused packet before the first paid call. If it cannot build one, it stops at $0 model spend. OpenAI calls also receive a conservative preflight estimate and are refused when the estimated call floor exceeds the remaining run budget.

Run-report parsing now understands Repair Rat's real attempt fields, and GitHub report publication uses Node built-in RSA crypto instead of Windows PowerShell RSA.ImportFromPem.
