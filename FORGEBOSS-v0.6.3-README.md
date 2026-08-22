# ForgeBoss v0.6.3 — GitHub Report Hotfix

Fixes the `MethodNotFound,Publish-Run-Report.ps1` failure seen after the autonomous run.

Key behavior change:
- GitHub findings publication is now explicitly NON-FATAL.
- If the GitHub comment cannot be published, the full local run report is still kept and the SiteBoss run result is not changed.
- Failed candidate code is still not pushed.
- Merge and deploy remain disabled.

The publisher now also checks whether the current Windows PowerShell/.NET runtime supports `RSA.ImportFromPem` and returns a clear compatibility error instead of an opaque MethodNotFound failure.
