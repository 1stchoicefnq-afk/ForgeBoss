# ForgeBoss v0.4.4 — Windows Script Host Hotfix

The v0.4.3 launcher was written with UTF-8 BOM encoding. Windows Script Host on some Windows configurations treats that BOM as an invalid character at line 1, character 1.

v0.4.4 rewrites `START-FORGEBOSS.vbs` as strict ASCII with CRLF line endings and no BOM. It still launches `pythonw.exe` hidden, so there is no CMD/browser window in normal startup.
