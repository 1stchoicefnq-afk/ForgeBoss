# ForgeBoss v0.4.3 — No Console Launcher

Owner launcher is now `START-FORGEBOSS.vbs`, not CMD.

Windows Script Host starts `pythonw.exe` directly with hidden window style 0. It does not launch `cmd.exe`, PowerShell, or a browser as part of normal startup.

The old CMD launcher is retained only under ForgeBoss-Internal as a diagnostic fallback.

Background tournament/retest subprocess helpers also use Windows `CREATE_NO_WINDOW` where applicable.
