# ForgeBoss v0.4.5 — Stable Desktop

This hotfix targets the two owner-facing failures seen on Windows:
1. black console windows flashing repeatedly;
2. the ForgeBoss window showing "Not Responding".

The desktop no longer runs executor readiness probes on the Tk UI thread. They run in a background thread every 30 seconds, so slow Node/OpenCode/Python checks cannot freeze the window.

The server's engine probes use Windows CREATE_NO_WINDOW, and the league/tournament helpers use the same flag where their local subprocess helper supports it.

Normal startup remains START-FORGEBOSS.vbs -> pythonw.exe with hidden window style 0.
