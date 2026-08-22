# ForgeBoss v0.5.1 — WebView Black-Screen Hotfix

v0.5 could install pywebview successfully and then show a black owner window on some Windows setups.

v0.5.1 changes the desktop bootstrap:
- loads `pro.html` as an actual local file instead of injecting a large HTML string;
- lets pywebview auto-select the best available Windows renderer rather than forcing EdgeChromium;
- uses the SiteBoss logo as a normal relative local asset;
- shows a visible "Connecting to ForgeBoss engine..." indicator until the Python bridge is ready;
- writes startup exceptions to `state/dashboard/desktop-startup-error.txt` while still avoiding a console window.

No browser URL is shown and normal startup remains `START-FORGEBOSS.vbs`.
