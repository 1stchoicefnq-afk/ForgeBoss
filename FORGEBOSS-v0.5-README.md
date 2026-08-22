# ForgeBoss v0.5 — Professional Desktop Shell

Owner launcher: `START-FORGEBOSS.vbs`.

v0.5 replaces the Tk owner dashboard with a native pywebview/WebView2 window rendering local HTML/CSS. No browser tab or localhost URL is used. Python methods are exposed directly through pywebview's JS API.

On first launch only, ForgeBoss silently installs pywebview into its isolated runtime if missing. This setup makes no model calls and no GitHub writes.

The UI uses the supplied SiteBoss logo, mint/teal + orange branding, sidebar navigation, structured cards, plain-English activity timeline, re-test outcomes, executor readiness, session controls and safety state.
