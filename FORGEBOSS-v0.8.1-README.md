# ForgeBoss v0.8.1 — Self-test Sync

v0.8 changed the focused output limit from a literal PowerShell expression to
`Get-OpenAIOutputLimit`, because the cheap-first model router sets the limit through
the process environment.

The inherited cost-funnel self-test still looked for the old literal expression and
therefore failed before any paid work.

v0.8.1 updates that test to verify the actual v0.8 contract:
- dynamic output limit is wired;
- the process environment output-token control exists.

No model call is involved in this startup failure.
