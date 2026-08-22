# ForgeBoss v0.7.3 — Zero-Spend Loop Hotfix

The v0.7.2 report proved the API cost guard worked: all four cycles cost $0.00.
It also exposed a controller bug: pre-model failures were incorrectly treated as
SiteBoss repair failures and retried.

v0.7.3:
- stops immediately on any Repair Rat fatal that occurred before a model call;
- classifies a budget preflight refusal as BUDGET_BLOCKED, not a SiteBoss failure;
- classifies other zero-call plumbing failures as INFRA_ERROR;
- fixes focused-scope specialist validation by comparing the controller plan to the
  full controller-approved boundary while retaining the smaller focused edit boundary;
- fixes the blank budget-preflight numbers in PowerShell formatting;
- reduces focused maximum output to 3,000 tokens;
- distinguishes worker safe-stop wording from an owner pressing STOP SAFELY.

No paid call should be retried merely because ForgeBoss itself failed before the model ran.
