# ForgeBoss v1.7.3 — Hard One-Call Guard

The latest report still contained 2 Luna API calls. v1.7.2 limited known controller callers to MaxAttempts=1,
but Repair Rat itself still accepted a higher MaxAttempts value when invoked through another path.

v1.7.3 makes the rule intrinsic and non-bypassable by normal launch paths:
- Repair Rat forcibly sets MaxAttempts=1 internally.
- The attempt loop refuses to begin a second paid attempt after any API call.
- The model-call path independently refuses a second paid invocation.
- Reports identify `one-paid-call-v1.7.3` and effective_paid_attempt_cap=1.
- The dashboard stops as INFRA_ERROR if any Repair Rat report ever claims api_calls > 1.

The existing targeted-gates partial-win logic remains in place.
