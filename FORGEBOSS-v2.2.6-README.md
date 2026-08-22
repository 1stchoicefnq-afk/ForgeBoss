# ForgeBoss v2.2.6 - Fatal Fingerprint + Travis Identity

Small hardening patch only.

1. cycle_records now stores fatal_failure and a normalized fatal_fingerprint, and the generic repeated-fatal
spend breaker compares against prior cycle fingerprints. This makes the generic circuit breaker real.

2. The learned Travis repair now emits:
   const identity = JSON.stringify([providerKey, String(messageId)]);
instead of delimiter concatenation, removing provider/messageId collision ambiguity.

No locator self-heal and no broader redesign. Patch cache schema v23.
