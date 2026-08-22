# ForgeBoss v2.1.7 - Symbol Role + Runtime Guard

FB-20260822-034207 reached actual model inference for the 40001 family.

What the run proved:
- cycle 1 again solved the known Travis 22P05/NUL defect locally for $0;
- cycle 2 diagnosed a plausible bounded backoff repair, but inserted await-bearing code before the
  async function definition, making the CommonJS module unloadable (ERR_REQUIRE_ASYNC_MODULE);
- cycle 3 then selected the correct symbol `withSerializableRetry`, but that identifier has
  definition/call/export occurrences and the old resolver could not distinguish them.

Fixes:
- edit anchors now carry anchor_role = definition/reference/any;
- function implementation changes can resolve the unique definition while ignoring calls/exports;
- await-bearing code cannot be inserted before an async function declaration;
- changed CommonJS modules are smoke-required after node --check, catching ERR_REQUIRE_ASYNC_MODULE
  before expensive acceptance;
- introduced runtime/npm regressions reset the candidate and become PATCH_CANDIDATE_INVALID instead
  of NEXT_TARGET_FOUND;
- learned $0 repair, strict-schema preflight and deterministic symbol safety remain enabled;
- patch cache schema v15.
