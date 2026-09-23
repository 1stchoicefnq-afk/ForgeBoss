# Windows-native process broker acceptance

Target parent: PR #212 at exact head `03cdaf13269a09e981391783df5aba1fd6917aac`.

Run from the ForgeBoss repository root on native Windows:

```powershell
node --test forgeboss/executors/process_broker.test.js forgeboss/executors/process_broker.windows.test.js
```

Expected: all portable tests and all Windows-native tests pass with exit code 0.

This harness checks timeout/cancel descendant cleanup, repeated cancellation, explicit-only environment and absolute path enforcement.

Still requires separate manual/native evidence for visible console flicker and forced termination of the broker's own parent process. A hard-killed Node process cannot rely on `process.on("exit")` cleanup.
