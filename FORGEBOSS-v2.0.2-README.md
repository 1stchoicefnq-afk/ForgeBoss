# ForgeBoss v2.0.2 - Run Elapsed Timer

Dashboard timing behavior:
- Timed sessions continue to show `Time left` as HH:MM:SS.
- `RUN UNTIL STOPPED` sessions now show `Running for` and count upward from `started_at`.
- The completed unlimited session can retain a `Last runtime` value because ForgeBoss stores `finished_at`.
- The legacy browser dashboard now also sends the correct `duration_mode` for RUN UNTIL STOPPED.

All v2.0.1 Patch Contract Recovery and v2.0 control-plane foundation changes remain included.
