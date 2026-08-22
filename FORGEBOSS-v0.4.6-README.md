# ForgeBoss v0.4.6 — Re-test Results Dashboard

The native dashboard now reads `state/tournament/retest-last.json` directly and displays:
- mini-SWE PASS / FAIL / missing;
- OpenHands PASS / FAIL / missing;
- failed-check count where available;
- whether there is a winner;
- explicit `$0.00 new AI spend` for the re-test.

This does not rerun the model. Existing candidate evidence is reused.

The activity feed newline rendering is also corrected so `\n\n` is not shown literally.
