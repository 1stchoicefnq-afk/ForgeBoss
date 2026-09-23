# ForgeBoss Loading Screen v4.6 — display smoothing candidate

This branch-staged candidate contains the exact **v4.5 -> v4.6 display-only delta** for the ForgeBoss loading screen.

## Goal

Stop the splash from visually jumping from a reported value such as 42% straight to DONE/100%.

The display now visibly increments one integer at a time up to the latest authoritative ForgeBoss percentage:

`1, 2, 3 ... 42`

If ForgeBoss later reports READY/100:

`43, 44, 45 ... 99, 100`

## Authority boundary

This is deliberately **display only**.

It does not change:
- Stage 1 engine semantics
- startup authority
- READY / FAILED authority
- launcher dispatch
- budget / STOP gates
- root of trust
- ForgeBoss status publication

The animation may never run ahead of the latest ForgeBoss-reported percentage.

## Exact package

ZIP SHA-256:

`187091c3c960b73e1c50ef1dfea722fe777cb599cb35cef6b4c38f927823559f`

Package name:

`ForgeBoss_LoadingScreen_DisplaySmooth_v4_6.zip`

## Exact runtime file identity

v4.5 `LoadingScreen/Show-ForgeBossSplash.ps1`:

`8fb6f48f8e25546f829cdaee2951f3d223932e4cf4f3fcb884d1e13649ffc129`

v4.6:

`f2687482602f5224834d382047bcf933e189c4a504cb05b57707cd306f63bd68`

Review the exact delta in `loading-v4.5-to-v4.6.patch`.

Native Windows visual acceptance remains required before promotion.
