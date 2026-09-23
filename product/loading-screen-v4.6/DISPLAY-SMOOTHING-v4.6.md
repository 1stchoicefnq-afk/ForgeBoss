# ForgeBoss loading-screen display smoothing v4.6

## Scope

Display-only change. ForgeBoss startup authority, status publication, READY/FAILED semantics, launcher dispatch, bridge behavior, and engine behavior are unchanged.

## Problem

The splash previously assigned the displayed percentage directly from the latest canonical status. A real status sequence such as `42 -> 100/READY` therefore appeared as an instant jump.

## Change

`LoadingScreen/Show-ForgeBossSplash.ps1` now keeps two values:

- `reportedPct` / `targetPct`: the latest canonical ForgeBoss ceiling.
- `pct`: the displayed value.

A 25 ms UI animation timer increments the displayed value by exactly one integer until it reaches the latest reported target. It never advances beyond the latest ForgeBoss-reported percentage.

Example:

`ForgeBoss reports 42` -> splash visibly shows `1, 2, 3 ... 42`.

`ForgeBoss later reports READY/100` -> splash visibly shows `43, 44 ... 99, 100`, holds READY briefly, then closes.

## Safety boundary

This does not fabricate startup completion. The visual counter cannot outrun the authoritative status value. READY is still accepted only from ForgeBoss's existing status/view logic. FAILED and LAUNCH_ERROR remain terminal display states.

## Validation

The package verifier checks that:

- the existing 350 ms authoritative-status polling remains;
- the new 25 ms animation timer exists;
- the display increments with `pct++`;
- direct `pct = status.percent` and direct `pct = 100` snapping are absent.

Native Windows visual acceptance is still required before treating this as independently accepted.
