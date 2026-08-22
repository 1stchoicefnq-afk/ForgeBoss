# ForgeBoss v2.0.6 - Validation Regression Guard

Run FB-20260820-220941 exposed two ForgeBoss defects.

- `$changed.Count` could crash when PowerShell returned a scalar. It is now `@($changed).Count`.
- A candidate removed `providerKey` / message-id preconditions while later code still referenced
  `providerKey`, producing widespread ReferenceError failures. ForgeBoss now refuses PARTIAL WIN
  retention whenever npm_test fails or validation shows a new ReferenceError/SyntaxError/TypeError/
  missing-identifier regression.

Controller/runtime exceptions after a paid call now stop as INFRA_ERROR rather than entering the
paid context-shrink path. Repair Rat instructions also explicitly preserve declarations and
preconditions around contextual edits. Patch cache schema is v6.
