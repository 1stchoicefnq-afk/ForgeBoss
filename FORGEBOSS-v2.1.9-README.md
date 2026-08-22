# ForgeBoss v2.1.9 - Exact Symbol Locator
Adds exact current-source locators (`L<line>:<exact trimmed line>`) to patch operations. When semantic
role still leaves multiple symbol occurrences, ForgeBoss verifies the chosen locator against current
source before materializing the edit. No fuzzy matching. Retry traces, role anchors, runtime guards and
the zero-API learned repair remain. Patch cache schema v17.
