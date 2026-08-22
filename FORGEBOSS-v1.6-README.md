# ForgeBoss v1.6 — Surgical Patch First

The v1.5.1 live diagnosis proved the remaining refusal was caused by the patch-output contract, not by missing tools:
Luna identified a likely repair but refused because Repair Rat required complete replacement contents for every
changed file and the context/output budget made that unsafe.

v1.6 replaces whole-file output with surgical exact-match edits:
- each edit contains path, exact old_text and replacement new_text;
- old_text must exist exactly once, otherwise ForgeBoss refuses the edit;
- paths remain strictly allowlisted;
- unexpected changed files are rejected;
- full acceptance still runs after application.

This removes the need for the model to reconstruct or emit large complete files and makes truncation/whole-file
reconstruction an invalid refusal reason.
