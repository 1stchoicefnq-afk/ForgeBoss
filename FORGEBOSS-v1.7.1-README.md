# ForgeBoss v1.7.1 — Focused Partial-Win Hotfix

The latest run proved v1.7 had two migration/accumulation edge cases:

1. The first focused packet in a v1.7 install could have been created by v1.6 and therefore lacked
   `primary_failed_step`. Repair Rat then failed to recognise that the 22P05/NUL defect was actually fixed.
2. Repair Rat immediately started Attempt 2 from the authoritative head, which discarded the working
   conversation.js sub-fix and paid Luna again. That is why 22P05 returned in Attempt 2.

v1.7.1:
- derives target steps from legacy `failed_steps` when primary_failed_step is absent;
- can prove a focused defect family cleared by disappearance of its high-confidence signature;
- never performs a second paid code-producing attempt inside the same focused Repair Rat run;
- feeds only the latest Repair Rat attempt into the next failure-feedback packet so fixed signatures do not
  contaminate the next diagnosis;
- keeps the existing partial-proven accumulation/playbook behavior.

This should turn the demonstrated NUL repair into a retained PARTIAL WIN and then move to the 40001 family.
