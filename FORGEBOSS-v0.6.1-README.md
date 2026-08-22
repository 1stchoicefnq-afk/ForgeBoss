# ForgeBoss v0.6.1 — Run Until Stopped

The owner-facing duration option is now labelled:

**RUN UNTIL STOPPED**

The backend behavior is unchanged: ForgeBoss keeps starting new bounded build cycles until the owner presses **STOP SAFELY**, the session budget is exhausted, the cycle safety limit is reached, or the stagnation guard stops repeated failures.

The dashboard footer now shows **v0.6.1** so it is obvious which extracted build is running.
