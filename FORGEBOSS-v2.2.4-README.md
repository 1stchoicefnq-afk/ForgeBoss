# ForgeBoss v2.2.4 - Path Containment Hardening

Independent review found a sibling-prefix containment bug in evidence-scope expansion:
C:\SiteBossOld\... could pass a raw StartsWith(C:\SiteBoss) check.

Fixes:
- component-aware repository root prefix using a directory separator;
- exact root handled explicitly;
- extension/index candidates containment-checked again;
- src/ relative-path gate retained;
- sibling-prefix regression added;
- patch cache schema v21.

All prior v2.2.x hardening remains.
