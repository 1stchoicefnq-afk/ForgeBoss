# ForgeBoss v1.9.1 - Windows Unicode Hotfix

The live diagnosis failure:

    UnicodeEncodeError: 'charmap' codec can't encode character '\u2192'

was caused by Unicode UI/log text being written through a Windows locale stream that could not encode the arrow character.

v1.9.1:
- forces dashboard stdout/stderr to UTF-8 with replacement fallback;
- forces Python child processes to PYTHONUTF8=1 and PYTHONIOENCODING=utf-8;
- replaces runtime-facing fancy arrows/dashes/check symbols with ASCII equivalents;
- keeps the v1.9 Patch Transaction Engine unchanged.

No paid model call is required to verify this hotfix.
