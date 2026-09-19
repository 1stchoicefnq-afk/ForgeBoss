from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "START-FORGEBOSS.vbs"
SHELL = ROOT / "dashboard" / "pro_shell.py"
SETUP = ROOT / "SETUP-FORGEBOSS-ENGINES.cmd"


def fail(message: str) -> None:
    print(f"[FAIL] {message}")
    raise SystemExit(1)


def main() -> int:
    if not LAUNCHER.is_file():
        fail("START-FORGEBOSS.vbs is missing")
    if not SHELL.is_file():
        fail("dashboard/pro_shell.py is missing")
    if not SETUP.is_file():
        fail("SETUP-FORGEBOSS-ENGINES.cmd is missing")

    text = LAUNCHER.read_text(encoding="utf-8-sig")

    if "ForgeBoss-Internal" in text:
        fail("launcher still references the historical ForgeBoss-Internal layout")

    match = re.search(
        r'^scriptPath\s*=\s*root\s*&\s*"(?P<rel>[^"]+)"',
        text,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    if not match:
        fail("could not parse launcher scriptPath assignment")

    rel = match.group("rel").replace("\\\\", "/").replace("\\", "/").lstrip("/")
    resolved = ROOT / Path(rel)
    if resolved.resolve() != SHELL.resolve():
        fail(f"launcher resolves to {resolved}, expected {SHELL}")

    if "SETUP-FORGEBOSS-ENGINES.cmd" not in text:
        fail("launcher no longer directs the user to the canonical setup script")

    print("[PASS] Windows launcher layout points to the canonical dashboard shell")
    print(f"[PASS] shell: {SHELL}")
    print(f"[PASS] setup: {SETUP}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
