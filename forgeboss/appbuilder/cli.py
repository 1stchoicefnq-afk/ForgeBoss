from __future__ import annotations

import argparse
import json
from pathlib import Path

from .blueprint import compile_blueprint


def main() -> int:
    ap = argparse.ArgumentParser(description="Compile an app idea into a ForgeBoss build blueprint.")
    ap.add_argument("--idea", help="Plain-language app idea.")
    ap.add_argument("--idea-file", help="UTF-8 text file containing the app idea.")
    ap.add_argument("--name")
    ap.add_argument("--template", choices=["web-saas", "website", "expo-mobile", "api-service", "desktop-app"])
    ap.add_argument("--constraint", action="append", default=[])
    ap.add_argument("--capability", action="append", default=[])
    ap.add_argument("--output", default="-", help="Output JSON path, or - for stdout.")
    ns = ap.parse_args()

    if bool(ns.idea) == bool(ns.idea_file):
        ap.error("provide exactly one of --idea or --idea-file")
    idea = ns.idea if ns.idea is not None else Path(ns.idea_file).read_text(encoding="utf-8")

    result = compile_blueprint(
        idea,
        name=ns.name,
        template=ns.template,
        capabilities=ns.capability,
        constraints=ns.constraint,
    )
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if ns.output == "-":
        print(payload, end="")
    else:
        Path(ns.output).write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
