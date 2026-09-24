from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from forgeboss.security.executor_guard import _resolve_git_executable


class Stage1GateError(RuntimeError):
    pass


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as ex:
        raise Stage1GateError("INSTALLED_STATE_INVALID") from ex
    if not isinstance(value, dict):
        raise Stage1GateError("INSTALLED_STATE_INVALID")
    return value


def installed_engine(installed_state: Path, env: dict[str, str] | None = None) -> tuple[Path, str]:
    state_path = installed_state.resolve(strict=True)
    state = _load_json(state_path)
    root_raw = state.get("engineRoot")
    sha = str(state.get("engineSha") or state.get("engineSHA") or state.get("revision") or "").lower()
    if not isinstance(root_raw, str) or not root_raw.strip():
        raise Stage1GateError("INSTALLED_ENGINE_ROOT_MISSING")
    root = Path(root_raw).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise Stage1GateError("INSTALLED_ENGINE_ROOT_INVALID")
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        raise Stage1GateError("INSTALLED_ENGINE_SHA_INVALID")
    candidate = (env or os.environ).get("FORGEBOSS_ENGINE_ROOT")
    if candidate:
        try:
            env_root = Path(candidate).expanduser().resolve(strict=True)
        except Exception as ex:
            raise Stage1GateError("ENGINE_ROOT_ENV_INVALID") from ex
        if env_root != root:
            raise Stage1GateError("ENGINE_ROOT_ENV_MISMATCH")
    return root, sha


def verify_engine(installed_state: Path, env: dict[str, str] | None = None) -> dict:
    root, expected = installed_engine(installed_state, env)
    git = _resolve_git_executable()
    clean_env = {
        **{k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")},
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
    }

    def run(*args: str) -> str:
        cp = subprocess.run(
            [str(git), "-C", str(root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            env=clean_env,
            timeout=20,
            check=False,
        )
        if cp.returncode:
            raise Stage1GateError("ENGINE_GIT_CHECK_FAILED")
        return cp.stdout

    head = run("rev-parse", "--verify", "HEAD").strip().lower()
    if head != expected:
        raise Stage1GateError("ENGINE_SHA_MISMATCH")
    dirty = run("status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise Stage1GateError("ENGINE_TREE_DIRTY")
    top = Path(run("rev-parse", "--show-toplevel").strip()).resolve(strict=True)
    if top != root:
        raise Stage1GateError("ENGINE_ROOT_NOT_GIT_TOPLEVEL")
    return {
        "ok": True,
        "engineRoot": str(root),
        "engineSha": head,
        "gitExecutable": str(git),
        "readOnly": True,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("installed_state")
    ns = ap.parse_args(argv)
    try:
        result = verify_engine(Path(ns.installed_state))
    except Exception as ex:
        print(json.dumps({"ok": False, "error": type(ex).__name__, "detail": str(ex)}, sort_keys=True))
        return 13
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
