from __future__ import annotations
import json, os, sys


def main() -> int:
    raw = sys.stdin.readline(1024 * 1024 + 1)
    if not raw or len(raw) > 1024 * 1024:
        return 90
    try:
        payload = json.loads(raw)
    except Exception:
        return 91
    if not isinstance(payload, dict) or set(payload) != {"argv", "cwd", "env"}:
        return 92
    argv = payload["argv"]
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or not x for x in argv):
        return 93
    if not os.path.isabs(argv[0]):
        return 94
    cwd = payload["cwd"]
    if cwd is not None:
        if not isinstance(cwd, str) or not os.path.isabs(cwd):
            return 95
        os.chdir(cwd)
    env = payload["env"]
    if env is None:
        env = dict(os.environ)
    if not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items()):
        return 96
    os.execve(argv[0], argv, env)
    return 97


if __name__ == "__main__":
    raise SystemExit(main())
