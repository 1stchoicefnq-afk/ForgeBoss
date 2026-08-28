"""SiteBoss deep-agent sandbox policy.

Security model (DEEPAGENTS lane):
  * every path the agent supplies is untrusted and must survive ``norm``;
  * packet scopes are the only grant of authority and are never widened at runtime;
  * the resolved (post-symlink) path must satisfy the scope check as well as the
    logical path, otherwise an in-workspace symlink is a scope escape;
  * command execution is an allowlist of interpreter *classes* plus an argument
    policy that forbids inline-code evaluation and network package execution.

Known ceiling: any approved test runner executes repository code, so this module
provides containment of the *tool surface*, not OS-level isolation. See
AUDIT.md for the findings that require an OS sandbox to close.
"""

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
import os
import re
import shutil
import subprocess


class SecurityDenial(RuntimeError):
    pass


class StalePacket(RuntimeError):
    pass


class BudgetExceeded(RuntimeError):
    pass


# Hard ceilings. Packet-supplied budgets are clamped to these; a packet may
# lower a budget but never raise it above the controller-owned maximum.
MAX_COMMANDS_CEILING = 12
MAX_FILE_MODIFICATIONS_CEILING = 8
MAX_SUBAGENTS_CEILING = 1
MAX_MODEL_CALLS_CEILING = 4

MAX_READ_BYTES = 4 * 1024 * 1024
MAX_WRITE_BYTES = 4 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 300
OUTPUT_CAPTURE_LIMIT = 20000

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")

# Reserved DOS device names. "tests/NUL" is a legal POSIX filename but opens a
# character device on Windows, so it is denied on every platform to keep the
# policy decision identical across hosts.
_WINDOWS_RESERVED = {"con", "prn", "aux", "nul"} | {
    f"{stem}{n}" for stem in ("com", "lpt") for n in range(1, 10)
}


def norm(p):
    """Normalise an agent-supplied path to a workspace-relative POSIX path."""
    if not isinstance(p, str) or not p.strip():
        raise SecurityDenial("empty path")
    if _CONTROL_CHARS.search(p):
        raise SecurityDenial("control character in path")
    p = p.replace("\\", "/")
    if _DRIVE_PREFIX.match(p) or p.startswith("//"):
        raise SecurityDenial("absolute host path denied")
    if p.startswith("~"):
        raise SecurityDenial("home expansion denied")
    pp = PurePosixPath("/" + p.lstrip("/"))
    if ".." in pp.parts:
        raise SecurityDenial("parent traversal denied")
    rel = pp.as_posix().lstrip("/")
    for part in rel.split("/"):
        if not part:
            continue
        if ":" in part:
            # Drive-relative paths and NTFS alternate data streams
            # ("file.js:evil") bypass extension and scope reasoning.
            raise SecurityDenial("drive or stream qualifier denied")
        if part != part.rstrip(" ."):
            # Windows silently strips trailing dots/spaces, so "no.js." and
            # "no.js" would name the same file while comparing as different.
            raise SecurityDenial("trailing space or dot component denied")
        if part.split(".")[0].lower() in _WINDOWS_RESERVED:
            raise SecurityDenial("reserved device name denied")
    return rel


def scope_match(rel, scopes):
    """Return the normalised scope entry granting ``rel``, or None."""
    rel = norm(rel)
    for s in scopes or ():
        try:
            ns = norm(s)
        except SecurityDenial:
            # A malformed scope entry never grants authority and must not turn
            # an in-scope request into an unrelated error.
            continue
        if not ns:
            continue
        if rel == ns or rel.startswith(ns.rstrip("/") + "/"):
            return ns
    return None


def under(rel, scopes):
    return scope_match(rel, scopes) is not None


def _validate_scope(name, scopes):
    if isinstance(scopes, str) or not isinstance(scopes, (tuple, list)):
        raise SecurityDenial(f"{name} must be a tuple of paths")
    for s in scopes:
        norm(s)  # raises SecurityDenial on any malformed entry


def clamp_budget(value, default, ceiling):
    try:
        v = int(value)
    except (TypeError, ValueError):
        v = default
    return max(0, min(v, ceiling))


@dataclass(frozen=True)
class ImmutablePacket:
    packet_id: str
    expected_head: str
    role: str
    read_scope: tuple[str, ...]
    write_scope: tuple[str, ...]
    required_tests: tuple[str, ...] = ()
    review_exclusions: tuple[str, ...] = ()
    max_commands: int = MAX_COMMANDS_CEILING
    max_file_modifications: int = MAX_FILE_MODIFICATIONS_CEILING
    max_subagents: int = MAX_SUBAGENTS_CEILING
    max_model_calls: int = MAX_MODEL_CALLS_CEILING

    def __post_init__(self):
        if not isinstance(self.packet_id, str) or not self.packet_id.strip():
            raise SecurityDenial("packet_id required")
        if not isinstance(self.expected_head, str) or not self.expected_head.strip():
            raise SecurityDenial("expected_head required")
        _validate_scope("read_scope", self.read_scope)
        _validate_scope("write_scope", self.write_scope)
        for name, ceiling in (
            ("max_commands", MAX_COMMANDS_CEILING),
            ("max_file_modifications", MAX_FILE_MODIFICATIONS_CEILING),
            ("max_subagents", MAX_SUBAGENTS_CEILING),
            ("max_model_calls", MAX_MODEL_CALLS_CEILING),
        ):
            v = getattr(self, name)
            if not isinstance(v, int) or isinstance(v, bool):
                raise SecurityDenial(f"{name} must be an int")
            if v < 0 or v > ceiling:
                raise SecurityDenial(f"{name} outside controller ceiling")


@dataclass
class Evidence:
    files_read: list[str] = field(default_factory=list)
    files_changed: list[str] = field(default_factory=list)
    commands_run: list[dict] = field(default_factory=list)
    tests: list[dict] = field(default_factory=list)


# --- command policy ---------------------------------------------------------

# Interpreter classes the sandbox will start. "npx" is deliberately absent: it
# fetches and executes arbitrary remote packages, which is unreviewable code
# entering the workspace from the network.
_ALLOWED_EXECUTABLES = {"node", "npm", "python", "python3", "pytest"}

# Only these exact basenames start a process. ".bat"/".ps1"/".com" are excluded
# because they are shell shims, not the interpreter; "python3.12" is accepted
# because it is the ordinary POSIX name for the interpreter already allowed.
_EXECUTABLE_RE = re.compile(r"^(node|npm|pytest|python3(?:\.\d+)?|python)(\.exe|\.cmd)?$")

# Flags that turn an interpreter into an arbitrary-code evaluator, defeating
# the point of an executable allowlist.
_PYTHON_DENIED_FLAGS = {"-c", "--command", "-i", "--interactive", "-"}
_NODE_DENIED_FLAGS = {
    "-e", "--eval", "-p", "--print", "-r", "--require", "--import",
    "--loader", "--experimental-loader", "--input-type", "-i", "--interactive",
}
_PYTHON_ALLOWED_MODULES = {"pytest", "unittest"}
# npm subcommands that neither install from the network nor read credentials.
_NPM_ALLOWED_SUBCOMMANDS = {"test", "t", "run", "run-script"}


def _executable_stem(arg0):
    name = Path(arg0.replace("\\", "/")).name.lower()
    m = _EXECUTABLE_RE.match(name)
    if not m:
        raise SecurityDenial("command class denied")
    stem = m.group(1)
    return "python3" if stem.startswith("python3") else stem


def _check_argument_policy(stem, args):
    for a in args:
        if not isinstance(a, str):
            raise SecurityDenial("command arguments must be strings")
        if _CONTROL_CHARS.search(a):
            raise SecurityDenial("control character in command argument")
    if stem in ("python", "python3"):
        if not args:
            raise SecurityDenial("interactive interpreter denied")
        if args[0] in _PYTHON_DENIED_FLAGS:
            raise SecurityDenial("inline code execution denied")
        if args[0] == "-m":
            if len(args) < 2 or args[1] not in _PYTHON_ALLOWED_MODULES:
                raise SecurityDenial("module execution denied")
        elif args[0].startswith("-"):
            raise SecurityDenial("interpreter flag denied")
    elif stem == "node":
        if not args:
            raise SecurityDenial("interactive interpreter denied")
        for a in args:
            base = a.split("=", 1)[0]
            if base in _NODE_DENIED_FLAGS:
                raise SecurityDenial("inline code execution denied")
    elif stem == "npm":
        if not args or args[0].startswith("-"):
            raise SecurityDenial("npm subcommand required")
        if args[0] not in _NPM_ALLOWED_SUBCOMMANDS:
            raise SecurityDenial("npm subcommand denied")


class GuardedWorkspace:
    def __init__(self, root, packet):
        self.root = Path(root).resolve()
        self.packet = packet
        self.evidence = Evidence()
        self.command_count = 0
        self.modified = set()

    # -- paths --------------------------------------------------------------
    def real(self, rel):
        """Resolve ``rel`` inside the workspace, rejecting every escape route."""
        rel = norm(rel)
        candidate = (self.root / rel).resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError as e:
            raise SecurityDenial("workspace escape denied") from e
        parts = rel.split("/")
        cur = self.root
        for i, part in enumerate(parts):
            cur = cur / part
            # is_symlink() is lstat-based and therefore also true for dangling
            # symlinks, which exists() reports as absent while open() still
            # follows them out of the workspace.
            if cur.is_symlink() or cur.exists():
                try:
                    cur.resolve().relative_to(self.root)
                except ValueError as e:
                    raise SecurityDenial("symlink/junction escape denied") from e
            if i < len(parts) - 1 and cur.exists() and not cur.is_dir():
                raise SecurityDenial("path traverses a non-directory")
        return candidate

    def _resolved_rel(self, real_path):
        return real_path.relative_to(self.root).as_posix()

    def _authorise(self, rel, scopes, action):
        if not under(rel, scopes):
            raise SecurityDenial(f"{action} outside packet scope")
        real_path = self.real(rel)
        # An in-workspace symlink keeps the logical path in scope while the
        # bytes land somewhere else; re-check the post-resolution path.
        if not under(self._resolved_rel(real_path), scopes):
            raise SecurityDenial(f"{action} outside packet scope after resolution")
        return real_path

    def read_text(self, rel):
        scopes = tuple(self.packet.read_scope) + tuple(self.packet.write_scope)
        p = self._authorise(rel, scopes, "read")
        if not p.is_file():
            raise SecurityDenial("read target is not a regular file")
        if p.stat().st_size > MAX_READ_BYTES:
            raise SecurityDenial("read exceeds size limit")
        x = p.read_text(encoding="utf-8")
        n = norm(rel)
        if n not in self.evidence.files_read:
            self.evidence.files_read.append(n)
        return x

    def write_text(self, rel, content):
        if not isinstance(content, str):
            raise SecurityDenial("write content must be a string")
        if len(content.encode("utf-8")) > MAX_WRITE_BYTES:
            raise SecurityDenial("write exceeds size limit")
        p = self._authorise(rel, self.packet.write_scope, "write")
        n = norm(rel)
        if p.exists() and n not in self.evidence.files_read:
            # Blind overwrite of an existing file destroys content the agent
            # never observed; force the read-modify-write ordering.
            raise SecurityDenial("read-before-write required for existing file")
        if len(self.modified | {n}) > self.packet.max_file_modifications:
            raise BudgetExceeded("max file modifications")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        self.modified.add(n)
        if n not in self.evidence.files_changed:
            self.evidence.files_changed.append(n)
        # The file now exists and its content is known to the agent, so a
        # follow-up write is still a read-before-write.
        if n not in self.evidence.files_read:
            self.evidence.files_read.append(n)

    # -- commands -----------------------------------------------------------
    def _resolve_executable(self, arg0):
        """Return (absolute executable path, allowlisted stem)."""
        if not isinstance(arg0, str) or not arg0.strip():
            raise SecurityDenial("empty command")
        if _CONTROL_CHARS.search(arg0):
            raise SecurityDenial("control character in command")
        stem = _executable_stem(arg0)
        if stem not in _ALLOWED_EXECUTABLES:
            raise SecurityDenial("command class denied")
        if "/" in arg0.replace("\\", "/"):
            found = Path(arg0).expanduser()
            if not found.is_absolute():
                found = (self.root / found).resolve(strict=False)
        else:
            which = shutil.which(arg0, path=os.environ.get("PATH", ""))
            if not which:
                raise SecurityDenial("executable not found on PATH")
            found = Path(which)
        found = found.resolve(strict=False)
        if not found.is_file():
            raise SecurityDenial("executable not found")
        # A workspace-resident binary is agent-controlled content. Naming it
        # "npm.cmd" would otherwise satisfy the allowlist and execute anything.
        try:
            found.relative_to(self.root)
        except ValueError:
            return found, stem
        raise SecurityDenial("executable inside workspace denied")

    def _child_env(self):
        """Minimal environment: no host secrets reach the child process."""
        env = {
            "PATH": os.environ.get("PATH", ""),
            "NODE_ENV": "test",
            "SITEBOSS_SANDBOX": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            # Blocks code injection through ~/.local site-packages and
            # usercustomize.py, which the PATH allowlist does not cover.
            "PYTHONNOUSERSITE": "1",
            "NO_COLOR": "1",
        }
        if os.name == "nt":
            # Windows processes fail to start or lose sockets/TLS without
            # these; they carry no secret material.
            for k in ("SystemRoot", "SYSTEMROOT", "COMSPEC", "PATHEXT", "WINDIR", "TEMP", "TMP"):
                v = os.environ.get(k)
                if v:
                    env[k] = v
        return env

    def run_command(self, argv, test=False):
        if self.command_count >= self.packet.max_commands:
            raise BudgetExceeded("max command count")
        if isinstance(argv, (str, bytes)) or not isinstance(argv, (list, tuple)):
            raise SecurityDenial("argv must be a list of strings")
        argv = list(argv)
        if not argv:
            raise SecurityDenial("empty command")
        exe, stem = self._resolve_executable(argv[0])
        _check_argument_policy(stem, argv[1:])
        self.command_count += 1
        rec = {"argv": argv, "exit_code": None, "stdout": "", "stderr": "", "timed_out": False}
        try:
            r = subprocess.run(
                [str(exe)] + argv[1:],
                cwd=self.root,
                text=True,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=COMMAND_TIMEOUT_SECONDS,
                shell=False,
                env=self._child_env(),
            )
        except subprocess.TimeoutExpired as e:
            # Record before re-raising so a hung command still leaves evidence.
            rec["timed_out"] = True
            rec["stderr"] = "command timed out"
            self.evidence.commands_run.append(rec)
            if test:
                self.evidence.tests.append(rec)
            raise BudgetExceeded("command timeout") from e
        rec["exit_code"] = r.returncode
        rec["stdout"] = (r.stdout or "")[-OUTPUT_CAPTURE_LIMIT:]
        rec["stderr"] = (r.stderr or "")[-OUTPUT_CAPTURE_LIMIT:]
        self.evidence.commands_run.append(rec)
        if test:
            self.evidence.tests.append(rec)
        return rec


def required_tests_satisfied(packet, evidence):
    """True only when every required test ran to a zero exit code."""
    if not packet.required_tests:
        return True
    passed = [" ".join(r.get("argv") or []) for r in evidence.tests if r.get("exit_code") == 0]
    return all(any(rt == c or rt in c for c in passed) for rt in packet.required_tests)


def reconcile_evidence(claim, workspace, packet):
    """Replace model-authored evidence with what the sandbox actually observed.

    The agent authors its own result object, so ``scope_respected`` and the
    file/command lists are attacker-influenced values. Only the workspace
    knows what happened.
    """
    out = dict(claim or {})
    ev = workspace.evidence
    if out.get("status") not in ("COMPLETED", "BLOCKED", "FAILED"):
        out["status"] = "FAILED"
    out["files_read"] = list(ev.files_read)
    out["files_changed"] = list(ev.files_changed)
    out["commands_run"] = list(ev.commands_run)
    out["tests"] = list(ev.tests)
    out["packet_id"] = packet.packet_id
    scope_ok = all(under(f, tuple(packet.read_scope) + tuple(packet.write_scope)) for f in ev.files_read)
    write_ok = all(under(f, packet.write_scope) for f in ev.files_changed)
    out["scope_respected"] = scope_ok
    out["write_authority_respected"] = write_ok
    out["review_required"] = True
    tests_ok = required_tests_satisfied(packet, ev)
    if not (scope_ok and write_ok and tests_ok):
        out["status"] = "BLOCKED"
        blockers = list(out.get("blockers") or [])
        if not scope_ok:
            blockers.append("READ_SCOPE_VIOLATION")
        if not write_ok:
            blockers.append("WRITE_SCOPE_VIOLATION")
        if not tests_ok:
            blockers.append("REQUIRED_TESTS_NOT_SATISFIED")
        out["blockers"] = blockers
    return out


def revalidate_resume(packet, current_head, lease_valid, controller_version_ok):
    if not isinstance(current_head, str) or not current_head.strip():
        raise StalePacket("STALE_GITHUB_HEAD")
    if current_head.strip() != packet.expected_head.strip():
        raise StalePacket("STALE_GITHUB_HEAD")
    # Strict identity: a truthy non-boolean (e.g. the string "expired") must
    # not be read as a valid lease.
    if lease_valid is not True:
        raise StalePacket("LEASE_EXPIRED")
    if controller_version_ok is not True:
        raise StalePacket("STALE_CONTROLLER_VERSION")
