from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil

from forgeboss.security.executor_guard import (
    SecurityError,
    _assert_posix_git_trust,
    _assert_windows_acl_trust,
    _assert_windows_parent_replacement_trust,
    fhash,
    is_linklike,
)


class HostToolIdentityError(RuntimeError):
    """Raised when a host executable cannot be trusted by ForgeBoss."""


@dataclass(frozen=True)
class HostToolIdentity:
    name: str
    path: str
    sha256: str
    size: int


def _trust_chain(executable: Path) -> None:
    if os.name == "nt":
        try:
            _assert_windows_acl_trust(executable)
            cur = executable.parent
            while True:
                _assert_windows_parent_replacement_trust(cur)
                if cur.parent == cur:
                    break
                cur = cur.parent
        except SecurityError as ex:
            raise HostToolIdentityError(str(ex)) from ex
    else:
        try:
            _assert_posix_git_trust(executable)
        except SecurityError as ex:
            raise HostToolIdentityError(str(ex)) from ex


def resolve_trusted_host_executable(name: str) -> HostToolIdentity:
    if not isinstance(name, str) or not name or any(ch in name for ch in "\x00\r\n/\\"):
        raise HostToolIdentityError("host tool name is invalid")

    lookup = name + ".exe" if os.name == "nt" and not name.lower().endswith(".exe") else name
    found = shutil.which(lookup)
    if not found:
        raise HostToolIdentityError(f"host executable unavailable: {lookup}")

    candidate = Path(found)
    if is_linklike(candidate):
        raise HostToolIdentityError("linklike host executable denied")
    try:
        path = candidate.resolve(strict=True)
    except OSError as ex:
        raise HostToolIdentityError(f"host executable unavailable: {lookup}") from ex

    if not path.is_file():
        raise HostToolIdentityError("host executable is not a regular file")
    if is_linklike(path):
        raise HostToolIdentityError("linklike host executable denied")

    _trust_chain(path)

    before_stat = path.stat()
    before = fhash(path)
    _trust_chain(path)
    after = fhash(path)
    after_stat = path.stat()
    if before != after:
        raise HostToolIdentityError("host executable identity changed while hashing")
    if (
        before_stat.st_size != after_stat.st_size
        or getattr(before_stat, "st_mtime_ns", None) != getattr(after_stat, "st_mtime_ns", None)
    ):
        raise HostToolIdentityError("host executable metadata changed while hashing")

    return HostToolIdentity(
        name=name,
        path=str(path),
        sha256=before,
        size=int(after_stat.st_size),
    )


def assert_trusted_host_executable(identity: HostToolIdentity) -> HostToolIdentity:
    current = resolve_trusted_host_executable(identity.name)
    if current.path != identity.path or current.sha256 != identity.sha256 or current.size != identity.size:
        raise HostToolIdentityError("host executable identity changed")
    return current