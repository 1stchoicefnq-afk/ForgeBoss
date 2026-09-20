from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_INVENTORY_MODE = "forgeboss-package-v2-git-bound"
_INVENTORY_ROOT = "forgeboss"
_CACHE_DIR = "__pycache__"


class IdentityError(RuntimeError):
    pass


def _is_linklike(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if hasattr(path, "is_junction") and path.is_junction():
            return True
    except OSError:
        return True
    return False


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _run_git(root: Path, *args: str, binary: bool = False):
    try:
        cp = subprocess.run(
            ["git", "-C", str(root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
            text=not binary,
            encoding=None if binary else "utf-8",
            errors=None if binary else "strict",
            env={**{k:v for k,v in os.environ.items() if not k.upper().startswith("GIT_")},
                 "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,
                 "GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0","GIT_ASKPASS":""},
        )
    except Exception as ex:
        raise IdentityError("unable to establish authoritative git identity") from ex
    if cp.returncode != 0:
        raise IdentityError("authoritative git identity command failed")
    return cp.stdout


def _assert_no_link_components(root: Path, target: Path):
    current = target
    checked = []
    while True:
        checked.append(current)
        if current == root:
            break
        if current.parent == current:
            raise IdentityError("manifest file path escapes code root")
        current = current.parent
    for item in reversed(checked):
        if _is_linklike(item):
            raise IdentityError("build identity path contains symlink/junction: " + str(item))


def _normal_rel(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise IdentityError("manifest file path is empty")
    rel = PurePosixPath(raw.replace("\\", "/"))
    if rel.is_absolute() or ".." in rel.parts or not rel.parts:
        raise IdentityError("manifest file path escapes code root")
    return rel.as_posix()


def _authoritative_inventory(root: Path) -> dict[str, str]:
    package = root / _INVENTORY_ROOT
    _assert_no_link_components(root, package)
    try:
        package = package.resolve(strict=True)
    except Exception as ex:
        raise IdentityError("authoritative ForgeBoss package root is missing or unreadable") from ex
    if not package.is_dir():
        raise IdentityError("authoritative ForgeBoss package root is not a directory")
    out: dict[str, str] = {}
    folded: dict[str, str] = {}
    try:
        entries = sorted(package.rglob("*"), key=lambda p: str(p).casefold())
    except Exception as ex:
        raise IdentityError("unable to enumerate authoritative ForgeBoss package") from ex
    for item in entries:
        rel_parts = item.relative_to(root).parts
        if _CACHE_DIR in rel_parts:
            continue
        if _is_linklike(item):
            raise IdentityError("authoritative package contains symlink/junction: " + item.relative_to(root).as_posix())
        if item.is_dir():
            continue
        if not item.is_file():
            raise IdentityError("authoritative package contains non-regular entry: " + item.relative_to(root).as_posix())
        rel = item.relative_to(root).as_posix()
        key = rel.casefold()
        if key in folded and folded[key] != rel:
            raise IdentityError("authoritative package contains case-colliding paths")
        folded[key] = rel
        out[rel] = _sha256_file(item)
    if not out:
        raise IdentityError("authoritative ForgeBoss package inventory is empty")
    return out


def _git_bound_inventory(root: Path, revision: str) -> dict[str, str]:
    top = Path(str(_run_git(root, "rev-parse", "--show-toplevel")).strip()).resolve(strict=True)
    if top != root:
        raise IdentityError("codeRoot is not the authoritative git checkout root")
    head = str(_run_git(root, "rev-parse", "--verify", "HEAD")).strip().lower()
    if head != revision:
        raise IdentityError("declared revision does not match checkout HEAD")
    raw = _run_git(root, "ls-tree", "-r", "-z", "--full-tree", head, "--", _INVENTORY_ROOT, binary=True)
    out: dict[str, str] = {}
    folded: dict[str, str] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, raw_name = record.split(b"\t", 1)
        mode, obj_type, oid = meta.decode("ascii").split(" ")
        name = raw_name.decode("utf-8", "strict").replace("\\", "/")
        if obj_type != "blob" or mode not in {"100644", "100755"}:
            raise IdentityError("authoritative git tree contains unsupported entry: " + name)
        if _CACHE_DIR in PurePosixPath(name).parts:
            continue
        key = name.casefold()
        if key in folded and folded[key] != name:
            raise IdentityError("authoritative git tree contains case-colliding paths")
        folded[key] = name
        blob = _run_git(root, "cat-file", "blob", oid, binary=True)
        out[name] = _sha256_bytes(blob)
    if not out:
        raise IdentityError("authoritative git ForgeBoss package inventory is empty")
    return out


def _inventory_digest(files: dict[str, str]) -> str:
    canonical = [[name, files[name]] for name in sorted(files)]
    return hashlib.sha256(_canonical_json(canonical)).hexdigest()


def verify_build_manifest(manifest_path, expected_root=None, expected_revision=None, expected_manifest_sha256=None):
    raw_manifest_path = Path(manifest_path)
    if _is_linklike(raw_manifest_path):
        raise IdentityError("build manifest must not be a symlink/junction")
    try:
        path = raw_manifest_path.resolve(strict=True)
    except Exception as ex:
        raise IdentityError("build manifest is missing or unreadable") from ex
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected_manifest_sha256 and digest != str(expected_manifest_sha256).lower():
        raise IdentityError("build manifest digest mismatch")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except Exception as ex:
        raise IdentityError("build manifest is unreadable") from ex
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise IdentityError("unsupported build manifest schema")
    if manifest.get("inventoryMode") != _INVENTORY_MODE:
        raise IdentityError("build manifest must bind the complete git-backed ForgeBoss package inventory")
    revision = str(manifest.get("revision") or "").lower()
    if not _SHA_RE.fullmatch(revision):
        raise IdentityError("build manifest revision must be an exact git SHA")
    if expected_revision and revision != str(expected_revision).lower():
        raise IdentityError("running controller revision does not match expected known-good SHA")
    raw_root = Path(str(manifest.get("codeRoot") or ""))
    if _is_linklike(raw_root):
        raise IdentityError("build manifest codeRoot must not be a symlink/junction")
    try:
        root = raw_root.resolve(strict=True)
    except Exception as ex:
        raise IdentityError("build manifest codeRoot is missing or unreadable") from ex
    if expected_root is not None and root != Path(expected_root).resolve(strict=True):
        raise IdentityError("build manifest codeRoot does not match running checkout")
    entrypoint = _normal_rel(str(manifest.get("entrypoint") or ""))
    if not entrypoint.startswith(_INVENTORY_ROOT + "/"):
        raise IdentityError("build manifest entrypoint must be inside authoritative ForgeBoss package")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise IdentityError("build manifest must bind authoritative package files")
    normalized: dict[str, str] = {}
    folded: dict[str, str] = {}
    for raw_rel, expected_hash in files.items():
        rel = _normal_rel(raw_rel)
        if rel != str(raw_rel).replace("\\", "/"):
            raise IdentityError("build manifest file path is not canonical: " + str(raw_rel))
        if not rel.startswith(_INVENTORY_ROOT + "/"):
            raise IdentityError("build manifest contains file outside authoritative ForgeBoss package")
        key = rel.casefold()
        if key in folded and folded[key] != rel:
            raise IdentityError("build manifest contains case-colliding paths")
        folded[key] = rel
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
            raise IdentityError("build manifest contains invalid file digest")
        normalized[rel] = expected_hash.lower()
    if entrypoint not in normalized:
        raise IdentityError("build manifest must bind its entrypoint")
    actual = _authoritative_inventory(root)
    git_files = _git_bound_inventory(root, revision)
    if set(actual) != set(git_files):
        raise IdentityError("working package file set does not match declared git revision")
    for rel, actual_hash in actual.items():
        if git_files.get(rel) != actual_hash:
            raise IdentityError("working package bytes do not match declared git revision: " + rel)
    if set(normalized) != set(actual):
        raise IdentityError("build manifest inventory is incomplete or stale")
    for rel, actual_hash in actual.items():
        if normalized.get(rel) != actual_hash:
            raise IdentityError("build file digest mismatch: " + rel)
    actual_tree = _inventory_digest(actual)
    declared_tree = str(manifest.get("treeSha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", declared_tree) or declared_tree != actual_tree:
        raise IdentityError("build manifest authoritative tree digest mismatch")
    canonical = {"schema": 1, "inventoryMode": _INVENTORY_MODE, "revision": revision, "codeRoot": str(root), "entrypoint": entrypoint, "treeSha256": actual_tree, "files": actual}
    return {"verified": True, "revision": revision, "codeRoot": str(root), "entrypoint": entrypoint, "manifestPath": str(path), "manifestSha256": digest, "identitySha256": hashlib.sha256(_canonical_json(canonical)).hexdigest(), "treeSha256": actual_tree, "inventoryMode": _INVENTORY_MODE, "fileCount": len(actual), "files": actual}


def runtime_identity_from_env(root):
    root = Path(root).resolve(strict=True)
    self_build = os.environ.get("FORGEBOSS_SELF_BUILD_MODE") == "YES"
    manifest_path = os.environ.get("FORGEBOSS_BUILD_MANIFEST")
    expected_revision = os.environ.get("FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA")
    expected_manifest = os.environ.get("FORGEBOSS_EXPECTED_MANIFEST_SHA256")
    if self_build:
        if not manifest_path:
            raise IdentityError("self-build mode requires FORGEBOSS_BUILD_MANIFEST")
        if not expected_revision or not _SHA_RE.fullmatch(expected_revision.lower()):
            raise IdentityError("self-build mode requires exact FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA")
        if not expected_manifest or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_manifest):
            raise IdentityError("self-build mode requires FORGEBOSS_EXPECTED_MANIFEST_SHA256")
        return verify_build_manifest(manifest_path, root, expected_revision, expected_manifest)
    if manifest_path:
        return verify_build_manifest(manifest_path, root, expected_revision, expected_manifest)
    return {"verified": False, "revision": None, "codeRoot": str(root), "entrypoint": None, "manifestPath": None, "manifestSha256": None, "identitySha256": None, "treeSha256": None, "inventoryMode": None, "fileCount": 0, "files": {}}
