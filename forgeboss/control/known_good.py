from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_INVENTORY_MODE = "forgeboss-package-v1"
_INVENTORY_ROOT = "forgeboss"
_CACHE_DIR = "__pycache__"


class IdentityError(RuntimeError):
    pass


def _is_linklike(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    try:
        if hasattr(path, "is_junction") and path.is_junction():
            return True
    except OSError:
        return True
    return False


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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


def _relative_file(root: Path, raw: str) -> Path:
    rel = PurePosixPath(_normal_rel(raw))
    raw_target = root / Path(*rel.parts)
    _assert_no_link_components(root, raw_target)
    try:
        target = raw_target.resolve(strict=True)
    except Exception as ex:
        raise IdentityError("manifest file is missing or unreadable: " + raw) from ex
    try:
        if os.path.commonpath([str(root), str(target)]) != str(root):
            raise IdentityError("manifest file path escapes code root")
    except ValueError as ex:
        raise IdentityError("manifest file path escapes code root") from ex
    if not target.is_file():
        raise IdentityError("manifest file must be a regular file")
    return target


def _authoritative_inventory(root: Path) -> dict[str, str]:
    package = root / _INVENTORY_ROOT
    _assert_no_link_components(root, package)
    try:
        package = package.resolve(strict=True)
    except Exception as ex:
        raise IdentityError("authoritative ForgeBoss package root is missing or unreadable") from ex
    if not package.is_dir():
        raise IdentityError("authoritative ForgeBoss package root is not a directory")
    out = {}
    folded = {}
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
        try:
            out[rel] = _sha256_file(item)
        except Exception as ex:
            raise IdentityError("unable to hash authoritative package file: " + rel) from ex
    if not out:
        raise IdentityError("authoritative ForgeBoss package inventory is empty")
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
    if not path.is_file():
        raise IdentityError("build manifest must be a regular file")
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
        raise IdentityError("build manifest must bind the complete authoritative ForgeBoss package inventory")
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
    if not root.is_dir():
        raise IdentityError("build manifest codeRoot is not a directory")
    if expected_root is not None and root != Path(expected_root).resolve(strict=True):
        raise IdentityError("build manifest codeRoot does not match running checkout")
    entrypoint = _normal_rel(str(manifest.get("entrypoint") or ""))
    if not entrypoint.startswith(_INVENTORY_ROOT + "/"):
        raise IdentityError("build manifest entrypoint must be inside authoritative ForgeBoss package")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise IdentityError("build manifest must bind authoritative package files")
    normalized_files = {}
    folded = {}
    for raw_rel, expected_hash in files.items():
        rel = _normal_rel(raw_rel)
        if rel != raw_rel.replace("\\", "/"):
            raise IdentityError("build manifest file path is not canonical: " + str(raw_rel))
        if not rel.startswith(_INVENTORY_ROOT + "/"):
            raise IdentityError("build manifest contains file outside authoritative ForgeBoss package")
        key = rel.casefold()
        if key in folded and folded[key] != rel:
            raise IdentityError("build manifest contains case-colliding paths")
        folded[key] = rel
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
            raise IdentityError("build manifest contains invalid file digest")
        normalized_files[rel] = expected_hash.lower()
    if entrypoint not in normalized_files:
        raise IdentityError("build manifest must bind its entrypoint")
    actual_files = _authoritative_inventory(root)
    expected_names = set(normalized_files)
    actual_names = set(actual_files)
    if expected_names != actual_names:
        missing = sorted(actual_names - expected_names)
        unexpected = sorted(expected_names - actual_names)
        detail = []
        if missing:
            detail.append("unbound actual files=" + ",".join(missing[:8]))
        if unexpected:
            detail.append("manifest-only files=" + ",".join(unexpected[:8]))
        raise IdentityError("build manifest inventory is incomplete or stale" + (": " + "; ".join(detail) if detail else ""))
    for rel, actual in actual_files.items():
        if actual != normalized_files[rel]:
            raise IdentityError("build file digest mismatch: " + rel)
    declared_tree = str(manifest.get("treeSha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", declared_tree):
        raise IdentityError("build manifest treeSha256 is missing or invalid")
    actual_tree = _inventory_digest(actual_files)
    if declared_tree != actual_tree:
        raise IdentityError("build manifest authoritative tree digest mismatch")
    canonical = {
        "schema": 1,
        "inventoryMode": _INVENTORY_MODE,
        "revision": revision,
        "codeRoot": str(root),
        "entrypoint": entrypoint,
        "treeSha256": actual_tree,
        "files": actual_files,
    }
    return {
        "verified": True,
        "revision": revision,
        "codeRoot": str(root),
        "entrypoint": entrypoint,
        "manifestPath": str(path),
        "manifestSha256": digest,
        "identitySha256": hashlib.sha256(_canonical_json(canonical)).hexdigest(),
        "treeSha256": actual_tree,
        "inventoryMode": _INVENTORY_MODE,
        "fileCount": len(actual_files),
        "files": actual_files,
    }


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
    return {
        "verified": False,
        "revision": None,
        "codeRoot": str(root),
        "entrypoint": None,
        "manifestPath": None,
        "manifestSha256": None,
        "identitySha256": None,
        "treeSha256": None,
        "inventoryMode": None,
        "fileCount": 0,
        "files": {},
    }
