from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sys
from pathlib import Path, PurePosixPath

MANIFEST = "PACKAGE-MANIFEST.json"
STATIC_VERIFICATION = "PACKAGE-VERIFICATION.json"
_FORBIDDEN_STDLIB_ATTRS = {("os", "mkdir"), ("subprocess", "Popen")}


class PackageVerificationError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _normal_rel(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise PackageVerificationError("MANIFEST_PATH_INVALID")
    p = PurePosixPath(raw.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise PackageVerificationError("MANIFEST_PATH_INVALID")
    return p.as_posix()


def _manifest_files(manifest: dict) -> dict[str, dict]:
    raw = manifest.get("files")
    out: dict[str, dict] = {}
    if isinstance(raw, dict):
        for name, value in raw.items():
            if isinstance(value, str):
                row = {"sha256": value}
            elif isinstance(value, dict):
                row = dict(value)
            else:
                raise PackageVerificationError("MANIFEST_FILES_INVALID")
            out[_normal_rel(name)] = row
    elif isinstance(raw, list):
        for value in raw:
            if not isinstance(value, dict):
                raise PackageVerificationError("MANIFEST_FILES_INVALID")
            name = _normal_rel(value.get("path") or value.get("name") or "")
            if name in out:
                raise PackageVerificationError("MANIFEST_DUPLICATE_PATH")
            out[name] = dict(value)
    else:
        raise PackageVerificationError("MANIFEST_FILES_INVALID")
    if not out:
        raise PackageVerificationError("MANIFEST_FILES_EMPTY")
    return out


def _actual_files(root: Path) -> set[str]:
    out = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise PackageVerificationError("PACKAGE_SYMLINK_DENIED:" + path.relative_to(root).as_posix())
        if path.is_dir():
            continue
        if not path.is_file():
            raise PackageVerificationError("PACKAGE_NONREGULAR_DENIED:" + path.relative_to(root).as_posix())
        rel = path.relative_to(root).as_posix()
        if rel == MANIFEST:
            continue
        out.add(rel)
    return out


def _stdlib_aliases(tree: ast.AST) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    modules: dict[str, str] = {}
    attrs: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"os", "subprocess"}:
                    modules[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in {"os", "subprocess"}:
            for alias in node.names:
                if alias.name == "*":
                    raise PackageVerificationError("PYTHON_STAR_IMPORT_DENIED")
                attrs[alias.asname or alias.name] = (node.module, alias.name)
    return modules, attrs


def _target_identity(target: ast.AST, modules: dict[str, str], attrs: dict[str, tuple[str, str]]):
    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
        module = modules.get(target.value.id)
        if module:
            return module, target.attr
    if isinstance(target, ast.Name):
        return attrs.get(target.id)
    return None


def _check_python_no_processwide_monkeypatch(path: Path) -> None:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    except Exception as ex:
        raise PackageVerificationError("PYTHON_PARSE_FAILED:" + str(path)) from ex
    modules, attrs = _stdlib_aliases(tree)
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if isinstance(node, ast.Assign):
                targets.extend(node.targets)
            else:
                targets.append(node.target)
        elif isinstance(node, ast.Delete):
            targets.extend(node.targets)
        for target in targets:
            ident = _target_identity(target, modules, attrs)
            if ident in _FORBIDDEN_STDLIB_ATTRS:
                raise PackageVerificationError(
                    "PROCESSWIDE_MONKEYPATCH_DENIED:" + path.as_posix() + ":" + ".".join(ident)
                )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"setattr", "delattr"}:
            args = node.args
            if len(args) >= 2 and isinstance(args[0], ast.Name) and isinstance(args[1], ast.Constant) and isinstance(args[1].value, str):
                module = modules.get(args[0].id)
                ident = (module, args[1].value) if module else None
                if ident in _FORBIDDEN_STDLIB_ATTRS:
                    raise PackageVerificationError(
                        "PROCESSWIDE_MONKEYPATCH_DENIED:" + path.as_posix() + ":" + ".".join(ident)
                    )


def _check_all_python(root: Path) -> int:
    count = 0
    for path in sorted(root.rglob("*.py")):
        if path.is_symlink():
            raise PackageVerificationError("PACKAGE_SYMLINK_DENIED:" + path.relative_to(root).as_posix())
        _check_python_no_processwide_monkeypatch(path)
        count += 1
    return count


def verify_package(root: Path) -> dict:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise PackageVerificationError("PACKAGE_ROOT_INVALID")
    manifest_path = root / MANIFEST
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise PackageVerificationError("MANIFEST_MISSING")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except Exception as ex:
        raise PackageVerificationError("MANIFEST_INVALID") from ex
    if not isinstance(manifest, dict):
        raise PackageVerificationError("MANIFEST_INVALID")
    if (root / STATIC_VERIFICATION).exists():
        raise PackageVerificationError("STATIC_VERIFICATION_FILE_DENIED")

    expected = _manifest_files(manifest)
    actual = _actual_files(root)
    expected_set = set(expected)
    if actual != expected_set:
        missing = sorted(expected_set - actual)
        extra = sorted(actual - expected_set)
        raise PackageVerificationError(
            "PACKAGE_FILESET_MISMATCH missing=" + json.dumps(missing) + " extra=" + json.dumps(extra)
        )

    checked = []
    for rel in sorted(expected):
        row = expected[rel]
        want = str(row.get("sha256") or "").lower()
        if len(want) != 64 or any(c not in "0123456789abcdef" for c in want):
            raise PackageVerificationError("MANIFEST_HASH_INVALID:" + rel)
        path = root / Path(rel)
        got = _sha256(path)
        if got != want:
            raise PackageVerificationError("PACKAGE_HASH_MISMATCH:" + rel)
        if "size" in row or "sizeBytes" in row:
            size = row.get("size", row.get("sizeBytes"))
            if not isinstance(size, int) or size < 0 or path.stat().st_size != size:
                raise PackageVerificationError("PACKAGE_SIZE_MISMATCH:" + rel)
        checked.append(rel)

    python_files = _check_all_python(root)
    return {
        "ok": True,
        "root": str(root),
        "manifestSha256": _sha256(manifest_path),
        "filesVerified": len(checked),
        "pythonFilesBehaviorScanned": python_files,
        "staticVerificationFilePresent": False,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ns = ap.parse_args(argv)
    try:
        result = verify_package(Path(ns.root))
    except Exception as ex:
        print(json.dumps({"ok": False, "error": type(ex).__name__, "detail": str(ex)}, sort_keys=True))
        return 13
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
