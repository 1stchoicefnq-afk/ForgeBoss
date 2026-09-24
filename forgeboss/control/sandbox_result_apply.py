from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import shutil
import tempfile
from typing import Iterable, Sequence

from forgeboss.control.governed_sandbox import (
    ManifestEntry,
    SandboxResult,
    _assert_result_tree_safe,
    _copy_regular_file,
    create_sanitized_source,
    manifest_sha256,
    manifest_tree,
)
from forgeboss.control.scheduler import _canonical_path as _scope_path
from forgeboss.security.executor_guard import (
    SecurityError,
    _WorkspaceFence,
    _assert_live_control_lease,
    _verify_unlocked,
    assert_paths_contained,
    validate_packet,
)


class SandboxApplyError(RuntimeError):
    """Raised when sandbox output cannot be safely applied to the host workspace."""


@dataclass(frozen=True)
class PlannedMutation:
    path: str
    action: str
    baseline_sha256: str | None
    result_sha256: str | None


@dataclass(frozen=True)
class SandboxApplyEvidence:
    task_id: str
    run_id: str
    owner_epoch: int
    executor: str
    changed_paths: tuple[str, ...]
    before_manifest_sha256: str
    result_manifest_sha256: str
    after_manifest_sha256: str
    rolled_back: bool = False


def _raw_identity(path: str) -> str:
    clean = path.replace("\\", "/").strip("/")
    parts = tuple(part for part in clean.split("/") if part not in ("", "."))
    if not parts or any(part == ".." for part in parts):
        raise SandboxApplyError(f"invalid manifest path: {path!r}")
    return "/".join(parts)


def _canonical_entries(
    entries: Sequence[ManifestEntry],
    *,
    label: str,
) -> dict[str, ManifestEntry]:
    out: dict[str, ManifestEntry] = {}
    for item in entries:
        raw = _raw_identity(item.path)
        canonical = _scope_path(raw)
        if not canonical:
            raise SandboxApplyError(f"{label} contains empty canonical path: {raw}")
        # R0 permits case differences but rejects trailing-dot/space aliases and
        # path-shape rewrites that collapse to a different Windows identity.
        if raw.casefold() != canonical:
            raise SandboxApplyError(
                f"{label} path is a Windows alias rather than an exact path: {raw}"
            )
        if canonical in out:
            raise SandboxApplyError(
                f"{label} contains duplicate canonical path: {canonical}"
            )
        out[canonical] = item
    return out


def _allowed_map(allowed_paths: Sequence[str]) -> dict[str, str]:
    try:
        allowed, _ = validate_packet(
            {"allowed_files": list(allowed_paths), "context_files": []}
        )
    except SecurityError as ex:
        raise SandboxApplyError(f"allowed path contract is invalid: {ex}") from ex
    out: dict[str, str] = {}
    for raw in allowed:
        canonical = _scope_path(raw)
        if not canonical:
            raise SandboxApplyError("allowed path has empty canonical identity")
        if raw.casefold() != canonical:
            raise SandboxApplyError(
                f"allowed path is a Windows alias rather than an exact path: {raw}"
            )
        if canonical in out:
            raise SandboxApplyError(
                f"duplicate allowed path after canonicalisation: {canonical}"
            )
        out[canonical] = raw
    return out


def capture_sanitized_manifest(source: Path) -> tuple[tuple[ManifestEntry, ...], str]:
    source = source.resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="forgeboss-apply-baseline-"
    ) as temp_raw:
        temp = Path(temp_raw).resolve(strict=True)
        create_sanitized_source(source, temp)
        entries = manifest_tree(temp)
        return entries, manifest_sha256(entries)


def _plan(
    baseline_entries: Sequence[ManifestEntry],
    result_entries: Sequence[ManifestEntry],
    allowed_paths: Sequence[str],
) -> tuple[PlannedMutation, ...]:
    baseline = _canonical_entries(baseline_entries, label="baseline manifest")
    result = _canonical_entries(result_entries, label="result manifest")
    allowed = _allowed_map(allowed_paths)
    mutations = []

    for canonical in sorted(set(baseline) | set(result)):
        before = baseline.get(canonical)
        after = result.get(canonical)
        if before == after:
            continue
        if canonical not in allowed:
            path = after.path if after is not None else before.path
            raise SandboxApplyError(
                f"sandbox changed path outside exact allowedPaths: {path}"
            )

        expected_path = allowed[canonical]
        before_path = before.path if before is not None else None
        after_path = after.path if after is not None else None

        # R0 deliberately rejects rename/case-only rewrite semantics.
        if before_path is not None and before_path.casefold() != expected_path.casefold():
            raise SandboxApplyError(
                f"baseline path spelling differs from allowed path: {before_path}"
            )
        if after_path is not None and after_path.casefold() != expected_path.casefold():
            raise SandboxApplyError(
                f"result path spelling differs from allowed path: {after_path}"
            )
        if before_path is not None and after_path is not None and before_path != after_path:
            raise SandboxApplyError(
                f"path rename/case rewrite is unsupported in R0: {before_path} -> {after_path}"
            )

        if before is None:
            action = "add"
        elif after is None:
            action = "delete"
        else:
            action = "modify"
        mutations.append(
            PlannedMutation(
                path=expected_path,
                action=action,
                baseline_sha256=before.sha256 if before else None,
                result_sha256=after.sha256 if after else None,
            )
        )

    return tuple(mutations)


def _authority(sandbox: SandboxResult, source: Path) -> dict[str, object]:
    return {
        "taskId": sandbox.task_id,
        "runId": sandbox.run_id,
        "ownerEpoch": sandbox.owner_epoch,
        "worktreePath": str(source),
    }


def _parent_chain_safe(source: Path, relative: str) -> Path:
    try:
        assert_paths_contained(source, [relative])
    except SecurityError as ex:
        raise SandboxApplyError(f"target path escapes workspace: {relative}") from ex
    target = source / relative
    current = target.parent
    while current != source:
        if current.exists():
            try:
                if current.is_symlink() or (
                    hasattr(current, "is_junction") and current.is_junction()
                ):
                    raise SandboxApplyError(
                        f"target parent is linklike: {relative}"
                    )
            except OSError as ex:
                raise SandboxApplyError(
                    f"target parent identity unavailable: {relative}"
                ) from ex
        current = current.parent
    return target


def _make_parent_dirs(source: Path, target: Path) -> list[Path]:
    missing = []
    current = target.parent
    while current != source and not current.exists():
        missing.append(current)
        current = current.parent
    if current != source:
        _parent_chain_safe(source, str(target.relative_to(source)).replace("\\", "/"))
    created = []
    for directory in reversed(missing):
        directory.mkdir()
        created.append(directory)
    return created


def _copy_result_to_temp(
    result_root: Path,
    relative: str,
    staging_root: Path,
    expected_sha256: str,
) -> Path:
    source = result_root / relative
    if not source.exists():
        raise SandboxApplyError(f"result file disappeared before apply: {relative}")
    temp = staging_root / relative
    _copy_regular_file(source, temp, relative)
    actual = ManifestEntry(
        path=relative,
        sha256=_file_sha256(temp),
        size=int(temp.stat().st_size),
    )
    if actual.sha256 != expected_sha256:
        try:
            temp.unlink()
        except OSError:
            pass
        raise SandboxApplyError(f"result file changed during apply staging: {relative}")
    return temp


def _file_sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _restore(
    source: Path,
    applied: Sequence[PlannedMutation],
    backups: dict[str, Path | None],
    created_dirs: Sequence[Path],
) -> None:
    errors = []
    for mutation in reversed(tuple(applied)):
        target = source / mutation.path
        backup = backups.get(mutation.path)
        try:
            if backup is None:
                if target.exists() or target.is_symlink():
                    target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(backup, target)
        except Exception as ex:
            errors.append(f"{mutation.path}: {ex}")
    for directory in reversed(tuple(created_dirs)):
        try:
            directory.rmdir()
        except OSError:
            pass
    if errors:
        raise SandboxApplyError(
            "ROLLBACK_FAILED: " + "; ".join(errors)
        )


def apply_sandbox_result(
    sandbox: SandboxResult,
    *,
    source_workspace: str | Path,
    allowed_paths: Sequence[str],
    lease_path: str | Path,
    lease_token: str,
    packet_path: str | Path,
) -> SandboxApplyEvidence:
    source = Path(source_workspace).resolve(strict=True)
    if source.parent == source:
        raise SandboxApplyError("workspace root cannot be filesystem root")
    result_root = Path(sandbox.result_dir).resolve(strict=True)
    try:
        common = Path(os.path.commonpath((str(source), str(result_root))))
    except ValueError as ex:
        raise SandboxApplyError("result/workspace path identity is invalid") from ex
    if common in (source, result_root):
        raise SandboxApplyError(
            "sandbox result directory must be disjoint from the real workspace"
        )
    _assert_result_tree_safe(result_root)

    if sandbox.source_manifest_sha256 != manifest_sha256(sandbox.source_manifest):
        raise SandboxApplyError("stored source manifest identity is invalid")
    if sandbox.result_manifest_sha256 != manifest_sha256(sandbox.result_manifest):
        raise SandboxApplyError("stored result manifest identity is invalid")

    actual_result = manifest_tree(result_root)
    actual_result_digest = manifest_sha256(actual_result)
    if actual_result_digest != sandbox.result_manifest_sha256:
        raise SandboxApplyError("sandbox result changed after extraction")

    mutations = _plan(
        sandbox.source_manifest,
        actual_result,
        allowed_paths,
    )
    authority = _authority(sandbox, source)

    with _WorkspaceFence(source):
        try:
            _verify_unlocked(
                Path(lease_path),
                lease_token,
                packet_path,
                source,
                sandbox.executor,
            )
            _assert_live_control_lease(authority, sandbox.executor)
        except SecurityError as ex:
            raise SandboxApplyError(f"live host authority is invalid: {ex}") from ex

        _, current_digest = capture_sanitized_manifest(source)
        if current_digest != sandbox.source_manifest_sha256:
            raise SandboxApplyError(
                "host workspace drifted from the exact pre-run sandbox baseline"
            )

        if not mutations:
            _assert_live_control_lease(authority, sandbox.executor)
            return SandboxApplyEvidence(
                task_id=sandbox.task_id,
                run_id=sandbox.run_id,
                owner_epoch=sandbox.owner_epoch,
                executor=sandbox.executor,
                changed_paths=(),
                before_manifest_sha256=current_digest,
                result_manifest_sha256=actual_result_digest,
                after_manifest_sha256=current_digest,
            )

        result_map = _canonical_entries(actual_result, label="result manifest")
        allowed = _allowed_map(allowed_paths)
        backups: dict[str, Path | None] = {}
        staged: dict[str, Path] = {}
        created_dirs: list[Path] = []
        applied: list[PlannedMutation] = []
        rollback = Path(
            tempfile.mkdtemp(
                prefix=".forgeboss-rollback-",
                dir=source.parent,
            )
        ).resolve(strict=True)
        preserve_rollback = False
        cleanup_error: Exception | None = None

        try:
            staging_root = rollback / "staged"
            backup_root = rollback / "backup"
            staging_root.mkdir()
            backup_root.mkdir()

            for mutation in mutations:
                canonical = _scope_path(mutation.path)
                relative = allowed[canonical]
                target = _parent_chain_safe(source, relative)

                if target.exists():
                    backup = backup_root / relative
                    _copy_regular_file(target, backup, relative)
                    backups[mutation.path] = backup
                else:
                    backups[mutation.path] = None

                if mutation.action != "delete":
                    result_entry = result_map[canonical]
                    staged[mutation.path] = _copy_result_to_temp(
                        result_root,
                        result_entry.path,
                        staging_root,
                        result_entry.sha256,
                    )

            # Nothing in the real workspace has changed yet.
            _, latest_digest = capture_sanitized_manifest(source)
            if latest_digest != sandbox.source_manifest_sha256:
                raise SandboxApplyError(
                    "host workspace changed after apply planning"
                )
            _assert_live_control_lease(authority, sandbox.executor)
            _verify_unlocked(
                Path(lease_path),
                lease_token,
                packet_path,
                source,
                sandbox.executor,
            )

            for mutation in mutations:
                # Cancellation/release/expiry between any two files stops the
                # transaction and triggers rollback of files already applied.
                _assert_live_control_lease(authority, sandbox.executor)
                canonical = _scope_path(mutation.path)
                relative = allowed[canonical]
                target = _parent_chain_safe(source, relative)

                if mutation.action == "delete":
                    target.unlink()
                else:
                    created_dirs.extend(_make_parent_dirs(source, target))
                    os.replace(staged[mutation.path], target)
                applied.append(mutation)

            _assert_live_control_lease(authority, sandbox.executor)
            _, after_digest = capture_sanitized_manifest(source)
            if after_digest != actual_result_digest:
                raise SandboxApplyError(
                    "post-apply manifest does not equal exact sandbox result"
                )

            evidence = SandboxApplyEvidence(
                task_id=sandbox.task_id,
                run_id=sandbox.run_id,
                owner_epoch=sandbox.owner_epoch,
                executor=sandbox.executor,
                changed_paths=tuple(m.path for m in mutations),
                before_manifest_sha256=current_digest,
                result_manifest_sha256=actual_result_digest,
                after_manifest_sha256=after_digest,
            )
        except Exception as ex:
            try:
                _restore(source, applied, backups, created_dirs)
            except Exception as rollback_ex:
                preserve_rollback = True
                raise SandboxApplyError(
                    "apply failed and rollback also failed; recovery material "
                    f"preserved at {rollback}: {rollback_ex}"
                ) from ex
            raise
        finally:
            if not preserve_rollback:
                try:
                    shutil.rmtree(rollback)
                except Exception as ex:
                    cleanup_error = ex

        if cleanup_error is not None:
            raise SandboxApplyError(
                f"rollback staging cleanup failed: {cleanup_error}"
            )
        return evidence
