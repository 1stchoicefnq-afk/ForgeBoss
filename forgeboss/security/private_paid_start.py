from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from forgeboss.security import executor_guard as guard

ROOT = Path(__file__).resolve().parents[2]
CONTROL_DB = ROOT / "state" / "forgebossd" / "forgeboss.db"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class PrivatePaidStartError(guard.SecurityError):
    pass


def _file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _exact_revision(packet: dict, signed_env: dict) -> str:
    revision = str(packet.get("expected_head_revision") or packet.get("exact_head") or "").lower()
    if not _SHA_RE.fullmatch(revision):
        raise PrivatePaidStartError("private paid execution requires an exact 40-hex revision")
    base = str(signed_env.get("baseSha") or "").lower()
    if base != revision:
        raise PrivatePaidStartError("signed control base SHA differs from private execution revision")
    return revision


def _validate_writer_row(row, authority: dict, workspace: Path, executor: str) -> None:
    if row is None:
        raise PrivatePaidStartError("durable writer authority no longer matches signed run/epoch")
    if float(row["expires_at"]) <= time.time():
        raise PrivatePaidStartError("durable writer authority expired before paid start")
    if Path(str(row["worktree_path"])).resolve() != workspace.resolve():
        raise PrivatePaidStartError("durable writer worktree differs from signed paid workspace")
    runtime = str(row["assigned_runtime"] or "")
    if runtime and runtime != executor:
        raise PrivatePaidStartError("durable assigned runtime differs from paid executor")
    if float(row["budget_reserved"] or 0.0) != float(authority["budgetUsd"]):
        raise PrivatePaidStartError("durable reserved budget differs from signed paid authority")


def _writer_identity(authority: dict):
    task_id = str(authority.get("taskId") or "")
    run_id = str(authority.get("runId") or "")
    try:
        epoch = int(authority.get("ownerEpoch"))
    except Exception as ex:
        raise PrivatePaidStartError("signed control ownerEpoch is invalid") from ex
    if not task_id or not run_id or epoch <= 0:
        raise PrivatePaidStartError("signed control task/run/epoch identity is incomplete")
    return task_id, run_id, epoch


def _select_writer(db, authority: dict):
    task_id, run_id, epoch = _writer_identity(authority)
    return db.execute(
        """SELECT wl.*, t.assigned_runtime FROM workspace_leases wl
           JOIN tasks t ON t.task_id=wl.task_id
           WHERE wl.task_id=? AND wl.owner_run_id=? AND wl.owner_epoch=? AND wl.released_at IS NULL""",
        (task_id, run_id, epoch),
    ).fetchone()


def _assert_current_durable_writer(authority: dict, workspace: Path, executor: str) -> None:
    if not CONTROL_DB.exists():
        raise PrivatePaidStartError("authoritative control database is unavailable")
    uri = "file:" + CONTROL_DB.resolve().as_posix() + "?mode=ro"
    db = None
    try:
        db = sqlite3.connect(uri, uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        row = _select_writer(db, authority)
    except PrivatePaidStartError:
        raise
    except Exception as ex:
        raise PrivatePaidStartError("unable to verify durable current writer authority") from ex
    finally:
        try:
            if db is not None:
                db.close()
        except Exception:
            pass
    _validate_writer_row(row, authority, workspace, executor)


@contextmanager
def _hold_current_durable_writer(authority: dict, workspace: Path, executor: str):
    """Prevent claim/release/reassign while paid authority is consumed and snapshotted."""
    if not CONTROL_DB.exists():
        raise PrivatePaidStartError("authoritative control database is unavailable")
    db = None
    begun = False
    try:
        db = sqlite3.connect(str(CONTROL_DB.resolve()), timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        begun = True
        row = _select_writer(db, authority)
        _validate_writer_row(row, authority, workspace, executor)
        yield
        db.execute("COMMIT")
        begun = False
    except PrivatePaidStartError:
        raise
    except Exception as ex:
        raise PrivatePaidStartError("unable to fence durable writer authority during paid start") from ex
    finally:
        if db is not None:
            if begun:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
            try:
                db.close()
            except Exception:
                pass


def _git_archive_exact(workspace: Path, revision: str) -> bytes:
    git_bin = shutil.which("git.exe") or shutil.which("git")
    if not git_bin:
        raise PrivatePaidStartError("git executable unavailable for private exact snapshot")
    env = os.environ.copy()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"})
    with tempfile.TemporaryDirectory(prefix="forgeboss-git-home-") as clean_home:
        env["HOME"] = clean_home
        env["USERPROFILE"] = clean_home
        env["XDG_CONFIG_HOME"] = clean_home
        proc = subprocess.run(
            [git_bin, "archive", "--format=tar", revision],
            cwd=str(workspace),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            env=env,
        )
    if proc.returncode != 0 or not proc.stdout:
        raise PrivatePaidStartError("unable to materialize exact Git revision for private paid execution")
    return bytes(proc.stdout)


def _safe_extract_tar(raw: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
        members = tf.getmembers()
        for member in members:
            rel = PurePosixPath(member.name.replace("\\", "/"))
            if rel.is_absolute() or ".." in rel.parts or not rel.parts:
                raise PrivatePaidStartError("private snapshot archive contains unsafe path")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise PrivatePaidStartError("private snapshot archive contains link/device entry")
            if not (member.isdir() or member.isfile()):
                raise PrivatePaidStartError("private snapshot archive contains unsupported entry")
        for member in members:
            target = destination / PurePosixPath(member.name).as_posix()
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tf.extractfile(member)
            if source is None:
                raise PrivatePaidStartError("private snapshot archive file is unreadable")
            with target.open("wb") as out:
                shutil.copyfileobj(source, out)
            try:
                os.chmod(target, member.mode & 0o777)
            except OSError:
                pass


def _path_state(root: Path, rel: str):
    path = root / guard.norm(rel)
    if not path.exists():
        return {"kind": "missing"}
    if guard.is_linklike(path) or not path.is_file():
        return {"kind": "unsafe"}
    return {"kind": "file", "sha256": _file_digest(path), "size": path.stat().st_size}


def _assert_packet_inputs_match_private(host: Path, private: Path, packet: dict) -> None:
    allowed, context = guard.validate_packet(packet)
    for rel in allowed + context:
        if _path_state(host, rel) != _path_state(private, rel):
            raise PrivatePaidStartError("host packet input differs from bound exact Git revision: " + rel)


def _atomic_copy_file(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".forgeboss-tmp", dir=str(target.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        shutil.copy2(source, tmp)
        os.replace(tmp, target)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def prepare_private_paid_start(lease_path, token, packet_path, workspace, executor, control_envelope, cli_budget):
    host = Path(workspace).resolve()
    packet_path = Path(packet_path)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    private_root = Path(tempfile.mkdtemp(prefix="forgeboss-paid-private-"))
    try:
        lease_before = json.loads(Path(lease_path).read_text(encoding="utf-8"))
        signed_env = guard._load_control_envelope(control_envelope)
        pre_authority = guard._control_authority(control_envelope, lease_before, host, executor)
        if float(signed_env.get("expiresAt") or 0) <= time.time():
            raise PrivatePaidStartError("signed control authority expired before paid start")
        revision = _exact_revision(packet, signed_env)
        if guard._positive_budget(cli_budget) != pre_authority["budgetUsd"]:
            raise PrivatePaidStartError("runner budget differs from signed current writer authority")

        # SQLite BEGIN IMMEDIATE prevents the controller from releasing or
        # reassigning this writer while the exact authority is consumed and the
        # immutable private execution view is materialized.
        with _hold_current_durable_writer(pre_authority, host, executor):
            with guard.paid_start_authority(
                lease_path, token, packet_path, host, executor, control_envelope, cli_budget
            ) as authority:
                for key in ("taskId", "runId", "ownerEpoch", "envelopeSha256", "budgetUsd"):
                    if authority.get(key) != pre_authority.get(key):
                        raise PrivatePaidStartError("paid authority changed between writer fence and consume: " + key)
                archive = _git_archive_exact(host, revision)
                _safe_extract_tar(archive, private_root)
                if (private_root / ".git").exists():
                    raise PrivatePaidStartError("private paid snapshot unexpectedly contains Git metadata")
                guard.assert_no_link_escape(private_root)
                allowed, context = guard.validate_packet(packet)
                guard.assert_paths_contained(private_root, allowed + context)
                _assert_packet_inputs_match_private(host, private_root, packet)
                private_baseline = guard.snapshot(private_root)
                host_baseline = guard.snapshot(host)
                persisted = json.loads(Path(lease_path).read_text(encoding="utf-8"))
                bound = persisted.get("paid_authority") or {}
                for key in ("taskId", "runId", "ownerEpoch", "envelopeSha256", "budgetUsd"):
                    if bound.get(key) != authority.get(key):
                        raise PrivatePaidStartError("durable paid authority binding mismatch: " + key)
        return {
            "workspace": str(private_root),
            "hostWorkspace": str(host),
            "packet": packet,
            "privateBaseline": private_baseline,
            "hostBaseline": host_baseline,
            "authority": authority,
            "leasePath": str(Path(lease_path)),
        }
    except Exception:
        shutil.rmtree(private_root, ignore_errors=True)
        raise


def commit_private_result(session: dict) -> list[str]:
    private = Path(session["workspace"]).resolve()
    host = Path(session["hostWorkspace"]).resolve()
    packet = dict(session["packet"])
    allowed, _ = guard.validate_packet(packet)
    after = guard.snapshot(private)
    changed = guard.changed(session["privateBaseline"], after)
    allowed_keys = {rel.casefold() for rel in allowed}
    bad = [rel for rel in changed if rel.casefold() not in allowed_keys]
    links = [rel for rel in changed if (after.get(rel) or {}).get("kind") == "link"]
    if bad:
        raise PrivatePaidStartError("private paid executor changed out-of-scope paths: " + json.dumps(bad))
    if links:
        raise PrivatePaidStartError("private paid executor created linklike output: " + json.dumps(links))
    if guard.snapshot(host) != session["hostBaseline"]:
        raise PrivatePaidStartError("host worktree changed concurrently during private paid execution")
    guard.assert_paths_contained(host, allowed)
    for rel in changed:
        src = private / rel
        dst = host / rel
        if src.exists():
            if guard.is_linklike(src) or not src.is_file():
                raise PrivatePaidStartError("private paid output is not a regular file: " + rel)
            _atomic_copy_file(src, dst)
        elif dst.exists():
            if guard.is_linklike(dst) or not dst.is_file():
                raise PrivatePaidStartError("host destination became unsafe before delete: " + rel)
            dst.unlink()
    return changed


def cleanup_private_session(session: dict | None) -> None:
    if not session:
        return
    try:
        shutil.rmtree(Path(session["workspace"]), ignore_errors=True)
    except Exception:
        pass
