from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import stat
import subprocess
import tempfile
from pathlib import Path

from forgeboss.security import executor_guard as guard


class IsolationBrokerError(guard.SecurityError):
    pass


_MAX_REPLY = 16 * 1024 * 1024
_MAX_FILE = 8 * 1024 * 1024


def _positive_budget(raw):
    if isinstance(raw, bool):
        raise IsolationBrokerError("paid budget must be a finite positive number")
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError) as ex:
        raise IsolationBrokerError("paid budget must be a finite positive number") from ex
    if not math.isfinite(value) or value <= 0:
        raise IsolationBrokerError("paid budget must be a finite positive number")
    return value


def _broker_path() -> Path:
    test_override = os.environ.get("FORGEBOSS_TEST_ISOLATION_BROKER")
    if test_override:
        if os.environ.get("FORGEBOSS_TEST_MODE") != "YES":
            raise IsolationBrokerError("isolation broker override is test-only")
        return Path(test_override).resolve(strict=True)
    if os.name == "nt":
        program_files = Path(os.environ.get("ProgramFiles") or r"C:\Program Files")
        path = program_files / "ForgeBoss" / "ForgeBossIsolationBrokerClient.exe"
    else:
        path = Path("/usr/libexec/forgeboss-isolation-broker")
    try:
        path = path.resolve(strict=True)
    except Exception as ex:
        raise IsolationBrokerError("privilege-separated isolation broker is not installed") from ex
    if guard.is_linklike(path) or not path.is_file():
        raise IsolationBrokerError("isolation broker executable is not a trusted regular file")
    if os.name != "nt":
        st = path.stat()
        if st.st_uid != 0 or (stat.S_IMODE(st.st_mode) & 0o022):
            raise IsolationBrokerError("isolation broker executable is not root-owned and write-protected")
    else:
        trusted_root = (Path(os.environ.get("ProgramFiles") or r"C:\Program Files") / "ForgeBoss").resolve(strict=False)
        try:
            if os.path.commonpath([str(trusted_root), str(path)]) != str(trusted_root):
                raise IsolationBrokerError("isolation broker executable is outside protected Program Files root")
        except ValueError as ex:
            raise IsolationBrokerError("isolation broker executable path is invalid") from ex
    return path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write_bytes(target: Path, data: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".forgeboss-broker", dir=str(target.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _expected_authority(lease_path, control_envelope, workspace, executor, cli_budget):
    lease = json.loads(Path(lease_path).read_text(encoding="utf-8"))
    authority = guard._control_authority(control_envelope, lease, Path(workspace).resolve(), executor)
    budget = _positive_budget(cli_budget)
    if budget != float(authority["budgetUsd"]):
        raise IsolationBrokerError("runner budget differs from signed control authority")
    for key in ("taskId", "runId", "ownerEpoch", "envelopeSha256"):
        if not authority.get(key):
            raise IsolationBrokerError("signed control authority is incomplete: " + key)
    return authority


def _call_broker(request: dict) -> dict:
    broker = _broker_path()
    raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
    proc = subprocess.run(
        [str(broker), "run-mini-swe-v1"],
        input=raw,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3600,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or b"")[-1200:].decode("utf-8", "replace")
        raise IsolationBrokerError("privilege-separated isolation broker rejected paid run: " + detail)
    if not proc.stdout or len(proc.stdout) > _MAX_REPLY:
        raise IsolationBrokerError("isolation broker returned missing/oversized result")
    try:
        reply = json.loads(proc.stdout.decode("utf-8"))
    except Exception as ex:
        raise IsolationBrokerError("isolation broker returned invalid JSON") from ex
    if not isinstance(reply, dict) or reply.get("schema") != 1 or reply.get("ok") is not True:
        raise IsolationBrokerError("isolation broker returned invalid result envelope")
    if reply.get("isolated") is not True or reply.get("hostWorkspaceMounted") is not False:
        raise IsolationBrokerError("broker did not prove a private non-host-mounted execution view")
    if reply.get("workerHasRuntimeControl") is not False:
        raise IsolationBrokerError("paid worker retained Docker/VM runtime control")
    if reply.get("paidConsumed") is not True:
        raise IsolationBrokerError("broker did not durably consume paid authority")
    return reply


def _validate_reply_authority(reply: dict, expected: dict) -> None:
    actual = reply.get("authority")
    if not isinstance(actual, dict):
        raise IsolationBrokerError("broker result is missing exact authority binding")
    for key in ("taskId", "runId", "ownerEpoch", "envelopeSha256"):
        if actual.get(key) != expected.get(key):
            raise IsolationBrokerError("broker authority mismatch: " + key)
    if _positive_budget(actual.get("budgetUsd")) != float(expected["budgetUsd"]):
        raise IsolationBrokerError("broker authority mismatch: budgetUsd")


def _apply_changes(host: Path, packet: dict, baseline: dict, changes) -> list[str]:
    if guard.snapshot(host) != baseline:
        raise IsolationBrokerError("host worktree changed while isolated paid execution was running")
    allowed, _ = guard.validate_packet(packet)
    allowed_keys = {p.casefold(): p for p in allowed}
    if not isinstance(changes, list):
        raise IsolationBrokerError("broker changes must be an array")
    seen = set()
    applied = []
    for item in changes:
        if not isinstance(item, dict):
            raise IsolationBrokerError("broker change entry is invalid")
        rel = guard.norm(item.get("path"))
        key = rel.casefold()
        if key not in allowed_keys or key in seen:
            raise IsolationBrokerError("broker returned duplicate/out-of-scope path: " + rel)
        seen.add(key)
        target = host / allowed_keys[key]
        guard.assert_paths_contained(host, [allowed_keys[key]])
        action = item.get("action")
        if action == "delete":
            if target.exists():
                if guard.is_linklike(target) or not target.is_file():
                    raise IsolationBrokerError("host delete target became unsafe: " + rel)
                target.unlink()
            applied.append(rel)
            continue
        if action != "write":
            raise IsolationBrokerError("broker change action is invalid: " + rel)
        encoded = item.get("contentBase64")
        if not isinstance(encoded, str):
            raise IsolationBrokerError("broker write is missing content: " + rel)
        try:
            data = base64.b64decode(encoded, validate=True)
        except Exception as ex:
            raise IsolationBrokerError("broker write content is invalid base64: " + rel) from ex
        if len(data) > _MAX_FILE:
            raise IsolationBrokerError("broker write exceeds per-file output limit: " + rel)
        expected_hash = str(item.get("sha256") or "").lower()
        if expected_hash != _sha256(data):
            raise IsolationBrokerError("broker write digest mismatch: " + rel)
        if target.exists() and (guard.is_linklike(target) or not target.is_file()):
            raise IsolationBrokerError("host write target became unsafe: " + rel)
        _atomic_write_bytes(target, data)
        applied.append(rel)
    return applied


def run_isolated_mini_swe(lease_path, token, packet_path, workspace, control_envelope, cli_budget, model_name, image):
    host = Path(workspace).resolve()
    packet_path = Path(packet_path)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    guard.validate_packet(packet)
    guard.assert_no_link_escape(host)
    authority = _expected_authority(lease_path, control_envelope, host, "mini-swe", cli_budget)
    host_baseline = guard.snapshot(host)
    request = {
        "schema": 1,
        "operation": "run-mini-swe-v1",
        "workspace": str(host),
        "packetPath": str(packet_path.resolve()),
        "leasePath": str(Path(lease_path).resolve()),
        "leaseToken": str(token),
        "controlEnvelope": control_envelope,
        "budgetUsd": float(authority["budgetUsd"]),
        "model": str(model_name),
        "image": str(image),
        "expectedAuthority": {k: authority[k] for k in ("taskId", "runId", "ownerEpoch", "envelopeSha256", "budgetUsd")},
    }
    reply = _call_broker(request)
    _validate_reply_authority(reply, authority)
    applied = _apply_changes(host, packet, host_baseline, reply.get("changes", []))
    return {
        "completed": reply.get("completed") is True,
        "cost_usd": reply.get("cost_usd"),
        "calls": reply.get("calls"),
        "error": reply.get("error"),
        "applied": applied,
        "authority": authority,
    }
