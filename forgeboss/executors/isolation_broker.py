from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import subprocess
from pathlib import Path

from forgeboss.security import executor_guard as guard


class IsolationBrokerError(guard.SecurityError):
    pass


_MAX_REPLY = 16 * 1024 * 1024


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


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _broker_path() -> Path:
    override = os.environ.get("FORGEBOSS_TEST_ISOLATION_BROKER")
    if override:
        if os.environ.get("FORGEBOSS_TEST_MODE") != "YES":
            raise IsolationBrokerError("isolation broker override is test-only")
        return Path(override).resolve(strict=True)
    if os.name == "nt":
        path = Path(os.environ.get("ProgramFiles") or r"C:\Program Files") / "ForgeBoss" / "ForgeBossIsolationBrokerClient.exe"
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


def _file_state(path: Path):
    if not path.exists():
        return {"kind": "missing"}
    if guard.is_linklike(path) or not path.is_file():
        return {"kind": "unsafe"}
    data = path.read_bytes()
    return {"kind": "file", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _capture_targets(host: Path, packet: dict):
    allowed, _ = guard.validate_packet(packet)
    result = {}
    for rel in allowed:
        guard.assert_paths_contained(host, [rel])
        state = _file_state(host / rel)
        if state.get("kind") == "unsafe":
            raise IsolationBrokerError("host target is unsafe before broker run: " + rel)
        result[rel] = state
    return result


def _capture_authority(host: Path):
    return {
        "ordinary": guard.snapshot(host),
        "git": guard.git_metadata_snapshot(host),
        "head": guard.git(host, "rev-parse", "HEAD"),
        "worktree": guard.git(host, "rev-parse", "--show-toplevel"),
    }


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
    proc = subprocess.run(
        [str(broker), "run-mini-swe-v2"],
        input=_canonical(request),
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
    if not isinstance(reply, dict) or reply.get("schema") != 2 or reply.get("ok") is not True:
        raise IsolationBrokerError("isolation broker returned invalid result envelope")
    required_true = ("isolated", "paidConsumed", "reintegrated", "reintegrationProtected", "ordinaryWorkersDeniedDirectWrite", "preopenedWritableHandlesExcluded")
    for field in required_true:
        if reply.get(field) is not True:
            raise IsolationBrokerError("isolation broker did not prove protected reintegration: " + field)
    if reply.get("hostWorkspaceMounted") is not False or reply.get("workerHasRuntimeControl") is not False:
        raise IsolationBrokerError("broker boundary exposed host/runtime control")
    if reply.get("localCopybackRequired") is not False:
        raise IsolationBrokerError("broker attempted to delegate reintegration back to ordinary worker")
    if reply.get("changes") not in (None, []):
        raise IsolationBrokerError("broker returned local file payloads after protected reintegration")
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


def _verify_receipt(reply: dict, request: dict, host: Path, packet: dict, pre_authority: dict, pre_targets: dict):
    receipt = reply.get("reintegrationReceipt")
    if not isinstance(receipt, dict) or receipt.get("schema") != 1:
        raise IsolationBrokerError("broker result is missing protected reintegration receipt")
    if receipt.get("requestSha256") != _digest(request):
        raise IsolationBrokerError("reintegration receipt request binding mismatch")
    if receipt.get("preAuthoritySha256") != _digest(pre_authority):
        raise IsolationBrokerError("reintegration receipt host authority binding mismatch")
    if receipt.get("preTargetsSha256") != _digest(pre_targets):
        raise IsolationBrokerError("reintegration receipt target preimage binding mismatch")
    allowed, _ = guard.validate_packet(packet)
    applied = receipt.get("appliedPaths")
    if not isinstance(applied, list) or len(applied) != len(set(x.casefold() for x in applied if isinstance(x, str))):
        raise IsolationBrokerError("reintegration receipt applied path set is invalid")
    allowed_keys = {p.casefold(): p for p in allowed}
    for rel in applied:
        if not isinstance(rel, str) or rel.casefold() not in allowed_keys:
            raise IsolationBrokerError("reintegration receipt contains out-of-scope path")
    post_targets = receipt.get("postTargets")
    if not isinstance(post_targets, dict):
        raise IsolationBrokerError("reintegration receipt missing post-target state")
    canonical_post = {}
    for key, canonical_rel in allowed_keys.items():
        expected = post_targets.get(canonical_rel)
        if expected is None:
            expected = pre_targets[canonical_rel]
        if not isinstance(expected, dict):
            raise IsolationBrokerError("reintegration receipt post-target state is invalid: " + canonical_rel)
        actual = _file_state(host / canonical_rel)
        if actual != expected:
            raise IsolationBrokerError("host target does not match broker protected reintegration receipt: " + canonical_rel)
        canonical_post[canonical_rel] = actual
    current_authority = _capture_authority(host)
    if current_authority.get("git") != pre_authority.get("git") or current_authority.get("head") != pre_authority.get("head") or current_authority.get("worktree") != pre_authority.get("worktree"):
        raise IsolationBrokerError("host Git authority changed across broker protected reintegration")
    expected_ordinary = dict(pre_authority["ordinary"])
    for rel in allowed:
        state = canonical_post[rel]
        if state.get("kind") == "missing":
            expected_ordinary.pop(rel, None)
        else:
            expected_ordinary[rel] = state
    if current_authority.get("ordinary") != expected_ordinary:
        raise IsolationBrokerError("host ordinary state does not equal broker protected reintegration receipt")
    if receipt.get("postAuthoritySha256") != _digest(current_authority):
        raise IsolationBrokerError("reintegration receipt post-authority digest mismatch")
    return [allowed_keys[x.casefold()] for x in applied]


def run_isolated_mini_swe(lease_path, token, packet_path, workspace, control_envelope, cli_budget, model_name, image):
    host = Path(workspace).resolve()
    packet_path = Path(packet_path)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    guard.validate_packet(packet)
    guard.assert_no_link_escape(host)
    authority = _expected_authority(lease_path, control_envelope, host, "mini-swe", cli_budget)
    pre_authority = _capture_authority(host)
    pre_targets = _capture_targets(host, packet)
    request = {
        "schema": 2,
        "operation": "run-mini-swe-v2",
        "workspace": str(host),
        "packetPath": str(packet_path.resolve()),
        "leasePath": str(Path(lease_path).resolve()),
        "leaseToken": str(token),
        "controlEnvelope": control_envelope,
        "budgetUsd": float(authority["budgetUsd"]),
        "model": str(model_name),
        "image": str(image),
        "expectedAuthority": {k: authority[k] for k in ("taskId", "runId", "ownerEpoch", "envelopeSha256", "budgetUsd")},
        "preAuthority": pre_authority,
        "preAuthoritySha256": _digest(pre_authority),
        "preTargets": pre_targets,
        "preTargetsSha256": _digest(pre_targets),
    }
    reply = _call_broker(request)
    _validate_reply_authority(reply, authority)
    applied = _verify_receipt(reply, request, host, packet, pre_authority, pre_targets)
    return {
        "completed": reply.get("completed") is True,
        "cost_usd": reply.get("cost_usd"),
        "calls": reply.get("calls"),
        "error": reply.get("error"),
        "applied": applied,
        "authority": authority,
    }
