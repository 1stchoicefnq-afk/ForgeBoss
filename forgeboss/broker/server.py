from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
import secrets
import socket
import sqlite3
import stat
import struct
import time
from pathlib import Path

from forgeboss.executors.isolation_broker import _canonical
from forgeboss.security import executor_guard as guard
from .crypto import ProtectedAuthorityVerifier, ReceiptSigner, broker_root, load_service_gid
from .runtime import materialize_base, quarantine_run, run_mini_swe
from .reintegrate import build_and_handoff, result_ref as make_result_ref


class BrokerServerError(RuntimeError):
    pass


MAX_REQUEST = 16 * 1024 * 1024
WIN_PIPE = r"\\.\pipe\ForgeBossIsolationBroker.v3"
LINUX_SOCKET = Path("/run/forgeboss/isolation-broker-v3.sock")


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _positive(value, label="budget") -> float:
    if isinstance(value, bool):
        raise BrokerServerError(label + " must be finite positive")
    try:
        result = float(value)
    except Exception as ex:
        raise BrokerServerError(label + " must be finite positive") from ex
    if not math.isfinite(result) or result <= 0:
        raise BrokerServerError(label + " must be finite positive")
    return result


def _nonnegative(value, label) -> float:
    if isinstance(value, bool):
        raise BrokerServerError(label + " must be finite nonnegative")
    try:
        result = float(value)
    except Exception as ex:
        raise BrokerServerError(label + " must be finite nonnegative") from ex
    if not math.isfinite(result) or result < 0:
        raise BrokerServerError(label + " must be finite nonnegative")
    return result


def _finite_time(value, label: str) -> float:
    try:
        result = float(value)
    except Exception as ex:
        raise BrokerServerError(label + " invalid") from ex
    if not math.isfinite(result):
        raise BrokerServerError(label + " invalid")
    return result


def _hex(value, count: int) -> bool:
    return isinstance(value, str) and len(value) == count and all(c in "0123456789abcdef" for c in value.lower())


def _envelope(raw):
    try:
        envelope = json.loads(raw) if isinstance(raw, str) else None
    except Exception as ex:
        raise BrokerServerError("control envelope invalid JSON") from ex
    if not isinstance(envelope, dict):
        raise BrokerServerError("control envelope missing")
    unsigned = dict(envelope)
    unsigned.pop("signature", None)
    return envelope, unsigned, _digest(unsigned)


def _norm_list(values):
    if not isinstance(values, list):
        raise BrokerServerError("path list invalid")
    result = [guard.norm(value) for value in values]
    if len({value.casefold() for value in result}) != len(result):
        raise BrokerServerError("path list case collision")
    return result


def _authority_view(request: dict) -> dict:
    if request.get("schema") != 3 or request.get("operation") != "run-mini-swe-v3":
        raise BrokerServerError("unsupported broker request")
    envelope, unsigned, envelope_sha = _envelope(request.get("controlEnvelope"))
    allowed = _norm_list(unsigned.get("allowedPaths"))
    packet = request.get("packet")
    if not isinstance(packet, dict):
        raise BrokerServerError("embedded packet missing")
    packet_allowed, _ = guard.validate_packet(packet)
    if [x.casefold() for x in packet_allowed] != [x.casefold() for x in allowed]:
        raise BrokerServerError("packet scope differs from control authority")
    task = str(unsigned.get("taskId") or "")
    run = str(unsigned.get("runId") or "")
    base = str(unsigned.get("baseSha") or "").lower()
    worktree = str(unsigned.get("worktreePath") or "")
    try:
        owner_epoch = int(unsigned.get("ownerEpoch"))
    except Exception as ex:
        raise BrokerServerError("control authority ownerEpoch invalid") from ex
    expires_at = _finite_time(unsigned.get("expiresAt"), "control authority expiry")
    if not task or not run or owner_epoch <= 0 or not _hex(base, 40) or not worktree:
        raise BrokerServerError("control authority identity incomplete")
    if expires_at <= time.time():
        raise BrokerServerError("control authority expired")
    budget = _positive(unsigned.get("budgetUsd"))
    runtime = unsigned.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("adapter") != "mini-swe":
        raise BrokerServerError("control authority runtime is not mini-swe")
    checks = {
        "taskId": task,
        "runId": run,
        "ownerEpoch": owner_epoch,
        "envelopeSha256": envelope_sha,
        "budgetUsd": budget,
        "worktreePath": str(Path(worktree).resolve()),
        "baseSha": base,
        "allowedPaths": allowed,
        "expiresAt": expires_at,
    }
    if str(Path(str(request.get("workspace") or "")).resolve()) != checks["worktreePath"]:
        raise BrokerServerError("request workspace differs from control authority")
    if _positive(request.get("budgetUsd")) != budget:
        raise BrokerServerError("request budget differs from control authority")
    expected = request.get("expectedAuthority")
    if not isinstance(expected, dict):
        raise BrokerServerError("expected authority missing")
    for key, value in checks.items():
        got = expected.get(key)
        if key == "budgetUsd":
            if _positive(got) != value:
                raise BrokerServerError("expected authority mismatch: " + key)
        elif key == "worktreePath":
            if str(Path(str(got)).resolve()) != value:
                raise BrokerServerError("expected authority mismatch: " + key)
        elif key == "allowedPaths":
            try:
                got_paths = [guard.norm(str(x)).casefold() for x in (got or [])]
            except Exception as ex:
                raise BrokerServerError("expected authority mismatch: " + key) from ex
            if got_paths != [x.casefold() for x in value]:
                raise BrokerServerError("expected authority mismatch: " + key)
        elif key == "baseSha":
            if str(got).lower() != value:
                raise BrokerServerError("expected authority mismatch: " + key)
        elif got != value:
            raise BrokerServerError("expected authority mismatch: " + key)
    pre_authority = request.get("preAuthority")
    pre_targets = request.get("preTargets")
    if not isinstance(pre_authority, dict) or request.get("preAuthoritySha256") != _digest(pre_authority):
        raise BrokerServerError("preAuthority digest mismatch")
    if not isinstance(pre_targets, dict) or request.get("preTargetsSha256") != _digest(pre_targets):
        raise BrokerServerError("preTargets digest mismatch")
    model = str(request.get("model") or "")
    image = str(request.get("image") or "")
    if runtime.get("model") and model != str(runtime.get("model")):
        raise BrokerServerError("model differs from protected authority")
    if image != "node:22-bookworm":
        raise BrokerServerError("unapproved broker runtime image")
    return {
        **checks,
        "packet": packet,
        "runtime": runtime,
        "model": model,
        "image": image,
        "resultRef": make_result_ref(task, run),
        "legacySignature": envelope.get("signature"),
        "preAuthority": pre_authority,
    }


def _read_regular_file(path: Path, label: str) -> bytes:
    try:
        if guard.is_linklike(path) or not path.is_file():
            raise BrokerServerError(label + " is not a regular non-link file")
        return path.read_bytes()
    except BrokerServerError:
        raise
    except Exception as ex:
        raise BrokerServerError("cannot read " + label) from ex


def _spend_binding(spend: dict, view: dict, lease_expiry: float) -> dict:
    if not isinstance(spend, dict) or int(spend.get("schema", 0)) != 1:
        raise BrokerServerError("paid lease lacks durable spend reservation binding")
    budget_run_id = str(spend.get("budgetRunId") or "")
    workspace_lease_id = str(spend.get("workspaceLeaseId") or "")
    task = str(spend.get("taskId") or "")
    run = str(spend.get("runId") or "")
    worktree = str(spend.get("worktreePath") or "")
    current_head = str(spend.get("currentHead") or "").lower()
    provider = str(spend.get("provider") or "")
    model = str(spend.get("model") or "")
    status = str(spend.get("status") or "")
    try:
        epoch = int(spend.get("ownerEpoch"))
    except Exception as ex:
        raise BrokerServerError("spend reservation ownerEpoch invalid") from ex
    reserved = _positive(spend.get("budgetReservedUsd"), "workspace reserved budget")
    task_allocated = _positive(spend.get("taskBudgetAllocatedUsd"), "task allocated budget")
    task_spent = _nonnegative(spend.get("taskBudgetSpentUsd"), "task spent budget")
    global_cap = _positive(spend.get("budgetRunCapUsd"), "global budget cap")
    global_reserved = _nonnegative(spend.get("budgetRunReservedUsd"), "global reserved budget")
    expires_at = _finite_time(spend.get("expiresAt"), "spend reservation expiry")
    now = time.time()
    if not budget_run_id or not workspace_lease_id:
        raise BrokerServerError("spend reservation identity missing")
    if status != "active":
        raise BrokerServerError("workspace spend reservation is not active")
    if task != view["taskId"] or run != view["runId"] or epoch != view["ownerEpoch"]:
        raise BrokerServerError("spend reservation task/run/epoch mismatch")
    if str(Path(worktree).resolve()) != view["worktreePath"]:
        raise BrokerServerError("spend reservation worktree mismatch")
    if not _hex(current_head, 40) or current_head != view["baseSha"]:
        raise BrokerServerError("spend reservation current head mismatch")
    if reserved != view["budgetUsd"]:
        raise BrokerServerError("workspace reserved budget mismatch")
    if task_spent > task_allocated or reserved > task_allocated or global_reserved > global_cap or task_allocated > global_reserved:
        raise BrokerServerError("durable task/global budget backing invalid")
    if provider != str(view["runtime"].get("provider") or "") or model != view["model"]:
        raise BrokerServerError("spend reservation provider/model mismatch")
    if expires_at <= now or expires_at > lease_expiry + 1e-9:
        raise BrokerServerError("spend reservation expiry invalid")
    allowed_hash = _digest(view["allowedPaths"])
    if str(spend.get("allowedPathsSha256") or "") != allowed_hash:
        raise BrokerServerError("spend reservation scope mismatch")
    if str(spend.get("envelopeSha256") or "") != view["envelopeSha256"]:
        raise BrokerServerError("spend reservation envelope mismatch")
    expected_workspace_lease_id = _digest(
        {
            "taskId": task,
            "runId": run,
            "ownerEpoch": epoch,
            "worktreePath": str(Path(worktree).resolve()),
            "currentHead": current_head,
            "budgetReservedUsd": reserved,
            "budgetRunId": budget_run_id,
        }
    )
    if workspace_lease_id != expected_workspace_lease_id:
        raise BrokerServerError("workspace spend lease identity mismatch")
    return {
        "schema": 1,
        "budgetRunId": budget_run_id,
        "workspaceLeaseId": workspace_lease_id,
        "taskId": task,
        "runId": run,
        "ownerEpoch": epoch,
        "worktreePath": str(Path(worktree).resolve()),
        "currentHead": current_head,
        "budgetReservedUsd": reserved,
        "taskBudgetAllocatedUsd": task_allocated,
        "taskBudgetSpentUsd": task_spent,
        "budgetRunCapUsd": global_cap,
        "budgetRunReservedUsd": global_reserved,
        "provider": provider,
        "model": model,
        "expiresAt": expires_at,
        "status": "active",
        "allowedPathsSha256": allowed_hash,
        "envelopeSha256": view["envelopeSha256"],
    }


def _validate_paid_lease(request: dict, view: dict) -> dict:
    raw_path = str(request.get("leasePath") or "")
    token = str(request.get("leaseToken") or "")
    if not raw_path or not token:
        raise BrokerServerError("paid lease/token missing")
    path = Path(raw_path)
    if not path.is_absolute():
        raise BrokerServerError("paid lease path must be absolute")
    path = path.resolve()
    try:
        state_root = guard.STATE.resolve()
        if os.path.commonpath([str(state_root), str(path)]) != str(state_root):
            raise BrokerServerError("paid lease path is outside executor-security state")
    except ValueError as ex:
        raise BrokerServerError("paid lease path is outside executor-security state") from ex
    raw = _read_regular_file(path, "paid lease")
    try:
        lease = json.loads(raw.decode("utf-8"))
    except Exception as ex:
        raise BrokerServerError("paid lease JSON invalid") from ex
    if not isinstance(lease, dict) or lease.get("schema") != 3:
        raise BrokerServerError("paid lease schema invalid")
    now = time.time()
    issued_at = _finite_time(lease.get("issued_at"), "paid lease issued_at")
    expires_at = _finite_time(lease.get("expires_at"), "paid lease expiry")
    if issued_at > now + 5 or expires_at <= now or expires_at <= issued_at:
        raise BrokerServerError("paid lease expired/invalid")
    if lease.get("executor") != "mini-swe":
        raise BrokerServerError("paid lease executor mismatch")
    if str(Path(str(lease.get("workspace") or "")).resolve()) != view["worktreePath"]:
        raise BrokerServerError("paid lease workspace mismatch")
    if lease.get("paid_consumed") is True or lease.get("paid_authority") not in (None, {}):
        raise BrokerServerError("paid lease already consumed")
    if lease.get("isolation_verified") is not True:
        raise BrokerServerError("paid lease isolation proof missing")
    expected_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(str(lease.get("token_sha256") or ""), expected_token_hash):
        raise BrokerServerError("paid lease token mismatch")
    allowed = _norm_list(lease.get("allowed_files"))
    if [x.casefold() for x in allowed] != [x.casefold() for x in view["allowedPaths"]]:
        raise BrokerServerError("paid lease scope mismatch")
    packet_path = Path(str(request.get("packetPath") or ""))
    if not packet_path.is_absolute():
        raise BrokerServerError("packet path must be absolute")
    packet_raw = _read_regular_file(packet_path.resolve(), "packet")
    packet_sha = _bytes_digest(packet_raw)
    if packet_sha != str(lease.get("packet_sha256") or ""):
        raise BrokerServerError("paid lease packet digest mismatch")
    try:
        packet_disk = json.loads(packet_raw.decode("utf-8"))
    except Exception as ex:
        raise BrokerServerError("packet JSON invalid") from ex
    if packet_disk != view["packet"]:
        raise BrokerServerError("embedded packet differs from leased packet")
    if lease.get("baseline") != view["preAuthority"].get("ordinary"):
        raise BrokerServerError("paid lease ordinary baseline mismatch")
    if lease.get("git_metadata") != view["preAuthority"].get("git"):
        raise BrokerServerError("paid lease Git baseline mismatch")
    spend = _spend_binding(lease.get("spend_authority"), view, expires_at)
    lease_sha = _bytes_digest(raw)
    return {
        "schema": 1,
        "leasePath": str(path),
        "leaseSha256": lease_sha,
        "leaseTokenSha256": expected_token_hash,
        "leaseExpiresAt": expires_at,
        "packetSha256": packet_sha,
        "spendAuthority": spend,
    }


def _db():
    root = broker_root()
    connection = sqlite3.connect(root / "broker-state.sqlite3", timeout=30, isolation_level=None)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS paid_consumes_v2("
        "workspace_lease_id TEXT PRIMARY KEY,"
        "authority_key TEXT UNIQUE NOT NULL,"
        "consume_id TEXT NOT NULL,"
        "request_sha TEXT NOT NULL,"
        "attestation_id TEXT NOT NULL,"
        "lease_sha TEXT NOT NULL,"
        "lease_token_sha TEXT NOT NULL,"
        "budget_run_id TEXT NOT NULL,"
        "consumed_at REAL NOT NULL,"
        "status TEXT NOT NULL)"
    )
    return connection


def _consume(view: dict, request_sha: str, protected, paid_lease: dict):
    spend = paid_lease["spendAuthority"]
    workspace_lease_id = spend["workspaceLeaseId"]
    authority_key = _digest(
        {
            "taskId": view["taskId"],
            "runId": view["runId"],
            "ownerEpoch": view["ownerEpoch"],
            "envelopeSha256": view["envelopeSha256"],
        }
    )
    consume_id = secrets.token_hex(16)
    connection = _db()
    try:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute(
            "SELECT 1 FROM paid_consumes_v2 WHERE workspace_lease_id=? OR authority_key=?",
            (workspace_lease_id, authority_key),
        ).fetchone():
            raise BrokerServerError("protected paid lease/reservation already consumed/replay")
        connection.execute(
            "INSERT INTO paid_consumes_v2 VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                workspace_lease_id,
                authority_key,
                consume_id,
                request_sha,
                protected.attestation_id,
                paid_lease["leaseSha256"],
                paid_lease["leaseTokenSha256"],
                spend["budgetRunId"],
                time.time(),
                "consumed",
            ),
        )
        connection.execute("COMMIT")
    except Exception:
        try:
            connection.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        connection.close()
    return workspace_lease_id, consume_id


def _finish(workspace_lease_id: str, status: str):
    connection = _db()
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE paid_consumes_v2 SET status=? WHERE workspace_lease_id=?", (status, workspace_lease_id)
        )
        connection.execute("COMMIT")
    except Exception:
        try:
            connection.execute("ROLLBACK")
        except Exception:
            pass
    finally:
        connection.close()


def _authority_reply(view):
    return {key: view[key] for key in ("taskId", "runId", "ownerEpoch", "envelopeSha256", "budgetUsd")}


def _paid_receipt_fields(paid_lease: dict, consume_id: str) -> dict:
    spend = paid_lease["spendAuthority"]
    return {
        "paidConsumeId": consume_id,
        "paidLeaseSha256": paid_lease["leaseSha256"],
        "paidLeaseTokenSha256": paid_lease["leaseTokenSha256"],
        "paidLeaseExpiresAt": paid_lease["leaseExpiresAt"],
        "paidWorkspaceLeaseId": spend["workspaceLeaseId"],
        "paidBudgetRunId": spend["budgetRunId"],
        "paidBudgetReservedUsd": spend["budgetReservedUsd"],
        "paidTaskBudgetAllocatedUsd": spend["taskBudgetAllocatedUsd"],
        "paidTaskBudgetSpentUsd": spend["taskBudgetSpentUsd"],
        "paidBudgetRunCapUsd": spend["budgetRunCapUsd"],
        "paidBudgetRunReservedUsd": spend["budgetRunReservedUsd"],
        "paidReservationExpiresAt": spend["expiresAt"],
    }


def _failure_receipt(request_sha, request, view, protected, paid_lease, consume_id, error, cost, calls):
    authority = _authority_reply(view)
    receipt = {
        "schema": 3,
        "requestSha256": request_sha,
        "preAuthoritySha256": request["preAuthoritySha256"],
        "preTargetsSha256": request["preTargetsSha256"],
        "authoritySha256": _digest(authority),
        "protectedAuthorityAttestationId": protected.attestation_id,
        **_paid_receipt_fields(paid_lease, consume_id),
        "baseCommit": view["baseSha"],
        "resultCommit": None,
        "resultTree": None,
        "appliedPaths": [],
        "allowedPathsSha256": _digest(view["allowedPaths"]),
        "diffSha256": None,
        "resultRef": None,
        "expectedOldOid": None,
        "committedNewOid": None,
        "handoffRepoId": None,
        "hostWorktreeAuthoritative": False,
        "receiptId": secrets.token_hex(16),
        "failedBeforeResult": True,
    }
    return {
        "schema": 3,
        "ok": True,
        "isolated": True,
        "paidConsumed": True,
        "reintegrated": False,
        "reintegrationProtected": True,
        "ordinaryWorkersDeniedDirectWrite": True,
        "preopenedWritableHandlesExcluded": True,
        "hostWorkspaceMounted": False,
        "workerHasRuntimeControl": False,
        "localCopybackRequired": False,
        "changes": [],
        "authority": authority,
        "reintegrationReceipt": receipt,
        "completed": False,
        "cost_usd": cost,
        "calls": calls,
        "error": error,
    }


class BrokerServer:
    def __init__(self, authority_verifier=None, signer=None, materializer=materialize_base, runner=run_mini_swe, handoff=build_and_handoff):
        self.authority_verifier = authority_verifier or ProtectedAuthorityVerifier()
        self.signer = signer or ReceiptSigner()
        self.materializer = materializer
        self.runner = runner
        self.handoff = handoff

    def handle(self, request):
        if not isinstance(request, dict):
            raise BrokerServerError("request must be object")
        request_sha = _digest(request)
        view = _authority_view(request)
        paid_lease = _validate_paid_lease(request, view)
        protected = self.authority_verifier.verify(
            {
                "envelopeSha256": view["envelopeSha256"],
                "taskId": view["taskId"],
                "runId": view["runId"],
                "ownerEpoch": view["ownerEpoch"],
                "baseSha": view["baseSha"],
                "worktreePath": view["worktreePath"],
                "budgetUsd": view["budgetUsd"],
                "expiresAt": view["expiresAt"],
                "allowedPaths": view["allowedPaths"],
                "runtime": view["runtime"],
                "resultRef": view["resultRef"],
                "paidLease": paid_lease,
            }
        )
        if protected.result_ref != view["resultRef"] or protected.runtime != view["runtime"]:
            raise BrokerServerError("protected controller authority result-ref/runtime mismatch")
        if protected.paid_lease != paid_lease:
            raise BrokerServerError("protected controller authority paid-lease mismatch")
        workspace_lease_id, consume_id = _consume(view, request_sha, protected, paid_lease)
        repo = None
        run_result = None
        result = None
        try:
            repo = self.materializer(Path(view["worktreePath"]), view["baseSha"], view["runId"])
            run_result = self.runner(repo, view["packet"], view["budgetUsd"], view["model"], view["image"])
            if run_result.completed is not True:
                raise BrokerServerError("paid Mini-SWE run failed after protected consume: " + str(run_result.error or "unknown error"))
            candidate = self.handoff(repo, view["baseSha"], view["allowedPaths"], view["taskId"], view["runId"])
            if candidate.result_ref != view["resultRef"]:
                raise BrokerServerError("protected handoff ref differs from controller-attested result ref")
            result = candidate
            _finish(workspace_lease_id, "result_committed")
            authority = _authority_reply(view)
            receipt = {
                "schema": 3,
                "requestSha256": request_sha,
                "preAuthoritySha256": request["preAuthoritySha256"],
                "preTargetsSha256": request["preTargetsSha256"],
                "authoritySha256": _digest(authority),
                "protectedAuthorityAttestationId": protected.attestation_id,
                **_paid_receipt_fields(paid_lease, consume_id),
                "baseCommit": result.base_commit,
                "resultCommit": result.result_commit,
                "resultTree": result.result_tree,
                "appliedPaths": list(result.applied_paths),
                "allowedPathsSha256": _digest(view["allowedPaths"]),
                "diffSha256": result.diff_sha256,
                "resultRef": result.result_ref,
                "expectedOldOid": result.old_oid,
                "committedNewOid": result.new_oid,
                "handoffRepoId": result.handoff_repo_id,
                "hostWorktreeAuthoritative": False,
                "receiptId": secrets.token_hex(16),
            }
            signed = {
                "schema": 3,
                "ok": True,
                "isolated": True,
                "paidConsumed": True,
                "reintegrated": True,
                "reintegrationProtected": True,
                "ordinaryWorkersDeniedDirectWrite": True,
                "preopenedWritableHandlesExcluded": True,
                "hostWorkspaceMounted": False,
                "workerHasRuntimeControl": False,
                "localCopybackRequired": False,
                "changes": [],
                "authority": authority,
                "reintegrationReceipt": receipt,
                "completed": True,
                "cost_usd": run_result.cost_usd,
                "calls": run_result.calls,
                "error": None,
            }
            envelope = self.signer.sign(signed)
            _finish(workspace_lease_id, "completed")
            return envelope
        except Exception as ex:
            if repo is not None:
                quarantine_run(repo)
            if result is not None:
                _finish(workspace_lease_id, "result_committed")
                raise
            _finish(workspace_lease_id, "failed")
            cost = getattr(run_result, "cost_usd", None) if run_result is not None else None
            calls = getattr(run_result, "calls", None) if run_result is not None else None
            return self.signer.sign(_failure_receipt(request_sha, request, view, protected, paid_lease, consume_id, f"{type(ex).__name__}: {ex}", cost, calls))


def _read_sock(connection, count):
    out = b""
    while len(out) < count:
        chunk = connection.recv(count - len(out))
        if not chunk:
            raise BrokerServerError("client closed early")
        out += chunk
    return out


def serve_linux(server, stop_event=None):
    parent = LINUX_SOCKET.parent
    if not parent.exists():
        raise BrokerServerError("protected runtime directory missing; service setup prerequisite not satisfied")
    st = parent.stat()
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o022:
        raise BrokerServerError("broker runtime directory owner/mode invalid")
    service_gid = load_service_gid()
    try:
        old = LINUX_SOCKET.lstat()
        if not stat.S_ISSOCK(old.st_mode) or old.st_uid != os.geteuid():
            raise BrokerServerError("unsafe object occupies broker socket path")
        LINUX_SOCKET.unlink()
    except FileNotFoundError:
        pass
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind(str(LINUX_SOCKET))
        os.chown(LINUX_SOCKET, os.geteuid(), service_gid)
        os.chmod(LINUX_SOCKET, 0o660)
        sock.listen(16)
        sock.settimeout(1.0)
        while stop_event is None or not stop_event.is_set():
            try:
                connection, _ = sock.accept()
            except socket.timeout:
                continue
            with connection:
                try:
                    length = struct.unpack("!I", _read_sock(connection, 4))[0]
                    if length <= 0 or length > MAX_REQUEST:
                        raise BrokerServerError("request length invalid")
                    response = server.handle(json.loads(_read_sock(connection, length).decode("utf-8")))
                except Exception as ex:
                    response = {"error": f"{type(ex).__name__}: {ex}"}
                raw = _canonical(response)
                connection.sendall(struct.pack("!I", len(raw)) + raw)


def _win_libs_server():
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    V = wintypes.LPVOID; D = wintypes.DWORD; H = wintypes.HANDLE; B = wintypes.BOOL; PD = ctypes.POINTER(D)
    kernel32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, D, D, D, D, D, D, V]; kernel32.CreateNamedPipeW.restype = H
    kernel32.ConnectNamedPipe.argtypes = [H, V]; kernel32.ConnectNamedPipe.restype = B
    kernel32.DisconnectNamedPipe.argtypes = [H]; kernel32.DisconnectNamedPipe.restype = B
    kernel32.ReadFile.argtypes = [H, V, D, PD, V]; kernel32.ReadFile.restype = B
    kernel32.WriteFile.argtypes = [H, V, D, PD, V]; kernel32.WriteFile.restype = B
    kernel32.CloseHandle.argtypes = [H]; kernel32.CloseHandle.restype = B
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, D, D, V, D, D, H]; kernel32.CreateFileW.restype = H
    kernel32.LocalFree.argtypes = [V]; kernel32.LocalFree.restype = V
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, D, ctypes.POINTER(V), ctypes.POINTER(D)]; advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = B
    return kernel32, advapi32, wintypes


def _win_read(kernel32, handle, count):
    from ctypes import wintypes
    out = bytearray()
    while len(out) < count:
        buf = ctypes.create_string_buffer(count - len(out)); got = wintypes.DWORD()
        if not kernel32.ReadFile(handle, buf, count - len(out), ctypes.byref(got), None) or got.value <= 0:
            raise BrokerServerError("pipe read failed")
        out.extend(buf.raw[:got.value])
    return bytes(out)


def _win_write(kernel32, handle, data):
    from ctypes import wintypes
    offset = 0
    while offset < len(data):
        buf = ctypes.create_string_buffer(data[offset:]); written = wintypes.DWORD()
        if not kernel32.WriteFile(handle, buf, len(data) - offset, ctypes.byref(written), None) or written.value <= 0:
            raise BrokerServerError("pipe write failed")
        offset += written.value


def wake_windows_pipe():
    if os.name != "nt":
        return
    kernel32, _, _ = _win_libs_server(); handle = kernel32.CreateFileW(WIN_PIPE, 0xC0000000, 0, None, 3, 0, None); bad = ctypes.c_void_p(-1).value
    if ctypes.cast(handle, ctypes.c_void_p).value not in (None, bad):
        kernel32.CloseHandle(handle)


def serve_windows(server, stop_event=None):
    kernel32, advapi32, wintypes = _win_libs_server(); V = wintypes.LPVOID; D = wintypes.DWORD; B = wintypes.BOOL; descriptor = V()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;SY)(A;;GRGW;;;AU)", 1, ctypes.byref(descriptor), None):
        raise BrokerServerError("cannot create protected broker pipe DACL")
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("nLength", D), ("lpSecurityDescriptor", V), ("bInheritHandle", B)]
    attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False); first = True
    try:
        while stop_event is None or not stop_event.is_set():
            access = 0x00000003 | (0x00080000 if first else 0); first = False
            handle = kernel32.CreateNamedPipeW(WIN_PIPE, access, 0, 16, MAX_REQUEST, MAX_REQUEST, 0, ctypes.byref(attributes))
            if ctypes.cast(handle, ctypes.c_void_p).value in (None, ctypes.c_void_p(-1).value):
                raise BrokerServerError("cannot create fixed broker named pipe")
            try:
                connected = kernel32.ConnectNamedPipe(handle, None)
                if not connected and ctypes.get_last_error() != 535:
                    raise BrokerServerError("broker named-pipe connect failed")
                if stop_event is not None and stop_event.is_set():
                    continue
                try:
                    length = struct.unpack("!I", _win_read(kernel32, handle, 4))[0]
                    if length <= 0 or length > MAX_REQUEST:
                        raise BrokerServerError("request length invalid")
                    response = server.handle(json.loads(_win_read(kernel32, handle, length).decode("utf-8")))
                except Exception as ex:
                    response = {"error": f"{type(ex).__name__}: {ex}"}
                raw = _canonical(response); _win_write(kernel32, handle, struct.pack("!I", len(raw)) + raw)
            finally:
                kernel32.DisconnectNamedPipe(handle); kernel32.CloseHandle(handle)
    finally:
        kernel32.LocalFree(descriptor)


def serve_forever(stop_event=None):
    server = BrokerServer()
    if os.name == "nt":
        serve_windows(server, stop_event)
    else:
        serve_linux(server, stop_event)
