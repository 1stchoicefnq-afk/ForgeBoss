from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

EXPECTED_GITHUB = {
    "read_github_control",
    "publish_report_comment",
    "publish_reviewed_draft_pr",
}
EXPECTED_STAGE1 = {
    "authorize_self_build_launch",
    "prepare_self_build",
    "prepare_self_build_replacement",
    "compose_self_build_successor",
    "activate_self_build_successor",
    "prove_self_build_activation_rollback",
    "self_build_current_known_good",
    "self_build_status",
    "revoke_self_build_worker",
    "record_self_build_handoff",
    "review_self_build_candidate",
    "accept_self_build_candidate",
}
EXPECTED_ALL = EXPECTED_GITHUB | EXPECTED_STAGE1


def load(path: Path) -> dict:
    value=json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value,dict):
        raise RuntimeError("JSON_OBJECT_REQUIRED:"+str(path))
    return value


def probe_matrix(state: dict) -> list[tuple[str, dict, str | None]]:
    nonce=uuid.uuid4().hex[:16]
    run_id="verify-missing-"+nonce
    task_id="verify-task-"+nonce
    worker_id="verify-worker-"+nonce
    protected=Path(state["protectedRoot"])
    missing_source=protected/("__verify_missing_source_"+nonce)
    sha=str(state["engineSha"]).lower()
    launch={
        "schema":1,
        "repository":"1stchoicefnq-afk/ForgeBoss",
        "controlRevision":1,
        "taskId":task_id,
        "runId":worker_id,
        "ownerEpoch":1,
        "builderId":"builder-probe",
        "assignmentGeneration":1,
        "assignmentSha256":"2"*64,
        "branch":"forgeboss/verify-probe",
        "worktreePath":str(protected/("__verify_missing_worktree_"+nonce)),
        "runtimeId":"mini-swe",
        "allowedPaths":["forgeboss/__init__.py"],
        "packetSha256":"3"*64,
        "budgetUsd":"0.01",
        "globalBudgetRunId":run_id,
        "globalBudgetReservationId":task_id,
        "expiresAt":time.time()+60.0,
    }
    worker_payload={
        "runId":run_id,"taskId":task_id,"workerRunId":worker_id,
        "ownerEpoch":1,
    }
    return [
        ("authorize_self_build_launch",{"launch":launch},"RUN_NOT_FOUND"),
        ("prepare_self_build",{"sourceRoot":str(missing_source),"baseSha":sha,"runId":run_id},"SELF_BUILD_PAYLOAD_INVALID"),
        ("prepare_self_build_replacement",{"runId":run_id},"RUN_NOT_FOUND"),
        ("compose_self_build_successor",{"runId":run_id},"RUN_NOT_FOUND"),
        ("activate_self_build_successor",{"runId":run_id},"RUN_NOT_FOUND"),
        ("prove_self_build_activation_rollback",{"runId":run_id},"RUN_NOT_FOUND"),
        ("self_build_current_known_good",{},None),
        ("self_build_status",{"runId":run_id},"RUN_NOT_FOUND"),
        ("revoke_self_build_worker",{**worker_payload,"reason":"verify-non-mutating-probe"},"RUN_NOT_FOUND"),
        ("record_self_build_handoff",{**worker_payload,"evidence":{"schema":1}},"RUN_NOT_FOUND"),
        ("review_self_build_candidate",dict(worker_payload),"RUN_NOT_FOUND"),
        ("accept_self_build_candidate",dict(worker_payload),"RUN_NOT_FOUND"),
    ]


def assert_inventory(operations) -> dict:
    actual=set(operations)
    missing=sorted(EXPECTED_ALL-actual)
    unexpected=sorted(actual-EXPECTED_ALL)
    if missing or unexpected:
        raise RuntimeError("AUTHORITY_OPERATION_INVENTORY_MISMATCH missing="+json.dumps(missing)+" unexpected="+json.dumps(unexpected))
    return {"missing":[],"unexpected":[],"count":len(actual)}


def main(argv=None) -> int:
    ap=argparse.ArgumentParser();ap.add_argument("--installed",required=True);ns=ap.parse_args(argv)
    try:
        state=load(Path(ns.installed))
        engine=Path(state["engineRoot"]).resolve(strict=True)
        sys.path.insert(0,str(engine))
        from forgeboss.protected_authority.client import ProtectedAuthorityClient
        from forgeboss.protected_authority.protocol import OPERATIONS

        inventory=assert_inventory(OPERATIONS)
        cfg=load(Path(state["protectedRoot"])/"authority-config.json")
        if cfg.get("authorityApi")!="self_build_runtime_receipts_v1":
            raise RuntimeError("AUTHORITY_API_CONFIG_MISMATCH")
        client_cfg=load(Path(state["clientRoot"])/"client-config.json")
        client=ProtectedAuthorityClient.from_files(
            peer_id=client_cfg["peerId"],
            repository=client_cfg["repository"],
            control_revision=int(client_cfg["controlRevision"]),
            peer_private_key_file=client_cfg["peerKeyFile"],
            receipt_public_key_file=client_cfg["receiptPublicKeyFile"],
            pipe_name=client_cfg["pipeName"],
            timeout=3.0,
        )

        rows=[]
        seen=set()
        for operation,payload,expected_refusal in probe_matrix(state):
            try:
                response=client.call_evidence(operation,payload)
            except Exception as ex:
                raise RuntimeError("STAGE1_OPERATION_CALL_FAILED:"+operation+":"+str(getattr(ex,"code",type(ex).__name__))) from ex
            receipt=response.get("receipt") or {}
            result=response.get("result") or {}
            if receipt.get("operation")!=operation:
                raise RuntimeError("STAGE1_RECEIPT_OPERATION_MISMATCH:"+operation)
            if expected_refusal is None:
                if result.get("authorityRefused") is True:
                    raise RuntimeError("STAGE1_OPERATION_UNEXPECTED_REFUSAL:"+operation+":"+str(result.get("errorCode")))
                kind="signed_success";code=None
            else:
                if result.get("authorityRefused") is not True:
                    raise RuntimeError("STAGE1_OPERATION_EXPECTED_REFUSAL:"+operation)
                code=result.get("errorCode")
                if code!=expected_refusal:
                    raise RuntimeError("STAGE1_OPERATION_WRONG_REFUSAL:"+operation+":"+str(code))
                kind="signed_refusal"
            seen.add(operation)
            rows.append({"operation":operation,"kind":kind,"errorCode":code,"receiptOperation":receipt.get("operation"),"ok":True})

        missing_exercise=sorted(EXPECTED_STAGE1-seen)
        extra_exercise=sorted(seen-EXPECTED_STAGE1)
        if missing_exercise or extra_exercise:
            raise RuntimeError("STAGE1_OPERATION_EXERCISE_MISMATCH missing="+json.dumps(missing_exercise)+" extra="+json.dumps(extra_exercise))
        print(json.dumps({
            "ok":True,
            "authorityApi":cfg.get("authorityApi"),
            "inventory":inventory,
            "stage1Required":len(EXPECTED_STAGE1),
            "stage1Exercised":len(seen),
            "cases":rows,
        },sort_keys=True))
        return 0
    except Exception as ex:
        print(json.dumps({"ok":False,"error":type(ex).__name__,"code":getattr(ex,"code",None),"detail":str(ex)},sort_keys=True))
        return 13


if __name__=="__main__":
    raise SystemExit(main())
