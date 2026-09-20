from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation

_OID=re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HEX64=re.compile(r"^[0-9a-f]{64}$")


def canonical_digest(value)->str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")).hexdigest()


def _money(value):
    if isinstance(value,bool):raise ValueError("boolean money denied")
    out=Decimal(str(value))
    if not out.is_finite() or out<0:raise ValueError("money invalid")
    return out


def evaluate_p0_session(record:dict)->dict:
    """Evaluate durable Issue #178 three-cycle acceptance evidence.

    This never invents missing proof. Every acceptance condition must be
    explicitly present in the durable session record.
    """
    blockers=[]
    def require(name,ok,detail):
        if not ok:blockers.append({"name":name,"detail":str(detail)})

    require("record",isinstance(record,dict),"session record must be an object")
    if not isinstance(record,dict):
        result={"schema":1,"status":"FAIL","blockers":blockers}
        result["evidence_digest"]=canonical_digest(result)
        return result

    require("schema",record.get("schema")==1,"session evidence schema must be 1")
    supplied_record_digest=str(record.get("session_record_digest") or "").lower()
    record_core={k:v for k,v in record.items() if k not in {"session_record_digest","p0_evaluation"}}
    require("session-record-digest",bool(_HEX64.fullmatch(supplied_record_digest)) and supplied_record_digest==canonical_digest(record_core),"durable session record digest mismatch")
    session_id=str(record.get("session_id") or "")
    require("session-id",bool(session_id),"session id missing")
    require("proof-mode",record.get("proof_mode") is True,"P0 proof mode was not owner-authorized")
    require("cycle-target",record.get("cycle_target")==3,"exactly three cycles are required")
    require("completed-cycles",record.get("completed_cycles")==3,"three cycles did not complete")
    require("stop-gate",record.get("stop_requested") is False,"STOP gate was requested")
    require("session-error",record.get("error") in {None,""},"session recorded an error")

    try:
        budget=_money(record.get("session_budget_usd"))
        reserved=_money(record.get("reserved_cap_usd"))
        require("budget-authority",budget>=Decimal("6.00"),f"owner budget {budget} is below $6.00")
        require("budget-reservation",reserved==Decimal("6.00"),f"reserved protected caps must equal $6.00, got {reserved}")
        require("budget-ceiling",reserved<=budget,f"reserved {reserved} exceeds owner budget {budget}")
    except (InvalidOperation,ValueError,TypeError) as ex:
        budget=reserved=None;require("budget-authority",False,ex)

    rows=record.get("runs")
    require("run-count",isinstance(rows,list) and len(rows)==3,"exactly three durable run records are required")
    ordered=[]
    if isinstance(rows,list):
        try:ordered=sorted(rows,key=lambda x:int(x.get("cycle_index",0)) if isinstance(x,dict) else 0)
        except Exception:ordered=[]
    require("cycle-indexes",[x.get("cycle_index") for x in ordered if isinstance(x,dict)]==[1,2,3],"cycle indexes must be exactly 1,2,3")

    previous_successor=None
    accepted=[]
    for expected,row in enumerate(ordered,1):
        if not isinstance(row,dict):
            require(f"cycle-{expected}",False,"cycle row invalid");continue
        run_id=str(row.get("run_id") or "")
        base=str(row.get("base_revision") or "").lower()
        successor=str(row.get("successor_sha") or "").lower()
        require(f"cycle-{expected}-run-id",bool(run_id),"run id missing")
        require(f"cycle-{expected}-base",bool(_OID.fullmatch(base)),f"invalid base revision {base!r}")
        require(f"cycle-{expected}-successor",bool(_OID.fullmatch(successor)),f"invalid successor revision {successor!r}")
        require(f"cycle-{expected}-changed",bool(base and successor and base!=successor),"accepted successor did not advance the exact base")
        if previous_successor is not None:
            require(f"cycle-{expected}-lineage",base==previous_successor,f"base {base} does not equal prior accepted successor {previous_successor}")
        activation=row.get("activation")
        authority=row.get("activation_authority")
        if not isinstance(activation,dict):
            require(f"cycle-{expected}-activation",False,"activation evidence missing")
        else:
            require(f"cycle-{expected}-activation-status",activation.get("status")=="ACTIVATED_KNOWN_GOOD",activation.get("status"))
            require(f"cycle-{expected}-activation-sha",str(activation.get("successor_sha") or "").lower()==successor,"activation successor binding mismatch")
            receipt=(authority or {}).get("receipt") if isinstance(authority,dict) else None
            require(f"cycle-{expected}-activation-receipt",isinstance(receipt,dict),"protected activation receipt missing")
            if isinstance(receipt,dict):
                require(f"cycle-{expected}-activation-operation",receipt.get("operation")=="activate_self_build_successor",receipt.get("operation"))
                require(f"cycle-{expected}-activation-result-digest",str(receipt.get("resultDigest") or "").lower()==canonical_digest(activation),"protected activation result digest mismatch")
                require(f"cycle-{expected}-activation-receipt-digest",str((authority or {}).get("receiptDigest") or "").lower()==canonical_digest(receipt),"protected activation receipt digest mismatch")
                require(f"cycle-{expected}-activation-signature",bool((authority or {}).get("receiptSignature")),"protected activation signature missing")
            probe=str(activation.get("probe_evidence_sha256") or "").lower()
            health=str(activation.get("health_evidence_sha256") or "").lower()
            require(f"cycle-{expected}-probe",bool(_HEX64.fullmatch(probe)),"authoritative probe digest missing/invalid")
            require(f"cycle-{expected}-health",bool(_HEX64.fullmatch(health)),"authoritative health digest missing/invalid")
            require(f"cycle-{expected}-generation",isinstance(activation.get("generation"),int) and not isinstance(activation.get("generation"),bool) and activation.get("generation")>0,"activation generation invalid")
        require(f"cycle-{expected}-run-error",row.get("error") in {None,""},"cycle recorded an error")
        require(f"cycle-{expected}-phase",row.get("phase")=="SUCCESSOR_ACTIVATED",row.get("phase"))
        if successor:accepted.append(successor);previous_successor=successor

    proof=record.get("rollback_proof")
    first=ordered[0] if ordered and isinstance(ordered[0],dict) else {}
    first_successor=str(first.get("successor_sha") or "").lower()
    if not isinstance(proof,dict):
        require("rollback-proof",False,"deliberate broken-candidate rollback evidence missing")
    else:
        require("rollback-status",proof.get("status")=="ROLLBACK_PROVEN",proof.get("status"))
        require("rollback-run",proof.get("run_id")==first.get("run_id"),"rollback drill must be bound to cycle 1 activated run")
        require("rollback-base",str(proof.get("known_good_revision") or "").lower()==first_successor,"rollback drill known-good must be cycle 1 successor")
        require("rollback-pointer",str(proof.get("pointer_revision") or "").lower()==first_successor,"rollback did not restore cycle 1 successor")
        require("rollback-phase",proof.get("final_phase")=="ROLLED_BACK",proof.get("final_phase"))
        require("rollback-process",proof.get("candidate_process_dead") is True,"broken candidate death not proven")
        require("rollback-workspace",proof.get("workspace_cleaned") is True,"broken candidate workspace cleanup not proven")
        broken=str(proof.get("broken_candidate_sha") or "").lower()
        require("rollback-broken-sha",bool(_OID.fullmatch(broken)) and broken!=first_successor,"deliberately broken candidate identity invalid")
        proof_digest=str(proof.get("evidence_digest") or "").lower()
        proof_core={k:v for k,v in proof.items() if k!="evidence_digest"}
        require("rollback-digest",bool(_HEX64.fullmatch(proof_digest)) and proof_digest==canonical_digest(proof_core),"rollback evidence digest missing/invalid")
        proof_authority=record.get("rollback_proof_authority")
        proof_receipt=(proof_authority or {}).get("receipt") if isinstance(proof_authority,dict) else None
        require("rollback-authority-receipt",isinstance(proof_receipt,dict),"protected rollback receipt missing")
        if isinstance(proof_receipt,dict):
            require("rollback-authority-operation",proof_receipt.get("operation")=="prove_self_build_activation_rollback",proof_receipt.get("operation"))
            require("rollback-authority-result-digest",str(proof_receipt.get("resultDigest") or "").lower()==canonical_digest(proof),"protected rollback result digest mismatch")
            require("rollback-authority-receipt-digest",str((proof_authority or {}).get("receiptDigest") or "").lower()==canonical_digest(proof_receipt),"protected rollback receipt digest mismatch")
            require("rollback-authority-signature",bool((proof_authority or {}).get("receiptSignature")),"protected rollback signature missing")

    final=record.get("final_known_good")
    third_successor=str(ordered[2].get("successor_sha") or "").lower() if len(ordered)==3 and isinstance(ordered[2],dict) else ""
    if not isinstance(final,dict):
        require("final-known-good",False,"final protected known-good evidence missing")
    else:
        require("final-phase",final.get("phase")=="READY",f"final protected state must be READY, got {final.get('phase')}")
        require("final-revision",str(final.get("revision") or "").lower()==third_successor,"final known-good is not cycle 3 successor")
        require("final-generation",isinstance(final.get("generation"),int) and not isinstance(final.get("generation"),bool) and final.get("generation")>0,"final generation invalid")
        require("final-manifest",bool(_HEX64.fullmatch(str(final.get("manifest_sha256") or "").lower())),"final manifest digest missing/invalid")
        require("final-identity",bool(_HEX64.fullmatch(str(final.get("identity_sha256") or "").lower())),"final identity digest missing/invalid")
        final_authority=record.get("final_known_good_authority")
        final_receipt=(final_authority or {}).get("receipt") if isinstance(final_authority,dict) else None
        require("final-authority-receipt",isinstance(final_receipt,dict),"protected final known-good receipt missing")
        if isinstance(final_receipt,dict):
            require("final-authority-operation",final_receipt.get("operation")=="self_build_current_known_good",final_receipt.get("operation"))
            require("final-authority-result-digest",str(final_receipt.get("resultDigest") or "").lower()==canonical_digest(final),"protected final known-good result digest mismatch")
            require("final-authority-receipt-digest",str((final_authority or {}).get("receiptDigest") or "").lower()==canonical_digest(final_receipt),"protected final known-good receipt digest mismatch")
            require("final-authority-signature",bool((final_authority or {}).get("receiptSignature")),"protected final known-good signature missing")

    result={
        "schema":1,"session_id":session_id,
        "status":"PASS" if not blockers else "FAIL",
        "cycle_count":len(ordered),"accepted_revisions":accepted,
        "rollback_proven":isinstance(proof,dict) and proof.get("status")=="ROLLBACK_PROVEN",
        "budget_usd":None if budget is None else format(budget,".2f"),
        "reserved_cap_usd":None if reserved is None else format(reserved,".2f"),
        "blockers":blockers,
    }
    result["evidence_digest"]=canonical_digest(result)
    return result
