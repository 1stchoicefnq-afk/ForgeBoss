from __future__ import annotations
import argparse, inspect, json, sys
from pathlib import Path

EXPECTED_GITHUB = {
    "read_github_control",
    "publish_report_comment",
    "publish_reviewed_draft_pr",
}
CURRENT_REQUIRED = {
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
EXPECTED_ALL = EXPECTED_GITHUB | CURRENT_REQUIRED

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--engine-root",required=True);ns=ap.parse_args()
    engine=Path(ns.engine_root).resolve(strict=True)
    sys.path.insert(0,str(engine))
    from forgeboss.protected_authority import protocol, service
    operations=set(protocol.OPERATIONS)
    missing=sorted(EXPECTED_ALL-operations)
    unexpected=sorted(operations-EXPECTED_ALL)
    legacy=sorted(x for x in operations if x.startswith("issue_stage1_"))
    sig=inspect.signature(service.create_production_service)
    params=list(sig.parameters)
    stage1_params=sorted(x for x in params if x.startswith("stage1_"))
    if missing or unexpected:
        raise RuntimeError("AUTHORITY_OPERATION_INVENTORY_MISMATCH missing="+json.dumps(missing)+" unexpected="+json.dumps(unexpected))
    if legacy:
        raise RuntimeError("LEGACY_ISSUE_STAGE1_OPERATIONS_PRESENT:"+",".join(legacy))
    if stage1_params:
        raise RuntimeError("OBSOLETE_STAGE1_SERVICE_PARAMETERS_PRESENT:"+",".join(stage1_params))
    print(json.dumps({
        "ok":True,
        "currentOperations":sorted(CURRENT_REQUIRED),
        "expectedAllOperations":sorted(EXPECTED_ALL),
        "unexpectedOperations":unexpected,
        "legacyIssueStage1Operations":False,
        "obsoleteStage1ServiceParameters":False,
        "serviceParameters":params,
    },sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
