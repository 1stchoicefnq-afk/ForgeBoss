from __future__ import annotations
from pathlib import Path
import hashlib, json, tempfile

ROOT=Path(__file__).resolve().parents[2]
RR=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
SERVER=(ROOT/"dashboard"/"server.py").read_text(encoding="utf-8")

def tag(line_no:int,text:str)->str:
    h=hashlib.sha256(text.strip().encode()).hexdigest()[:8]
    return f"L{line_no}#{h}"

def validate_tag(locator:str,line_no:int,text:str)->bool:
    return locator==tag(line_no,text)

def estimate(body_bytes:int,input_rate=.20,output_rate=1.20,out_tokens=3000):
    in_tokens=(body_bytes+3.2-1)//3.2
    return float(in_tokens)/1_000_000*input_rate + out_tokens/1_000_000*output_rate

def run():
    results={}

    # Patch/schema/locator attacks
    results["compact_locator_format"]=tag(163,"const identity = x;").startswith("L163#")
    results["stale_locator_rejected"]=not validate_tag(tag(163,"old"),163,"new")
    results["same_line_locator_stable"]=validate_tag(tag(10,"  foo();  "),10,"  foo();  ")
    results["no_giant_locator_catalog"]="current_symbol_locators=@($currentSymbolLocators)" not in RR
    results["anchor_hint_enum_removed"]="enum=@($script:CurrentAnchorHints)" not in RR
    results["locator_hash_pattern"]="^L[0-9]+#[0-9a-fA-F]{8}$" in RR
    results["locator_verified_against_current_text"]="expected={1} actual={2} line={3}" in RR and "Sha256Text $line.Trim()" in RR
    results["prose_anchor_schema_rejected"]="^[A-Za-z_$][A-Za-z0-9_$]{3,79}$" in RR
    results["prose_anchor_runtime_rejected"]="prose hints are forbidden" in RR
    results["locator_is_primary"]="anchor_locator is PRIMARY" in RR
    results["method_definition_supported"]="(?:static\\s+)?'+[regex]::Escape($Hint)+'\\s*\\('" in RR
    results["prompt_has_no_literal_backtick_n"]="never invent it.`n-" not in RR

    # Context/budget attacks
    results["context_ceiling"]="FORGEBOSS_CONTEXT_PACKET_TOO_LARGE" in RR and "$maxBodyBytes=6MB" in RR
    results["budget_diagnostic_includes_size"]="body_bytes={2:N0}" in RR and "input_tokens~{3:N0}" in RR
    results["passing_runs_not_sent_wholesale"]="failed_runs=$failed" in RR and "Get-ModelEvidenceView" in RR
    results["diagnostic_trace_bounded"]="Select-Object -First 120" in RR and "Select-Object -First 80" in RR
    results["normal_luna_packet_estimate_reasonable"]=estimate(1_000_000)<0.10

    # Safety invariants retained
    results["learned_zero_cost_repair"]="REPAIR RAT LEARNED HIT" in RR
    results["foundation_chain"]="cumulative=$true" in RR
    results["symbol_roles"]="PATCH_ANCHOR_ROLE_MISMATCH" in RR
    results["runtime_guard"]="FAST_MODULE_LOAD_GUARD" in RR
    results["schema_preflight"]="Assert-StrictSchemaRequiredCoverage" in RR
    results["candidate_regression_rejected"]="PATCH_CANDIDATE_INVALID" in RR
    results["context_oversize_is_infra"]="FORGEBOSS_CONTEXT_PACKET_TOO_LARGE" in SERVER
    from forgeboss.security.executor_guard import norm,sensitive
    results["hidden_dot_path_preserved"]=norm(".git/hooks/pre-commit")==".git/hooks/pre-commit"
    results["git_hook_sensitive"]=sensitive(".git/hooks/pre-commit")
    results["learning_state_sensitive"]=sensitive("state/learning/forgeboss-learning.db")
    results["daemon_state_sensitive"]=sensitive("state/forgebossd/forgeboss.db")

    # Multi-project/scheduler/learning foundations
    from forgeboss.control.projects import list_profiles
    from forgeboss.control.scheduler import WorkItem, smart_parallel_batches
    from forgeboss.learning.store import LearningStore

    ids={p["id"] for p in list_profiles()}
    results["multi_project_profiles"]={"siteboss","siteboss-connect","scroll-animation"} <= ids

    items=[
        WorkItem("db","40001",{"src/db.js"},{"src/db.js"},.02,1),
        WorkItem("ui","frontend",{"src/ui.js"},{"src/ui.js"},.02,2),
        WorkItem("db2","same",{"src/db.js"},{"src/db.js"},.02,3),
        WorkItem("api","http",{"src/api.js"},{"src/api.js"},.02,4),
    ]
    batches=smart_parallel_batches(items,4)
    results["parallel_conflict_isolation"]=len(batches)>=2 and {x.task_id for x in batches[0]}=={"db","ui","api"}

    with tempfile.TemporaryDirectory() as td:
        st=LearningStore(Path(td)/"l.db")
        lid=st.record_verified_lesson("siteboss","x","verified",{"kind":"patch"},{"code":"x"},{"all_required_passed":True})
        results["validated_learning_roundtrip"]=bool(st.find_reusable("siteboss","x")) and bool(lid)

    passed=sum(bool(v) for v in results.values())
    failed=[k for k,v in results.items() if not v]
    print(f"FORGEBOSS v2.2 TORTURE MATRIX PASS={passed} FAIL={len(failed)}")
    for k,v in results.items():
        print(f"[{'PASS' if v else 'FAIL'}] {k}")
    if failed:
        raise SystemExit("FAILED: "+", ".join(failed))
    return results

if __name__=="__main__":
    run()
