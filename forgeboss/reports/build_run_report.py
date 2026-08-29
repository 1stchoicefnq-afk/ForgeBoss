from __future__ import annotations
import argparse, hashlib, json, os, re, subprocess, time, uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"run-reports"
CREATE_NO_WINDOW=getattr(subprocess,"CREATE_NO_WINDOW",0)
_RUN_ID_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")

class ReportEvidenceError(RuntimeError):
    pass

def load(p,label="evidence"):
    path=Path(p)
    try:
        raw=path.read_text(encoding="utf-8-sig")
    except Exception as ex:
        raise ReportEvidenceError(f"{label} unreadable: {path}: {ex}") from ex
    try:
        value=json.loads(raw)
    except Exception as ex:
        raise ReportEvidenceError(f"{label} malformed JSON: {path}: {ex}") from ex
    if not isinstance(value,dict):
        raise ReportEvidenceError(f"{label} must be a JSON object: {path}")
    return value

def _validate_input(inp):
    if not isinstance(inp,dict):
        raise ReportEvidenceError("run evidence must be a JSON object")
    if not isinstance(inp.get("session"),dict):
        raise ReportEvidenceError("run evidence requires object session")
    if not isinstance(inp.get("cycles"),list) or any(not isinstance(c,dict) for c in inp["cycles"]):
        raise ReportEvidenceError("run evidence requires array cycles of objects")
    return inp

def _validate_run_id(value):
    if not isinstance(value,str):
        raise ReportEvidenceError("run_id must be a string")
    rid=value
    if not _RUN_ID_RE.fullmatch(rid):
        raise ReportEvidenceError("run_id must be 1..128 ASCII letters/digits/underscore/hyphen and start alphanumeric")
    return rid

def _contained_path(root:Path,name:str)->Path:
    base=root.resolve(strict=False)
    candidate=(base/name).resolve(strict=False)
    try:
        common=Path(os.path.commonpath([str(base),str(candidate)]))
    except ValueError as ex:
        raise ReportEvidenceError("report output escapes run-report state directory") from ex
    if common!=base or candidate==base:
        raise ReportEvidenceError("report output escapes run-report state directory")
    return candidate

def _report_paths(root:Path,rid:str):
    rid=_validate_run_id(rid)
    return (_contained_path(root,f"{rid}.json"),_contained_path(root,f"{rid}.txt"),_contained_path(root,f"{rid}-github.md"),_contained_path(root,"last.json"))

def _fsync_dir(path:Path):
    try: fd=os.open(str(path),os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
    except OSError:return
    try: os.fsync(fd)
    except OSError:pass
    finally: os.close(fd)

def _atomic_write_text(path:Path,text:str):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.parent/f".{path.name}.tmp-{uuid.uuid4().hex}"
    flags=os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0)
    fd=os.open(str(temp),flags,0o600)
    try:
        data=text.encode("utf-8")
        view=memoryview(data)
        while view:
            n=os.write(fd,view)
            if n<=0: raise OSError("short write")
            view=view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temp,path)
        _fsync_dir(path.parent)
    except Exception:
        try: temp.unlink()
        except FileNotFoundError: pass
        raise

def git(args,cwd):
    try:
        p=subprocess.run(["git.exe",*args],cwd=cwd,capture_output=True,text=True,timeout=90,creationflags=CREATE_NO_WINDOW)
        return p.stdout if p.returncode==0 else ""
    except Exception:return ""

def attempt_summary(report):
    out=[]
    for a in report.get("attempts",[]) or []:
        runs=[]
        for rr in a.get("runs",[]) or []:
            runs.append({"name":rr.get("name"),"exit_code":rr.get("exit_code"),"tail":rr.get("output_tail") or rr.get("tail"),"failure_lines":rr.get("failure_lines")})
        out.append({
          "attempt":a.get("attempt"),
          "specialists":a.get("specialists") or a.get("builder_specialists"),
          "files_changed":a.get("changed_paths") or a.get("files_changed") or [],
          "acceptance_passed":a.get("acceptance_passed"),
          "failure_count":a.get("failure_count"),
          "runs":runs,
          "findings":a.get("findings"),
          "blockers":a.get("blockers"),
          "summary":a.get("model_summary") or a.get("summary"),
          "reasoning_summary":a.get("reasoning_summary"),
          "failure_fingerprint":a.get("failure_fingerprint")
        })
    return out

def cycle_detail(c):
    rp=Path(c.get("report_path","")) if c.get("report_path") else None
    if rp is not None:
        if not rp.exists(): raise ReportEvidenceError(f"cycle evidence missing: {rp}")
        report=load(rp,"cycle evidence")
    else:
        report={}
    workspace=report.get("local_workspace")
    head=report.get("exact_head") or report.get("target_sha") or ""
    commit=report.get("local_commit") or ""
    diff=""
    if workspace and Path(workspace).exists():
        if head and commit: diff=git(["diff","--no-ext-diff","--unified=40",head,commit],workspace)
        elif head: diff=git(["diff","--no-ext-diff","--unified=40",head],workspace)
        else: diff=git(["diff","--no-ext-diff","--unified=40"],workspace)
    return {
      "cycle":c.get("cycle"),
      "exit_code":c.get("exit_code"),
      "cost_usd":c.get("cost_usd",0),
      "report_path":str(rp) if rp else None,
      "provider":report.get("provider"),
      "model":report.get("model") or c.get("routed_model"),
      "requested_mode":c.get("requested_mode"),
      "routed_model":c.get("routed_model"),
      "lane":c.get("lane"),
      "requested_model":report.get("requested_model"),
      "actual_models":report.get("actual_models") or [],
      "api_calls":report.get("api_calls"),
      "repair_contract":report.get("repair_contract"),
      "effective_paid_attempt_cap":report.get("effective_paid_attempt_cap"),
      "usage_input_tokens":report.get("usage_input_tokens"),
      "usage_cached_input_tokens":report.get("usage_cached_input_tokens"),
      "usage_output_tokens":report.get("usage_output_tokens"),
      "usage_calls":report.get("usage_calls") or [],
      "specialists":report.get("builder_specialists") or [],
      "passed":report.get("passed"),
      "partial_proven":report.get("partial_proven"),
      "resolved_focused_step":report.get("resolved_focused_step"),
      "retained_patch_path":report.get("retained_patch_path"),
      "workspace":workspace,
      "exact_head":head,
      "root_pr":report.get("root_pr"),
      "local_commit":commit,
      "fatal_failure":report.get("fatal_failure"),
      "attempts":attempt_summary(report),
      "code_diff":diff,
      "guarantees":report.get("guarantees") or {}
    }

def explain_cycle(c):
    attempts=c.get("attempts") or []
    a=attempts[-1] if attempts else {}
    changed=a.get("files_changed") or []
    failed=[x for x in (a.get("runs") or []) if x.get("exit_code") not in (None,0)]
    summary=str(a.get("summary") or "")
    reasoning=str(a.get("reasoning_summary") or "")
    if c.get("fatal_failure"):
        why=str((c.get("fatal_failure") or {}).get("reason") or "Unknown fatal error")
        if any(code in why for code in ("PATCH_CONTRACT_INVALID","PATCH_ANCHOR_ROLE_MISMATCH","PATCH_SEMANTIC_SCOPE_INVALID","AMBIGUOUS_SYMBOL_ANCHOR","PATCH_ANCHOR_INTENT_MISMATCH","PATCH_LINE_RANGE_TOO_WIDE","PATCH_CANDIDATE_INVALID","PATCH_CONTEXT_MISMATCH","PATCH_PRECONDITION_FAILED","AMBIGUOUS_EDIT_ANCHOR","STALE_FILE","PATH_OUTSIDE_SCOPE")):
            return {"status":"PATCH REJECTED","why":why,
                    "next":"Do not buy another format retry. Repair Rat should retain this as negative patch-contract memory and wait for a better bounded transaction."}
        return {"status":"FORGEBOSS FAULT","why":why,
                "next":"Fix ForgeBoss infrastructure before another paid repair."}
    if c.get("partial_proven"):
        return {"status":"PARTIAL WIN - FOCUSED DEFECT FIXED","why":"The focused defect passed its targeted validation; broader acceptance exposed a different remaining failure family.",
                "next":"Keep the verified sub-fix and focus the next cycle on the remaining failure family."}
    if not changed and a.get("failure_count") in (0,None) and (summary or reasoning):
        why=summary or reasoning
        low=why.lower()
        if "workspace" in low or "execution tools" in low or "tool access" in low:
            return {"status":"AI SAFE REFUSAL - TOOLING MISUNDERSTANDING","why":why,
                    "next":"ForgeBoss already owns the workspace/tests. Feed that execution contract explicitly and retry only once with local evidence."}
        if "complete-file" in low or "complete file" in low or "truncation" in low:
            return {"status":"AI SAFE REFUSAL - PATCH FORMAT BOTTLENECK","why":why,
                    "next":"Use surgical exact-match edits instead of whole-file replacement output."}
        return {"status":"AI SAFE REFUSAL","why":why,
                "next":"Gather the exact missing evidence for the PRIMARY focused defect. Do not let unrelated secondary failures block a supported narrow repair."}
    if changed and failed:
        names=", ".join(str(x.get("name")) for x in failed)
        return {"status":"NEXT TARGET FOUND - REFOCUS REQUIRED","why":"The candidate changed code but broader validation still has another failure set: "+names,
                "next":"Keep only verified sub-fixes; rebuild a fresh single-failure packet before any second paid call."}
    if changed and a.get("acceptance_passed") is True:
        return {"status":"GREEN CANDIDATE","why":"Candidate code passed Repair Rat acceptance.",
                "next":"Proceed to independent review/draft publication gate."}
    if failed:
        return {"status":"TEST FAILURE","why":", ".join(str(x.get("name")) for x in failed),
                "next":"Diagnose the failing test before another model call."}
    return {"status":"UNRESOLVED","why":summary or "No conclusive repair result recorded.",
            "next":"Inspect technical evidence before retrying."}

def render_text(obj):
    lines=[]
    lines += ["FORGEBOSS RUN REPORT","="*88,""]
    s=obj["session"]
    lines += ["EXECUTIVE SUMMARY",
              f"Run: {obj['run_id']}",
              f"Final stage: {s.get('final_stage')}",
              f"Stop reason: {s.get('stop_reason')}",
              f"Budget / spend: ${float(s.get('budget_usd') or 0):.2f} / ${float(s.get('spent_usd') or 0):.4f}",
              f"Cycles: {len(obj.get('cycles') or [])}",
              f"Draft PR: {s.get('draft_pr') or 'none'}",
              "Merge executed: NO",
              "Deploy executed: NO",""]
    for c in obj["cycles"]:
        ex=explain_cycle(c)
        lines += [f"CYCLE {c.get('cycle')} - {ex['status']}","-"*88,
                  f"Cost: ${float(c.get('cost_usd') or 0):.4f}",
                  f"AI lane/model: {c.get('lane') or '?'} / {c.get('model') or c.get('routed_model') or '?'}",
                  f"API calls: {c.get('api_calls')}",
                  f"Tokens: input={c.get('usage_input_tokens') or 0}, cached={c.get('usage_cached_input_tokens') or 0}, output={c.get('usage_output_tokens') or 0}",
                  f"Specialists: {', '.join(c.get('specialists') or []) or 'not recorded'}",
                  f"WHY IT STOPPED/FAILED: {ex['why']}",
                  f"RECOMMENDED NEXT ACTION: {ex['next']}",""]
        for a in c.get("attempts",[]):
            lines += [f"  Attempt {a.get('attempt')}",
                      f"  Result: passed={a.get('acceptance_passed')} failure_count={a.get('failure_count')}",
                      f"  Failure fingerprint: {a.get('failure_fingerprint') or 'none'}"]
            if a.get("summary"):lines.append("  AI / repair summary: "+str(a["summary"]))
            if a.get("reasoning_summary"):lines.append("  Engineering rationale: "+str(a["reasoning_summary"]))
            if a.get("findings"):lines.append("  Findings: "+json.dumps(a["findings"],ensure_ascii=False))
            if a.get("blockers"):lines.append("  Blockers: "+json.dumps(a["blockers"],ensure_ascii=False))
            changed=a.get("files_changed") or []
            lines.append("  Files changed: "+(", ".join(changed) if changed else "NONE"))
            runs=a.get("runs") or []
            if runs:
                lines.append("  TESTS:")
                for rr in runs:
                    ok=rr.get("exit_code")==0
                    lines.append(f"    [{'PASS' if ok else 'FAIL'}] {rr.get('name')} exit={rr.get('exit_code')}")
                    if not ok:
                        fl=rr.get("failure_lines")
                        if fl: lines.append("      Failure lines: "+str(fl)[-3000:])
                        tail=rr.get("tail")
                        if tail:
                            if isinstance(tail,list):tail="\n".join(str(x) for x in tail[-30:])
                            lines.append("      Output tail:\n"+str(tail)[-6000:])
            else:
                lines.append("  Tests after patch: NONE (usually means no patch was produced / safe refusal)")
        if c.get("fatal_failure"):
            lines += ["","  FORGEBOSS FATAL ERROR:",json.dumps(c["fatal_failure"],ensure_ascii=False,indent=2)]
        lines += ["","=== ACTUAL CODE DIFF ===",c.get("code_diff") or "(no retained diff / no patch was applied)",""]
    return "\n".join(lines)

def render_github(obj,sha):
    s=obj["session"]
    lines=["## ForgeBoss autonomous run report","",
      f"**Run:** `{obj['run_id']}`  ",
      f"**Final stage:** `{s.get('final_stage')}`  ",
      f"**Budget / recorded spend:** `${float(s.get('budget_usd') or 0):.2f}` / `${float(s.get('spent_usd') or 0):.4f}`  ",
      f"**Stop reason:** {s.get('stop_reason')}  ",
      f"**Draft PR:** {s.get('draft_pr') or 'none'}  ",
      "**Merge:** not executed  ",
      "**Deploy:** not executed  ","",
      "### Cycles"]
    for c in obj["cycles"]:
        lines += ["",f"#### Cycle {c.get('cycle')}",
                  f"- Exit: `{c.get('exit_code')}`",
                  f"- Cost: `${float(c.get('cost_usd') or 0):.4f}`",
                  f"- Specialists: `{', '.join(c.get('specialists') or []) or 'not recorded'}`",
                  f"- Result: `{explain_cycle(c)['status']}`", f"- Why: {explain_cycle(c)['why'][:1200]}", f"- Next: {explain_cycle(c)['next']}"]
        for a in c.get("attempts",[]):
            changed=a.get("files_changed") or []
            if changed: lines.append("- Files changed: "+", ".join(f"`{x}`" for x in changed[:20]))
            bad=[r.get("name") for r in a.get("runs",[]) if r.get("exit_code") not in (None,0)]
            if bad: lines.append("- Failed validation: "+", ".join(f"`{x}`" for x in bad[:20]))
            if a.get("blockers"):lines.append("- Blockers: `"+str(a.get("blockers"))[:1500].replace("`","'")+"`")
    lines += ["",f"Full local evidence SHA256: `{sha}`",
              "",
              "_ForgeBoss publishes findings only. Failed candidate code is not pushed. Green reviewed code is published separately as a draft PR by the existing publication gate._"]
    body="\n".join(lines)
    return body[:60000]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--input",required=True)
    ns=ap.parse_args()
    inp=_validate_input(load(ns.input,"run evidence"))
    raw_rid=inp["run_id"] if "run_id" in inp else time.strftime("%Y%m%d-%H%M%S")
    rid=_validate_run_id(raw_rid)
    cycles=[cycle_detail(c) for c in inp["cycles"]]
    obj={"schema":1,"kind":"forgeboss-run-report","run_id":rid,
         "generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
         "session":inp["session"],"cycles":cycles}
    text=render_text(obj)
    sha=hashlib.sha256(text.encode("utf-8")).hexdigest()
    obj["text_sha256"]=sha
    jp,tp,mp,last=_report_paths(STATE,rid)
    _atomic_write_text(jp,json.dumps(obj,indent=2))
    _atomic_write_text(tp,text)
    _atomic_write_text(mp,render_github(obj,sha))
    pointer={"run_id":rid,"json":str(jp),"text":str(tp),"github_markdown":str(mp),"sha256":sha}
    _atomic_write_text(last,json.dumps(pointer,indent=2))
    print(json.dumps(pointer))
    return 0
if __name__=="__main__":raise SystemExit(main())
