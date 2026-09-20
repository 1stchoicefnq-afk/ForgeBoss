from __future__ import annotations

import importlib.util
import math
import os
import shutil
import subprocess
from pathlib import Path
from typing import Mapping

from forgeboss.control.known_good import verify_build_manifest
from forgeboss.control.self_build import finish_line_one_plan
from forgeboss.security.executor_guard import _resolve_git_executable


def _inside(child:Path,parent:Path)->bool:
    try:
        return Path(os.path.commonpath([str(child),str(parent)]))==parent
    except ValueError:
        return False


def _git_head(root:Path,git:Path)->str:
    p=subprocess.run(
        [str(git),"-C",str(root),"rev-parse","HEAD"],
        capture_output=True,text=True,timeout=30,check=False,
        env={**{k:v for k,v in os.environ.items() if not k.upper().startswith("GIT_")},"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,"GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0","GIT_ASKPASS":""},
    )
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout or "git rev-parse failed").strip())
    value=p.stdout.strip().lower()
    if len(value) not in (40,64) or any(c not in "0123456789abcdef" for c in value):
        raise RuntimeError("Git HEAD is not an exact object id")
    return value


def _money(value)->float:
    if isinstance(value,bool):
        raise ValueError("budget invalid")
    out=float(value)
    if not math.isfinite(out) or out<=0:
        raise ValueError("budget invalid")
    return out


def self_build_preflight(source_path,*,running_root,requested_budget_usd,env:Mapping[str,str]|None=None,authoritative_known_good:Mapping|None=None)->dict:
    env=dict(os.environ if env is None else env)
    checks=[];blockers=[]

    def check(name,ok,detail):
        checks.append({"name":name,"ok":bool(ok),"detail":str(detail)})
        if not ok:blockers.append({"name":name,"detail":str(detail)})

    try:
        source=Path(source_path).expanduser().resolve(strict=True)
        check("source-folder",source.is_dir(),source)
    except Exception as ex:
        return {"ready":False,"checks":[],"blockers":[{"name":"source-folder","detail":str(ex)}]}

    running=Path(running_root).resolve(strict=True)
    required=("forgeboss/control/activation.py","forgeboss/control/known_good.py","dashboard/pro_shell.py","START-FORGEBOSS.vbs")
    missing=[rel for rel in required if not (source/rel).is_file()]
    check("forgeboss-source",not missing,"complete ForgeBoss tree" if not missing else "missing: "+", ".join(missing))
    check("git-checkout",(source/".git").exists(),"Git checkout required for self-build; ZIP-only input must be materialized first")

    try:
        git=_resolve_git_executable()
        check("trusted-git",True,git)
    except Exception as ex:
        git=None;check("trusted-git",False,ex)

    source_head=running_head=None
    if git is not None and (source/".git").exists():
        try:
            source_head=_git_head(source,git);check("source-head",True,source_head)
        except Exception as ex:check("source-head",False,ex)
        try:
            running_head=_git_head(running,git);check("running-head",True,running_head)
        except Exception as ex:check("running-head",False,ex)
    else:
        check("source-head",False,"trusted Git checkout unavailable")
        check("running-head",False,"trusted Git checkout unavailable")

    authoritative=dict(authoritative_known_good or {}) if isinstance(authoritative_known_good,Mapping) else None
    identity=None
    if authoritative is not None:
        try:
            auth_root=Path(str(authoritative.get("code_root") or "")).resolve(strict=True)
            auth_revision=str(authoritative.get("revision") or "").lower()
            auth_manifest=Path(str(authoritative.get("manifest_path") or "")).resolve(strict=True)
            auth_manifest_sha=str(authoritative.get("manifest_sha256") or "").lower()
            check("protected-known-good-root",auth_root==source,f"protected={auth_root} source={source}")
            check("self-target",bool(source_head and source_head==auth_revision),f"source={source_head} protected={auth_revision}")
            identity=verify_build_manifest(auth_manifest,source,auth_revision,auth_manifest_sha)
            check("known-good-manifest",identity.get("verified") is True,identity.get("revision"))
            if authoritative.get("identity_sha256") and identity.get("identitySha256")!=authoritative.get("identity_sha256"):
                check("protected-known-good-identity",False,"protected identity digest mismatch")
            else:
                check("protected-known-good-identity",True,identity.get("identitySha256"))
        except Exception as ex:
            identity=None
            check("protected-known-good-root",False,ex)
            check("self-target",False,"protected known-good identity unavailable")
            check("known-good-manifest",False,ex)
    else:
        if source_head and running_head:
            check("self-target",source_head==running_head,f"source={source_head} running={running_head}")
        else:
            check("self-target",False,"exact source/running identities unavailable")
        manifest=env.get("FORGEBOSS_BUILD_MANIFEST")
        expected=env.get("FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA")
        manifest_sha=env.get("FORGEBOSS_EXPECTED_MANIFEST_SHA256")
        if manifest and expected and manifest_sha:
            try:
                identity=verify_build_manifest(manifest,running,expected,manifest_sha)
                check("known-good-manifest",identity.get("verified") is True,identity.get("revision"))
            except Exception as ex:
                identity=None;check("known-good-manifest",False,ex)
        else:
            check("known-good-manifest",False,"FORGEBOSS_BUILD_MANIFEST / EXPECTED_KNOWN_GOOD_SHA / EXPECTED_MANIFEST_SHA256 not fully configured")

    kg=(identity or {}).get("revision") or (str((authoritative or {}).get("revision") or "") or running_head)
    if kg:
        try:
            plan=finish_line_one_plan(kg,"fl1-preflight")
            check("fl1-plan",True,f"2 initial builders + B2; global cap $${plan.global_budget_usd}")
        except Exception as ex:
            plan=None;check("fl1-plan",False,ex)
    else:
        plan=None;check("fl1-plan",False,"known-good revision unavailable")

    try:
        requested=_money(requested_budget_usd)
        required_cap=float(plan.global_budget_usd) if plan else 2.0
        check("owner-budget",requested>=required_cap,f"requested $${requested:.2f}; FL1 cap $${required_cap:.2f}")
    except Exception as ex:
        check("owner-budget",False,ex)

    raw_state=env.get("FORGEBOSS_STATE_ROOT")
    if raw_state:
        try:
            state=Path(raw_state).expanduser().resolve()
            check("external-runtime-state",not _inside(state,source),state)
        except Exception as ex:check("external-runtime-state",False,ex)
    else:
        check("external-runtime-state",False,"FORGEBOSS_STATE_ROOT is not configured outside the source tree")

    docker=shutil.which("docker.exe" if os.name=="nt" else "docker")
    check("docker",bool(docker),docker or "Docker executable not found")
    mini=importlib.util.find_spec("minisweagent")
    check("mini-swe",mini is not None,"mini-swe-agent installed" if mini else "mini-swe-agent not installed")
    has_model=bool(env.get("OPENAI_API_KEY") or env.get("LLM_API_KEY"))
    check("model-credential",has_model,"configured" if has_model else "OPENAI_API_KEY / LLM_API_KEY missing")

    peer_key=env.get("FORGEBOSS_AUTHORITY_PEER_KEY")
    receipt_pin=env.get("FORGEBOSS_AUTHORITY_RECEIPT_PUBLIC_KEY")
    check("authority-peer-key",bool(peer_key and Path(peer_key).is_file()),peer_key or "FORGEBOSS_AUTHORITY_PEER_KEY missing")
    check("authority-receipt-pin",bool(receipt_pin and Path(receipt_pin).is_file()),receipt_pin or "FORGEBOSS_AUTHORITY_RECEIPT_PUBLIC_KEY missing")
    if os.name=="nt":
        check("authority-endpoint",True,r"\\.\pipe\ForgeBossAuthority (availability checked at protected client call)")
    else:
        endpoint=env.get("FORGEBOSS_AUTHORITY_ENDPOINT_DIR")
        sock=Path(endpoint)/"authority.sock" if endpoint else None
        check("authority-endpoint",bool(sock and sock.exists()),sock or "FORGEBOSS_AUTHORITY_ENDPOINT_DIR missing")

    return {
        "ready":not blockers,
        "checks":checks,
        "blockers":blockers,
        "source_head":source_head,
        "running_head":running_head,
        "known_good_sha":(identity or {}).get("revision"),
        "plan":None if plan is None else plan.as_dict(),
    }


def concise_blockers(result:dict,limit:int=6)->str:
    blockers=list(result.get("blockers") or [])
    if not blockers:return "Self-build preflight passed."
    body="; ".join(f"{x.get('name')}: {x.get('detail')}" for x in blockers[:limit])
    if len(blockers)>limit:body+=f"; +{len(blockers)-limit} more"
    return body
