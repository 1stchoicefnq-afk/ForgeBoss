from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

from forgeboss.control.process_supervisor import ProcessSupervisor,SupervisorError
from forgeboss.protected_authority.client import ProtectedAuthorityClient
from forgeboss.security.executor_guard import issue_lease
from forgeboss.control.self_build_freeze import SelfBuildFreezeError,freeze_candidate,load_result_file


class SelfBuildLaunchError(RuntimeError):
    def __init__(self,code:str,message:str):
        super().__init__(message);self.code=code


_SECRET_ENV={
    "GH_TOKEN","GITHUB_TOKEN","GITHUB_PAT",
    "FORGEBOSS_AUTHORITY_PEER_KEY",
    "FORGEBOSS_AUTHORITY_RECEIPT_SIGNING_KEY",
    "FORGEBOSS_GITHUB_APP_PRIVATE_KEY",
}


def _inside(child:Path,parent:Path)->bool:
    try:return Path(os.path.commonpath([str(child),str(parent)]))==parent
    except ValueError:return False


def _atomic_json(path:Path,value:dict)->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+f".tmp-{os.getpid()}-{time.time_ns()}")
    data=(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+"\n").encode("utf-8")
    fd=os.open(str(tmp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as f:
            f.write(data);f.flush();os.fsync(f.fileno())
    finally:
        try:os.close(fd)
        except OSError:pass
    os.replace(tmp,path)


def _packet_sha(path:Path)->str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _cleanup_labeled_container(*,run_id:str,builder_id:str)->dict:
    docker=shutil.which("docker.exe") or shutil.which("docker")
    if not docker:
        raise SelfBuildLaunchError("DOCKER_CLI_MISSING","Docker executable disappeared during worker containment proof")
    filters=[
        "--filter",f"label=forgeboss.stage1.run={run_id}",
        "--filter",f"label=forgeboss.stage1.worker={builder_id}",
    ]
    empty_streak=0
    observed=[]
    for _ in range(12):
        q=subprocess.run([docker,"ps","-aq",*filters],capture_output=True,text=True,timeout=15,check=False)
        if q.returncode:
            raise SelfBuildLaunchError("DOCKER_CONTAINMENT_QUERY_FAILED",(q.stderr or q.stdout or "")[-1000:])
        ids=[x.strip() for x in (q.stdout or "").splitlines() if x.strip()]
        observed.extend(x for x in ids if x not in observed)
        if ids:
            empty_streak=0
            rm=subprocess.run([docker,"rm","-f",*ids],capture_output=True,text=True,timeout=30,check=False)
            if rm.returncode:
                raise SelfBuildLaunchError("DOCKER_CONTAINMENT_CLEANUP_FAILED",(rm.stderr or rm.stdout or "")[-1000:])
        else:
            empty_streak+=1
            if empty_streak>=2:
                return {"container_empty":True,"observed_container_ids":observed}
        time.sleep(0.2)
    raise SelfBuildLaunchError("DOCKER_CONTAINMENT_NOT_EMPTY","Docker worker container remained after bounded cleanup")


class SelfBuildLauncher:
    """Launches already-prepared ForgeBoss workers.

    Preparation authority comes from the protected service. This class only
    materializes public packet/bundle evidence under external state, obtains
    one-time executor leases, and launches workers under ProcessSupervisor.
    """
    def __init__(self,*,client:ProtectedAuthorityClient,supervisor:ProcessSupervisor,
                 state_root,python_executable=None,runner_path=None,
                 issue_lease_fn:Callable=issue_lease,freeze_fn:Callable=freeze_candidate,
                 container_cleanup_fn:Callable=_cleanup_labeled_container,clock:Callable=time.time):
        if not isinstance(client,ProtectedAuthorityClient):
            raise SelfBuildLaunchError("AUTHORITY_CLIENT_REQUIRED","protected authority client required")
        if not isinstance(supervisor,ProcessSupervisor):
            raise SelfBuildLaunchError("SUPERVISOR_REQUIRED","ProcessSupervisor required")
        self.client=client;self.supervisor=supervisor;self.issue_lease_fn=issue_lease_fn;self.freeze_fn=freeze_fn;self.container_cleanup_fn=container_cleanup_fn;self.clock=clock
        self.state_root=Path(state_root).expanduser().resolve()
        source_root=Path(__file__).resolve().parents[2]
        if _inside(self.state_root,source_root):
            raise SelfBuildLaunchError("STATE_ROOT_INSIDE_SOURCE","self-build launch state must be outside ForgeBoss source")
        self.run_root=self.state_root/"self-build-launch"
        self.python=Path(python_executable or sys.executable).resolve(strict=True)
        self.runner=Path(runner_path or (source_root/"forgeboss"/"executors"/"mini_swe_runner.py")).resolve(strict=True)

    def _paths(self,run_id:str,builder_id:str)->dict:
        base=self.run_root/run_id/builder_id
        return {
            "base":base,
            "packet":base/"packet.json",
            "bundle":base/"launch-bundle.json",
            "result":base/"result.json",
            "candidate":base/"candidate-evidence.json",
            "handoff":base/"handoff.json",
            "review":base/"review.json",
            "acceptance":base/"acceptance.json",
        }

    def _launch_payload(self,item:dict,packet_sha256:str,expires_at:float)->dict:
        authority=item.get("authority") or {}
        allowed=list((item.get("packet") or {}).get("allowed_files") or [])
        return {
            "schema":1,
            "repository":authority["repository"],
            "controlRevision":int(authority["control_revision"]),
            "taskId":authority["task_id"],
            "runId":authority["run_id"],
            "ownerEpoch":int(authority["owner_epoch"]),
            "builderId":authority["builder_id"],
            "assignmentGeneration":int(authority["assignment_generation"]),
            "assignmentSha256":authority["assignment_sha256"],
            "branch":authority["branch"],
            "worktreePath":str(Path(item["worktree"]).resolve()),
            "runtimeId":"mini-swe",
            "allowedPaths":allowed,
            "packetSha256":packet_sha256,
            "budgetUsd":str(authority["budget_usd"]),
            "globalBudgetRunId":authority["global_budget_run_id"],
            "globalBudgetReservationId":authority["global_budget_reservation_id"],
            "expiresAt":float(expires_at),
        }

    def _worker_env(self,*,lease:dict,bundle_path:Path,result_path:Path)->dict[str,str]:
        env={k:v for k,v in os.environ.items() if k not in _SECRET_ENV and not k.startswith("FORGEBOSS_AUTHORITY_")}
        env.update({
            "FORGEBOSS_ALLOW_PAID_EXECUTOR":"YES",
            "FORGEBOSS_SELF_BUILD_MODE":"YES",
            "FORGEBOSS_EXECUTOR_LEASE":str(lease["lease"]),
            "FORGEBOSS_EXECUTOR_LEASE_TOKEN":str(lease["token"]),
            "FORGEBOSS_PROTECTED_LAUNCH_BUNDLE":str(bundle_path),
            "FORGEBOSS_RESULT_FILE":str(result_path),
            "FORGEBOSS_STATE_ROOT":str(self.state_root),
            "PYTHONDONTWRITEBYTECODE":"1",
            "PYTHONUTF8":"1",
        })
        return env

    def _prepare_worker_launch(self,prepared_run:dict,item:dict)->dict:
        run_id=str(prepared_run.get("run_id") or "")
        builder_id=str(item.get("builder_id") or "")
        if not run_id or not builder_id:
            raise SelfBuildLaunchError("PREPARED_RUN_INVALID","run/builder identity missing")
        paths=self._paths(run_id,builder_id)
        if paths["base"].exists():
            raise SelfBuildLaunchError("LAUNCH_EVIDENCE_EXISTS","worker launch evidence already exists")
        _atomic_json(paths["packet"],item["packet"])
        packet_sha=_packet_sha(paths["packet"])
        lease=self.issue_lease_fn(str(paths["packet"]),item["worktree"],"mini-swe",1200)
        # Expensive packet snapshot + protected attestation happens before either
        # initial worker is started, so the concurrency proof is not defeated by
        # serial prelaunch preparation latency.
        signed=self._launch_payload(item,packet_sha,self.clock()+600.0)
        bundle=self.client.attest_launch_payload(signed)
        _atomic_json(paths["bundle"],bundle)
        env=self._worker_env(lease=lease,bundle_path=paths["bundle"],result_path=paths["result"])
        argv=[
            str(self.python),str(self.runner),str(paths["packet"]),
            str(Path(item["worktree"]).resolve()),str(item["authority"]["budget_usd"]),
        ]
        return {
            "run_id":run_id,"builder_id":builder_id,"item":item,"paths":paths,
            "packet_sha":packet_sha,"env":env,"argv":argv,
        }

    def _start_prepared_worker(self,prepared:dict)->dict:
        run_id=prepared["run_id"];builder_id=prepared["builder_id"];item=prepared["item"];paths=prepared["paths"]
        try:
            assignment=self.supervisor.launch(builder_id,prepared["argv"],cwd=item["worktree"],env=prepared["env"])
        except Exception as ex:
            try:self.client.revoke_self_build_worker(
                run_id=run_id,task_id=item["task_id"],
                worker_run_id=item["authority"]["run_id"],owner_epoch=item["owner_epoch"],
                reason="ProcessSupervisor launch failed",
            )
            except Exception:pass
            raise SelfBuildLaunchError("WORKER_LAUNCH_FAILED",str(ex)) from ex
        return {
            "builder_id":builder_id,
            "task_id":item["task_id"],
            "generation":assignment.generation,
            "pid":assignment.pid,
            "state":assignment.state,
            "started_at":assignment.started_at,
            "containment_id":assignment.containment_id,
            "worktree":item["worktree"],
            "packet_sha256":prepared["packet_sha"],
            "packet_file":str(paths["packet"]),
            "launch_bundle_file":str(paths["bundle"]),
            "result_file":str(paths["result"]),
            "budget_usd":str(item["authority"]["budget_usd"]),
        }

    def _initial_launch_failure(self,prepared_run:dict,launched:list[dict],live:list)->dict:
        rows=[]
        by_id={x.get("builder_id"):x for x in launched}
        for current in live:
            public=by_id.get(current.worker_id) or {}
            result=None
            result_file=public.get("result_file")
            if result_file and Path(result_file).is_file():
                try:result=json.loads(Path(result_file).read_text(encoding="utf-8"))
                except Exception:result={"completed":False,"error":"result evidence unreadable"}
            rows.append({
                "builder_id":current.worker_id,
                "generation":current.generation,
                "pid":current.pid,
                "state":current.state,
                "exit_code":current.exit_code,
                "containment_id":current.containment_id,
                "result_file":result_file,
                "result":result,
            })
        evidence={
            "schema":1,"run_id":str(prepared_run.get("run_id") or ""),
            "error_code":"CONCURRENCY_NOT_PROVEN",
            "message":"both initial builders were not simultaneously RUNNING",
            "workers":rows,"captured_at":self.clock(),
        }
        target=self.run_root/evidence["run_id"]/"initial-launch-failure.json"
        _atomic_json(target,evidence)
        return evidence

    def launch_worker(self,prepared_run:dict,item:dict)->dict:
        return self._start_prepared_worker(self._prepare_worker_launch(prepared_run,item))

    def launch_initial(self,prepared_run:dict)->dict:
        builders=list(prepared_run.get("builders") or [])
        if len(builders)!=2:
            raise SelfBuildLaunchError("INITIAL_BUILDER_COUNT_INVALID","first FL1 run requires exactly two initial builders")
        staged=[];launched=[]
        try:
            # Stage both non-paid launch envelopes/leases first. Only after both
            # are ready do we start the two worker processes back-to-back.
            for item in builders:
                staged.append(self._prepare_worker_launch(prepared_run,item))
            for prepared in staged:
                launched.append(self._start_prepared_worker(prepared))
            live=[self.supervisor.get(x["builder_id"],refresh=True) for x in launched]
            if any(x.state!="RUNNING" for x in live):
                evidence=self._initial_launch_failure(prepared_run,launched,live)
                summary=", ".join(f'{x["builder_id"]}={x["state"]}/exit={x["exit_code"]}' for x in evidence["workers"])
                raise SelfBuildLaunchError("CONCURRENCY_NOT_PROVEN","both initial builders were not simultaneously RUNNING; "+summary)
            proof_at=self.clock()
            return {
                "schema":1,"run_id":prepared_run["run_id"],"base_sha":prepared_run["base_sha"],
                "global_budget_cap_usd":prepared_run["global_budget_cap_usd"],
                "concurrent_proof":{"at":proof_at,"builders":[x["builder_id"] for x in launched],"states":[x.state for x in live]},
                "workers":launched,
            }
        except BaseException as ex:
            # Persist a useful initial-launch report even when the failure occurs
            # before the simultaneous-RUNNING proof has been established.
            diagnostic=self.run_root/str(prepared_run.get("run_id") or "")/"initial-launch-failure.json"
            if not diagnostic.is_file():
                rows=[]
                for public in launched:
                    try:
                        current=self.supervisor.get(public["builder_id"],refresh=True)
                        state=current.state;exit_code=current.exit_code;pid=current.pid;containment=current.containment_id
                    except Exception as status_error:
                        state="STATUS_UNAVAILABLE";exit_code=None;pid=public.get("pid");containment=public.get("containment_id")
                        status_error_text=f"{type(status_error).__name__}: {status_error}"
                    else:
                        status_error_text=None
                    result=None
                    result_file=public.get("result_file")
                    if result_file and Path(result_file).is_file():
                        try:result=json.loads(Path(result_file).read_text(encoding="utf-8"))
                        except Exception:result={"completed":False,"error":"result evidence unreadable"}
                    rows.append({
                        "builder_id":public.get("builder_id"),"generation":public.get("generation"),
                        "pid":pid,"state":state,"exit_code":exit_code,"containment_id":containment,
                        "result_file":result_file,"result":result,"status_error":status_error_text,
                    })
                _atomic_json(diagnostic,{
                    "schema":1,"run_id":str(prepared_run.get("run_id") or ""),
                    "error_code":str(getattr(ex,"code",type(ex).__name__)),
                    "message":str(ex),"workers":rows,"captured_at":self.clock(),
                })
            for public in reversed(launched):
                try:
                    self.supervisor.stop(public["builder_id"],public["generation"],timeout=5.0)
                    self.container_cleanup_fn(run_id=prepared_run["run_id"],builder_id=public["builder_id"])
                except Exception:pass
            # Preparation created protected authority for both initial tasks, so
            # revoke both on any failed launch attempt, even if one was never started.
            for item in builders:
                try:self.client.revoke_self_build_worker(
                    run_id=prepared_run["run_id"],task_id=item["task_id"],
                    worker_run_id=item["authority"]["run_id"],owner_epoch=item["owner_epoch"],
                    reason="initial two-builder launch rolled back",
                )
                except Exception:pass
            raise

    def launch_replacement(self,prepared_run:dict,replacement:dict,launched_run:dict)->dict:
        public=self.launch_worker(prepared_run,replacement)
        out={**launched_run,"workers":[*(launched_run.get("workers") or []),public]}
        out["replacement_proof"]={
            "at":self.clock(),
            "replacement_for":replacement.get("replacement_for"),
            "builder_id":replacement.get("builder_id"),
            "task_id":replacement.get("task_id"),
            "worktree":replacement.get("worktree"),
        }
        return out

    def status(self,launched_run:dict)->dict:
        rows=[]
        for worker in launched_run.get("workers") or []: