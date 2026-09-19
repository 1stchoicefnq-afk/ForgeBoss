from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Callable

from forgeboss.control.process_supervisor import ProcessSupervisor,SupervisorError
from forgeboss.protected_authority.client import ProtectedAuthorityClient
from forgeboss.security.executor_guard import issue_lease


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


class SelfBuildLauncher:
    """Launches already-prepared ForgeBoss workers.

    Preparation authority comes from the protected service. This class only
    materializes public packet/bundle evidence under external state, obtains
    one-time executor leases, and launches workers under ProcessSupervisor.
    """
    def __init__(self,*,client:ProtectedAuthorityClient,supervisor:ProcessSupervisor,
                 state_root,python_executable=None,runner_path=None,
                 issue_lease_fn:Callable=issue_lease,clock:Callable=time.time):
        if not isinstance(client,ProtectedAuthorityClient):
            raise SelfBuildLaunchError("AUTHORITY_CLIENT_REQUIRED","protected authority client required")
        if not isinstance(supervisor,ProcessSupervisor):
            raise SelfBuildLaunchError("SUPERVISOR_REQUIRED","ProcessSupervisor required")
        self.client=client;self.supervisor=supervisor;self.issue_lease_fn=issue_lease_fn;self.clock=clock
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
            "PYTHONUTF8":"1",
        })
        return env

    def launch_worker(self,prepared_run:dict,item:dict)->dict:
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
        # The lease token is intentionally never written into packet/bundle/result/run state.
        signed=self._launch_payload(item,packet_sha,self.clock()+600.0)
        bundle=self.client.attest_launch_payload(signed)
        _atomic_json(paths["bundle"],bundle)
        env=self._worker_env(lease=lease,bundle_path=paths["bundle"],result_path=paths["result"])
        argv=[
            str(self.python),str(self.runner),str(paths["packet"]),
            str(Path(item["worktree"]).resolve()),str(item["authority"]["budget_usd"]),
        ]
        try:
            assignment=self.supervisor.launch(builder_id,argv,cwd=item["worktree"],env=env)
        except Exception as ex:
            try:self.client.revoke_self_build_worker(
                run_id=run_id,task_id=item["task_id"],
                worker_run_id=item["authority"]["run_id"],owner_epoch=item["owner_epoch"],
                reason="ProcessSupervisor launch failed",
            )
            except Exception:pass
            raise SelfBuildLaunchError("WORKER_LAUNCH_FAILED",str(ex)) from ex
        public={
            "builder_id":builder_id,
            "task_id":item["task_id"],
            "generation":assignment.generation,
            "pid":assignment.pid,
            "state":assignment.state,
            "started_at":assignment.started_at,
            "containment_id":assignment.containment_id,
            "worktree":item["worktree"],
            "packet_sha256":packet_sha,
            "packet_file":str(paths["packet"]),
            "launch_bundle_file":str(paths["bundle"]),
            "result_file":str(paths["result"]),
            "budget_usd":str(item["authority"]["budget_usd"]),
        }
        return public

    def launch_initial(self,prepared_run:dict)->dict:
        builders=list(prepared_run.get("builders") or [])
        if len(builders)!=2:
            raise SelfBuildLaunchError("INITIAL_BUILDER_COUNT_INVALID","first FL1 run requires exactly two initial builders")
        launched=[]
        try:
            for item in builders:
                launched.append(self.launch_worker(prepared_run,item))
            live=[self.supervisor.get(x["builder_id"],refresh=True) for x in launched]
            if any(x.state!="RUNNING" for x in live):
                raise SelfBuildLaunchError("CONCURRENCY_NOT_PROVEN","both initial builders were not simultaneously RUNNING")
            proof_at=self.clock()
            return {
                "schema":1,"run_id":prepared_run["run_id"],"base_sha":prepared_run["base_sha"],
                "global_budget_cap_usd":prepared_run["global_budget_cap_usd"],
                "concurrent_proof":{"at":proof_at,"builders":[x["builder_id"] for x in launched],"states":[x.state for x in live]},
                "workers":launched,
            }
        except BaseException:
            for public,item in zip(reversed(launched),reversed(builders[:len(launched)])):
                try:self.supervisor.stop(public["builder_id"],public["generation"],timeout=5.0)
                except Exception:pass
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
            current=self.supervisor.get(worker["builder_id"],refresh=True)
            result_path=Path(worker["result_file"])
            result=None
            if result_path.is_file():
                try:
                    parsed=json.loads(result_path.read_text(encoding="utf-8"))
                    if isinstance(parsed,dict):result=parsed
                except Exception:result={"completed":False,"error":"result evidence unreadable"}
            rows.append({
                **worker,
                "state":current.state,
                "exit_code":current.exit_code,
                "result":result,
            })
        return {**launched_run,"workers":rows}

    def stop_worker(self,*,prepared_run:dict,launched_run:dict,builder_id:str,reason:str)->dict:
        public=next((x for x in launched_run.get("workers") or [] if x.get("builder_id")==builder_id),None)
        prepared_items=list(prepared_run.get("builders") or [])
        if isinstance(prepared_run.get("replacement"),dict):prepared_items.append(prepared_run["replacement"])
        item=next((x for x in prepared_items if x.get("builder_id")==builder_id),None)
        if public is None or item is None:
            raise SelfBuildLaunchError("WORKER_NOT_IN_RUN","worker not found in prepared/launch run")
        evidence=self.supervisor.stop(builder_id,int(public["generation"]),timeout=10.0)
        if evidence.state!="STOPPED" or not evidence.containment_empty:
            raise SelfBuildLaunchError("WORKER_STOP_UNPROVEN","ProcessSupervisor could not prove worker containment empty")
        response=self.client.revoke_self_build_worker(
            run_id=prepared_run["run_id"],task_id=item["task_id"],
            worker_run_id=item["authority"]["run_id"],owner_epoch=item["owner_epoch"],
            reason=reason,
        )
        return {"stopped":True,"builder_id":builder_id,"process_evidence":evidence.as_dict(),"authority_receipt":response}
