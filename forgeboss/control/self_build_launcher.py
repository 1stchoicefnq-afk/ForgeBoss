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
                try:
                    self.supervisor.stop(public["builder_id"],public["generation"],timeout=5.0)
                    self.container_cleanup_fn(run_id=prepared_run["run_id"],builder_id=public["builder_id"])
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

    @staticmethod
    def _prepared_item(prepared_run:dict,builder_id:str):
        containers=[]
        if isinstance(prepared_run,dict):
            containers.append(prepared_run)
            nested=prepared_run.get("prepared")
            if isinstance(nested,dict):containers.append(nested)
        for container in containers:
            for item in list(container.get("builders") or []):
                if item.get("builder_id")==builder_id:return item
            replacement=container.get("replacement")
            if isinstance(replacement,dict) and replacement.get("builder_id")==builder_id:return replacement
        return None

    def _load_candidate_evidence(self,path:Path,*,item:dict)->dict|None:
        if not path.is_file():return None
        try:value=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildLaunchError("CANDIDATE_EVIDENCE_INVALID","candidate evidence unreadable") from ex
        if not isinstance(value,dict) or value.get("schema")!=1:
            raise SelfBuildLaunchError("CANDIDATE_EVIDENCE_INVALID","candidate evidence schema invalid")
        digest=value.get("evidence_digest")
        unsigned={k:v for k,v in value.items() if k!="evidence_digest"}
        expected=hashlib.sha256(json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")).hexdigest()
        if digest!=expected:
            raise SelfBuildLaunchError("CANDIDATE_EVIDENCE_INVALID","candidate evidence digest mismatch")
        if value.get("task_id")!=item.get("task_id") or value.get("builder_id")!=item.get("builder_id"):
            raise SelfBuildLaunchError("CANDIDATE_EVIDENCE_INVALID","candidate evidence identity mismatch")
        return value

    def complete_worker(self,*,prepared_run:dict,launched_run:dict,builder_id:str)->dict:
        public=next((x for x in launched_run.get("workers") or [] if x.get("builder_id")==builder_id),None)
        item=self._prepared_item(prepared_run,builder_id)
        if public is None or item is None:
            raise SelfBuildLaunchError("WORKER_NOT_IN_RUN","worker not found in prepared/launch run")
        paths=self._paths(str(launched_run.get("run_id") or prepared_run.get("run_id") or ""),builder_id)
        if paths["handoff"].is_file():
            try:return json.loads(paths["handoff"].read_text(encoding="utf-8"))
            except Exception as ex:raise SelfBuildLaunchError("HANDOFF_EVIDENCE_INVALID","handoff evidence unreadable") from ex

        try:
            process=self.supervisor.complete(builder_id,int(public["generation"]),timeout=10.0)
        except SupervisorError as ex:
            raise SelfBuildLaunchError(ex.code,str(ex)) from ex
        process_evidence=process.as_dict()
        docker_evidence=self.container_cleanup_fn(
            run_id=str(launched_run.get("run_id") or prepared_run.get("run_id") or ""),
            builder_id=builder_id,
        )
        process_evidence["dockerContainmentEmpty"]=docker_evidence.get("container_empty") is True
        candidate=self._load_candidate_evidence(paths["candidate"],item=item)
        if candidate is None:
            try:
                result=load_result_file(public["result_file"],state_root=self.state_root)
                candidate=self.freeze_fn(
                    item=item,public=public,result=result,process_evidence=process_evidence,
                    python_executable=self.python,
                )
            except SelfBuildFreezeError as ex:
                raise SelfBuildLaunchError(ex.code,str(ex)) from ex
            _atomic_json(paths["candidate"],candidate)

        response=self.client.record_self_build_handoff(
            run_id=str(launched_run.get("run_id") or prepared_run.get("run_id") or ""),
            task_id=item["task_id"],
            worker_run_id=item["authority"]["run_id"],
            owner_epoch=item["owner_epoch"],
            evidence=candidate,
        )
        handoff={
            "schema":1,
            "run_id":str(launched_run.get("run_id") or prepared_run.get("run_id") or ""),
            "builder_id":builder_id,
            "task_id":item["task_id"],
            "base_sha":candidate["base_sha"],
            "candidate_sha":candidate["candidate_sha"],
            "candidate_evidence":candidate,
            "process_evidence":process_evidence,
            "protected_handoff_receipt":response,
            "review_status":"FROZEN_AWAITING_INDEPENDENT_REVIEW",
        }
        _atomic_json(paths["handoff"],handoff)
        return handoff

    def review_candidate(self,*,prepared_run:dict,launched_run:dict,builder_id:str)->dict:
        item=self._prepared_item(prepared_run,builder_id)
        if item is None:raise SelfBuildLaunchError("WORKER_NOT_IN_RUN","worker not found in prepared run")
        run_id=str(launched_run.get("run_id") or prepared_run.get("run_id") or "")
        response=self.client.review_self_build_candidate(
            run_id=run_id,task_id=item["task_id"],worker_run_id=item["authority"]["run_id"],
            owner_epoch=item["owner_epoch"],
        )
        _atomic_json(self._paths(run_id,builder_id)["review"],response)
        return response

    def accept_reviewed_candidate(self,*,prepared_run:dict,launched_run:dict,builder_id:str)->dict:
        item=self._prepared_item(prepared_run,builder_id)
        if item is None:raise SelfBuildLaunchError("WORKER_NOT_IN_RUN","worker not found in prepared run")
        run_id=str(launched_run.get("run_id") or prepared_run.get("run_id") or "")
        response=self.client.accept_self_build_candidate(
            run_id=run_id,task_id=item["task_id"],worker_run_id=item["authority"]["run_id"],
            owner_epoch=item["owner_epoch"],
        )
        _atomic_json(self._paths(run_id,builder_id)["acceptance"],response)
        return response

    def finish_review_accept_compose(self,*,prepared_run:dict,launched_run:dict,
                                     builder_ids=("builder-a","builder-b2"),stop_requested=None,
                                     timeout:float=1200.0,poll_seconds:float=0.5)->dict:
        ids=tuple(builder_ids)
        if ids!=("builder-a","builder-b2"):
            raise SelfBuildLaunchError("FINISH_BUILDER_SET_INVALID","Finish Line 1 must finish exactly A + B2")
        if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or timeout<=0 or timeout>3600:
            raise SelfBuildLaunchError("FINISH_TIMEOUT_INVALID","finish timeout invalid")
        if isinstance(poll_seconds,bool) or not isinstance(poll_seconds,(int,float)) or poll_seconds<=0 or poll_seconds>10:
            raise SelfBuildLaunchError("FINISH_POLL_INVALID","finish poll interval invalid")
        checker=stop_requested if callable(stop_requested) else (lambda:False)
        run_id=str(launched_run.get("run_id") or prepared_run.get("run_id") or "")
        if not run_id:
            raise SelfBuildLaunchError("PREPARED_RUN_INVALID","self-build run id missing")
        replacement=prepared_run.get("replacement")
        if not isinstance(replacement,dict) or replacement.get("builder_id")!="builder-b2":
            raise SelfBuildLaunchError("REPLACEMENT_REQUIRED","B2 replacement must exist before finish")
        launched_ids={str(x.get("builder_id") or "") for x in (launched_run.get("workers") or [])}
        if not set(ids).issubset(launched_ids):
            raise SelfBuildLaunchError("FINISH_WORKER_MISSING","A and B2 must both be launched before finish")

        pending=set(ids);handoffs={};reviews={};acceptances={};accepted=set()
        deadline=time.monotonic()+float(timeout)
        failure=None
        try:
            while pending:
                if checker():
                    raise SelfBuildLaunchError("OWNER_STOP_REQUESTED","owner stop requested during self-build finish")
                if time.monotonic()>=deadline:
                    raise SelfBuildLaunchError("FINISH_TIMEOUT","self-build workers did not finish within the bounded window")
                progressed=False
                for builder_id in ids:
                    if builder_id not in pending:continue
                    try:
                        handoffs[builder_id]=self.complete_worker(
                            prepared_run=prepared_run,launched_run=launched_run,builder_id=builder_id,
                        )
                    except SelfBuildLaunchError as ex:
                        if ex.code=="WORKER_STILL_RUNNING":continue
                        raise
                    pending.remove(builder_id);progressed=True
                if pending and not progressed:time.sleep(float(poll_seconds))

            for builder_id in ids:
                if checker():raise SelfBuildLaunchError("OWNER_STOP_REQUESTED","owner stop requested before independent review")
                response=self.review_candidate(prepared_run=prepared_run,launched_run=launched_run,builder_id=builder_id)
                reviews[builder_id]=response
                result=response.get("result") or {}
                if result.get("status")!="PASS":
                    raise SelfBuildLaunchError("INDEPENDENT_REVIEW_FAILED",f"{builder_id} independent review did not PASS")

            for builder_id in ids:
                if checker():raise SelfBuildLaunchError("OWNER_STOP_REQUESTED","owner stop requested before candidate acceptance")
                response=self.accept_reviewed_candidate(prepared_run=prepared_run,launched_run=launched_run,builder_id=builder_id)
                acceptances[builder_id]=response
                result=response.get("result") or {}
                if result.get("status")!="ACCEPTED":
                    raise SelfBuildLaunchError("CANDIDATE_ACCEPTANCE_FAILED",f"{builder_id} candidate was not accepted")
                accepted.add(builder_id)

            if checker():raise SelfBuildLaunchError("OWNER_STOP_REQUESTED","owner stop requested before successor composition")
            composition=self.client.compose_self_build_successor(run_id=run_id)
            successor=composition.get("result") or {}
            if successor.get("status")!="COMPOSED_AWAITING_ACTIVATION":
                raise SelfBuildLaunchError("SUCCESSOR_COMPOSITION_FAILED","protected successor composition did not complete")
            return {
                "schema":1,"run_id":run_id,"builders":list(ids),"handoffs":handoffs,
                "reviews":reviews,"acceptances":acceptances,"successor":successor,
                "protected_composition_receipt":composition,
            }
        except BaseException as ex:
            failure=ex
            for builder_id in ids:
                if builder_id in accepted:continue
                try:
                    self.stop_worker(
                        prepared_run=prepared_run,launched_run=launched_run,builder_id=builder_id,
                        reason="self-build finish aborted before protected acceptance",
                    )
                except Exception:
                    pass
            raise

    def activate_composed_successor(self,*,run_id:str)->dict:
        if not isinstance(run_id,str) or not run_id:
            raise SelfBuildLaunchError("RUN_ID_INVALID","self-build run id missing for activation")
        response=self.client.activate_self_build_successor(run_id=run_id)
        result=response.get("result") or {}
        if result.get("status")!="ACTIVATED_KNOWN_GOOD":
            raise SelfBuildLaunchError("SUCCESSOR_ACTIVATION_FAILED","protected successor activation did not complete")
        _atomic_json(self.run_root/run_id/"activation.json",response)
        return response

    def stop_worker(self,*,prepared_run:dict,launched_run:dict,builder_id:str,reason:str)->dict:
        public=next((x for x in launched_run.get("workers") or [] if x.get("builder_id")==builder_id),None)
        prepared_items=list(prepared_run.get("builders") or [])
        if isinstance(prepared_run.get("replacement"),dict):prepared_items.append(prepared_run["replacement"])
        item=next((x for x in prepared_items if x.get("builder_id")==builder_id),None)
        if public is None or item is None:
            raise SelfBuildLaunchError("WORKER_NOT_IN_RUN","worker not found in prepared/launch run")
        evidence=self.supervisor.stop(builder_id,int(public["generation"]),timeout=10.0)
        if evidence.state!="STOPPED" or not evidence.containment_empty:
            raise SelfBuildLaunchError("WORKER_STOP_UNPROVEN","ProcessSupervisor could not prove host-process containment empty")
        docker_evidence=self.container_cleanup_fn(
            run_id=str(prepared_run.get("run_id") or ""),
            builder_id=builder_id,
        )
        if docker_evidence.get("container_empty") is not True:
            raise SelfBuildLaunchError("WORKER_STOP_UNPROVEN","Docker worker containment is not empty")
        response=self.client.revoke_self_build_worker(
            run_id=prepared_run["run_id"],task_id=item["task_id"],
            worker_run_id=item["authority"]["run_id"],owner_epoch=item["owner_epoch"],
            reason=reason,
        )
        return {"stopped":True,"builder_id":builder_id,"process_evidence":evidence.as_dict(),"docker_evidence":docker_evidence,"authority_receipt":response}
