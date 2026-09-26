from __future__ import annotations
import argparse, hashlib, hmac, json, math, os, secrets, socketserver, threading, time, uuid
from pathlib import Path
from .store import ControlStore,BudgetReservationError,SCHEMA_VERSION
from .protocol import parse_frame,response,ProtocolError,PROTOCOL_MIN,PROTOCOL_MAX
from .envelope import secret_file,policy_secret_file,launch_secret_file,sign_envelope,verify_envelope,canonical
from .projects import list_profiles,load_profile
from .auth import verify_connect_proof
from forgeboss.security.executor_guard import validate_packet,assert_paths_contained,assert_no_link_escape,SecurityError
from forgeboss.policy.reuse_review_authority import ReuseReviewAuthorityError,evaluate_authorized_reuse_readiness
from .governed_launch import GovernedLaunchAttestationError,issue_governed_launch_attestation,runner_identity,verify_governed_launch_attestation
from .governed_host_launcher import GovernedHostLaunchError,assert_governed_workspace_ready,resolve_workspace_head,run_governed_worker

ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"forgebossd"
DB=STATE/"forgeboss.db"
HOST="127.0.0.1"
PORT=18765
WORKTREE_ROOT=Path(os.environ.get("FORGEBOSS_WORKTREE_ROOT") or (STATE/"worktrees")).resolve()
SAFE_TOOL_IDS={"git","node","npm","python","pytest","docker"}

class ForgeBossDaemon:
    def __init__(self):
        WORKTREE_ROOT.mkdir(parents=True,exist_ok=True)
        self.store=ControlStore(DB)
        self.secret_path,self.secret=secret_file(ROOT)
        self.policy_secret_path,self.policy_secret=policy_secret_file(ROOT)
        self.launch_secret_path,self.launch_secret=launch_secret_file(ROOT)
        key_paths={self.secret_path.resolve(),self.policy_secret_path.resolve(),self.launch_secret_path.resolve()}
        if len(key_paths)!=3:
            raise RuntimeError("daemon, policy approval and governed launch keys must use distinct files")
        if hmac.compare_digest(self.secret,self.policy_secret) or hmac.compare_digest(self.secret,self.launch_secret) or hmac.compare_digest(self.policy_secret,self.launch_secret):
            raise RuntimeError("daemon, policy approval and governed launch keys must be distinct")
        self.connect_nonces={}
        self.governed_launch_capability=secrets.token_urlsafe(32)
        self.started=time.time()
        self.idempotency={}
        self.active_governed_runs=set()
        self.lock=threading.RLock()

    def _idem(self,req,fn):
        key=req.get("idempotencyKey")
        if not key:return fn()
        digest=hashlib.sha256(canonical({"method":req["method"],"params":req.get("params",{})})).hexdigest()
        owner=False
        with self.lock:
            old=self.idempotency.get(key)
            if old:
                if old["digest"]!=digest:raise ProtocolError("IDEMPOTENCY_CONFLICT","key reused with different request")
                if old.get("done"):
                    if old.get("error") is not None:raise old["error"]
                    return old["result"]
                event=old["event"]
            else:
                event=threading.Event()
                self.idempotency[key]={"digest":digest,"event":event,"done":False,"at":time.time()}
                owner=True
        if not owner:
            event.wait()
            with self.lock:
                old=self.idempotency.get(key)
                if not old or old["digest"]!=digest:
                    raise ProtocolError("IDEMPOTENCY_STATE_INVALID","idempotency result disappeared")
                if old.get("error") is not None:raise old["error"]
                return old["result"]
        try:
            result=fn()
        except Exception as ex:
            with self.lock:
                entry=self.idempotency[key]
                entry["error"]=ex;entry["done"]=True;entry["at"]=time.time();event.set()
            raise
        with self.lock:
            entry=self.idempotency[key]
            entry["result"]=result;entry["done"]=True;entry["at"]=time.time();event.set()
            if len(self.idempotency)>2000:
                done=[k for k,v in self.idempotency.items() if v.get("done")]
                for old_key in sorted(done,key=lambda x:self.idempotency[x]["at"])[:500]:
                    self.idempotency.pop(old_key,None)
        return result

    def dispatch(self,req,connected):
        m=req["method"];p=req.get("params",{})
        if not connected and m!="connect":raise ProtocolError("CONNECT_REQUIRED","connect must be the first request")
        if m=="connect":
            v=int(p.get("protocolVersion",0))
            if v<PROTOCOL_MIN or v>PROTOCOL_MAX:raise ProtocolError("PROTOCOL_MISMATCH",f"supported {PROTOCOL_MIN}..{PROTOCOL_MAX}")
            caps=p.get("capabilities") or []
            if not isinstance(caps,list):raise ProtocolError("INVALID_PARAMS","capabilities must be array")
            try:verify_connect_proof(p,self.secret)
            except Exception as ex:raise ProtocolError("AUTH_FAILED",str(ex))
            nonce=str(p.get("nonce") or "");now=time.time()
            with self.lock:
                self.connect_nonces={k:v for k,v in self.connect_nonces.items() if now-v<60}
                if nonce in self.connect_nonces:raise ProtocolError("AUTH_REPLAY","connect nonce already used")
                self.connect_nonces[nonce]=now
            return {"connected":True,"protocolVersion":1,"server":"forgebossd","schemaVersion":SCHEMA_VERSION,
                    "capabilities":["tasks","governed-task-create","governed-launch-attestation","governed-host-launch","workspace-leases","owner-epochs","signed-envelopes","events","idempotency","project-profiles","smart-parallel","validated-learning","authenticated-connect","guarded-workspaces","windows-acl"],
                    "state":self.store.snapshot()}
        if m=="health":
            return {"status":"HEALTHY","uptimeSeconds":round(time.time()-self.started,1),"db":str(DB),"state":self.store.snapshot()}
        if m in ("task.create","task.create_governed"):
            def create():
                try:validate_packet({"allowed_files":p.get("allowedPaths",[]),"context_files":[]})
                except SecurityError as ex:raise ProtocolError("SCOPE_DENIED",str(ex))
                if m=="task.create":
                    return self.store.create_task(p)
                try:
                    readiness=evaluate_authorized_reuse_readiness(
                        task_id=p.get("taskId"),
                        repository=p.get("repository"),
                        base_sha=p.get("baseSha"),
                        objective=p.get("purpose"),
                        allowed_paths=p.get("allowedPaths",[]),
                        secret=self.policy_secret,
                        small_repair_exemption=p.get("smallRepairExemption"),
                        subsystem=p.get("subsystem"),
                        reuse_review=p.get("reuseReview"),
                        reuse_review_receipt=p.get("reuseReviewReceipt"),
                    )
                except ReuseReviewAuthorityError as ex:
                    raise ProtocolError("REUSE_AUTHORITY_INVALID",str(ex)) from ex
                if not readiness.ready:
                    raise ProtocolError("REUSE_GATE_BLOCKED",str(readiness.blocker))
                governed=dict(p)
                governed["governanceMode"]="reuse-v1"
                governed["workKind"]=readiness.work_kind
                def digest(value):
                    return hashlib.sha256(canonical(value)).hexdigest() if value is not None else None
                governed["reuseReviewSha256"]=digest(p.get("reuseReview"))
                governed["reuseReviewReceiptSha256"]=digest(p.get("reuseReviewReceipt"))
                governed["smallRepairExemptionSha256"]=digest(p.get("smallRepairExemption"))
                return self.store.create_task(governed)
            return self._idem(req,create)
        if m=="task.get":
            t=self.store.get_task(p["taskId"])
            if not t:raise ProtocolError("TASK_NOT_FOUND","task not found")
            return t
        if m=="run.launch_governed":
            def launch():
                task=self.store.get_task(p.get("taskId"))
                if not task:raise ProtocolError("TASK_NOT_FOUND","task not found")
                if task.get("governance_mode")!="reuse-v1":
                    raise ProtocolError("GOVERNED_TASK_REQUIRED","trusted governed launch requires a governed task")
                run_id=p.get("runId")
                if not isinstance(run_id,str) or not run_id.strip() or run_id!=run_id.strip() or len(run_id)>128 or any(ord(ch)<32 or ord(ch)==127 for ch in run_id):
                    raise ProtocolError("RUN_ID_REQUIRED","governed launch requires a stable safe runId")
                with self.lock:
                    existing_run=self.store.get_run(run_id)
                    if existing_run:
                        if str(existing_run.get("task_id"))!=str(task["task_id"]):
                            raise ProtocolError("RUN_ID_CONFLICT","runId already belongs to another task")
                        if str(existing_run.get("runtime_id") or "")!="mini-swe":
                            raise ProtocolError("RUN_ID_CONFLICT","runId already belongs to another runtime")
                        if str(existing_run.get("status") or "")=="running":
                            raise ProtocolError("RUN_ALREADY_ACTIVE","governed run is already active")
                        return {
                            "taskId":task["task_id"],"runId":run_id,"runtimeId":"mini-swe",
                            "outcome":str(existing_run.get("status") or "unknown"),
                            "replayed":True,
                        }
                    if run_id in self.active_governed_runs:
                        raise ProtocolError("RUN_ALREADY_ACTIVE","governed run is already launching")
                    self.active_governed_runs.add(run_id)
                try:
                    runtime_id=str(p.get("runtimeId") or "")
                    if runtime_id!="mini-swe":
                        raise ProtocolError("RUNTIME_NOT_APPROVED","governed host launch r0 permits mini-swe only")
                    try:
                        budget=float(p.get("budgetUsd"))
                    except Exception as ex:
                        raise ProtocolError("BUDGET_INVALID","governed launch budget must be numeric") from ex
                    if not math.isfinite(budget) or budget<=0:
                        raise ProtocolError("BUDGET_INVALID","governed launch budget must be finite and positive")
                    model=str(p.get("model") or "openai/gpt-5.6-luna")
                    provider=str(p.get("provider") or "openai")
                    if provider!="openai" or not model.startswith("openai/") or len(model)>200 or any(ord(ch)<32 or ord(ch)==127 for ch in model):
                        raise ProtocolError("MODEL_ID_INVALID","governed host launch r0 permits a safe OpenAI model identity only")
                    try:
                        allowed=json.loads(task.get("allowed_paths_json") or "[]")
                    except Exception as ex:
                        raise ProtocolError("TASK_STATE_INVALID","task writable scope is invalid") from ex
                    if not isinstance(allowed,list) or not allowed:
                        raise ProtocolError("TASK_STATE_INVALID","task writable scope is empty")
                    tools=["python","docker"]
                    worktree=str(p.get("worktreePath") or "")
                    current_head=str(p.get("currentHead") or "")
                    if not worktree or not current_head:
                        raise ProtocolError("INVALID_PARAMS","worktreePath and currentHead are required")
                    try:
                        candidate=Path(worktree).resolve(strict=True)
                        if os.path.commonpath([str(WORKTREE_ROOT),str(candidate)])!=str(WORKTREE_ROOT):
                            raise GovernedHostLaunchError("worktreePath escapes ForgeBoss worktree root")
                        assert_governed_workspace_ready(STATE/"launch-packets",candidate)
                    except (GovernedHostLaunchError,ValueError) as ex:
                        raise ProtocolError("GOVERNED_WORKSPACE_NOT_READY",str(ex)) from ex
                    try:
                        _,runner_sha=runner_identity(ROOT,runtime_id)
                        attestation=issue_governed_launch_attestation(
                            root=ROOT,
                            secret=self.launch_secret,
                            task_id=task["task_id"],
                            repository=task["repository"],
                            base_sha=task["base_sha"],
                            run_id=run_id,
                            worktree_path=worktree,
                            runtime_id=runtime_id,
                            allowed_paths=allowed,
                            allowed_tools=tools,
                            provider=provider,
                            model=model,
                            budget_usd=budget,
                            ttl_seconds=120,
                        )
                    except GovernedLaunchAttestationError as ex:
                        raise ProtocolError("GOVERNED_LAUNCH_ATTESTATION_INVALID",str(ex)) from ex
                    claim_params={
                        "taskId":task["task_id"],"repository":task["repository"],"baseSha":task["base_sha"],
                        "allowedPaths":allowed,"allowedTools":tools,"worktreePath":worktree,"runId":run_id,
                        "currentHead":current_head,"ttlSeconds":1800,"runtimeId":runtime_id,
                        "provider":provider,"model":model,"budgetUsd":budget,
                        "launchAttestation":attestation,
                        "_governedLaunchCapability":self.governed_launch_capability,
                    }
                    internal_key=hashlib.sha256((self.governed_launch_capability+":"+run_id).encode("utf-8")).hexdigest()
                    claim=self.dispatch(
                        {"method":"workspace.claim","idempotencyKey":"governed-claim:"+internal_key,"params":claim_params},
                        True,
                    )
                    env=claim["launchEnvelope"]
                    self.dispatch(
                        {"method":"worker.admit","idempotencyKey":"governed-admit:"+internal_key,
                         "params":{"envelope":env,"expectedHead":current_head}},
                        True,
                    )
                    worker=None
                    failure=None
                    release_safe=True
                    outcome="worker-failed"
                    result_head=current_head
                    try:
                        worker=run_governed_worker(
                            root=ROOT,
                            state_dir=STATE/"launch-packets",
                            task=task,
                            workspace=claim["lease"]["worktree_path"],
                            current_head=current_head,
                            runtime_id=runtime_id,
                            launch_envelope=env,
                            expected_runner_sha256=runner_sha,
                            budget_usd=budget,
                            model=model,
                            timeout_seconds=1200,
                        )
                        result_head=worker["result_head"]
                        outcome="worker-complete" if int(worker["returncode"])==0 else "worker-failed"
                    except GovernedHostLaunchError as ex:
                        failure=str(ex)
                        release_safe=bool(getattr(ex,"release_safe",False))
                        try:result_head=resolve_workspace_head(Path(claim["lease"]["worktree_path"]))
                        except Exception:result_head=current_head
                    finally:
                        if release_safe:
                            self.store.release(
                                task["task_id"],run_id,int(claim["lease"]["owner_epoch"]),
                                result_head,outcome,
                            )
                    if failure is not None:
                        raise ProtocolError("GOVERNED_HOST_LAUNCH_FAILED",failure)
                    return {
                        "taskId":task["task_id"],"runId":run_id,"runtimeId":runtime_id,
                        "outcome":outcome,"resultHead":result_head,
                        "runnerSha256":worker["runner_sha256"],
                        "workerReturnCode":int(worker["returncode"]),
                    }
                finally:
                    with self.lock:
                        self.active_governed_runs.discard(run_id)
            return self._idem(req,launch)
        if m=="workspace.claim":
            def do():
                task=self.store.get_task(p["taskId"])
                if not task:raise ProtocolError("TASK_NOT_FOUND","task not found")
                if task.get("governance_mode")=="reuse-v1":
                    supplied=str(p.get("_governedLaunchCapability") or "")
                    if not supplied or not hmac.compare_digest(supplied,self.governed_launch_capability):
                        raise ProtocolError(
                            "GOVERNED_DIRECT_CLAIM_DENIED",
                            "governed workspace claims are daemon-internal; use run.launch_governed",
                        )
                    attestation=p.get("launchAttestation")
                    if not attestation:
                        raise ProtocolError(
                            "GOVERNED_LAUNCH_ATTESTATION_REQUIRED",
                            "internal governed launch attestation missing",
                        )
                    try:
                        verify_governed_launch_attestation(
                            attestation,
                            root=ROOT,
                            secret=self.launch_secret,
                            task_id=p.get("taskId"),
                            repository=p.get("repository"),
                            base_sha=p.get("baseSha"),
                            run_id=p.get("runId"),
                            worktree_path=p.get("worktreePath"),
                            runtime_id=p.get("runtimeId"),
                            allowed_paths=p.get("allowedPaths",[]),
                            allowed_tools=p.get("allowedTools",[]),
                            provider=p.get("provider"),
                            model=p.get("model"),
                            budget_usd=p.get("budgetUsd",0),
                        )
                    except GovernedLaunchAttestationError as ex:
                        raise ProtocolError("GOVERNED_LAUNCH_ATTESTATION_INVALID",str(ex)) from ex
                if str(p.get("repository") or "")!=str(task["repository"]):raise ProtocolError("TASK_BINDING_MISMATCH","repository differs from task")
                if str(p.get("baseSha") or "")!=str(task["base_sha"]):raise ProtocolError("TASK_BINDING_MISMATCH","baseSha differs from task")
                try:allowed,_=validate_packet({"allowed_files":p.get("allowedPaths",[]),"context_files":[]})
                except SecurityError as ex:raise ProtocolError("SCOPE_DENIED",str(ex))
                task_keys={str(x).replace("\\","/").casefold() for x in json.loads(task.get("allowed_paths_json") or "[]")}
                if any(a.casefold() not in task_keys for a in allowed):raise ProtocolError("SCOPE_ESCALATION","workspace claim exceeds task allowedPaths")
                tools=p.get("allowedTools",[])
                if not isinstance(tools,list) or any(str(x) not in SAFE_TOOL_IDS for x in tools):raise ProtocolError("TOOL_DENIED","unapproved tool id")
                try:
                    candidate=Path(p["worktreePath"]).resolve(strict=False)
                    if os.path.commonpath([str(WORKTREE_ROOT),str(candidate)])!=str(WORKTREE_ROOT):raise SecurityError("worktreePath escapes ForgeBoss worktree root")
                    if candidate.exists():
                        assert_no_link_escape(candidate);assert_paths_contained(candidate,allowed)
                except (SecurityError,ValueError) as ex:raise ProtocolError("SCOPE_DENIED",str(ex))
                try:
                    lease=self.store.claim_workspace(p["taskId"],p["runId"],p["worktreePath"],p.get("branch"),p["currentHead"],
                                                     int(p.get("ttlSeconds",1200)),p.get("runtimeId"),WORKTREE_ROOT,
                                                     budget_reserved=p.get("budgetUsd",0))
                except BudgetReservationError as ex:
                    raise ProtocolError(ex.code,str(ex)) from ex
                env={
                  "envelopeVersion":1,"protocolVersion":1,"taskId":p["taskId"],"repository":p["repository"],
                  "baseSha":p["baseSha"],"branch":p.get("branch"),"worktreePath":lease["worktree_path"],"runId":p["runId"],
                  "attempt":int(p.get("attempt",1)),"ownerEpoch":int(lease["owner_epoch"]),
                  "runtime":{"adapter":p.get("runtimeId") or "unknown","provider":p.get("provider"),"model":p.get("model")},
                  "allowedPaths":allowed,"deniedPaths":p.get("deniedPaths",[]),"allowedTools":tools,
                  "contextBundleHash":p.get("contextBundleHash"),"transcript":p.get("transcript",{}),"events":p.get("events",{}),
                  "budgetUsd":float(lease["budget_reserved"]),"expiresAt":float(lease["expires_at"])
                }
                return {"lease":lease,"launchEnvelope":sign_envelope(env,self.secret)}
            return self._idem(req,do)
        if m=="worker.admit":
            def do():
                env=verify_envelope(p["envelope"],self.secret)
                lease=self.store.assert_writer(env["taskId"],env["runId"],env["ownerEpoch"],p.get("expectedHead"))
                if Path(env["worktreePath"]).resolve()!=Path(lease["worktree_path"]).resolve():
                    raise ProtocolError("WORKSPACE_MISMATCH","envelope workspace does not match lease")
                return {"admitted":True,"taskId":env["taskId"],"runId":env["runId"],"ownerEpoch":env["ownerEpoch"]}
            return self._idem(req,do)
        if m=="workspace.heartbeat":
            return self._idem(req,lambda:self.store.heartbeat(p["taskId"],p["runId"],int(p["ownerEpoch"]),int(p.get("ttlSeconds",1200)),p.get("currentHead")))
        if m=="workspace.assert":
            return self.store.assert_writer(p["taskId"],p["runId"],int(p["ownerEpoch"]),p.get("expectedHead"))
        if m=="workspace.release":
            return self._idem(req,lambda:(self.store.release(p["taskId"],p["runId"],int(p["ownerEpoch"]),p.get("resultHead"),p.get("outcome","released")) or {"released":True}))
        if m=="state.snapshot":
            out=self.store.snapshot(); out["projects"]=list_profiles(); return out
        if m=="project.list": return {"projects":list_profiles()}
        if m=="project.get": return load_profile(p["projectId"])
        raise ProtocolError("METHOD_NOT_FOUND",m)

DAEMON=ForgeBossDaemon()

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        connected=False
        while True:
            line=self.rfile.readline(256*1024+1)
            if not line:return
            req_id=None
            try:
                req=parse_frame(line)
                req_id=req["id"]
                payload=DAEMON.dispatch(req,connected)
                if req["method"]=="connect":connected=True
                out=response(req_id,True,payload)
            except ProtocolError as e:
                out=response(req_id or "unknown",False,error={"code":e.code,"message":str(e)})
            except Exception as e:
                out=response(req_id or "unknown",False,error={"code":type(e).__name__.upper(),"message":str(e)})
            self.wfile.write((json.dumps(out,separators=(",",":"))+"\n").encode("utf-8"))
            self.wfile.flush()

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--host",default=HOST)
    ap.add_argument("--port",type=int,default=PORT)
    ns=ap.parse_args()
    if ns.host not in ("127.0.0.1","localhost","::1"):
        raise SystemExit("forgebossd refuses non-loopback bind")
    STATE.mkdir(parents=True,exist_ok=True)
    with Server((ns.host,ns.port),Handler) as srv:
        print(json.dumps({"forgebossd":"ready","host":ns.host,"port":ns.port,"db":str(DB)}),flush=True)
        srv.serve_forever()

if __name__=="__main__":main()