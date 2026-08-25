from __future__ import annotations
import argparse,hashlib,json,os,socketserver,subprocess,sys,tempfile,threading,time,uuid
from pathlib import Path
from .store import ControlStore,BudgetReservationError
from .protocol import parse_frame,response,ProtocolError,PROTOCOL_MIN,PROTOCOL_MAX
from .envelope import secret_file,sign_envelope,verify_envelope,canonical
from .projects import list_profiles,load_profile
from .auth import verify_connect_proof
from .known_good import runtime_identity_from_env
from .activation import ActivationError,ActivationManager,process_identity,process_is_same_and_alive,submit_candidate_probe
from .client import Client
from forgeboss.security.executor_guard import validate_packet,assert_paths_contained,assert_no_link_escape,SecurityError

ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"forgebossd";DB=STATE/"forgeboss.db";HOST="127.0.0.1";PORT=18765
WORKTREE_ROOT=Path(os.environ.get("FORGEBOSS_WORKTREE_ROOT") or (STATE/"worktrees")).resolve()
SAFE_TOOL_IDS={"git","node","npm","python","pytest","docker"};MUTATING_METHODS={"task.create","workspace.claim","workspace.heartbeat","workspace.release"}
_PROBE_SUBMIT_LOCK=threading.Lock();_PROBE_SUBMITTED=False

def _activation_dir():
    raw=os.environ.get("FORGEBOSS_ACTIVATION_STATE")
    if not raw:return STATE/"known-good"
    try:return Path(raw).resolve(strict=True).parent
    except Exception as ex:raise SystemExit("invalid ForgeBoss activation state: "+str(ex))

def _start_activation_fence():
    nonce=os.environ.get("FORGEBOSS_ACTIVATION_NONCE");state_raw=os.environ.get("FORGEBOSS_ACTIVATION_STATE");parent_raw=os.environ.get("FORGEBOSS_ACTIVATION_PARENT_IDENTITY")
    if not any((nonce,state_raw,parent_raw)):return
    if not all((nonce,state_raw,parent_raw)):raise SystemExit("incomplete ForgeBoss activation fence")
    try:state_path=Path(state_raw).resolve(strict=True);parent=json.loads(parent_raw)
    except Exception as ex:raise SystemExit("invalid ForgeBoss activation fence: "+str(ex))
    if not isinstance(parent,dict) or not parent.get("pid") or not parent.get("startToken") or not parent.get("exe"):raise SystemExit("invalid activation parent process identity")
    def watch():
        while True:
            try:s=json.loads(state_path.read_text(encoding="utf-8"))
            except Exception:os._exit(75)
            if s.get("activationNonce")!=nonce:os._exit(75)
            phase=s.get("phase")
            if phase=="PROMOTED":return
            if phase in {"ROLLBACK_PENDING","ROLLED_BACK","FAILED","QUARANTINED"}:os._exit(75)
            if not process_is_same_and_alive(parent):os._exit(75)
            time.sleep(.5)
    threading.Thread(target=watch,name="forgeboss-activation-fence",daemon=True).start()

def _activation_probe_enabled():return bool(os.environ.get("FORGEBOSS_PROBE_ENDPOINT") or os.environ.get("FORGEBOSS_PROBE_CHALLENGE") or os.environ.get("FORGEBOSS_ACTIVATION_NONCE"))

def _run_candidate_selftests():
    env=os.environ.copy()
    for key in tuple(env):
        if key.startswith("FORGEBOSS_PROBE_") or key.startswith("FORGEBOSS_ACTIVATION_") or key in {"FORGEBOSS_SELF_BUILD_MODE","FORGEBOSS_BUILD_MANIFEST","FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA","FORGEBOSS_EXPECTED_MANIFEST_SHA256"}:env.pop(key,None)
    try:cp=subprocess.run([sys.executable,"-m","unittest","forgeboss.control.test_known_good","forgeboss.control.test_activation"],cwd=str(ROOT),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90,check=False)
    except Exception:return False
    return cp.returncode==0

def _probe_multiagent_store():
    STATE.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="activation-multiagent-",dir=str(STATE)) as td:
        base=Path(td);workroot=base/"worktrees";workroot.mkdir();store=ControlStore(base/"probe.db")
        suffix=uuid.uuid4().hex;base_sha="a"*40
        def task(tid,path):return {"taskId":tid,"repository":"1stchoicefnq-afk/ForgeBoss","purpose":"activation-probe","baseSha":base_sha,"branch":"probe/"+tid,"allowedPaths":[path],"requiredTests":[],"budgetUsd":1}
        t1="probe-a-"+suffix;t2="probe-b-"+suffix;r1="run-a-"+suffix;r2="run-b-"+suffix
        store.create_task(task(t1,"forgeboss/control/a.py"));store.create_task(task(t2,"forgeboss/control/b.py"))
        l1=store.claim_workspace(t1,r1,str(workroot/t1),"probe/a",base_sha,120,"runtime-a",workroot,budget_reserved=.1)
        l2=store.claim_workspace(t2,r2,str(workroot/t2),"probe/b",base_sha,120,"runtime-b",workroot,budget_reserved=.1)
        if int(l1["owner_epoch"])<=0 or int(l2["owner_epoch"])<=0 or l1["owner_run_id"]==l2["owner_run_id"]:return False
        store.assert_writer(t1,r1,l1["owner_epoch"],base_sha);store.assert_writer(t2,r2,l2["owner_epoch"],base_sha)
        stale=False;collision=False
        try:store.assert_writer(t1,"stale-owner",l1["owner_epoch"],base_sha)
        except PermissionError:stale=True
        try:store.claim_workspace(t1,"collision-"+suffix,str(workroot/(t1+"-collision")),"probe/c",base_sha,120,"runtime-c",workroot,budget_reserved=.1)
        except RuntimeError:collision=True
        if not stale or not collision:return False
        store.heartbeat(t1,r1,l1["owner_epoch"],120,base_sha);store.heartbeat(t2,r2,l2["owner_epoch"],120,base_sha)
        store.release(t1,r1,l1["owner_epoch"],base_sha,"probe-ok");store.release(t2,r2,l2["owner_epoch"],base_sha,"probe-ok")
        snap=store.snapshot();return isinstance(snap,dict) and not snap.get("leases")

def _candidate_protocol_checks(host,port):
    c=None
    try:
        c=Client(host,port,timeout=5)
        health=c.call("health",mutation=False)
        control=health.get("status")=="HEALTHY" and isinstance(health.get("state"),dict) and health.get("controllerProcessIdentity",{}).get("pid")==os.getpid()
        multi=c.call("probe.multiagent",mutation=False)
        return bool(control),bool(multi.get("multiAgent") is True)
    except Exception:return False,False
    finally:
        if c:
            try:c.close()
            except Exception:pass

def _submit_candidate_activation_probe(daemon,host,port):
    global _PROBE_SUBMITTED
    if not _activation_probe_enabled():return False
    endpoint=os.environ.get("FORGEBOSS_PROBE_ENDPOINT");challenge=os.environ.get("FORGEBOSS_PROBE_CHALLENGE");nonce=os.environ.get("FORGEBOSS_ACTIVATION_NONCE")
    if not endpoint or not challenge or not nonce:raise SystemExit("incomplete candidate probe environment")
    with _PROBE_SUBMIT_LOCK:
        if _PROBE_SUBMITTED:raise SystemExit("candidate probe already submitted")
        try:fresh_proc=process_identity(os.getpid());state=daemon.activation.status()
        except Exception as ex:raise SystemExit("candidate probe preflight failed: "+str(ex))
        startup=bool(daemon.identity.get("verified")) and bool(fresh_proc) and fresh_proc==daemon.processIdentity
        health=bool(state.get("activationNonce")==nonce and state.get("phase") in {"STARTING","PROBING"} and process_is_same_and_alive(daemon.processIdentity))
        control,multiagent=_candidate_protocol_checks(host,port);selftests=_run_candidate_selftests()
        result={"startup":startup,"health":health,"control":control,"selftests":selftests,"multiAgent":multiagent,"identity":{"revision":daemon.identity.get("revision"),"manifestSha256":daemon.identity.get("manifestSha256"),"identitySha256":daemon.identity.get("identitySha256")}}
        if not all(result[k] is True for k in ("startup","health","control","selftests","multiAgent")):raise SystemExit("candidate activation probe checks failed")
        try:submit_candidate_probe(result)
        except Exception as ex:raise SystemExit("candidate activation probe submission failed: "+str(ex))
        _PROBE_SUBMITTED=True;return True

class ForgeBossDaemon:
    def __init__(self):
        WORKTREE_ROOT.mkdir(parents=True,exist_ok=True);self.identity=runtime_identity_from_env(ROOT)
        try:self.processIdentity=process_identity(os.getpid())
        except Exception as ex:raise SystemExit("unable to establish controller process identity: "+str(ex))
        if not self.processIdentity:raise SystemExit("unable to establish controller process identity")
        self.activation=ActivationManager(_activation_dir(),self.identity,self.processIdentity)
        if self.identity.get("verified") and not os.environ.get("FORGEBOSS_ACTIVATION_NONCE"):self.activation.recover()
        self.store=ControlStore(DB);self.secret_path,self.secret=secret_file(ROOT);self.connect_nonces={};self.started=time.time();self.idempotency={};self.lock=threading.RLock()
    def _assert_mutation_authority(self):
        try:self.activation.assert_mutation_authority(self.identity,self.processIdentity)
        except ActivationError as ex:raise ProtocolError("MUTATION_AUTHORITY_DENIED",str(ex)) from ex
    def _state_snapshot(self):
        out=self.store.snapshot();out["controllerIdentity"]=dict(self.identity);out["controllerProcessIdentity"]=dict(self.processIdentity);out["activation"]=self.activation.status();return out
    def _idem(self,req,fn):
        key=req.get("idempotencyKey")
        if not key:return fn()
        digest=hashlib.sha256(canonical({"method":req["method"],"params":req.get("params",{})})).hexdigest()
        with self.lock:
            old=self.idempotency.get(key)
            if old:
                if old["digest"]!=digest:raise ProtocolError("IDEMPOTENCY_CONFLICT","key reused with different request")
                return old["result"]
            result=fn();self.idempotency[key]={"digest":digest,"result":result,"at":time.time()};return result
    def dispatch(self,req,connected):
        m=req["method"];p=req.get("params",{})
        if not connected and m!="connect":raise ProtocolError("CONNECT_REQUIRED","connect must be the first request")
        if m in MUTATING_METHODS:self._assert_mutation_authority()
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
            return {"connected":True,"protocolVersion":1,"server":"forgebossd","schemaVersion":3,"capabilities":["tasks","workspace-leases","owner-epochs","signed-envelopes","events","idempotency","project-profiles","smart-parallel","validated-learning","authenticated-connect","guarded-workspaces","windows-acl","known-good-identity","mutation-authority"],"controllerIdentity":dict(self.identity),"controllerProcessIdentity":dict(self.processIdentity),"state":self._state_snapshot()}
        if m=="health":return {"status":"HEALTHY","uptimeSeconds":round(time.time()-self.started,1),"db":str(DB),"controllerIdentity":dict(self.identity),"controllerProcessIdentity":dict(self.processIdentity),"activation":self.activation.status(),"state":self._state_snapshot()}
        if m=="probe.multiagent":
            if not _activation_probe_enabled():raise ProtocolError("PROBE_ONLY","multi-agent probe is activation-only")
            return {"multiAgent":bool(_probe_multiagent_store())}
        if m=="task.create":
            def create():
                try:validate_packet({"allowed_files":p.get("allowedPaths",[]),"context_files":[]})
                except SecurityError as ex:raise ProtocolError("SCOPE_DENIED",str(ex))
                return self.store.create_task(p)
            return self._idem(req,create)
        if m=="task.get":
            t=self.store.get_task(p["taskId"])
            if not t:raise ProtocolError("TASK_NOT_FOUND","task not found")
            return t
        if m=="workspace.claim":
            def do():
                task=self.store.get_task(p["taskId"])
                if not task:raise ProtocolError("TASK_NOT_FOUND","task not found")
                if str(p.get("repository") or "")!=str(task["repository"]) or str(p.get("baseSha") or "")!=str(task["base_sha"]):raise ProtocolError("TASK_BINDING_MISMATCH","task binding differs")
                try:allowed,_=validate_packet({"allowed_files":p.get("allowedPaths",[]),"context_files":[]})
                except SecurityError as ex:raise ProtocolError("SCOPE_DENIED",str(ex))
                task_keys={str(x).replace("\\","/").casefold() for x in json.loads(task.get("allowed_paths_json") or "[]")}
                if any(a.casefold() not in task_keys for a in allowed):raise ProtocolError("SCOPE_ESCALATION","workspace claim exceeds task allowedPaths")
                tools=p.get("allowedTools",[])
                if not isinstance(tools,list) or any(str(x) not in SAFE_TOOL_IDS for x in tools):raise ProtocolError("TOOL_DENIED","unapproved tool id")
                try:
                    candidate=Path(p["worktreePath"]).resolve(strict=False)
                    if os.path.commonpath([str(WORKTREE_ROOT),str(candidate)])!=str(WORKTREE_ROOT):raise SecurityError("worktreePath escapes ForgeBoss worktree root")
                    if candidate.exists():assert_no_link_escape(candidate);assert_paths_contained(candidate,allowed)
                except (SecurityError,ValueError) as ex:raise ProtocolError("SCOPE_DENIED",str(ex))
                try:lease=self.store.claim_workspace(p["taskId"],p["runId"],p["worktreePath"],p.get("branch"),p["currentHead"],int(p.get("ttlSeconds",1200)),p.get("runtimeId"),WORKTREE_ROOT,budget_reserved=p.get("budgetUsd",0))
                except BudgetReservationError as ex:raise ProtocolError(ex.code,str(ex)) from ex
                env={"envelopeVersion":1,"protocolVersion":1,"taskId":p["taskId"],"repository":p["repository"],"baseSha":p["baseSha"],"branch":p.get("branch"),"worktreePath":lease["worktree_path"],"runId":p["runId"],"attempt":int(p.get("attempt",1)),"ownerEpoch":int(lease["owner_epoch"]),"runtime":{"adapter":p.get("runtimeId") or "unknown","provider":p.get("provider"),"model":p.get("model")},"allowedPaths":allowed,"deniedPaths":p.get("deniedPaths",[]),"allowedTools":tools,"contextBundleHash":p.get("contextBundleHash"),"transcript":p.get("transcript",{}),"events":p.get("events",{}),"budgetUsd":float(lease["budget_reserved"]),"expiresAt":float(lease["expires_at"])}
                return {"lease":lease,"launchEnvelope":sign_envelope(env,self.secret)}
            return self._idem(req,do)
        if m=="worker.admit":
            env=verify_envelope(p["envelope"],self.secret);lease=self.store.assert_writer(env["taskId"],env["runId"],env["ownerEpoch"],p.get("expectedHead"));return {"admitted":True,"taskId":env["taskId"],"runId":env["runId"],"ownerEpoch":env["ownerEpoch"]}
        if m=="workspace.heartbeat":return self._idem(req,lambda:self.store.heartbeat(p["taskId"],p["runId"],int(p["ownerEpoch"]),int(p.get("ttlSeconds",1200)),p.get("currentHead")))
        if m=="workspace.assert":return self.store.assert_writer(p["taskId"],p["runId"],int(p["ownerEpoch"]),p.get("expectedHead"))
        if m=="workspace.release":return self._idem(req,lambda:(self.store.release(p["taskId"],p["runId"],int(p["ownerEpoch"]),p.get("resultHead"),p.get("outcome","released")) or {"released":True}))
        if m=="state.snapshot":out=self._state_snapshot();out["projects"]=list_profiles();return out
        if m=="project.list":return {"projects":list_profiles()}
        if m=="project.get":return load_profile(p["projectId"])
        raise ProtocolError("METHOD_NOT_FOUND",m)

DAEMON=ForgeBossDaemon()
class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        connected=False
        while True:
            line=self.rfile.readline(256*1024+1)
            if not line:return
            req_id=None
            try:req=parse_frame(line);req_id=req["id"];payload=DAEMON.dispatch(req,connected);connected=connected or req["method"]=="connect";out=response(req_id,True,payload)
            except ProtocolError as e:out=response(req_id or "unknown",False,error={"code":e.code,"message":str(e)})
            except Exception as e:out=response(req_id or "unknown",False,error={"code":type(e).__name__.upper(),"message":str(e)})
            self.wfile.write((json.dumps(out,separators=(",",":"))+"\n").encode());self.wfile.flush()
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--host",default=HOST);ap.add_argument("--port",type=int,default=PORT);ns=ap.parse_args()
    if ns.host not in ("127.0.0.1","localhost","::1"):raise SystemExit("forgebossd refuses non-loopback bind")
    _start_activation_fence();STATE.mkdir(parents=True,exist_ok=True)
    with Server((ns.host,ns.port),Handler) as srv:
        host,port=srv.server_address[:2];thread=threading.Thread(target=srv.serve_forever,name="forgeboss-probe-server",daemon=True);thread.start()
        try:
            if _activation_probe_enabled():_submit_candidate_activation_probe(DAEMON,host,port)
            print(json.dumps({"forgebossd":"ready","host":host,"port":port,"db":str(DB),"controllerIdentity":DAEMON.identity,"controllerProcessIdentity":DAEMON.processIdentity}),flush=True)
            thread.join()
        finally:srv.shutdown();thread.join(timeout=5)
if __name__=="__main__":main()
