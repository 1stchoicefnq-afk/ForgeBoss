    if len({x.casefold() for x in allowed})!=len(allowed):raise SecurityError("duplicate allowed_files after Windows casefold")
    for p in allowed:
        if sensitive(p):raise SecurityError("sensitive/high-impact write path denied: "+p)
    for p in context:
        k=p.casefold()
        if k==".git" or k.startswith(".git/"):raise SecurityError("Git metadata read denied")
    return allowed,context
def exact_head(work,packet):
    exp=packet.get("expected_head_revision") or packet.get("exact_head")
    if exp and (Path(work)/".git").exists():
        got=git(work,"rev-parse","HEAD")
        if got!=exp:raise SecurityError(f"exact HEAD mismatch {got} != {exp}")
def no_remotes(work):
    if (Path(work)/".git").exists() and git(work,"remote").strip():raise SecurityError("Git remotes present in executor workspace")
def isolation_ok(executor):
    if executor=="mini-swe":return True
    return os.environ.get("FORGEBOSS_OS_ISOLATION_VERIFIED")=="YES"
def _positive_budget(raw):
    if isinstance(raw,bool):raise SecurityError("paid budget must be a finite positive number")
    try:v=float(raw)
    except (TypeError,ValueError,OverflowError) as e:raise SecurityError("paid budget must be a finite positive number") from e
    if not math.isfinite(v) or v<=0:raise SecurityError("paid budget must be a finite positive number")
    return v
def _atomic_write_json(path,obj):
    path=Path(path);tmp=path.with_name(path.name+f".tmp-{os.getpid()}-{secrets.token_hex(4)}")
    data=json.dumps(obj,sort_keys=True,indent=2).encode("utf-8");fd=os.open(str(tmp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as f:f.write(data);f.flush();os.fsync(f.fileno())
    finally:
        try:os.close(fd)
        except OSError:pass
    os.replace(tmp,path)
class _WorkspaceFence:
    def __init__(self,workspace):self.path=STATE/("paid-start-"+hashlib.sha256(str(Path(workspace).resolve()).encode()).hexdigest()+".lock");self.f=None
    def __enter__(self):
        self.f=self.path.open("a+b");self.f.seek(0,2)
        if self.f.tell()==0:self.f.write(b"\0");self.f.flush()
        self.f.seek(0)
        if os.name=="nt":
            import msvcrt;msvcrt.locking(self.f.fileno(),msvcrt.LK_LOCK,1)
        else:
            import fcntl;fcntl.flock(self.f.fileno(),fcntl.LOCK_EX)
        return self
    def __exit__(self,*_):
        try:
            self.f.seek(0)
            if os.name=="nt":
                import msvcrt;msvcrt.locking(self.f.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl;fcntl.flock(self.f.fileno(),fcntl.LOCK_UN)
        finally:self.f.close();self.f=None
def _load_control_envelope(raw):
    if not isinstance(raw,str) or not raw.strip():raise SecurityError("signed control envelope missing")
    text=raw.strip();p=Path(text)
    if not text.startswith("{") and p.exists():text=p.read_text(encoding="utf-8")
    try:payload=json.loads(text)
    except Exception as e:raise SecurityError("signed control envelope is invalid JSON") from e
    try:
        from forgeboss.control.envelope import secret_file,verify_envelope
        _,secret=secret_file(ROOT);return verify_envelope(payload,secret)
    except Exception as e:raise SecurityError("signed control envelope verification failed: "+str(e)) from e
def _control_authority(raw,lease,workspace,executor):
    env=_load_control_envelope(raw);work=Path(workspace).resolve()
    if Path(env.get("worktreePath","")).resolve()!=work:raise SecurityError("control envelope workspace mismatch")
    task=str(env.get("taskId") or "").strip();run=str(env.get("runId") or "").strip()
    if not task or not run:raise SecurityError("control envelope task/run identity missing")
    try:epoch=int(env.get("ownerEpoch"))
    except Exception as e:raise SecurityError("control envelope ownerEpoch invalid") from e
    if epoch<=0:raise SecurityError("control envelope ownerEpoch invalid")
    runtime=env.get("runtime")
    if not isinstance(runtime,dict) or str(runtime.get("adapter") or "")!=executor:raise SecurityError("control envelope runtime differs from executor")
    attested_fields=("runnerPath","runnerSha256","interpreterPath","interpreterSha256")
    if any(not runtime.get(name) for name in attested_fields):raise SecurityError("control envelope missing governed runtime identity")
    try:
        from forgeboss.control.governed_launch import resolve_runner_identity
        identity=resolve_runner_identity(executor,repo_root=ROOT)
    except Exception as e:raise SecurityError("unable to resolve governed runtime identity: "+str(e)) from e
    expected_runtime={
        "runnerPath":identity.runner_path,
        "runnerSha256":identity.runner_sha256,
        "interpreterPath":identity.interpreter_path,
        "interpreterSha256":identity.interpreter_sha256,
    }
    for name,value in expected_runtime.items():
        if runtime.get(name)!=value:raise SecurityError("control envelope governed runtime identity mismatch: "+name)
    image=runtime.get("containerImage")
    if executor=="mini-swe":
        if not isinstance(image,str) or not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}",image):
            raise SecurityError("control envelope mini-swe container image is not digest-pinned")
    elif image is not None:
        raise SecurityError("control envelope container image is invalid for executor")
    packet_sha=str(env.get("packetSha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}",packet_sha):raise SecurityError("control envelope packet SHA-256 missing or invalid")
    if packet_sha!=str(lease.get("packet_sha256") or "").lower():raise SecurityError("control envelope packet differs from executor lease")
    budget=_positive_budget(env.get("budgetUsd"));ea=[norm(x) for x in env.get("allowedPaths",[])];la=[norm(x) for x in lease.get("allowed_files",[])]
    if [x.casefold() for x in ea]!=[x.casefold() for x in la]:raise SecurityError("control envelope allowedPaths differ from executor lease")
    unsigned=json.dumps(env,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    return {"taskId":task,"runId":run,"ownerEpoch":epoch,"budgetUsd":budget,"worktreePath":str(work),"runtime":runtime,"expiresAt":float(env["expiresAt"]),"allowedPaths":ea,"envelopeSha256":hashlib.sha256(unsigned).hexdigest()}
def _assert_live_control_lease(authority,executor,db_path=None,now=None):
    if not isinstance(authority,dict):raise SecurityError("control authority is invalid")
    db=Path(db_path) if db_path is not None else ROOT/"state"/"forgebossd"/"forgeboss.db"
    try:db=db.resolve(strict=True)
    except Exception as e:raise SecurityError("ForgeBoss control DB unavailable: "+str(e)) from e
    if not db.is_file():raise SecurityError("ForgeBoss control DB unavailable")
    current=time.time() if now is None else float(now)
    try:
        conn=sqlite3.connect(db.as_uri()+"?mode=ro",uri=True,timeout=5)
        conn.row_factory=sqlite3.Row
        try:
            row=conn.execute("""SELECT wl.owner_run_id,wl.owner_epoch,wl.released_at,wl.expires_at,wl.worktree_path,
              t.status,t.cancel_requested_at,t.assigned_runtime,t.governance_mode
              FROM workspace_leases wl JOIN tasks t ON t.task_id=wl.task_id
              WHERE wl.task_id=?""",(authority["taskId"],)).fetchone()
        finally:conn.close()
    except SecurityError:raise
    except Exception as e:raise SecurityError("unable to verify live ForgeBoss control lease: "+str(e)) from e
    if not row:raise SecurityError("live ForgeBoss control lease missing")
    if str(row["owner_run_id"])!=str(authority["runId"]):raise SecurityError("live control run identity mismatch")
    if int(row["owner_epoch"])!=int(authority["ownerEpoch"]):raise SecurityError("live control owner epoch mismatch")
    if row["released_at"] is not None:raise SecurityError("live control lease already released")
    if float(row["expires_at"])<=current:raise SecurityError("live control lease expired")
    if str(row["status"])!="running":raise SecurityError("governed task is not running")
    if row["cancel_requested_at"] is not None:raise SecurityError("governed task cancellation requested")
    if str(row["assigned_runtime"] or "")!=str(executor):raise SecurityError("live control runtime identity mismatch")
    if str(row["governance_mode"] or "")!="reuse-v1":raise SecurityError("task is not governed by reuse-v1")
    try:
        if Path(row["worktree_path"]).resolve()!=Path(authority["worktreePath"]).resolve():
            raise SecurityError("live control workspace mismatch")
    except SecurityError:raise
    except Exception as e:raise SecurityError("unable to verify live control workspace: "+str(e)) from e
    return True

def issue_lease(packet_path,workspace,executor,ttl=1200):
    pp=Path(packet_path);work=Path(workspace).resolve();packet=json.loads(pp.read_text(encoding="utf-8"));allowed,context=validate_packet(packet)
    if executor in ("openhands","opencode") and not isolation_ok(executor):raise SecurityError(f"{executor} write-capable execution is quarantined until OS/network isolation is verified")
    with _WorkspaceFence(work):
        assert_no_link_escape(work);assert_paths_contained(work,allowed+context);exact_head(work,packet);no_remotes(work);token=secrets.token_urlsafe(32)
        lease={"schema":3,"executor":executor,"workspace":str(work),"packet_sha256":phash(pp),"allowed_files":allowed,"allowed_keys":[x.casefold() for x in allowed],"issued_at":time.time(),"expires_at":time.time()+ttl,"token_sha256":hashlib.sha256(token.encode()).hexdigest(),"baseline":snapshot(work),"git_metadata":git_metadata_snapshot(work),"isolation_verified":isolation_ok(executor),"paid_consumed":False,"paid_authority":None,"revoked_at":None}
        lp=STATE/f"lease-{int(time.time()*1000)}-{secrets.token_hex(4)}.json";_atomic_write_json(lp,lease)
    return {"ok":True,"lease":str(lp),"token":token}

def revoke_lease(lease_path,token,workspace,executor):
    lp=Path(lease_path)
    try:resolved=lp.resolve(strict=True)
    except Exception as e:raise SecurityError("executor lease file unavailable: "+str(e)) from e
    try:
        if resolved.parent!=STATE.resolve(strict=True):raise SecurityError("executor lease path is outside protected state")
    except SecurityError:raise
    except Exception as e:raise SecurityError("executor lease state path unavailable: "+str(e)) from e
    with _WorkspaceFence(workspace):
        try:lease=json.loads(resolved.read_text(encoding="utf-8"))
        except Exception as e:raise SecurityError("executor lease is unreadable: "+str(e)) from e
        if lease.get("executor")!=executor:raise SecurityError("executor identity mismatch")
        if Path(lease.get("workspace","")).resolve()!=Path(workspace).resolve():raise SecurityError("workspace mismatch")
        supplied=hashlib.sha256(str(token).encode()).hexdigest()
        if not secrets.compare_digest(str(lease.get("token_sha256","")),supplied):raise SecurityError("lease token mismatch")
        if lease.get("revoked_at") is None:
            lease["revoked_at"]=time.time();_atomic_write_json(resolved,lease)
        try:
            resolved.unlink()
            return {"revoked":True,"removed":True}
        except FileNotFoundError:
            return {"revoked":True,"removed":True}
        except Exception as e:
            return {"revoked":True,"removed":False,"error":f"{type(e).__name__}: {e}"}

def issue(packet_path,workspace,executor,ttl=1200):
    print(json.dumps(issue_lease(packet_path,workspace,executor,ttl)));return 0
def _verify_unlocked(lease_path,token,packet_path,workspace,executor):
    lease=json.loads(Path(lease_path).read_text(encoding="utf-8"));work=Path(workspace).resolve();pp=Path(packet_path)
    if lease.get("revoked_at") is not None:raise SecurityError("executor lease revoked")
    if time.time()>float(lease.get("expires_at",0)):raise SecurityError("executor lease expired")
    if lease.get("executor")!=executor:raise SecurityError("executor identity mismatch")
    if Path(lease.get("workspace","")).resolve()!=work:raise SecurityError("workspace mismatch")
    if lease.get("packet_sha256")!=phash(pp):raise SecurityError("packet changed after lease")
    if not secrets.compare_digest(lease.get("token_sha256",""),hashlib.sha256(token.encode()).hexdigest()):raise SecurityError("lease token mismatch")
    packet=json.loads(pp.read_text(encoding="utf-8"));allowed,context=validate_packet(packet);assert_no_link_escape(work);assert_paths_contained(work,allowed+context);exact_head(work,packet);no_remotes(work)
    baseline=lease.get("baseline")
    if not isinstance(baseline,dict):raise SecurityError("executor lease missing workspace baseline")
    pre=changed(baseline,snapshot(work))
    if pre:raise SecurityError("workspace changed after executor lease before execution: "+json.dumps(pre))
    if executor in ("openhands","opencode") and not isolation_ok(executor):raise SecurityError(f"{executor} isolation proof disappeared after lease")
    before=lease.get("git_metadata")
    if not isinstance(before,dict):raise SecurityError("executor lease missing Git metadata baseline")
    ch=changed(before,git_metadata_snapshot(work))
    if ch:raise SecurityError("Git metadata changed after lease before execution: "+json.dumps(ch))
    return lease
def verify(lease_path,token,packet_path,workspace,executor):
    with _WorkspaceFence(workspace):return _verify_unlocked(lease_path,token,packet_path,workspace,executor)
@contextmanager
def paid_start_authority(lease_path,token,packet_path,workspace,executor,control_envelope,cli_budget=None):
    lease_path=Path(lease_path)
    with _WorkspaceFence(workspace):
        lease=_verify_unlocked(lease_path,token,packet_path,workspace,executor)
        if lease.get("paid_consumed") is True:raise SecurityError("paid executor authority already consumed")
        authority=_control_authority(control_envelope,lease,workspace,executor);budget=authority["budgetUsd"]
        _assert_live_control_lease(authority,executor)
        if cli_budget is not None and _positive_budget(cli_budget)!=budget:raise SecurityError("runner budget differs from signed control authority")
        ch=changed(lease.get("git_metadata"),git_metadata_snapshot(Path(workspace).resolve()))
        if ch:raise SecurityError("Git metadata changed at paid-start boundary: "+json.dumps(ch))
        lease["paid_consumed"]=True;lease["paid_consumed_at"]=time.time();lease["paid_authority"]=authority;_atomic_write_json(lease_path,lease)
        yield authority
def postflight(lease_path,token,packet_path,workspace,executor):
    lease=verify(lease_path,token,packet_path,workspace,executor)
    with _WorkspaceFence(workspace):
        before=lease.get("git_metadata")
        if not isinstance(before,dict):raise SecurityError("executor lease missing Git metadata baseline")
        gc=changed(before,git_metadata_snapshot(workspace))
        if gc:raise SecurityError("Git metadata changed during executor run: "+json.dumps(gc))
        after=snapshot(workspace);ch=changed(lease.get("baseline") or {},after);allowed={x.casefold() for x in (lease.get("allowed_files") or [])};bad=[p for p in ch if p.casefold() not in allowed];links=[p for p in ch if (after.get(p) or {}).get("kind")=="link"]
        if bad:raise SecurityError("out-of-scope changes: "+json.dumps(bad))
        if links:raise SecurityError("symlink/junction changes denied: "+json.dumps(links))
        no_remotes(Path(workspace))
    print(json.dumps({"ok":True,"changed_paths":ch,"scope_ok":True,"isolation_verified":lease.get("isolation_verified"),"paid_consumed":lease.get("paid_consumed") is True}));return 0
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True);x=sp.add_parser("issue");x.add_argument("--packet",required=True);x.add_argument("--workspace",required=True);x.add_argument("--executor",required=True);x.add_argument("--ttl",type=int,default=1200)
    for n in ("verify","postflight"):
        x=sp.add_parser(n);x.add_argument("--lease",required=True);x.add_argument("--token",required=True);x.add_argument("--packet",required=True);x.add_argument("--workspace",required=True);x.add_argument("--executor",required=True)
    ns=ap.parse_args()
    try:
        if ns.cmd=="issue":return issue(ns.packet,ns.workspace,ns.executor,ns.ttl)
        if ns.cmd=="verify":verify(ns.lease,ns.token,ns.packet,ns.workspace,ns.executor);print(json.dumps({"ok":True}));return 0
        return postflight(ns.lease,ns.token,ns.packet,ns.workspace,ns.executor)
    except Exception as e:print(json.dumps({"ok":False,"error":f"{type(e).__name__}: {e}"}));return 13
if __name__=="__main__":raise SystemExit(main())