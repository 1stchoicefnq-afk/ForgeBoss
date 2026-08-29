from pathlib import Path
import re

wp=Path('forgeboss/control/workspace.py')
s=wp.read_text(encoding='utf-8')
s=s.replace('import tempfile\nimport time\nimport uuid\n','import tempfile\nimport time\nimport uuid\nimport sys\n',1)

def rf(name,new):
    global s
    pat=rf'(?ms)^def {re.escape(name)}\(.*?(?=^def |\Z)'
    s2,n=re.subn(pat,new.rstrip()+'\n\n',s,count=1)
    if n!=1: raise SystemExit(f'function replace failed {name}: {n}')
    s=s2

insert='''def _linux_native_identity(path: Path) -> dict:
    if not sys.platform.startswith("linux"):
        raise WorkspaceProvisionError("WORKSPACE_IDENTITY_INVALID", "Linux native identity unavailable")
    try:
        import ctypes
        libc=ctypes.CDLL(None,use_errno=True)
        class FH(ctypes.Structure):
            _fields_=[("handle_bytes",ctypes.c_uint),("handle_type",ctypes.c_int),("f_handle",ctypes.c_ubyte*128)]
        fn=libc.name_to_handle_at
        fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.POINTER(FH),ctypes.POINTER(ctypes.c_int),ctypes.c_int]
        fn.restype=ctypes.c_int
        h=FH();h.handle_bytes=128;mount_id=ctypes.c_int()
        rc=fn(-100,os.fsencode(path),ctypes.byref(h),ctypes.byref(mount_id),0)
        if rc!=0:
            err=ctypes.get_errno();raise OSError(err,os.strerror(err))
        raw=bytes(h.f_handle[:h.handle_bytes]).hex()
        if not raw: raise OSError("empty Linux file handle")
        return {"mountId":int(mount_id.value),"handleType":int(h.handle_type),"handleHex":raw}
    except WorkspaceProvisionError: raise
    except Exception as ex:
        raise WorkspaceProvisionError("WORKSPACE_IDENTITY_INVALID",f"stable Linux workspace file handle unavailable: {path}: {ex}") from ex

'''
marker='def _path_identity(path: Path, code: str = "WORKSPACE_IDENTITY_INVALID") -> dict:\n'
if marker not in s: raise SystemExit('path identity marker missing')
s=s.replace(marker,insert+marker,1)
rf('_path_identity','''def _path_identity(path: Path, code: str = "WORKSPACE_IDENTITY_INVALID") -> dict:
    _assert_no_link_components(path, code);_assert_plain_existing_path(path, code)
    try: st=path.stat();resolved=path.resolve(strict=True)
    except OSError as ex: raise WorkspaceProvisionError(code,f"cannot inspect workspace identity: {path}") from ex
    if not stat.S_ISDIR(st.st_mode): raise WorkspaceProvisionError(code,"workspace generation must be a directory")
    ino=int(getattr(st,"st_ino",0));ctime_ns=int(getattr(st,"st_ctime_ns",int(st.st_ctime*1_000_000_000)));dev=int(getattr(st,"st_dev",-1))
    if ino<=0 or ctime_ns<=0 or dev<0: raise WorkspaceProvisionError(code,"stable workspace file identity unavailable")
    out={"resolved":str(resolved),"dev":dev,"ino":ino,"ctimeNs":ctime_ns,"mode":int(st.st_mode)}
    try:
        if os.name=="nt":
            from .windows_cleanup import native_identity
            out["native"]=native_identity(path)
        elif sys.platform.startswith("linux"):
            out["linuxHandle"]=_linux_native_identity(path)
        else:
            raise WorkspaceProvisionError(code,"crash-safe native generation identity unavailable on this platform")
    except WorkspaceProvisionError: raise
    except Exception as ex: raise WorkspaceProvisionError(code,f"cannot bind native workspace identity: {path}: {ex}") from ex
    return out''')
rf('_identity_shape_valid','''def _identity_shape_valid(identity: dict | None) -> bool:
    if not isinstance(identity,dict): return False
    base={"resolved","dev","ino","ctimeNs","mode"};keys=set(identity)
    if keys not in (base|{"native"},base|{"linuxHandle"}): return False
    if not isinstance(identity["resolved"],str) or not identity["resolved"]: return False
    try:
        if not (int(identity["dev"])>=0 and int(identity["ino"])>0 and int(identity["ctimeNs"])>0 and int(identity["mode"])>0): return False
    except (TypeError,ValueError): return False
    if "native" in identity:
        n=identity["native"]
        if not isinstance(n,dict) or set(n)!={"volumeSerial","fileId","creationTime"}: return False
        try: volume=int(n["volumeSerial"]);creation=int(n["creationTime"])
        except (TypeError,ValueError): return False
        fid=str(n["fileId"]).lower()
        return volume>=0 and creation>0 and len(fid)==32 and all(ch in "0123456789abcdef" for ch in fid)
    h=identity.get("linuxHandle")
    if not isinstance(h,dict) or set(h)!={"mountId","handleType","handleHex"}: return False
    try: mount=int(h["mountId"]);typ=int(h["handleType"])
    except (TypeError,ValueError): return False
    raw=str(h["handleHex"]).lower()
    return mount>=0 and typ>=0 and bool(raw) and len(raw)%2==0 and all(ch in "0123456789abcdef" for ch in raw)''')
insert2='''def _stable_generation_equal(before: dict, after: dict) -> bool:
    if not (_identity_shape_valid(before) and _identity_shape_valid(after)): return False
    if not all(int(before[k])==int(after[k]) for k in ("dev","ino","mode")): return False
    if ("native" in before)!=("native" in after) or ("linuxHandle" in before)!=("linuxHandle" in after): return False
    return before.get("native")==after.get("native") and before.get("linuxHandle")==after.get("linuxHandle")

'''
marker2='def _same_live_object(before: dict, after: dict) -> bool:\n'
s=s.replace(marker2,insert2+marker2,1)
rf('_same_live_object','''def _same_live_object(before: dict, after: dict) -> bool:
    return _stable_generation_equal(before,after)''')
insert3='''def _generation_continuity_matches(path: Path, expected: dict | None) -> bool:
    if not _identity_shape_valid(expected): return False
    try: observed=_path_identity(path)
    except WorkspaceProvisionError: return False
    return _stable_generation_equal(expected,observed)

'''
marker3='def _identity_matches(path: Path, expected: dict | None) -> bool:\n'
s=s.replace(marker3,insert3+marker3,1)
rf('_identity_matches','''def _identity_matches(path: Path, expected: dict | None) -> bool:
    if not _identity_shape_valid(expected): return False
    try: observed=_path_identity(path)
    except WorkspaceProvisionError: return False
    if observed["resolved"]!=expected["resolved"]: return False
    if not _stable_generation_equal(expected,observed): return False
    return int(observed["ctimeNs"])==int(expected["ctimeNs"])''')
s=s.replace('if value["state"] not in {"preparing", "provisioning", "finalizing", "quarantined"}:','if value["state"] not in {"preparing", "provisioning", "renaming", "finalizing", "quarantined"}:',1)
rf('discover_quarantined_workspaces','''def discover_quarantined_workspaces(workspace_root: str | os.PathLike[str]) -> list[dict]:
    root=_canonical_existing_dir(workspace_root,"WORKSPACE_ROOT_INVALID");qdir=_quarantine_dir(root);records=[];referenced_stages=set()
    for path in sorted(qdir.glob("*.json")):
        record=_read_record(path);target=Path(record["target"]);stage=Path(record["stage"])
        try: common=Path(os.path.commonpath([str(root),str(target)]));stage_common=Path(os.path.commonpath([str(root),str(stage)]))
        except ValueError as ex: raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID","recorded path escapes workspace root") from ex
        if common!=root or stage_common!=root: raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID","recorded path escapes workspace root")
        referenced_stages.add(str(stage))
        if record["state"]!="quarantined":
            previous=record["state"];record["state"]="quarantined";record["recoveredAfterRestart"]=True;record["recoveredFromState"]=previous;_write_record(path,record)
        records.append(dict(record))
    for stage in sorted(root.glob(f"{STAGE_PREFIX}*")):
        if str(stage) in referenced_stages: continue
        state="orphan-untrusted" if stage.is_symlink() or _is_reparse(stage) else "orphan-untracked"
        records.append({"version":QUARANTINE_VERSION,"state":state,"stage":str(stage),"target":None})
    return records''')
rf('reconcile_quarantined_workspace','''def reconcile_quarantined_workspace(workspace: str | os.PathLike[str], workspace_root: str | os.PathLike[str], generation_id: str) -> dict:
    root,target=_candidate_under_root(workspace,workspace_root);found=_record_for_target(root,target)
    if found is None: raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_NOT_FOUND","no quarantine record exists")
    record_path,record=found
    if record["generation"]!=generation_id: raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH","quarantine generation does not match requested cleanup generation",generation_id=record["generation"])
    stage=Path(record["stage"]);existing=target if (target.exists() or target.is_symlink() or _is_reparse(target)) else stage
    if existing.exists() or existing.is_symlink() or _is_reparse(existing):
        _assert_no_link_components(existing,"WORKSPACE_CLEANUP_DENIED");_assert_plain_existing_path(existing,"WORKSPACE_CLEANUP_DENIED")
        inflight=record.get("recoveredFromState") in {"provisioning","renaming"}
        matches=_generation_continuity_matches(existing,record.get("identity")) if inflight else _identity_matches(existing,record.get("identity"))
        if not matches: raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH","surviving workspace no longer matches quarantined generation identity",generation_id=generation_id)
        if inflight:
            record["identity"]=_path_identity(existing);record["state"]="quarantined";_write_record(record_path,record)
        try: _rmtree_windows_safe(existing,record.get("identity"))
        except Exception as ex: raise WorkspaceProvisionError("WORKSPACE_CLEANUP_FAILED",f"quarantined workspace cleanup failed: {ex}",cleanup_code=type(ex).__name__.upper(),generation_id=generation_id) from ex
    _remove_record_after_absence(record_path,target,stage)
    return {"reconciled":True,"generation":generation_id,"target":str(target)}''')
rf('_provision_failure_cleanup','''def _provision_failure_cleanup(root: Path, target: Path, stage: Path, record_path: Path, record: dict, provision_error: BaseException) -> None:
    candidate=target if (target.exists() or target.is_symlink() or _is_reparse(target)) else stage;cleanup_error=None
    try:
        if candidate.exists() or candidate.is_symlink() or _is_reparse(candidate):
            _assert_no_link_components(candidate,"WORKSPACE_CLEANUP_DENIED");_assert_plain_existing_path(candidate,"WORKSPACE_CLEANUP_DENIED")
            if record.get("state") in {"provisioning","renaming"}:
                if not _generation_continuity_matches(candidate,record.get("identity")): raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH","failed generation identity changed before cleanup")
                record["identity"]=_path_identity(candidate);_write_record(record_path,record)
            elif not _identity_matches(candidate,record.get("identity")): raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH","failed generation identity changed before cleanup")
            _rmtree_windows_safe(candidate,record.get("identity"))
        _remove_record_after_absence(record_path,target,stage)
    except BaseException as ex: cleanup_error=ex
    if cleanup_error is None:return
    quarantined=dict(record);quarantined["state"]="quarantined";survivor=target if (target.exists() or target.is_symlink() or _is_reparse(target)) else stage
    try:
        if survivor.exists() or survivor.is_symlink() or _is_reparse(survivor):
            if not _generation_continuity_matches(survivor,record.get("identity")): raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH","cleanup failed after generation replacement")
            quarantined["identity"]=_path_identity(survivor)
    except BaseException as identity_error:
        quarantined["identity"]=record.get("identity");cleanup_error=WorkspaceProvisionError("WORKSPACE_IDENTITY_INVALID",f"cleanup failed and survivor identity could not be refreshed safely: {identity_error}")
    quarantined["provisionError"]={"code":_exception_code(provision_error),"message":str(provision_error)};quarantined["cleanupError"]={"code":_exception_code(cleanup_error),"message":str(cleanup_error)}
    try:_write_record(record_path,quarantined)
    except Exception as record_error: raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_WRITE_FAILED",f"provisioning failed ({_exception_code(provision_error)}); cleanup failed ({_exception_code(cleanup_error)}); quarantine persistence failed ({type(record_error).__name__})",provision_code=_exception_code(provision_error),cleanup_code=_exception_code(cleanup_error),generation_id=record["generation"]) from record_error
    raise WorkspaceProvisionError("WORKSPACE_PROVISION_CLEANUP_FAILED",f"provisioning failed ({_exception_code(provision_error)}); cleanup/quarantine failed ({_exception_code(cleanup_error)})",provision_code=_exception_code(provision_error),cleanup_code=_exception_code(cleanup_error),generation_id=record["generation"]) from cleanup_error''')
rf('provision_workspace','''def provision_workspace(source_repo: str | os.PathLike[str], workspace: str | os.PathLike[str], workspace_root: str | os.PathLike[str], base_sha: str, task_branch: str, git_executable: str | os.PathLike[str]) -> WorkspaceIdentity:
    git=_git_executable(git_executable);root,target=_workspace_target(workspace,workspace_root);source=inspect_source(source_repo,base_sha,git);branch=_validate_branch(git,task_branch);requested=source["base_sha"]
    generation=uuid.uuid4().hex;target_hash=hashlib.sha256(str(target).encode("utf-8")).hexdigest()[:16];stage=root/f"{STAGE_PREFIX}{target_hash}-{generation}";record_path=_record_path(root,target)
    record={"version":QUARANTINE_VERSION,"generation":generation,"target":str(target),"stage":str(stage),"identity":None,"state":"preparing","updatedAt":time.time()}
    try:
        stage.mkdir(mode=0o700);_fsync_dir(root)
        record["identity"]=_path_identity(stage);record["state"]="provisioning";_write_record(record_path,record)
        with tempfile.TemporaryDirectory(prefix="forgeboss-git-template-",dir=str(root)) as template_dir:
            _run_git(git,["-c","protocol.file.allow=always","clone","--no-local","--no-hardlinks","--no-checkout","--no-tags",f"--template={Path(template_dir)}",source["source_root"],str(stage)],cwd=root)
        for remote in [x for x in _git_text(git,["remote"],cwd=stage).splitlines() if x.strip()]: _run_git(git,["remote","remove",remote],cwd=stage)
        _run_git(git,["checkout","--detach",requested],cwd=stage);_run_git(git,["branch","-f",branch,requested],cwd=stage);_run_git(git,["checkout",branch],cwd=stage)
        if not _generation_continuity_matches(stage,record["identity"]): raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH","workspace generation changed during provisioning")
        stable_stage_identity=_path_identity(stage);record["identity"]=stable_stage_identity;record["state"]="renaming";_write_record(record_path,record)
        if target.exists() or target.is_symlink() or _is_reparse(target): raise WorkspaceProvisionError("WORKSPACE_EXISTS","workspace target appeared during provisioning")
        stage.rename(target);_fsync_dir(root);renamed_identity=_path_identity(target)
        if not _same_live_object(stable_stage_identity,renamed_identity): raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH","workspace object changed across final rename")
        record["identity"]=renamed_identity;record["state"]="finalizing";_write_record(record_path,record)
        identity=verify_workspace(target,root,requested,branch,git,source_identity=source,_allow_generation=generation);_remove_record_after_absence_for_success(record_path,stage);return identity
    except BaseException as ex:
        _provision_failure_cleanup(root,target,stage,record_path,record,ex);raise''')
wp.write_text(s,encoding='utf-8')

hp=Path('forgeboss/control/windows_cleanup.py')
h=hp.read_text(encoding='utf-8')
h=h.replace('return {"volumeSerial":int(x.VolumeSerialNumber),"fileId":bytes(x.FileId.Identifier).hex()}','''y=BHFI()\n    if not K.GetFileInformationByHandle(h,ctypes.byref(y)): _err("cannot read handle creation identity")\n    creation=(int(y.b.dwHighDateTime)<<32)|int(y.b.dwLowDateTime)\n    return {"volumeSerial":int(x.VolumeSerialNumber),"fileId":bytes(x.FileId.Identifier).hex(),"creationTime":creation}''',1)
h=h.replace('out.append((name,fid,int(r.attrs)))','out.append((name,fid,int(r.ct)&((1<<64)-1),int(r.attrs)))',1)
h=h.replace('for name,fid,listed in _entries(parent):','for name,fid,created,listed in _entries(parent):',1)
h=h.replace('attrs=_attrs(h);vol,opened=_id64(h)','attrs=_attrs(h);vol,opened=_id64(h);basic=BASIC()\n            if not K.GetFileInformationByHandleEx(h,0,ctypes.byref(basic),ctypes.sizeof(basic)): _err("cannot read child creation identity")',1)
h=h.replace('if vol!=pvol or opened!=fid: raise WindowsCleanupError(f"cleanup child identity changed: {name}")','if vol!=pvol or opened!=fid or (int(basic.c)&((1<<64)-1))!=created: raise WindowsCleanupError(f"cleanup child identity changed: {name}")',1)
h=h.replace('set(expected_native)!={"volumeSerial","fileId"}','set(expected_native)!={"volumeSerial","fileId","creationTime"}',1)
h=h.replace('try:vol=int(expected_native["volumeSerial"]);fid=str(expected_native["fileId"]).lower()','try:vol=int(expected_native["volumeSerial"]);fid=str(expected_native["fileId"]).lower();creation=int(expected_native["creationTime"])',1)
h=h.replace('if vol<0 or len(fid)!=32','if vol<0 or creation<=0 or len(fid)!=32',1)
h=h.replace('if obs!={"volumeSerial":vol,"fileId":fid}:','if obs!={"volumeSerial":vol,"fileId":fid,"creationTime":creation}:',1)
hp.write_text(h,encoding='utf-8')

tp=Path('forgeboss/control/test_workspace.py')
t=tp.read_text(encoding='utf-8')
t=t.replace('if Path(path)==survivor: return dict(forged)','if Path(path).resolve()==survivor.resolve(): return dict(forged)',1)
t=t.replace('cp=subprocess.run(["cmd.exe","/d","/c",f\'mklink /J "{child}" "{outside}"\'],capture_output=True,text=True)','cp=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command","New-Item","-ItemType","Junction","-Path",str(child),"-Target",str(outside)],capture_output=True,text=True)',1)
extra='''\n    def _seed_inflight_record(self,target,state="provisioning"):\n        from forgeboss.control import workspace as m\n        root,canonical=m._candidate_under_root(target,self.workspaces);generation="c"*32;stage=root/f"{STAGE_PREFIX}crash-{generation}";stage.mkdir()\n        record={"version":m.QUARANTINE_VERSION,"generation":generation,"target":str(canonical),"stage":str(stage),"identity":m._path_identity(stage),"state":state,"updatedAt":0.0}\n        m._write_record(m._record_path(root,canonical),record);return root,canonical,stage,generation,record\n\n    def test_restart_reconciles_inflight_provisioning_generation(self):\n        target=self.workspaces/"crash-provision";_,_,stage,generation,_=self._seed_inflight_record(target)\n        found=discover_quarantined_workspaces(self.workspaces);row=next(x for x in found if x.get("generation")==generation);self.assertEqual(row.get("recoveredFromState"),"provisioning")\n        out=reconcile_quarantined_workspace(target,self.workspaces,generation);self.assertTrue(out["reconciled"]);self.assertFalse(stage.exists());self.assertIsNone(quarantine_status(target,self.workspaces))\n\n    def test_restart_rejects_replaced_inflight_generation(self):\n        from forgeboss.control import workspace as m\n        target=self.workspaces/"crash-replaced";_,_,stage,generation,record=self._seed_inflight_record(target)\n        m._rmtree_windows_safe(stage,record["identity"]);stage.mkdir();(stage/"attacker.txt").write_text("new")\n        discover_quarantined_workspaces(self.workspaces)\n        with self.assertRaises(WorkspaceProvisionError) as cm: reconcile_quarantined_workspace(target,self.workspaces,generation)\n        self.assertEqual(cm.exception.code,"WORKSPACE_GENERATION_MISMATCH");self.assertTrue((stage/"attacker.txt").exists())\n\n    def test_restart_reconciles_post_rename_generation(self):\n        from forgeboss.control import workspace as m\n        target=self.workspaces/"crash-rename";root,canonical,stage,generation,record=self._seed_inflight_record(target,"renaming");stage.rename(canonical)\n        found=discover_quarantined_workspaces(self.workspaces);row=next(x for x in found if x.get("generation")==generation);self.assertEqual(row.get("recoveredFromState"),"renaming")\n        out=reconcile_quarantined_workspace(target,self.workspaces,generation);self.assertTrue(out["reconciled"]);self.assertFalse(canonical.exists())\n'''
footer='\n\nif __name__ == "__main__": unittest.main()\n'
if footer not in t: raise SystemExit('test footer missing')
t=t.replace(footer,extra+footer,1)
tp.write_text(t,encoding='utf-8')
