from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from forgeboss.control.self_build_coordinator import SelfBuildCoordinator,SelfBuildCoordinatorError
from forgeboss.control.store import ControlStore
from forgeboss.control.workspace_state import ProtectedWorkspaceState
from forgeboss.security.executor_guard import _resolve_git_executable


class SelfBuildRuntimeError(RuntimeError):
    def __init__(self,code:str,message:str):
        super().__init__(message);self.code=code


def _fsync_dir(path:Path)->None:
    if os.name=="nt":return
    fd=os.open(str(path),os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


def _atomic_json(path:Path,value:dict)->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=str(path.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as f:
            json.dump(value,f,sort_keys=True,indent=2)
            f.write("\n");f.flush();os.fsync(f.fileno())
        os.replace(tmp,path);_fsync_dir(path.parent)
    finally:
        try:
            if os.path.exists(tmp):os.unlink(tmp)
        except OSError:pass


class SelfBuildRuntime:
    """Service-principal runtime for ForgeBoss self-build preparation.

    This class performs NO model/API call. It only creates protected task,
    workspace and budget authority. Paid launch remains separately attested.
    """
    def __init__(self,*,protected_root:Path,boundary,receipt_public_key_b64:str,
                 git_resolver=_resolve_git_executable):
        root=Path(protected_root)
        if not root.is_absolute():
            raise SelfBuildRuntimeError("PROTECTED_ROOT_INVALID","protected root must be absolute")
        self.root=root.resolve(strict=True)
        boundary.assert_service_principal(self.root)
        self.boundary=boundary
        self.git_resolver=git_resolver

        self.workspace_root=self.root/"self-build-workspaces"
        self.run_root=self.root/"self-build-runs"
        self.activation_root=self.root/"activation"
        for p in (self.workspace_root,self.run_root,self.activation_root):
            p.mkdir(mode=0o700,exist_ok=True)
            boundary.assert_protected_path(p,protected_root=self.root)

        self.workspace_state=ProtectedWorkspaceState(protected_root=self.root,boundary=boundary)
        self.store=ControlStore(self.root/"self-build-control.sqlite3")
        boundary.assert_protected_path(self.root/"self-build-control.sqlite3",protected_root=self.root)
        self.coordinator=SelfBuildCoordinator(
            store=self.store,receipt_public_key_b64=receipt_public_key_b64
        )

    def close(self):
        try:self.workspace_state.close()
        finally:
            try:self.store.db.close()
            except Exception:pass

    def _assert_service(self)->None:
        try:self.boundary.assert_service_principal(self.root)
        except Exception as ex:raise SelfBuildRuntimeError("SERVICE_PRINCIPAL_DENIED","protected self-build service principal denied") from ex

    def _assert_path(self,path:Path)->None:
        self._assert_service()
        try:self.boundary.assert_protected_path(path,protected_root=self.root)
        except Exception as ex:raise SelfBuildRuntimeError("PROTECTED_STATE_DENIED","protected self-build state path denied") from ex

    def _pointer(self)->dict:
        path=self.activation_root/"known-good.json"
        self._assert_service()
        if not path.is_file():
            raise SelfBuildRuntimeError("KNOWN_GOOD_POINTER_MISSING","protected activation known-good pointer is missing")
        self._assert_path(path)
        try:value=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildRuntimeError("KNOWN_GOOD_POINTER_INVALID","protected known-good pointer is unreadable") from ex
        if not isinstance(value,dict):
            raise SelfBuildRuntimeError("KNOWN_GOOD_POINTER_INVALID","protected known-good pointer is invalid")
        return value

    def _run_path(self,run_id:str)->Path:
        if not isinstance(run_id,str) or not run_id or len(run_id)>64 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for c in run_id):
            raise SelfBuildRuntimeError("RUN_ID_INVALID","self-build run id invalid")
        return self.run_root/(run_id+".json")

    def prepare(self,payload:dict)->dict:
        try:
            source=Path(payload["sourceRoot"]).resolve(strict=True)
            base=str(payload["baseSha"]).lower()
            run_id=str(payload["runId"])
        except Exception as ex:
            raise SelfBuildRuntimeError("SELF_BUILD_PAYLOAD_INVALID","self-build prepare payload invalid") from ex
        path=self._run_path(run_id)
        if path.exists():
            raise SelfBuildRuntimeError("RUN_ALREADY_EXISTS","self-build run id already exists")
        git=self.git_resolver()
        try:
            result=self.coordinator.prepare_initial_run(
                source_root=source,
                known_good_pointer=self._pointer(),
                base_sha=base,
                run_id=run_id,
                workspace_root=self.workspace_root,
                git_executable=git,
                protected_state=self.workspace_state,
            )
        except SelfBuildCoordinatorError as ex:
            raise SelfBuildRuntimeError(ex.code,str(ex)) from ex
        record={"schema":1,"phase":"PREPARED","prepared":result,"replacement":None}
        _atomic_json(path,record)
        self._assert_path(path)
        return result

    def prepare_replacement(self,payload:dict)->dict:
        run_id=str(payload.get("runId") or "")
        path=self._run_path(run_id)
        if not path.is_file():
            raise SelfBuildRuntimeError("RUN_NOT_FOUND","self-build run not found")
        self._assert_path(path)
        try:record=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run state unreadable") from ex
        if not isinstance(record,dict) or record.get("schema")!=1 or record.get("phase")!="PREPARED" or not isinstance(record.get("prepared"),dict):
            raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run is not replacement-ready")
        if record.get("replacement") is not None:
            raise SelfBuildRuntimeError("REPLACEMENT_ALREADY_PREPARED","replacement authority already exists")
        prepared=record["prepared"]
        git=self.git_resolver()
        try:
            replacement=self.coordinator.prepare_replacement(
                prepared_run=prepared,
                source_root=prepared["source_root"],
                workspace_root=self.workspace_root,
                git_executable=git,
                protected_state=self.workspace_state,
            )
        except SelfBuildCoordinatorError as ex:
            raise SelfBuildRuntimeError(ex.code,str(ex)) from ex
        record["replacement"]=replacement
        record["phase"]="REPLACEMENT_PREPARED"
        _atomic_json(path,record)
        return replacement

    def status(self,payload:dict)->dict:
        run_id=str(payload.get("runId") or "")
        path=self._run_path(run_id)
        if not path.is_file():raise SelfBuildRuntimeError("RUN_NOT_FOUND","self-build run not found")
        self._assert_path(path)
        try:value=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run state unreadable") from ex
        if not isinstance(value,dict) or value.get("schema")!=1:
            raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run state invalid")
        return value
