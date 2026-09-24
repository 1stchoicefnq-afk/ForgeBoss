from __future__ import annotations
import argparse, inspect, json, os, sys, time, ctypes
from ctypes import wintypes
from pathlib import Path

def jload(path:Path):
    value=json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value,dict):raise RuntimeError("invalid json object: "+str(path))
    return value

def creation_filetime():
    k=ctypes.WinDLL("kernel32",use_last_error=True)
    c=wintypes.FILETIME();e=wintypes.FILETIME();kt=wintypes.FILETIME();u=wintypes.FILETIME()
    if not k.GetProcessTimes(k.GetCurrentProcess(),ctypes.byref(c),ctypes.byref(e),ctypes.byref(kt),ctypes.byref(u)):
        raise OSError(ctypes.get_last_error(),"GetProcessTimes")
    return (int(c.dwHighDateTime)<<32)|int(c.dwLowDateTime)

def atomic_json(path:Path,value):
    tmp=path.with_name(path.name+f".tmp-{os.getpid()}")
    with tmp.open("w",encoding="utf-8",newline="\n") as f:
        json.dump(value,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)

def main():
    if os.name!="nt":raise SystemExit("Windows authority host only")
    ap=argparse.ArgumentParser();ap.add_argument("--installed",required=True);ns=ap.parse_args()
    installed=Path(ns.installed).resolve(strict=True);state=jload(installed)
    engine=Path(state["engineRoot"]).resolve(strict=True)
    sys.path.insert(0,str(engine))
    from forgeboss.protected_authority.protocol import AuthorityError, OPERATIONS
    from forgeboss.protected_authority.service import create_production_service
    from forgeboss.protected_authority.lifecycle import WindowsNamedPipeServer
    root=Path(state["protectedRoot"]).resolve(strict=True);cfg=jload(root/"authority-config.json")
    if str(cfg.get("engineSha","")).lower()!=str(state.get("engineSha","")).lower() or Path(cfg["engineRoot"]).resolve(strict=True)!=engine:
        raise RuntimeError("AUTHORITY_ENGINE_IDENTITY_MISMATCH")
    if cfg.get("authorityApi")!="self_build_runtime_receipts_v1":
        raise RuntimeError("AUTHORITY_API_CONFIG_MISMATCH")
    required={
        "authorize_self_build_launch","prepare_self_build","prepare_self_build_replacement",
        "compose_self_build_successor","activate_self_build_successor",
        "prove_self_build_activation_rollback","self_build_current_known_good",
        "self_build_status","revoke_self_build_worker","record_self_build_handoff",
        "review_self_build_candidate","accept_self_build_candidate",
    }
    operations=set(OPERATIONS)
    missing=sorted(required-operations)
    legacy=sorted(x for x in operations if x.startswith("issue_stage1_"))
    service_params=set(inspect.signature(create_production_service).parameters)
    obsolete=sorted(x for x in service_params if x.startswith("stage1_"))
    if missing:raise RuntimeError("CURRENT_STAGE1_OPERATIONS_MISSING:"+",".join(missing))
    if legacy:raise RuntimeError("LEGACY_ISSUE_STAGE1_OPERATIONS_PRESENT:"+",".join(legacy))
    if obsolete:raise RuntimeError("OBSOLETE_STAGE1_SERVICE_PARAMETERS_PRESENT:"+",".join(obsolete))
    log_path=root/"authority-user.log"
    def log(msg):
        line=time.strftime("%Y-%m-%d %H:%M:%S")+" "+str(msg)+"\n"
        with log_path.open("a",encoding="utf-8",newline="\n") as f:f.write(line)
    service=create_production_service(
        protected_root=str(root),expected_service_principal=cfg["userSid"],
        peer_principals={cfg["peerId"]:cfg["userSid"]},
        peer_public_keys={cfg["peerId"]:cfg["peerPublicKeyB64"]},
        github_app_id=1,github_installation_id=1,
        github_private_key_file=cfg["githubPrivateKeyFile"],
        receipt_signing_key_file=cfg["receiptSigningKeyFile"],
        allowed_repositories=[cfg["repository"]],github_enabled=False,
    )
    server=WindowsNamedPipeServer(service=service,boundary=service.boundary,protected_root=root,
                                  allowed_peer_sids={cfg["userSid"]},max_instances=4,
                                  preauth_timeout_ms=1000,handler_timeout_ms=300000,poll_interval=0.01,
                                  pipe_name=cfg["pipeName"])
    server.start()
    atomic_json(root/"authority.pid.json",{"schema":1,"pid":os.getpid(),"creationFileTime":creation_filetime(),
                "executable":str(Path(sys.executable).resolve()),"script":str(Path(__file__).resolve()),"startedAt":time.time()})
    log("authority started")
    try:
        while True:
            try:
                rows=server.serve_batch()
                for row in rows:
                    if isinstance(row,AuthorityError) and row.code not in {"IPC_PREAUTH_TIMEOUT","IPC_CLIENT_DISCONNECTED"}:
                        log(f"authority batch error code={row.code} detail={row}")
            except AuthorityError as ex:
                log(f"authority server error code={ex.code} detail={ex}")
                if ex.code=="IPC_ALL_INSTANCES_QUARANTINED":
                    raise SystemExit(42)
                time.sleep(0.05)
    finally:
        try:server.close()
        except Exception as ex:log("authority close error "+repr(ex))
        try:(root/"authority.pid.json").unlink()
        except OSError:pass
        log("authority stopped")
if __name__=="__main__":main()
