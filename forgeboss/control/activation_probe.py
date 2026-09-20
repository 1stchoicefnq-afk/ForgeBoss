from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

from .auth import make_connect_proof

_MAX_FRAME=256*1024
_TESTS=(
    ("selftests",("forgeboss.control.test_activation","forgeboss.control.test_known_good")),
    ("multiAgent",("forgeboss.control.test_process_supervisor","forgeboss.control.test_self_build_launcher")),
)
_SECRET_NAMES={
    "OPENAI_API_KEY","LLM_API_KEY","ANTHROPIC_API_KEY","GOOGLE_API_KEY","GEMINI_API_KEY",
    "GH_TOKEN","GITHUB_TOKEN","GITHUB_PAT",
}
_SECRET_PREFIXES=("FORGEBOSS_AUTHORITY_","GITHUB_","GH_")


class ActivationProbeError(RuntimeError):
    pass


def _canonical_digest(value)->str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")).hexdigest()


def _probe_env()->dict[str,str]:
    out={}
    for key,value in os.environ.items():
        upper=key.upper()
        if upper in _SECRET_NAMES or any(upper.startswith(prefix) for prefix in _SECRET_PREFIXES):
            continue
        if upper in {"PYTHONPATH","PYTHONHOME","PYTHONSTARTUP","PYTHONINSPECT"} or upper.startswith("GIT_"):
            continue
        out[key]=value
    out.update({
        "PYTHONUTF8":"1","PYTHONDONTWRITEBYTECODE":"1",
        "FORGEBOSS_ALLOW_PAID_EXECUTOR":"NO",
        "GIT_TERMINAL_PROMPT":"0","GIT_ASKPASS":"",
    })
    return out


def write_activation_ready(path,*,pid:int,nonce:str,generation:int,host:str,port:int,identity:dict,state_root:str)->dict:
    target=Path(path)
    if not target.is_absolute():
        raise ActivationProbeError("activation ready path must be absolute")
    try:target.parent.resolve(strict=True)
    except Exception as ex:raise ActivationProbeError("activation ready parent missing") from ex
    if target.exists() or target.is_symlink():
        raise ActivationProbeError("activation ready file already exists")
    if isinstance(pid,bool) or not isinstance(pid,int) or pid<=0:
        raise ActivationProbeError("activation ready pid invalid")
    if not isinstance(nonce,str) or len(nonce)<32:
        raise ActivationProbeError("activation ready nonce invalid")
    if isinstance(generation,bool) or not isinstance(generation,int) or generation<=0:
        raise ActivationProbeError("activation ready generation invalid")
    if host!="127.0.0.1" or isinstance(port,bool) or not isinstance(port,int) or not 1<=port<=65535:
        raise ActivationProbeError("activation ready endpoint invalid")
    if not isinstance(identity,dict):
        raise ActivationProbeError("activation ready identity invalid")
    state=Path(state_root)
    if not state.is_absolute():raise ActivationProbeError("activation ready state root invalid")
    state_text=str(state.resolve(strict=False))
    record={"schema":1,"pid":pid,"nonce":nonce,"generation":generation,"host":host,"port":port,"identity":dict(identity),"stateRoot":state_text}
    raw=(json.dumps(record,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode("utf-8")
    flags=os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0)
    try:fd=os.open(str(target),flags,0o600)
    except Exception as ex:raise ActivationProbeError("activation ready file create failed") from ex
    try:
        os.write(fd,raw);os.fsync(fd)
    finally:os.close(fd)
    return record


def read_activation_ready(path,*,timeout:float=10.0)->tuple[dict,str]:
    target=Path(path)
    if not target.is_absolute():
        raise ActivationProbeError("activation ready path must be absolute")
    deadline=time.monotonic()+float(timeout)
    last_error=None
    while time.monotonic()<deadline:
        try:
            if target.is_symlink():
                raise ActivationProbeError("activation ready file must not be a link")
            raw=target.read_bytes()
            if not raw or len(raw)>64*1024:
                raise ActivationProbeError("activation ready file size invalid")
            value=json.loads(raw.decode("utf-8"))
            if not isinstance(value,dict) or set(value)!={"schema","pid","nonce","generation","host","port","identity","stateRoot"}:
                raise ActivationProbeError("activation ready file shape invalid")
            if value.get("schema")!=1:
                raise ActivationProbeError("activation ready file schema invalid")
            if isinstance(value.get("pid"),bool) or not isinstance(value.get("pid"),int) or value["pid"]<=0:
                raise ActivationProbeError("activation ready pid invalid")
            if not isinstance(value.get("nonce"),str) or len(value["nonce"])<32:
                raise ActivationProbeError("activation ready nonce invalid")
            if isinstance(value.get("generation"),bool) or not isinstance(value.get("generation"),int) or value["generation"]<=0:
                raise ActivationProbeError("activation ready generation invalid")
            if value.get("host")!="127.0.0.1":
                raise ActivationProbeError("activation candidate must bind exact loopback host")
            if isinstance(value.get("port"),bool) or not isinstance(value.get("port"),int) or not 1<=value["port"]<=65535:
                raise ActivationProbeError("activation ready port invalid")
            if not isinstance(value.get("identity"),dict):
                raise ActivationProbeError("activation ready identity invalid")
            state=Path(str(value.get("stateRoot") or ""))
            if not state.is_absolute():
                raise ActivationProbeError("activation ready state root invalid")
            value["stateRoot"]=str(state.resolve(strict=False))
            return value,hashlib.sha256(raw).hexdigest()
        except FileNotFoundError as ex:
            last_error=ex
        except (json.JSONDecodeError,UnicodeError) as ex:
            last_error=ex
        time.sleep(0.05)
    if isinstance(last_error,BaseException):
        raise ActivationProbeError("activation ready file did not become readable") from last_error
    raise ActivationProbeError("activation ready file did not become available")


def _recv_frame(f,expected_id:str)->dict:
    raw=f.readline(_MAX_FRAME+1)
    if not raw or len(raw)>_MAX_FRAME:
        raise ActivationProbeError("candidate control response frame invalid")
    try:value=json.loads(raw.decode("utf-8"))
    except Exception as ex:raise ActivationProbeError("candidate control response is not JSON") from ex
    if not isinstance(value,dict) or value.get("type")!="res" or value.get("id")!=expected_id:
        raise ActivationProbeError("candidate control response binding mismatch")
    if value.get("ok") is not True:
        err=value.get("error") or {}
        raise ActivationProbeError("candidate control request failed: "+str(err.get("code") or "UNKNOWN"))
    payload=value.get("payload")
    if not isinstance(payload,dict):
        raise ActivationProbeError("candidate control payload invalid")
    return payload


def _send(f,method:str,params:dict)->dict:
    rid=secrets.token_hex(16)
    frame={"type":"req","id":rid,"method":method,"params":params}
    f.write((json.dumps(frame,separators=(",",":"),ensure_ascii=False)+"\n").encode("utf-8"));f.flush()
    return _recv_frame(f,rid)


def probe_control_endpoint(root,host:str,port:int,candidate_identity:dict,*,state_root,timeout:float=5.0)->dict:
    root=Path(root).resolve(strict=True)
    if host!="127.0.0.1" or isinstance(port,bool) or not isinstance(port,int) or not 1<=port<=65535:
        raise ActivationProbeError("candidate control endpoint invalid")
    state=Path(state_root)
    if not state.is_absolute():raise ActivationProbeError("candidate daemon state root invalid")
    state=state.resolve(strict=True)
    try:
        if os.path.normcase(os.path.commonpath([str(root),str(state)]))==os.path.normcase(str(root)):
            raise ActivationProbeError("candidate daemon state root must remain outside code root")
    except ValueError:
        pass
    secret_path=state/"daemon-secret.bin"
    if secret_path.is_symlink():
        raise ActivationProbeError("candidate daemon secret path is a link")
    try:secret=secret_path.read_bytes()
    except Exception as ex:raise ActivationProbeError("candidate daemon secret unavailable") from ex
    if len(secret)<32 or len(secret)>4096:
        raise ActivationProbeError("candidate daemon secret invalid")

    try:
        sock=socket.create_connection((host,port),timeout=float(timeout))
    except Exception as ex:raise ActivationProbeError("candidate control endpoint unavailable") from ex
    try:
        sock.settimeout(float(timeout));f=sock.makefile("rwb")
        cp={"protocolVersion":1,"client":"forgeboss-activation-probe","capabilities":["health","state"],
            "timestamp":int(time.time()),"nonce":secrets.token_hex(16)}
        cp["authProof"]=make_connect_proof(cp,secret)
        connected=_send(f,"connect",cp)
        capabilities=connected.get("capabilities")
        if connected.get("connected") is not True or not isinstance(capabilities,list):
            raise ActivationProbeError("candidate control connect proof invalid")
        health=_send(f,"health",{})
        if health.get("status")!="HEALTHY":
            raise ActivationProbeError("candidate health is not HEALTHY")
        try:db_parent=Path(str(health.get("db") or "")).resolve(strict=False).parent
        except Exception as ex:raise ActivationProbeError("candidate health DB path invalid") from ex
        if db_parent!=state:
            raise ActivationProbeError("candidate health state root mismatch")
        identity=health.get("identity")
        if not isinstance(identity,dict):
            raise ActivationProbeError("candidate health identity missing")
        for key in ("revision","manifestSha256","treeSha256","identitySha256"):
            if identity.get(key)!=candidate_identity.get(key):
                raise ActivationProbeError("candidate health identity mismatch: "+key)
        snapshot=_send(f,"state.snapshot",{})
        for key in ("tasks","leases","workers","budgetRuns"):
            if not isinstance(snapshot.get(key),list):
                raise ActivationProbeError("candidate control snapshot invalid")
        if "smart-parallel" not in capabilities:
            raise ActivationProbeError("candidate multi-agent capability missing")
        return {
            "connected":True,"healthy":True,"control":True,"multiAgentCapability":True,
            "capabilities":sorted(str(x) for x in capabilities),
            "identity":identity,
            "snapshotDigest":_canonical_digest(snapshot),"stateRoot":str(state),
        }
    finally:
        try:f.close()
        except Exception:pass
        try:sock.close()
        except Exception:pass


def run_activation_core_tests(root,*,timeout:float=240.0)->dict:
    root=Path(root).resolve(strict=True)
    rows=[];status={}
    bootstrap=(
        "import sys,unittest;"
        "root=sys.argv[1];mods=sys.argv[2:];sys.path.insert(0,root);"
        "suite=unittest.TestSuite();loader=unittest.defaultTestLoader;"
        "[suite.addTests(loader.loadTestsFromName(m)) for m in mods];"
        "result=unittest.TextTestRunner(verbosity=2).run(suite);"
        "raise SystemExit(0 if result.wasSuccessful() else 1)"
    )
    for label,modules in _TESTS:
        command="python -I -c <activation-test-bootstrap> "+" ".join(modules)
        argv=[sys.executable,"-I","-c",bootstrap,str(root),*modules]
        try:
            p=subprocess.run(argv,cwd=str(root),env=_probe_env(),stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=float(timeout),check=False)
        except Exception as ex:
            raise ActivationProbeError(f"activation {label} test execution failed") from ex
        output=(p.stdout or "")+"\n"+(p.stderr or "")
        row={"label":label,"command":command,"exitCode":int(p.returncode),
             "outputSha256":hashlib.sha256(output.encode("utf-8")).hexdigest()}
        row["receiptSha256"]=_canonical_digest(row);rows.append(row);status[label]=p.returncode==0
    return {"rows":rows,"selftests":bool(status.get("selftests")),"multiAgent":bool(status.get("multiAgent"))}

