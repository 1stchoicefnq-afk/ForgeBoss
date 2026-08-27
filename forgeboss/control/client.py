from __future__ import annotations
import json,socket,uuid,time,secrets
from pathlib import Path
from .envelope import secret_file
from .auth import make_connect_proof
ROOT=Path(__file__).resolve().parents[2]
HOST="127.0.0.1";PORT=18765

class Client:
    def __init__(self,host=HOST,port=PORT,timeout=5):
        self.s=socket.create_connection((host,port),timeout=timeout)
        self.f=self.s.makefile("rwb")
        _,secret=secret_file(ROOT)
        cp={"protocolVersion":1,"client":"forgeboss-cli","capabilities":["tasks","leases"],"timestamp":int(time.time()),"nonce":secrets.token_hex(16)}
        cp["authProof"]=make_connect_proof(cp,secret)
        self.call("connect",cp,mutation=False)
    def call(self,method,params=None,mutation=None):
        if mutation is None:mutation=method in {"task.create","workspace.claim","workspace.heartbeat","workspace.release","worker.admit"}
        obj={"type":"req","id":uuid.uuid4().hex,"method":method,"params":params or {}}
        if mutation:obj["idempotencyKey"]=uuid.uuid4().hex
        self.f.write((json.dumps(obj,separators=(",",":"))+"\n").encode("utf-8"));self.f.flush()
        res=json.loads(self.f.readline().decode("utf-8"))
        if not res.get("ok"):raise RuntimeError(f"{res.get('error',{}).get('code')}: {res.get('error',{}).get('message')}")
        return res.get("payload",{})
    def close(self):
        try:self.f.close()
        finally:self.s.close()

def protected_worker_launch_signer(transport,trust,required_generation=None):
    """Create the narrow protected signer client without loading any private signing key."""
    from .authority import WorkerLaunchSignerClient
    return WorkerLaunchSignerClient(transport,trust,required_generation=required_generation)
