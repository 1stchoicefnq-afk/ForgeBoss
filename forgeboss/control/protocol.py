from __future__ import annotations
import json

PROTOCOL_MIN=1
PROTOCOL_MAX=1
MAX_FRAME_BYTES=256*1024
MUTATIONS={"task.create","task.create_governed","task.cancel","workspace.claim","workspace.heartbeat","workspace.release","worker.admit"}

class ProtocolError(RuntimeError):
    def __init__(self,code,message):
        super().__init__(message);self.code=code

def parse_frame(line:bytes):
    if len(line)>MAX_FRAME_BYTES:raise ProtocolError("FRAME_TOO_LARGE","frame exceeds 256 KiB")
    try:obj=json.loads(line.decode("utf-8"))
    except Exception as e:raise ProtocolError("INVALID_JSON",str(e))
    if not isinstance(obj,dict):raise ProtocolError("INVALID_FRAME","frame must be object")
    if obj.get("type")!="req":raise ProtocolError("INVALID_FRAME","type must be req")
    if not isinstance(obj.get("id"),str) or not obj["id"]:raise ProtocolError("INVALID_FRAME","request id required")
    if not isinstance(obj.get("method"),str) or not obj["method"]:raise ProtocolError("INVALID_FRAME","method required")
    params=obj.get("params",{})
    if not isinstance(params,dict):raise ProtocolError("INVALID_FRAME","params must be object")
    if obj["method"] in MUTATIONS and not isinstance(obj.get("idempotencyKey"),str):
        raise ProtocolError("IDEMPOTENCY_REQUIRED","mutation requires idempotencyKey")
    return obj

def response(req_id,ok,payload=None,error=None):
    out={"type":"res","id":req_id,"ok":bool(ok)}
    if ok:out["payload"]=payload or {}
    else:out["error"]=error or {"code":"UNKNOWN","message":"unknown error"}
    return out