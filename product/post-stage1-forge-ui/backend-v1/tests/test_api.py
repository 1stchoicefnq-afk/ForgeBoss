from __future__ import annotations

import json
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from backend.api_server import serve


def request(url, method="GET", body=None, token=None, origin=None):
    data=None if body is None else json.dumps(body).encode("utf-8")
    headers={}
    if body is not None: headers["Content-Type"]="application/json"
    if token: headers["X-ForgeBoss-Token"]=token
    if origin: headers["Origin"]=origin
    req=urllib.request.Request(url,data=data,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=3) as r:
            return r.status,json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code,json.loads(e.read())


def test_api_boundary():
    with tempfile.TemporaryDirectory() as td:
        srv=serve(port=0,data_root=Path(td)/"state")
        th=threading.Thread(target=srv.serve_forever,daemon=True); th.start()
        base=f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            status,tok=request(base+"/api/session-token")
            assert status==200 and tok["token"]
            token=tok["token"]

            status,bad=request(base+"/api/project/register","POST",{"name":"Demo","project_root":td})
            assert status==403
            status,bad=request(base+"/api/project/register","POST",{"name":"Demo","project_root":td},token,origin="https://evil.example")
            assert status==403

            status,reg=request(base+"/api/project/register","POST",{"name":"Demo","project_root":td},token,origin=base)
            assert status==201
            pid,cid=reg["project_id"],reg["conversation_id"]
            assert srv.backend.memory.get_project_root(pid)==str(Path(td).resolve())

            secret="sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
            status,msg=request(base+"/api/chat/message","POST",{"project_id":pid,"conversation_id":cid,"role":"user","content":"key="+secret},token,origin=base)
            assert status==201
            status,ctx=request(base+f"/api/project/context?project_id={pid}")
            assert status==200
            encoded=json.dumps(ctx)
            assert secret not in encoded and "[REDACTED-SECRET]" in encoded

            status,prop=request(base+"/api/bible/propose","POST",{"project_id":pid,"bible_key":"RULES","content":"Do not delete data"},token,origin=base)
            assert status==201
            status,denied=request(base+"/api/bible/activate","POST",{"entry_id":prop["entry_id"],"owner_approved":False},token,origin=base)
            assert status==400
            status,ok=request(base+"/api/bible/activate","POST",{"entry_id":prop["entry_id"],"owner_approved":True},token,origin=base)
            assert status==200

            status,vault=request(base+"/api/vault/store","POST",{"provider":"OpenAI","secret":secret},token,origin=base)
            if sys.platform.startswith("win"):
                assert status==201 and secret not in json.dumps(vault)
            else:
                assert status==503
        finally:
            srv.shutdown(); srv.server_close(); srv.backend.close()


if __name__=="__main__":
    test_api_boundary(); print("[PASS] test_api_boundary")
    print("POST-STAGE1 API SELFTEST PASS=1 FAIL=0")
