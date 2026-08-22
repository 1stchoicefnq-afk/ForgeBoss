from pathlib import Path
import tempfile,time
from .store import ControlStore
from .envelope import sign_envelope,verify_envelope

with tempfile.TemporaryDirectory() as td:
    store=ControlStore(Path(td)/"db.sqlite")
    task=store.create_task({"taskId":"T1","repository":"owner/repo","purpose":"test","baseSha":"a"*40,"allowedPaths":["src/a.js"],"requiredTests":["npm test"],"budgetUsd":.2})
    assert task["status"]=="queued"
    lease=store.claim_workspace("T1","R1",str(Path(td)/"wt"),"fix/test","a"*40,ttl_seconds=60,runtime_id="repair-rat",worktree_root=Path(td))
    assert lease["owner_epoch"]==1
    store.assert_writer("T1","R1",1,"a"*40)
    try:store.assert_writer("T1","R1",0)
    except PermissionError:pass
    else:raise AssertionError("stale epoch accepted")
    store.release("T1","R1",1,"b"*40,"succeeded")
    lease2=store.claim_workspace("T1","R2",str(Path(td)/"wt2"),"fix/test2","b"*40,ttl_seconds=60,runtime_id="mini-swe",worktree_root=Path(td))
    assert lease2["owner_epoch"]==2
    secret=b"x"*32
    env=sign_envelope({"envelopeVersion":1,"protocolVersion":1,"taskId":"T1","repository":"owner/repo","baseSha":"a"*40,
      "branch":"fix/test","worktreePath":str(Path(td)/"wt2"),"runId":"R2","attempt":1,"ownerEpoch":2,
      "runtime":{"adapter":"mini-swe"},"allowedPaths":["src/a.js"],"deniedPaths":[],"allowedTools":["file.edit"],
      "contextBundleHash":"sha256:test","transcript":{},"events":{},"budgetUsd":.2,"expiresAt":time.time()+60},secret)
    assert verify_envelope(env,secret)["ownerEpoch"]==2
    bad=dict(env);bad["ownerEpoch"]=1
    try:verify_envelope(bad,secret)
    except PermissionError:pass
    else:raise AssertionError("tampered envelope accepted")
    snap=store.snapshot()
    assert snap["lastEventSeq"]>=3
print("FORGEBOSS v2.0 CONTROL PLANE SELFTEST PASS")
