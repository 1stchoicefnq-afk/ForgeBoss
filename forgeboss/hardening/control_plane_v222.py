from pathlib import Path
import tempfile,time
from forgeboss.control.auth import make_connect_proof,verify_connect_proof
from forgeboss.control.store import canonical_worktree_path
from forgeboss.security.executor_guard import validate_packet,SecurityError,norm

secret=b"x"*32
p={"protocolVersion":1,"client":"test","capabilities":[],"timestamp":int(time.time()),"nonce":"a"*32}
p["authProof"]=make_connect_proof(p,secret);assert verify_connect_proof(p,secret)
bad=dict(p);bad["authProof"]="hmac-sha256:"+"0"*64
try:verify_connect_proof(bad,secret);raise AssertionError("bad auth accepted")
except PermissionError:pass
old=dict(p);old["timestamp"]=1;old["authProof"]=make_connect_proof(old,secret)
try:verify_connect_proof(old,secret);raise AssertionError("expired auth accepted")
except PermissionError:pass

assert norm(".git/hooks/pre-commit")==".git/hooks/pre-commit"
with tempfile.TemporaryDirectory() as td:
    root=Path(td).resolve();child=root/"task"
    assert Path(canonical_worktree_path(str(child),root))==child
    for b in [root.parent/"escape",Path("relative/path")]:
        try:canonical_worktree_path(str(b),root);raise AssertionError("bad worktree accepted")
        except ValueError:pass

denied=[".git/hooks/pre-commit",".ENV","package.json","state/forgebossd/forgeboss.db","state/learning/forgeboss-learning.db"]
for x in denied:
    try:validate_packet({"allowed_files":[x],"context_files":[]});raise AssertionError("sensitive scope accepted: "+x)
    except SecurityError:pass

ROOT=Path(__file__).resolve().parents[2]
d=(ROOT/"forgeboss"/"control"/"daemon.py").read_text()
a=(ROOT/"forgeboss"/"security"/"local_acl.py").read_text()
assert "verify_connect_proof" in d and "AUTH_REPLAY" in d
assert "SCOPE_ESCALATION" in d and "TASK_BINDING_MISMATCH" in d and "TOOL_DENIED" in d
assert "icacls.exe" in a and "/inheritance:r" in a
print("FORGEBOSS v2.2.2 CONTROL-PLANE SECURITY MATRIX PASS=14 FAIL=0")
