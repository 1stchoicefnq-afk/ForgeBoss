from pathlib import Path
import tempfile,math
ROOT=Path(__file__).resolve().parents[2]
from forgeboss.safety.numbers import finite_number
from forgeboss.safety.cost_ledger import CostLedger
from forgeboss.safety.operation import new_operation_id,verify_result_id
for x in ["NaN","Infinity","-Infinity"]:
 try:finite_number(x);raise AssertionError(x)
 except ValueError:pass
with tempfile.TemporaryDirectory() as td:
 l=CostLedger(Path(td)/"c.db");l.set_budget("owner",.2);a=l.reserve("owner",.15)
 try:l.reserve("owner",.1);raise AssertionError("overspend")
 except RuntimeError:pass
 l.settle(a,.1)
oid=new_operation_id();verify_result_id({"operation_id":oid},oid)
try:verify_result_id({"operation_id":"old"},oid);raise AssertionError("stale")
except ValueError:pass
sv=(ROOT/"dashboard"/"server.py").read_text();rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig");rv=(ROOT/"SiteBoss-Rat-Review.ps1").read_text(encoding="utf-8-sig")
assert "budget_usd must be a finite number" in sv
assert "unknown paid fatal; fail closed" in sv
assert "$reserveOut=$RequestedOutputTokens" in rr
assert "UtcNow.ToString('yyyy-MM-dd')" in rr
assert "PROVIDER_BUDGET_UNSUPPORTED" in rr
assert "REVIEW_BUDGET_LEDGER_REQUIRED" in rv
assert "INSERT OR REPLACE INTO task_runs" not in (ROOT/"forgeboss"/"control"/"store.py").read_text()
assert "os.O_EXCL" in (ROOT/"forgeboss"/"control"/"envelope.py").read_text()
print("FORGEBOSS v2.2.7 RELEASE GATE PASS=13 FAIL=0")
