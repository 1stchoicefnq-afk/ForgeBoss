from __future__ import annotations
import ast,json,math,shutil,sqlite3,subprocess,tempfile
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]

class GateFailure(AssertionError):pass

def require(value,message):
 if not value:raise GateFailure(message)

def expect_raises(exc,fn,message):
 try:fn()
 except exc:return
 except Exception as e:raise GateFailure(f"{message}: wrong exception {type(e).__name__}: {e}") from e
 raise GateFailure(message)

def load_python_function(path,name,namespace=None):
 path=Path(path);tree=ast.parse(path.read_text(encoding="utf-8-sig"),filename=str(path))
 nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name]
 require(len(nodes)==1,f"expected exactly one live top-level Python function {name}")
 module=ast.Module(body=[nodes[0]],type_ignores=[]);ast.fix_missing_locations(module)
 ns=dict(namespace or {});exec(compile(module,str(path),"exec"),ns)
 return ns[name]

def _parents(tree):
 out={}
 for parent in ast.walk(tree):
  for child in ast.iter_child_nodes(parent):out[child]=parent
 return out

def _dead_ancestor(node,parents):
 cur=node
 while cur in parents:
  cur=parents[cur]
  if isinstance(cur,(ast.If,ast.While)) and isinstance(cur.test,ast.Constant) and not bool(cur.test.value):return True
 return False

def _inside_loop(node,parents):
 cur=node
 while cur in parents:
  cur=parents[cur]
  if isinstance(cur,(ast.For,ast.AsyncFor,ast.While)):return True
 return False

def _report_get_keys(node):
 keys=set()
 for n in ast.walk(node):
  if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=="get" and n.args and isinstance(n.args[0],ast.Constant) and isinstance(n.args[0].value,str):keys.add(n.args[0].value)
 return keys

def check_unknown_paid_fatal_semantics(path=ROOT/"dashboard"/"server.py"):
 path=Path(path);tree=ast.parse(path.read_text(encoding="utf-8-sig"),filename=str(path));parents=_parents(tree)
 funcs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="_run_session_impl"]
 require(len(funcs)==1,"dashboard _run_session_impl live function missing")
 for node in ast.walk(funcs[0]):
  if not isinstance(node,ast.If) or _dead_ancestor(node,parents) or not _inside_loop(node,parents):continue
  keys=_report_get_keys(node.test)
  if not {"api_calls","fatal_failure"}.issubset(keys):continue
  code_nonzero=any(isinstance(n,ast.Compare) and isinstance(n.left,ast.Name) and n.left.id=="code" and any(isinstance(op,ast.NotEq) for op in n.ops) and any(isinstance(c,ast.Constant) and c.value==0 for c in n.comparators) for n in ast.walk(node.test))
  if not code_nonzero:continue
  save_infra=False
  for n in ast.walk(node):
   if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=="save_status":
    if any(k.arg=="stage" and isinstance(k.value,ast.Constant) and k.value.value=="INFRA_ERROR" for k in n.keywords):save_infra=True
  constants={n.value for n in ast.walk(node) if isinstance(n,ast.Constant) and isinstance(n.value,str)}
  has_break=any(isinstance(n,ast.Break) for n in ast.walk(node))
  if save_infra and has_break and {"PROVIDER_RATE_LIMIT_TRANSIENT","PROVIDER_5XX_TRANSIENT"}.issubset(constants):return
 raise GateFailure("unknown paid fatal path is not behavior-bound to fail-closed INFRA_ERROR + break semantics")

def find_powershell():
 for name in ("pwsh","powershell.exe","powershell"):
  exe=shutil.which(name)
  if exe:return exe
 return None

def _psq(value):return "'"+str(value).replace("'","''")+"'"

def run_ps_function(source_path,function_name,prelude="",invocation="",ast_assertion=""):
 exe=find_powershell()
 if not exe:raise GateFailure("PowerShell runtime unavailable; Windows release invariants cannot be proven")
 source_path=Path(source_path).resolve()
 script=f"""$ErrorActionPreference='Stop'
try {{
 $source={_psq(source_path)}
 $name={_psq(function_name)}
 $tokens=$null;$errors=$null
 $ast=[System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
 if(@($errors).Count -gt 0){{throw ('PowerShell parse failed: '+(@($errors|ForEach-Object{{$_.Message}})-join'; '))}}
 $defs=@($ast.FindAll({{param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name}},$true))
 if($defs.Count -ne 1){{throw "expected exactly one live PowerShell function $name; found $($defs.Count)"}}
 $fnAst=$defs[0]
 {ast_assertion}
 Invoke-Expression $fnAst.Extent.Text
 {prelude}
 {invocation}
 Write-Output '__FORGEBOSS_GATE_OK__'
 exit 0
}} catch {{
 [Console]::Error.WriteLine($_.Exception.Message)
 exit 1
}}
"""
 with tempfile.TemporaryDirectory() as td:
  harness=Path(td)/"gate.ps1";harness.write_text(script,encoding="utf-8-sig")
  cp=subprocess.run([exe,"-NoLogo","-NoProfile","-NonInteractive","-File",str(harness)],capture_output=True,text=True,timeout=60)
 if cp.returncode!=0 or "__FORGEBOSS_GATE_OK__" not in cp.stdout:
  detail=(cp.stderr or cp.stdout).strip()[-2000:]
  raise GateFailure(f"PowerShell behavior check failed for {function_name}: {detail}")
 return cp.stdout

def check_dashboard_budget_behavior(path=ROOT/"dashboard"/"server.py"):
 fn=load_python_function(path,"normalize_session_budget",{"math":math,"MAX_SESSION_BUDGET_USD":10.0})
 for value in ("bad",float("nan"),float("inf"),float("-inf")):
  expect_raises(ValueError,lambda value=value:fn(value),f"dashboard accepted non-finite budget {value!r}")
 expect_raises(ValueError,lambda:fn(0.09),"dashboard accepted budget below minimum")
 expect_raises(ValueError,lambda:fn(10.01),"dashboard accepted budget above maximum")
 require(fn("1.25")==1.25,"dashboard rejected/altered valid finite budget")

def check_secret_exclusive_collision():
 from forgeboss.control import envelope
 with tempfile.TemporaryDirectory() as td:
  root=Path(td);p=root/"state"/"forgebossd"/"daemon-secret.bin";p.parent.mkdir(parents=True);original=b"A"*32;p.write_bytes(original)
  real_exists=Path.exists
  def stale_exists(self):
   if Path(self)==p:return False
   return real_exists(self)
  with mock.patch.object(Path,"exists",stale_exists):
   got_path,data=envelope.secret_file(root)
  require(Path(got_path)==p,"secret_file returned wrong path after collision")
  require(data==original and p.read_bytes()==original,"exclusive-create collision overwrote existing daemon secret")

def check_duplicate_task_run_behavior():
 from forgeboss.control.store import ControlStore
 with tempfile.TemporaryDirectory() as td:
  root=Path(td);store=ControlStore(root/"control.db")
  try:
   task={"taskId":"t1","repository":"owner/repo","purpose":"gate","baseSha":"abc","allowedPaths":["src/x"],"requiredTests":[],"budgetUsd":1}
   store.create_task(task)
   expect_raises(sqlite3.IntegrityError,lambda:store.create_task(task),"duplicate task identity overwrote existing task")
   require(store.get_task("t1")["purpose"]=="gate","duplicate task mutated existing row")
   workroot=root/"worktrees";workroot.mkdir();w1=workroot/"one";w2=workroot/"two";w1.mkdir();w2.mkdir()
   store.claim_workspace("t1","run-1",w1,"b1","abc",runtime_id="r",worktree_root=workroot)
   store.release("t1","run-1",1,outcome="released")
   before=dict(store.db.execute("SELECT * FROM task_runs WHERE run_id='run-1'").fetchone())
   expect_raises(sqlite3.IntegrityError,lambda:store.claim_workspace("t1","run-1",w2,"b2","abc",runtime_id="r",worktree_root=workroot),"duplicate run identity overwrote existing run")
   rows=store.db.execute("SELECT * FROM task_runs WHERE run_id='run-1'").fetchall()
   require(len(rows)==1,"duplicate run identity created multiple rows")
   after=dict(rows[0]);require(after["started_at"]==before["started_at"] and after["status"]==before["status"],"duplicate run overwrote prior run evidence")
  finally:store.db.close()

def check_ps_output_reservation(path=ROOT/"SiteBoss-Repair-Rat.ps1"):
 prelude="""$script:Usage=[ordered]@{estimated_usd=0.0}
function Get-OpenAIPricing { [pscustomobject]@{input=0.0;cached=0.0;output=1000000.0} }
function Get-RunBudgetLimit { return 5.0 }
function Log { param([string]$Message,[string]$Color='Gray') }
"""
 invocation="""$blocked=$false
try { Assert-EstimatedCallFitsBudget '' 6 } catch { $blocked=$_.Exception.Message.StartsWith('BUDGET PREFLIGHT STOP:') }
if(-not$blocked){throw 'requested output tokens were not reserved against remaining budget'}
Assert-EstimatedCallFitsBudget '' 4
"""
 run_ps_function(path,"Assert-EstimatedCallFitsBudget",prelude,invocation)

def check_ps_utc_rollover(path=ROOT/"SiteBoss-Repair-Rat.ps1"):
 prelude="""$Root=[IO.Path]::GetTempPath()
$script:fbGateToday=[DateTimeOffset]::UtcNow.ToString('yyyy-MM-dd')
$script:fbGateOld=[DateTimeOffset]::UtcNow.AddDays(-1).ToString('yyyy-MM-dd')
$script:fbGateA=1000.0+[double]$PID
$script:fbGateB=2000.0+([double]$PID/2.0)
$script:fbGateExpected=$script:fbGateA+$script:fbGateB
function Test-Path { param([string]$LiteralPath) return $true }
function Get-ChildItem {
 [CmdletBinding()]
 param([string]$LiteralPath,[switch]$File,[string]$Filter)
 if($LiteralPath -match 'repair-rat$'){
  return @([pscustomobject]@{FullName='today-repair.json'},[pscustomobject]@{FullName='old-repair.json'})
 }
 if($LiteralPath -match 'rat-review$'){
  return @([pscustomobject]@{FullName='today-review.json'})
 }
 return @()
}
function Get-Content {
 param([string]$LiteralPath,[switch]$Raw)
 switch($LiteralPath){
  'today-repair.json' { return (@{generated_at=($script:fbGateToday+'T00:00:00Z');usage_estimated_usd=$script:fbGateA}|ConvertTo-Json -Compress) }
  'today-review.json' { return (@{generated_at=($script:fbGateToday+'T23:59:59Z');usage_estimated_usd=$script:fbGateB}|ConvertTo-Json -Compress) }
  'old-repair.json' { return (@{generated_at=($script:fbGateOld+'T23:59:59Z');usage_estimated_usd=999999999}|ConvertTo-Json -Compress) }
  default { throw "unexpected fixture path: $LiteralPath" }
 }
}
"""
 ast_check="""$utc=@($fnAst.FindAll({param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and "$($n.Member.Value)" -eq 'UtcNow' -and "$($n.Expression.Extent.Text)" -match 'DateTimeOffset'},$true))
if($utc.Count -lt 1){throw 'Get-TodayCost is not bound to DateTimeOffset.UtcNow in the live function AST'}
"""
 invocation="""$v=[double](Get-TodayCost)
if([Math]::Abs($v-$script:fbGateExpected)-gt0.0001){throw "UTC cost rollover/counting failed: actual=$v expected=$script:fbGateExpected"}
"""
 run_ps_function(path,"Get-TodayCost",prelude,invocation,ast_check)

def check_ps_provider_budget_fail_closed(path=ROOT/"SiteBoss-Repair-Rat.ps1"):
 prelude="""$script:ApiCalls=0
$script:network=$false
$Config=@{AnthropicModel='test'}
function Invoke-WebRequest { $script:network=$true; throw 'NETWORK_CALLED' }
"""
 invocation="""$msg=''
try { Invoke-Claude 'test' @{} | Out-Null } catch { $msg=$_.Exception.Message }
if(-not$msg.StartsWith('PROVIDER_BUDGET_UNSUPPORTED:')){throw "Anthropic paid path did not fail closed at budget gate: $msg"}
if($script:ApiCalls-ne0-or$script:network){throw 'provider fail-closed check allowed paid/network side effect'}
"""
 run_ps_function(path,"Invoke-Claude",prelude,invocation)

def _check_review_function(path,name):
 prelude="""$script:network=$false
function Invoke-WebRequest { $script:network=$true; throw 'NETWORK_CALLED' }
"""
 invocation=f"""$msg=''
try {{ {name} 'test' @{{}} | Out-Null }} catch {{ $msg=$_.Exception.Message }}
if(-not$msg.StartsWith('REVIEW_BUDGET_LEDGER_REQUIRED:')){{throw "paid reviewer did not fail closed at ledger gate: $msg"}}
if($script:network){{throw 'review-ledger gate allowed network side effect'}}
"""
 run_ps_function(path,name,prelude,invocation)

def check_ps_review_ledger_fail_closed(path=ROOT/"SiteBoss-Rat-Review.ps1"):
 _check_review_function(path,"Invoke-OpenAIReview");_check_review_function(path,"Invoke-ClaudeReview")

def check_finite_numbers():
 from forgeboss.safety.numbers import finite_number
 for value in ("NaN","Infinity","-Infinity",float("nan"),float("inf")):
  expect_raises(ValueError,lambda value=value:finite_number(value),f"finite_number accepted {value!r}")
 require(finite_number("1.25")==1.25,"finite_number rejected valid value")

def check_cost_ledger():
 from forgeboss.safety.cost_ledger import CostLedger
 with tempfile.TemporaryDirectory() as td:
  ledger=CostLedger(Path(td)/"c.db");ledger.set_budget("owner",.2);rid=ledger.reserve("owner",.15)
  expect_raises(RuntimeError,lambda:ledger.reserve("owner",.1),"cost ledger allowed over-reservation")
  expect_raises(RuntimeError,lambda:ledger.settle(rid,.30),"cost ledger allowed over-cap settlement")
  row=ledger.db.execute("SELECT actual,status FROM reservations WHERE id=?",(rid,)).fetchone();require(row==(None,"reserved"),"denied settlement mutated reservation")
  ledger.settle(rid,.1);row=ledger.db.execute("SELECT actual,status FROM reservations WHERE id=?",(rid,)).fetchone();require(row==(.1,"settled"),"valid truthful settlement failed")
  ledger.db.close()

def check_operation_ids():
 from forgeboss.safety.operation import new_operation_id,verify_result_id
 oid=new_operation_id();verify_result_id({"operation_id":oid},oid)
 expect_raises(ValueError,lambda:verify_result_id({"operation_id":"old"},oid),"stale operation id accepted")

def run_gate():
 checks=[
  ("finite-number validation",check_finite_numbers),
  ("transactional cost ledger",check_cost_ledger),
  ("operation-id freshness",check_operation_ids),
  ("dashboard budget normalization",check_dashboard_budget_behavior),
  ("dashboard unknown paid fatal fail-closed",check_unknown_paid_fatal_semantics),
  ("exclusive daemon-secret collision",check_secret_exclusive_collision),
  ("duplicate task/run identity protection",check_duplicate_task_run_behavior),
  ("Repair Rat output-token reservation",check_ps_output_reservation),
  ("Repair Rat UTC daily rollover",check_ps_utc_rollover),
  ("Repair Rat unsupported-provider budget block",check_ps_provider_budget_fail_closed),
  ("Rat Review authoritative-ledger block",check_ps_review_ledger_fail_closed),
 ]
 passed=0;failed=[]
 for name,fn in checks:
  try:fn();passed+=1;print(f"[PASS] {name}")
  except Exception as e:failed.append((name,e));print(f"[FAIL] {name}: {type(e).__name__}: {e}")
 print(f"FORGEBOSS v2.2.7 RELEASE GATE PASS={passed} FAIL={len(failed)}")
 return 2 if failed else 0

def main():return run_gate()

if __name__=="__main__":raise SystemExit(main())