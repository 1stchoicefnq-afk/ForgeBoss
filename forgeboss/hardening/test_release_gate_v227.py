from __future__ import annotations
import tempfile,unittest
from pathlib import Path
import forgeboss.hardening.release_gate_v227 as gate

class ReleaseGateBehaviorTests(unittest.TestCase):
 def source(self,text,suffix):
  td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);p=Path(td.name)/("mutant"+suffix);p.write_text(text,encoding="utf-8");return p

 def test_python_comment_marker_cannot_substitute_for_budget_behavior(self):
  marker="budget_usd must be a finite number"
  text=f"# {marker}\ndef unrelated():\n return {marker!r}\n"
  self.assertIn(marker,text)  # reproduces the legacy false-PASS mechanism
  p=self.source(text,".py")
  with self.assertRaises(gate.GateFailure):gate.check_dashboard_budget_behavior(p)

 def test_dead_unknown_paid_fatal_branch_is_rejected(self):
  text="""def _run_session_impl(settings):
 while False:
  code=1;report={'api_calls':1,'fatal_failure':{'reason':'x'}}
  if code!=0 and report and int(report.get('api_calls') or 0)>0 and report.get('fatal_failure'):
   if not any(x in 'x' for x in ('PROVIDER_RATE_LIMIT_TRANSIENT','PROVIDER_5XX_TRANSIENT')):
    save_status(stage='INFRA_ERROR')
    break
"""
  p=self.source(text,".py")
  with self.assertRaises(gate.GateFailure):gate.check_unknown_paid_fatal_semantics(p)

 @unittest.skipUnless(gate.find_powershell(),"PowerShell runtime unavailable")
 def test_provider_marker_literal_cannot_substitute_for_fail_closed_behavior(self):
  marker="PROVIDER_BUDGET_UNSUPPORTED"
  text=f"""function Invoke-Claude([string]$Instructions,[object]$Payload){{
  $note='{marker}'
  return @{{ok=$true}}
}}
"""
  self.assertIn(marker,text)  # legacy marker gate would pass
  p=self.source(text,".ps1")
  with self.assertRaises(gate.GateFailure):gate.check_ps_provider_budget_fail_closed(p)

 @unittest.skipUnless(gate.find_powershell(),"PowerShell runtime unavailable")
 def test_output_reserve_marker_comment_cannot_substitute_for_accounting(self):
  marker="$reserveOut=$RequestedOutputTokens"
  text=f"""function Assert-EstimatedCallFitsBudget([string]$Body,[int]$RequestedOutputTokens){{
  # {marker}
  return
}}
"""
  self.assertIn(marker,text)  # legacy marker gate would pass
  p=self.source(text,".ps1")
  with self.assertRaises(gate.GateFailure):gate.check_ps_output_reservation(p)

 @unittest.skipUnless(gate.find_powershell(),"PowerShell runtime unavailable")
 def test_review_marker_literal_cannot_substitute_for_ledger_block(self):
  marker="REVIEW_BUDGET_LEDGER_REQUIRED"
  text=f"""function Invoke-OpenAIReview([string]$Instructions,[object]$Payload){{ $x='{marker}'; return @{{}} }}
function Invoke-ClaudeReview([string]$Instructions,[object]$Payload){{ $x='{marker}'; return @{{}} }}
"""
  self.assertIn(marker,text)
  p=self.source(text,".ps1")
  with self.assertRaises(gate.GateFailure):gate.check_ps_review_ledger_fail_closed(p)

 @unittest.skipUnless(gate.find_powershell(),"PowerShell runtime unavailable")
 def test_utc_rollover_executes_live_get_today_cost(self):
  gate.check_ps_utc_rollover()

 @unittest.skipUnless(gate.find_powershell(),"PowerShell runtime unavailable")
 def test_local_clock_or_constant_cannot_substitute_for_utc_rollover(self):
  text="""function Get-TodayCost {
  $today=[DateTimeOffset]::Now.ToString('yyyy-MM-dd')
  return 3.75
}
"""
  p=self.source(text,".ps1")
  with self.assertRaises(gate.GateFailure):gate.check_ps_utc_rollover(p)

 @unittest.skipUnless(gate.find_powershell(),"PowerShell runtime unavailable")
 def test_dead_utc_marker_plus_constant_cannot_substitute_for_rollover(self):
  text="""function Get-TodayCost {
  if($false){$unused=[DateTimeOffset]::UtcNow.ToString('yyyy-MM-dd')}
  return 3.75
}
"""
  p=self.source(text,".ps1")
  with self.assertRaises(gate.GateFailure):gate.check_ps_utc_rollover(p)

 def test_release_summary_is_runtime_counted_not_hardcoded(self):
  source=Path(gate.__file__).read_text(encoding="utf-8")
  self.assertNotIn("PASS=13 FAIL=0",source)
  self.assertIn("len(failed)",source)

if __name__=="__main__":unittest.main()