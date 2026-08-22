from __future__ import annotations
import tempfile,threading,unittest
from pathlib import Path
from forgeboss.safety.cost_ledger import CostLedger

class CostLedgerSettlementTests(unittest.TestCase):
 def ledger(self,cap=.20):
  path=Path(tempfile.mkdtemp())/'costs.db';ledger=CostLedger(path);ledger.set_budget('owner',cap);return path,ledger
 def row(self,ledger,rid):
  return ledger.db.execute("SELECT reserved,actual,status FROM reservations WHERE id=?",(rid,)).fetchone()
 def test_over_reservation_settlement_is_rejected_and_reservation_preserved(self):
  _,ledger=self.ledger();rid=ledger.reserve('owner',.15)
  with self.assertRaisesRegex(RuntimeError,'BUDGET_SETTLEMENT_DENIED'):ledger.settle(rid,.30)
  self.assertEqual(self.row(ledger,rid),(.15,None,'reserved'))
 def test_exact_reserved_actual_settles(self):
  _,ledger=self.ledger();rid=ledger.reserve('owner',.15);ledger.settle(rid,.15)
  self.assertEqual(self.row(ledger,rid),(.15,.15,'settled'))
 def test_lower_actual_settles_truthfully(self):
  _,ledger=self.ledger();rid=ledger.reserve('owner',.15);ledger.settle(rid,.10)
  self.assertEqual(self.row(ledger,rid),(.15,.10,'settled'))
 def test_exact_cap_settlement_succeeds(self):
  _,ledger=self.ledger();a=ledger.reserve('owner',.05);b=ledger.reserve('owner',.15);ledger.settle(a,.05);ledger.settle(b,.15)
  used=ledger.db.execute("SELECT SUM(actual) FROM reservations WHERE status='settled'").fetchone()[0]
  self.assertAlmostEqual(used,.20)
 def test_repeated_settlement_is_rejected_without_mutation(self):
  _,ledger=self.ledger();rid=ledger.reserve('owner',.15);ledger.settle(rid,.10)
  with self.assertRaisesRegex(RuntimeError,'BUDGET_RESERVATION_ALREADY_SETTLED'):ledger.settle(rid,.05)
  self.assertEqual(self.row(ledger,rid),(.15,.10,'settled'))
 def test_unknown_reservation_is_rejected(self):
  _,ledger=self.ledger()
  with self.assertRaisesRegex(RuntimeError,'BUDGET_RESERVATION_UNKNOWN'):ledger.settle('missing',.10)
 def test_concurrent_settlements_serialize_budget_check(self):
  path,seed=self.ledger();r1=seed.reserve('owner',.10);r2=seed.reserve('owner',.10);seed.db.close()
  barrier=threading.Barrier(2);out={}
  def settle(name,rid,actual):
   ledger=CostLedger(path);barrier.wait()
   try:ledger.settle(rid,actual);out[name]='ok'
   except RuntimeError as exc:out[name]=str(exc)
   finally:ledger.db.close()
  t1=threading.Thread(target=settle,args=('exact',r1,.10));t2=threading.Thread(target=settle,args=('over',r2,.15));t1.start();t2.start();t1.join();t2.join()
  self.assertEqual(out['exact'],'ok');self.assertEqual(out['over'],'BUDGET_SETTLEMENT_DENIED')
  verify=CostLedger(path);rows=verify.db.execute("SELECT id,actual,status FROM reservations ORDER BY id").fetchall();verify.db.close()
  state={rid:(actual,status) for rid,actual,status in rows};self.assertEqual(state[r1],(.10,'settled'));self.assertEqual(state[r2],(None,'reserved'))

if __name__=='__main__':unittest.main()
