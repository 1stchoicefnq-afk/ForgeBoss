import sqlite3,uuid
from .numbers import finite_number
class CostLedger:
 def __init__(self,path):
  self.db=sqlite3.connect(str(path),isolation_level=None,timeout=15)
  self.db.executescript("CREATE TABLE IF NOT EXISTS budgets(scope TEXT PRIMARY KEY,cap REAL);CREATE TABLE IF NOT EXISTS reservations(id TEXT PRIMARY KEY,scope TEXT,reserved REAL,actual REAL,status TEXT);")
 def set_budget(self,s,c):self.db.execute("INSERT INTO budgets VALUES(?,?) ON CONFLICT(scope) DO UPDATE SET cap=excluded.cap",(s,finite_number(c,"budget",0)))
 def reserve(self,s,a):
  a=finite_number(a,"reservation",0);self.db.execute("BEGIN IMMEDIATE")
  try:
   cap=self.db.execute("SELECT cap FROM budgets WHERE scope=?",(s,)).fetchone();used=self.db.execute("SELECT COALESCE(SUM(CASE WHEN status='settled' THEN actual ELSE reserved END),0) FROM reservations WHERE scope=? AND status IN ('reserved','settled')",(s,)).fetchone()[0]
   if cap and used+a>cap[0]+1e-12:raise RuntimeError("BUDGET_RESERVATION_DENIED")
   rid=str(uuid.uuid4());self.db.execute("INSERT INTO reservations VALUES(?,?,?,NULL,'reserved')",(rid,s,a));self.db.execute("COMMIT");return rid
  except Exception:self.db.execute("ROLLBACK");raise
 def settle(self,rid,a):self.db.execute("UPDATE reservations SET actual=?,status='settled' WHERE id=? AND status='reserved'",(finite_number(a,"actual",0),rid))
