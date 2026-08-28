from __future__ import annotations
import argparse,json,sys,time,hashlib
from pathlib import Path

try:
 from forgeboss.autonomy import state_store as ss
except ImportError:
 sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
 from forgeboss.autonomy import state_store as ss

ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"autonomy";STATE.mkdir(parents=True,exist_ok=True)
MEM=STATE/"repair-memory.json"
EMPTY={"schema":1,"entries":[]}
MAX_ENTRIES=500

def load(p):
 try:return json.loads(Path(p).read_text(encoding="utf-8-sig"))
 except:return {}

def entries_of(db):
 xs=db.get("entries")
 return xs if isinstance(xs,list) else []

def record_feedback(db,f):
 sig=f.get("signature")
 xs=entries_of(db)
 # upsert failed strategy evidence
 existing=next((x for x in xs if isinstance(x,dict) and x.get("signature")==sig and x.get("outcome")=="failed"),None)
 if existing:existing["seen_count"]=int(existing.get("seen_count",1))+1;existing["last_seen"]=time.time()
 else:xs.append({"signature":sig,"category":f.get("category"),"outcome":"failed","seen_count":1,"failed_steps":(f.get("acceptance") or {}).get("failed_steps",[]),"last_seen":time.time()})
 db["entries"]=xs[-MAX_ENTRIES:]
 return db

def record_report(db,r):
 xs=entries_of(db)
 for c in r.get("cycles",[]):
  if c.get("passed"):
   sig=hashlib.sha256((str(c.get("exact_head"))+str(c.get("specialists"))+str(c.get("code_diff"))).encode()).hexdigest()
   xs.append({"signature":sig,"category":"unknown","outcome":"proven","specialists":c.get("specialists"),"exact_head":c.get("exact_head"),"last_seen":time.time()})
 db["entries"]=xs[-MAX_ENTRIES:]
 return db

def query(db,q):
 cat=q.get("category");sig=q.get("failure_signature");xs=[x for x in entries_of(db) if isinstance(x,dict)]
 failed=[x for x in xs if x.get("outcome")=="failed" and (x.get("signature")==sig or x.get("category")==cat)][-8:]
 proven=[x for x in xs if x.get("outcome")=="proven" and x.get("category") in (cat,"unknown")][-5:]
 out={"failed_history":failed,"proven_history":proven}
 if db.get("_history_reset_unacknowledged"):
  # Paid-repair history was deliberately discarded during recovery and no
  # controller acknowledgement has cleared it yet; the caller must not treat
  # the empty history as "nothing was ever tried".
  out["history_reset_unacknowledged"]=True
 return out

def fail_closed(exc):
 payload={"fail_closed":True,"error":type(exc).__name__,"detail":str(exc),"failed_history":None,"proven_history":None}
 print(json.dumps(payload,separators=(",",":")))
 print("REPAIR MEMORY FAIL-CLOSED: "+str(exc),file=sys.stderr)
 return ss.exit_code_for(exc)

def main(argv=None):
 ap=argparse.ArgumentParser();ap.add_argument("--feedback");ap.add_argument("--report");ap.add_argument("--query");ns=ap.parse_args(argv)
 try:
  def mutate(db):
   if not isinstance(db.get("entries"),list):db["entries"]=[]
   db.setdefault("schema",1)
   if ns.feedback:
    f=load(ns.feedback)
    if f:record_feedback(db,f)
   if ns.report:
    r=load(ns.report)
    if r:record_report(db,r)
   return db
  if ns.feedback or ns.report:
   db=ss.update_db(MEM,mutate,default=EMPTY)
  else:
   # A pure query must never rewrite shared state.
   db=ss.load_db(MEM,default=EMPTY)
  if ns.query:
   print(json.dumps(query(db,load(ns.query)),separators=(",",":")))
  return 0
 except ss.StateStoreError as exc:
  return fail_closed(exc)
if __name__=="__main__":raise SystemExit(main())
