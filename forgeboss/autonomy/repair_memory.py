from __future__ import annotations
import argparse,json,sys,time,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from forgeboss.autonomy import state_store
STATE=ROOT/"state"/"autonomy";STATE.mkdir(parents=True,exist_ok=True)
MEM=STATE/"repair-memory.json"
EMPTY={"schema":1,"entries":[]}

def load(p):
 # Lenient only for *inputs* produced elsewhere in the pipeline. The shared
 # history DB is never loaded this way; see state_store.load_db.
 try:return json.loads(Path(p).read_text(encoding="utf-8-sig"))
 except:return {}

def record_feedback(db,f):
 sig=f.get("signature")
 # upsert failed strategy evidence
 existing=next((x for x in db["entries"] if x.get("signature")==sig and x.get("outcome")=="failed"),None)
 if existing:existing["seen_count"]=int(existing.get("seen_count",1))+1;existing["last_seen"]=time.time()
 else:db["entries"].append({"signature":sig,"category":f.get("category"),"outcome":"failed","seen_count":1,"failed_steps":(f.get("acceptance") or {}).get("failed_steps",[]),"last_seen":time.time()})

def record_report(db,r):
 for c in r.get("cycles",[]):
  if c.get("passed"):
   sig=hashlib.sha256((str(c.get("exact_head"))+str(c.get("specialists"))+str(c.get("code_diff"))).encode()).hexdigest()
   db["entries"].append({"signature":sig,"category":"unknown","outcome":"proven","specialists":c.get("specialists"),"exact_head":c.get("exact_head"),"last_seen":time.time()})

def query(db,q):
 cat=q.get("category");sig=q.get("failure_signature")
 entries=db.get("entries") or []
 failed=[x for x in entries if x.get("outcome")=="failed" and (x.get("signature")==sig or x.get("category")==cat)][-8:]
 proven=[x for x in entries if x.get("outcome")=="proven" and x.get("category") in (cat,"unknown")][-5:]
 return {"failed_history":failed,"proven_history":proven}

def main():
 ap=argparse.ArgumentParser();ap.add_argument("--feedback");ap.add_argument("--report");ap.add_argument("--query");ns=ap.parse_args()
 f=load(ns.feedback) if ns.feedback else {}
 r=load(ns.report) if ns.report else {}
 try:
  if f or r:
   # One serialised read-modify-write. Two workers recording concurrently both
   # observe the newest committed history, so neither loses the other's entry.
   def mutate(db):
    db.setdefault("schema",1);db.setdefault("entries",[])
    if f:record_feedback(db,f)
    if r:record_report(db,r)
    db["entries"]=db["entries"][-500:]
    return db
   db=state_store.update_db(MEM,mutate,default=EMPTY)
  else:
   db=state_store.load_db(MEM,default=EMPTY)
 except state_store.StateError as exc:
  # Fail closed: an unreadable history DB must never look like "no history yet",
  # because that silently re-authorises paid repair work already known to fail.
  err={"ok":False,"state_error":type(exc).__name__,"detail":str(exc),"fail_closed":True,
       "failed_history":None,"proven_history":None,
       "instruction":"Autonomy repair memory is unavailable. Do not treat this as an empty history."}
  sys.stderr.write("FORGEBOSS_REPAIR_MEMORY_ERROR="+json.dumps(err,separators=(",",":"))+"\n")
  if ns.query:print(json.dumps(err,separators=(",",":")))
  return 9 if isinstance(exc,(state_store.StateRecoveryRequiredError,state_store.StateCorruptionError)) else 8
 if ns.query:
  print(json.dumps(query(db,load(ns.query)),separators=(",",":")))
 return 0
if __name__=="__main__":raise SystemExit(main())
