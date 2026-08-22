from __future__ import annotations
import argparse,json,time,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"autonomy";STATE.mkdir(parents=True,exist_ok=True)
MEM=STATE/"repair-memory.json"

def load(p):
 try:return json.loads(Path(p).read_text(encoding="utf-8-sig"))
 except:return {}

def main():
 ap=argparse.ArgumentParser();ap.add_argument("--feedback");ap.add_argument("--report");ap.add_argument("--query");ns=ap.parse_args()
 db=load(MEM) or {"schema":1,"entries":[]}
 if ns.feedback:
  f=load(ns.feedback)
  if f:
   sig=f.get("signature")
   # upsert failed strategy evidence
   existing=next((x for x in db["entries"] if x.get("signature")==sig and x.get("outcome")=="failed"),None)
   if existing:existing["seen_count"]=int(existing.get("seen_count",1))+1;existing["last_seen"]=time.time()
   else:db["entries"].append({"signature":sig,"category":f.get("category"),"outcome":"failed","seen_count":1,"failed_steps":(f.get("acceptance") or {}).get("failed_steps",[]),"last_seen":time.time()})
 if ns.report:
  r=load(ns.report)
  if r:
   for c in r.get("cycles",[]):
    if c.get("passed"):
     sig=hashlib.sha256((str(c.get("exact_head"))+str(c.get("specialists"))+str(c.get("code_diff"))).encode()).hexdigest()
     db["entries"].append({"signature":sig,"category":"unknown","outcome":"proven","specialists":c.get("specialists"),"exact_head":c.get("exact_head"),"last_seen":time.time()})
 db["entries"]=db["entries"][-500:]
 MEM.write_text(json.dumps(db,indent=2),encoding="utf-8")
 if ns.query:
  q=load(ns.query);cat=q.get("category");sig=q.get("failure_signature")
  failed=[x for x in db["entries"] if x.get("outcome")=="failed" and (x.get("signature")==sig or x.get("category")==cat)][-8:]
  proven=[x for x in db["entries"] if x.get("outcome")=="proven" and x.get("category") in (cat,"unknown")][-5:]
  print(json.dumps({"failed_history":failed,"proven_history":proven},separators=(",",":")))
 return 0
if __name__=="__main__":raise SystemExit(main())
