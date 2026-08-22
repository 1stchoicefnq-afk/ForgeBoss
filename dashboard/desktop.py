from __future__ import annotations
import sys,threading,tkinter as tk,re
from tkinter import ttk,messagebox
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import server as fb
class App(tk.Tk):
 def __init__(self):
  super().__init__();self.title("ForgeBoss - Building SiteBoss");self.geometry("1100x700");self.minsize(900,600);self.configure(bg="#0b1020")
  self.duration=tk.StringVar(value="120");self.budget=tk.StringVar(value="3.00");self.mode=tk.StringVar(value="cost-optimized");self.stage=tk.StringVar(value="IDLE");self.msg=tk.StringVar(value="Ready");self.left=tk.StringVar(value="--:--:--");self.spend=tk.StringVar(value="$0.00 / $3.00");self.cycle=tk.StringVar(value="0")
  self.retest_summary=tk.StringVar(value="No saved re-test result yet")
  self.mini_result=tk.StringVar(value="WAITING")
  self.openhands_result=tk.StringVar(value="WAITING")
  self.retest_cost=tk.StringVar(value="$0.00 new AI spend")
  self.engine_cache={}
  self.engine_probe_running=False
  self.build()
  self.after(200,self.refresh)
  self.after(300,self.probe_engines_async)
 def lab(self,p,t,sz=10,b=False,fg="#eef4ff"):return tk.Label(p,text=t,bg=p.cget("bg"),fg=fg,font=("Segoe UI",sz,"bold" if b else "normal"))
 def card(self,p):return tk.Frame(p,bg="#141b2d",highlightbackground="#28334b",highlightthickness=1)
 def build(self):
  top=tk.Frame(self,bg="#0b1020");top.pack(fill="x",padx=24,pady=18);self.logo_img=None
  try:
   self.logo_img=tk.PhotoImage(file=str(HERE/"assets"/"siteboss-logo.png")).subsample(10,10);tk.Label(top,image=self.logo_img,bg="#0b1020").pack(side="left",padx=(0,10))
  except Exception:pass
  self.lab(top,"ForgeBoss",24,True,fg="#35d6bd").pack(side="left");self.lab(top,"  Building SiteBoss",11,False,"#f58a22").pack(side="left",pady=(10,0));tk.Label(top,textvariable=self.stage,bg="#10172a",fg="#69db9d",padx=14,pady=7,font=("Segoe UI",10,"bold")).pack(side="right")
  body=tk.Frame(self,bg="#0b1020");body.pack(fill="both",expand=True,padx=24,pady=(0,22));l=tk.Frame(body,bg="#0b1020");l.pack(side="left",fill="both",expand=True,padx=(0,9));r=tk.Frame(body,bg="#0b1020",width=330);r.pack(side="right",fill="y",padx=(9,0));r.pack_propagate(False)
  c=self.card(l);c.pack(fill="x",pady=(0,12));self.lab(c,"Work Session",13,True).pack(anchor="w",padx=16,pady=(14,8));f=tk.Frame(c,bg="#141b2d");f.pack(fill="x",padx=16)
  for i in range(3):f.columnconfigure(i,weight=1)
  for i,t in enumerate(["Duration (minutes)","Max API spend (USD)","Mode"]):self.lab(f,t,9,False,"#91a0b8").grid(row=0,column=i,sticky="w",padx=(0 if i==0 else 8,0))
  ttk.Combobox(f,textvariable=self.duration,values=("30","60","120","240","480"),state="readonly").grid(row=1,column=0,sticky="ew");ttk.Entry(f,textvariable=self.budget).grid(row=1,column=1,sticky="ew",padx=8);ttk.Combobox(f,textvariable=self.mode,values=("cost-optimized","balanced","strong"),state="readonly").grid(row=1,column=2,sticky="ew")
  b=tk.Frame(c,bg="#141b2d");b.pack(fill="x",padx=16,pady=12);tk.Button(b,text="START BUILDING SITEBOSS",command=self.start,bg="#35d6bd",fg="#07101f",relief="flat",pady=8).pack(side="left");tk.Button(b,text="STOP SAFELY",command=self.stop,bg="#47262d",fg="#ffd9dd",relief="flat",pady=8).pack(side="left",padx=8);tk.Button(b,text="$1 CATEGORY LEAGUE",command=self.league,bg="#222d45",fg="#eef4ff",relief="flat",pady=8).pack(side="left");tk.Button(b,text="RETEST LAST CANDIDATES $0",command=self.retest,bg="#1b594f",fg="#eef4ff",relief="flat",pady=8).pack(side="left",padx=8)
  st=tk.Frame(c,bg="#141b2d");st.pack(fill="x",padx=16,pady=(0,10))
  for i,(n,var) in enumerate([("Stage",self.stage),("Time left",self.left),("Spend",self.spend),("Cycle",self.cycle)]):
   st.columnconfigure(i,weight=1);x=tk.Frame(st,bg="#0e1527");x.grid(row=0,column=i,sticky="ew",padx=3);tk.Label(x,textvariable=var,bg="#0e1527",fg="#eef4ff",font=("Segoe UI",10,"bold")).pack(anchor="w",padx=8,pady=(7,0));self.lab(x,n,8,False,"#91a0b8").pack(anchor="w",padx=8,pady=(0,7))
  tk.Label(c,textvariable=self.msg,bg="#141b2d",fg="#91a0b8",anchor="w",wraplength=680).pack(fill="x",padx=16,pady=(0,12))
  a=self.card(l);a.pack(fill="both",expand=True);self.lab(a,"Live Activity",13,True).pack(anchor="w",padx=16,pady=(14,8));self.log=tk.Text(a,bg="#080d18",fg="#cbd6e8",relief="flat",font=("Consolas",9),wrap="word");self.log.pack(fill="both",expand=True,padx=16,pady=(0,16))
  res=self.card(r);res.pack(fill="x",pady=(0,12));self.lab(res,"Last Candidate Re-test",13,True).pack(anchor="w",padx=16,pady=(14,6))
  rr=tk.Frame(res,bg="#141b2d");rr.pack(fill="x",padx=16,pady=3);self.lab(rr,"mini-SWE",9).pack(side="left");tk.Label(rr,textvariable=self.mini_result,bg="#141b2d",fg="#35d6bd",font=("Segoe UI",9,"bold")).pack(side="right")
  rr2=tk.Frame(res,bg="#141b2d");rr2.pack(fill="x",padx=16,pady=3);self.lab(rr2,"OpenHands",9).pack(side="left");tk.Label(rr2,textvariable=self.openhands_result,bg="#141b2d",fg="#35d6bd",font=("Segoe UI",9,"bold")).pack(side="right")
  tk.Label(res,textvariable=self.retest_summary,bg="#141b2d",fg="#91a0b8",justify="left",anchor="w",wraplength=285).pack(fill="x",padx=16,pady=(7,2))
  tk.Label(res,textvariable=self.retest_cost,bg="#141b2d",fg="#f58a22",anchor="w",font=("Segoe UI",9,"bold")).pack(fill="x",padx=16,pady=(0,12))
  e=self.card(r);e.pack(fill="x",pady=(0,12));self.lab(e,"Executor Pool",13,True).pack(anchor="w",padx=16,pady=(14,8));self.ef=tk.Frame(e,bg="#141b2d");self.ef.pack(fill="x",padx=16,pady=(0,12))
  q=self.card(r);q.pack(fill="x");self.lab(q,"Safety",13,True).pack(anchor="w",padx=16,pady=(14,8))
  for n,val,col in [("Exact HEAD","ON","#69db9d"),("Bounded writes","ON","#69db9d"),("Independent review","ON","#69db9d"),("Draft PR","AFTER PASS","#ffd166"),("Merge","OFF","#ff7b7b"),("Deploy","OFF","#ff7b7b")]:
   x=tk.Frame(q,bg="#141b2d");x.pack(fill="x",padx=16,pady=4);self.lab(x,n,9).pack(side="left");self.lab(x,val,9,True,col).pack(side="right")
 def start(self):
  try:b=float(self.budget.get());d=int(self.duration.get())
  except:messagebox.showerror("ForgeBoss","Invalid duration/budget");return
  if messagebox.askyesno("Start",f"May spend up to ${b:.2f}. Draft PR only; no merge/deploy.\n\nStart?"):fb.start_session({"duration_minutes":d,"budget_usd":b,"workers":1,"mode":self.mode.get()})
 def stop(self):fb.stop_requested.set();fb.save_status(stop_requested=True,message="Safe stop requested; no new work will start.");fb.log("OWNER requested safe stop.")
 def retest(self):
  if messagebox.askyesno("Re-test candidates","Re-test the mini-SWE and OpenHands candidates you already paid for?\n\nCost: $0 AI spend. No GitHub writes."):threading.Thread(target=fb.retest_last_candidates,daemon=True).start()
 def league(self):
  if messagebox.askyesno("Category League","Run the $1 target category league? Paid Luna calls; no GitHub writes/merge/deploy."):threading.Thread(target=fb.run_category_league,args=(1.0,),daemon=True).start()
 def friendly_events(self,raw):
  events=[]
  for line in raw.splitlines():
   if not line.strip():continue
   ts=line[:8] if len(line)>=8 and line[2]==":" else ""
   x=line[10:] if ts else line
   low=x.lower()
   msg=None;kind="info"
   if "category league" in low and "===" in low:msg="Category league started - comparing workers across engineering task types.";kind="work"
   elif "paid executor tournament" in low:msg="Worker tournament started.";kind="work"
   elif "packet.ready" in low:msg="SiteBoss task prepared and ready for a worker.";kind="ok"
   elif '"executor": "mini-swe"' in low:msg="mini-SWE finished its attempt.";kind="work"
   elif '"executor": "openhands"' in low:msg="OpenHands finished its attempt.";kind="work"
   elif '"scope_ok": true' in low:msg="Worker stayed inside the allowed files.";kind="ok"
   elif '"scope_ok": false' in low:msg="Worker changed something outside its allowed area.";kind="warn"
   elif '"acceptance_passed": true' in low:msg="Candidate passed the required tests.";kind="ok"
   elif '"acceptance_passed": false' in low:msg="Candidate did not pass validation.";kind="warn"
   elif "docker argument list is empty" in low:msg="ForgeBoss validator hit an internal Docker launcher bug.";kind="warn"
   elif "retesting last paid candidates" in low:msg="Re-testing the existing paid candidates - no new AI spend.";kind="work"
   elif "forgeboss_retest_result" in low:msg="Existing candidate re-test finished.";kind="ok"
   elif "pr template case collision" in low or "repository hygiene" in low:msg="Repository template cleanup check completed.";kind="info"
   elif "safe stop" in low or "owner requested safe stop" in low:msg="Safe stop requested. No new work will start.";kind="warn"
   elif "cycle cost" in low:
    m=re.search(r'(\$[0-9.]+)',x);msg=f"AI work cost {m.group(1)} this cycle." if m else "AI cost updated.";kind="money"
   if msg:
    item=(ts,msg,kind)
    if not events or events[-1][1]!=msg:events.append(item)
  return events[-14:]

 def render_activity(self):
  raw=fb.LOG.read_text(encoding="utf-8",errors="replace")[-40000:] if fb.LOG.exists() else ""
  ev=self.friendly_events(raw)
  self.log.delete("1.0","end")
  if not ev:self.log.insert("end","ForgeBoss is ready. Start a build or category league when you want.")
  else:
   symbols={"ok":"PASS","warn":"!","work":"›","money":"$","info":"-"}
   for ts,msg,k in ev:self.log.insert("end",f"{symbols.get(k,'-')}  {ts}  {msg}\n\n")
  self.log.see("end")

 def probe_engines_async(self):
  if self.engine_probe_running:return
  self.engine_probe_running=True
  def work():
   try:self.engine_cache=fb.check_engines()
   except Exception as e:self.msg.set("Engine check failed: "+str(e))
   finally:
    self.engine_probe_running=False
    try:self.after(30000,self.probe_engines_async)
    except Exception:pass
  threading.Thread(target=work,daemon=True).start()

 def load_retest_result(self):
  p=fb.ROOT/"state"/"tournament"/"retest-last.json"
  if not p.exists():
   self.mini_result.set("NO RESULT");self.openhands_result.set("NO RESULT");self.retest_summary.set("Click RETEST LAST CANDIDATES $0 to test the saved work.");return
  try:
   j=json.loads(p.read_text(encoding="utf-8"))
   rows={x.get("executor"):x for x in j.get("results",[])}
   def label(name):
    x=rows.get(name,{})
    if x.get("missing"):return "MISSING"
    if x.get("acceptance_passed"):return "PASS"
    n=x.get("failure_count")
    return "FAIL" if n is None else f"FAIL ({n})"
   self.mini_result.set(label("mini-swe"));self.openhands_result.set(label("openhands"))
   winner=j.get("winner")
   if winner=="both-pass-needs-cost-tiebreak":summary="Both candidates passed. mini-SWE was cheaper in the paid run; independent review is the next gate."
   elif winner:summary=f"{winner} passed validation. The other candidate did not."
   else:
    failed=[]
    for name,x in rows.items():
     if not x.get("acceptance_passed") and not x.get("missing"):failed.append(f"{name}: {x.get('failure_count','?')} failed checks")
    summary="No verified winner yet. "+("; ".join(failed) if failed else "See internal evidence for the failed validation.")
   self.retest_summary.set(summary)
   self.retest_cost.set("$0.00 new AI spend - reused existing candidates")
  except Exception as e:
   self.retest_summary.set("Could not read saved re-test result: "+str(e))

 def refresh(self):
  try:
   self.load_retest_result()
   s=fb.load_status();s["engines"]=self.engine_cache;self.stage.set(("RUNNING - " if s.get("running") else "")+s.get("stage","IDLE"));self.msg.set(s.get("message",""));self.cycle.set(str(s.get("current_cycle",0)));self.spend.set(f"${float(s.get('spent_usd',0)):.2f} / ${float(s.get('budget_usd',0)):.2f}")
   if s.get("running") and s.get("ends_at"):
    from datetime import datetime,timezone
    sec=max(0,int((datetime.fromisoformat(s["ends_at"])-datetime.now(timezone.utc)).total_seconds()));self.left.set(f"{sec//3600:02}:{(sec%3600)//60:02}:{sec%60:02}")
   else:self.left.set("--:--:--")
   for x in self.ef.winfo_children():x.destroy()
   for n,i in s.get("engines",{}).items():
    x=tk.Frame(self.ef,bg="#141b2d");x.pack(fill="x",pady=3);self.lab(x,n,9).pack(side="left");self.lab(x,"READY" if i.get("ready") else "NOT READY",9,True,"#69db9d" if i.get("ready") else "#ff7b7b").pack(side="right")
   self.render_activity()
  except Exception as e:self.msg.set("Dashboard error: "+str(e))
  self.after(1000,self.refresh)
if __name__=="__main__":App().mainloop()
