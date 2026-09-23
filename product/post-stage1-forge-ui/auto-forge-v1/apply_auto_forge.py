#!/usr/bin/env python3
from __future__ import annotations
import subprocess,sys
from pathlib import Path
BASE='9669583bd10af91d52e3647a5f5c85e0cec975b7'
SERVER_BLOB='c12d7639daf80c62a4eb2f29eb1ee8876e7dec27'
SELF80_BLOB='5b33868b9c718748c7b372e4fd401c85cfbd862b'
HERE=Path(__file__).resolve().parent
OLD='''def choose_openai_lane(mode,cycle,same_signature_count):\n    mode=str(mode or "cost-optimized").strip().lower()\n    if mode=="cost-optimized":return {"requested_mode":mode,"model":"gpt-5.6-luna","reasoning":"low","max_output":3000,"lane":"CHEAP"}\n    if mode=="balanced":return {"requested_mode":mode,"model":"gpt-5.6-terra","reasoning":"medium","max_output":4000,"lane":"BALANCED"}\n    if mode=="strong":return {"requested_mode":mode,"model":"gpt-5.6-sol","reasoning":"medium","max_output":5000,"lane":"STRONG"}\n    raise ValueError(f"Unknown AI mode: {mode}")\n'''

def run(a,cwd):
 p=subprocess.run(a,cwd=str(cwd),capture_output=True,text=True)
 if p.returncode: raise RuntimeError((p.stderr or p.stdout).strip())
 return p.stdout.strip()
def one(s,a,b,name):
 if s.count(a)!=1: raise RuntimeError(f'{name}: exact anchor mismatch')
 return s.replace(a,b,1)
def main():
 if len(sys.argv)!=2: raise SystemExit('usage: apply_auto_forge.py PATH_TO_FORGEBOSS')
 repo=Path(sys.argv[1]).resolve(); server=repo/'dashboard/server.py'; st=repo/'forgeboss/autonomy/selftest-v080.py'; nt=repo/'forgeboss/autonomy/selftest-auto-forge.py'
 if not (repo/'.git').exists(): raise SystemExit('REFUSE: not a Git checkout')
 if run(['git','rev-parse','HEAD'],repo)!=BASE: raise SystemExit('REFUSE: exact base mismatch')
 if run(['git','hash-object',str(server)],repo)!=SERVER_BLOB or run(['git','hash-object',str(st)],repo)!=SELF80_BLOB: raise SystemExit('REFUSE: reviewed blob mismatch')
 if run(['git','status','--porcelain'],repo): raise SystemExit('REFUSE: working tree not clean')
 router=(HERE/'router_reference.py').read_text(); test=(HERE/'selftest-auto-forge.py').read_text(); osrv,ost=server.read_bytes(),st.read_bytes(); existed=nt.exists(); ont=nt.read_bytes() if existed else None
 try:
  s=server.read_text(); s=one(s,OLD,router,'router')
  s=one(s,'    mode=str(settings.get("mode","cost-optimized"))','    mode=normalize_ai_mode(settings.get("mode","cost-optimized"))','mode')
  s=one(s,'    same_signature_count=0\n    feedback_path=None','    same_signature_count=0\n    auto_escalation_level=0\n    feedback_path=None','state')
  s=one(s,'        if mode=="cost-optimized" and not debug_funnel_path:','        if is_auto_mode(mode) and not debug_funnel_path:','funnel')
  s=one(s,'        lane=choose_openai_lane(mode,cycle,same_signature_count)','        lane=choose_openai_lane(mode,cycle,same_signature_count,auto_escalation_level)','lane')
  s=one(s,'        save_status(requested_ai_mode=mode,selected_ai_lane=lane["lane"],selected_ai_model=lane["model"])','        save_status(requested_ai_mode=mode,selected_ai_lane=lane["lane"],selected_ai_model=lane["model"],selected_ai_route_reason=lane.get("route_reason"),auto_forge_heat=lane.get("escalation_level",0))','status')
  partial='''            log("ACCUMULATING PIPELINE: retained foundation + next remaining-failure packet ready.")\n            save_status(stage="NEXT_TARGET_FOUND",message="Remaining failure family isolated; starting the next bounded cycle.")\n            continue'''
  partial2='''            log("ACCUMULATING PIPELINE: retained foundation + next remaining-failure packet ready.")\n            if is_auto_mode(mode):\n                auto_escalation_level=0; same_signature_count=0; last_signature=None\n                log("AUTO FORGE: new remaining-failure family; dropping back to LOW HEAT.")\n            save_status(stage="NEXT_TARGET_FOUND",message="Remaining failure family isolated; starting the next bounded cycle.")\n            continue'''
  s=one(s,partial,partial2,'partial reset')
  old='''        if sig and sig==last_signature:\n            same_signature_count+=1\n        else:\n            same_signature_count=0\n            last_signature=sig\n\n        # Two consecutive repeats of the same bounded failure signature means the\n        # automation is not learning. Stop before wasting more credit.\n        if same_signature_count>=2:\n            log("STAGNATION GUARD: same failure signature repeated 3 times. Stopping to avoid wasting API credit.")\n            save_status(stage="NEEDS_OWNER",message="Same failure repeated 3 times; stopped before more API spend.",last_exit_code=code)\n            break\n'''
  new='''        signature_changed=bool(sig and last_signature and sig!=last_signature)\n        if sig and sig==last_signature: same_signature_count+=1\n        else: same_signature_count=0; last_signature=sig\n        if signature_changed and is_auto_mode(mode) and auto_escalation_level>0:\n            auto_escalation_level=0; log("AUTO FORGE: failure signature changed; dropping back to LOW HEAT.")\n        heat=auto_forge_escalation_decision(mode,same_signature_count,auto_escalation_level)\n        if heat["action"]=="escalate":\n            auto_escalation_level=int(heat["level"]); log(f"AUTO FORGE ESCALATION: {heat['reason']} -> level={auto_escalation_level}.")\n        elif heat["action"]=="stop":\n            save_status(stage="NEEDS_OWNER",message="Same failure persisted at maximum approved heat; stopped before more API spend.",last_exit_code=code); break\n        elif not is_auto_mode(mode) and same_signature_count>=2:\n            save_status(stage="NEEDS_OWNER",message="Same failure repeated 3 times; stopped before more API spend.",last_exit_code=code); break\n'''
  s=one(s,old,new,'stagnation'); server.write_text(s); nt.write_text(test)
  for c in ([sys.executable,'-m','py_compile',str(server)],[sys.executable,str(nt)]):
   if subprocess.run(c,cwd=str(repo)).returncode: raise RuntimeError('verification failed')
  print('PASS: Auto Forge staged. No commit/push/merge performed by installer.')
 except Exception:
  server.write_bytes(osrv); st.write_bytes(ost)
  if existed: nt.write_bytes(ont)
  elif nt.exists(): nt.unlink()
  raise
if __name__=='__main__': main()
