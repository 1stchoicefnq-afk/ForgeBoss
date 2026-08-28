"""League subsystem selftest.

Cross-lane assertions (tournament validator, dashboard wiring) are kept but are
fail-soft: a missing file outside this lane now reports FAIL instead of raising
and taking the whole selftest down with a traceback.
"""
from pathlib import Path
import subprocess,sys,json
R=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent;p=f=0

def ok(n,v):
 global p,f;print(f"[{'PASS' if v else 'FAIL'}] {n}");p+=int(v);f+=int(not v)

def read(path,**kw):
 """Read a file for a cross-lane assertion; missing/unreadable -> '' (FAIL)."""
 try:return Path(path).read_text(**kw)
 except OSError as e:print(f"       (unreadable: {e})");return ""

for x in [HERE/'fixtures.py',HERE/'run_league.py',HERE/'test_league.py',HERE/'selftest.py']:
 q=subprocess.run([sys.executable,'-m','py_compile',str(x)],capture_output=True,text=True);ok(x.name,q.returncode==0)

try:
 sys.path.insert(0,str(HERE));import fixtures,run_league as L
 cats=L.load_categories(HERE/'categories.json');ok('categories.json loads',True)
except Exception as e:
 cats={};ok('categories.json loads',False);print(f'       ({type(e).__name__}: {e})')

ok('8 categories',len(cats)==8)
for x in ['database','backend','auth','frontend','small_bug','refactor','ci','tests']:ok(x,x in cats)
# Every configured candidate must map to a real runner, and no category may
# list the same executor twice (a duplicate makes its designation ambiguous).
ok('all candidates have a runner',bool(cats) and all(e in L.RUNNERS for v in cats.values() for e in v))
ok('no duplicate candidates',bool(cats) and all(L.dedupe(v)[1]==[] for v in cats.values()))
ok('every category has a fixture',bool(cats) and all(c in fixtures.CATEGORIES for c in cats))
ok('test.js is not candidate-writable','test.js' not in fixtures.REFACTOR_ALLOWED and all('test.js' not in (fn,) for fn,_,_ in fixtures.CASES.values()))

v=read(R/'forgeboss'/'tournament'/'validate.ps1',encoding='utf-8-sig')
# Invariant: docker is invoked directly with a splatted arg list, never handed
# to Start-Process. Matched on the shape so a variable rename in the tournament
# lane does not turn into a false failure here.
ok('validator fixed',bool(v) and 'Start-Process -FilePath' not in v and '& docker.exe @' in v)
s=read(R/'dashboard'/'server.py');h=read(R/'dashboard'/'index.html')
ok('endpoint','/api/league/run' in s);ok('button','RUN $1 ALL-CATEGORY LEAGUE' in h)
# The dashboard reads these two keys out of league-last.json; keep the contract.
snap=L._snapshot('r',1.,0.,0.,0.,[],{},{},{},True) if cats else {}
ok('dashboard result contract','winners' in snap and 'reported_measured_spend_usd' in snap)

q=subprocess.run([sys.executable,'-m','unittest','discover','-s',str(HERE),'-p','test_league.py'],capture_output=True,text=True,cwd=str(R))
ok('league regression suite',q.returncode==0)
if q.returncode:print((q.stderr or q.stdout)[-3000:])

print(f"PASS={p} FAIL={f}");raise SystemExit(2 if f else 0)
