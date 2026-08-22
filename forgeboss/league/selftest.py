from pathlib import Path
import subprocess,sys,json
R=Path(__file__).resolve().parents[2];p=f=0
def ok(n,v):
 global p,f;print(f"[{'PASS' if v else 'FAIL'}] {n}");p+=int(v);f+=int(not v)
for x in [R/'forgeboss'/'league'/'fixtures.py',R/'forgeboss'/'league'/'run_league.py']:
 q=subprocess.run([sys.executable,'-m','py_compile',str(x)],capture_output=True,text=True);ok(x.name,q.returncode==0)
c=json.loads((R/'forgeboss'/'league'/'categories.json').read_text())['categories'];ok('8 categories',len(c)==8)
for x in ['database','backend','auth','frontend','small_bug','refactor','ci','tests']:ok(x,x in c)
v=(R/'forgeboss'/'tournament'/'validate.ps1').read_text(encoding='utf-8-sig');ok('validator fixed','Start-Process -FilePath' not in v and '& docker.exe @Args' in v)
s=(R/'dashboard'/'server.py').read_text();h=(R/'dashboard'/'index.html').read_text();ok('endpoint','/api/league/run'in s);ok('button','RUN $1 ALL-CATEGORY LEAGUE'in h)
print(f"PASS={p} FAIL={f}");raise SystemExit(2 if f else 0)
