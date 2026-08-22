from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2];p=f=0
def ok(n,v):
 global p,f;print(f"[{'PASS' if v else 'FAIL'}] {n}");p+=int(v);f+=int(not v)
files=[ROOT/'forgeboss'/'executors'/'mini_swe_runner.py',ROOT/'forgeboss'/'executors'/'openhands_runner.py',ROOT/'forgeboss'/'tournament'/'run_paid.py']
for x in files:
 r=subprocess.run([sys.executable,'-m','py_compile',str(x)],capture_output=True,text=True);ok(x.name+' compiles',r.returncode==0)
mini=files[0].read_text();oh=files[1].read_text();runp=files[2].read_text();server=(ROOT/'dashboard'/'server.py').read_text();html=(ROOT/'dashboard'/'index.html').read_text()
ok('mini-SWE Docker network disabled','"--network","none"' in mini)
ok('mini-SWE hard cost limit','cost_limit=budget' in mini)
ok('mini-SWE Luna default','gpt-5.6-luna' in mini)
ok('OpenHands Luna default','gpt-5.6-luna' in oh)
ok('OpenHands reports SDK cost','accumulated_cost' in oh)
ok('OpenHands scrubs GitHub/API env before tools','os.environ.pop(k,None)' in oh)
ok('same packet one controller read', 'packet-latest.json' in runp and 'siteboss-autopilot.js' in runp)
ok('exact head checkout','checkout","--detach",sha' in runp)
ok('remotes removed','remote","remove"' in runp)
ok('scope post-check','scope_ok=all' in runp)
ok('same deterministic validator','validate.ps1' in runp)
ok('no auto live promotion','PROVISIONAL_ONLY' in runp)
ok('dashboard paid tournament endpoint','/api/tournament/run' in server)
ok('dashboard explicit paid confirmation','This WILL make paid AI calls' in html)
print(f"FORGEBOSS v0.3 SELFTEST PASS={p} FAIL={f}");raise SystemExit(2 if f else 0)
