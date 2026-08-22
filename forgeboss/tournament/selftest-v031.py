from pathlib import Path
import subprocess,sys,re
ROOT=Path(__file__).resolve().parents[2];p=f=0
def ok(n,v):
 global p,f;print(f"[{'PASS' if v else 'FAIL'}] {n}");p+=int(v);f+=int(not v)
for x in [ROOT/'forgeboss'/'executors'/'mini_swe_runner.py',ROOT/'forgeboss'/'executors'/'openhands_runner.py',
          ROOT/'forgeboss'/'tournament'/'run_paid.py',ROOT/'forgeboss'/'tournament'/'prepare_template_cleanup.py']:
 r=subprocess.run([sys.executable,'-m','py_compile',str(x)],capture_output=True,text=True);ok(x.name+' compiles',r.returncode==0)
mini=(ROOT/'forgeboss'/'executors'/'mini_swe_runner.py').read_text()
oh=(ROOT/'forgeboss'/'executors'/'openhands_runner.py').read_text()
runp=(ROOT/'forgeboss'/'tournament'/'run_paid.py').read_text()
hp=(ROOT/'forgeboss'/'tournament'/'prepare_template_cleanup.py').read_text()
ok('mini required system template supplied','system_template=system_template' in mini)
ok('mini required instance template supplied','instance_template=instance_template' in mini)
ok('mini cost cap retained','cost_limit=budget' in mini)
ok('OpenHands home outside repo','tempfile.mkdtemp(prefix="forgeboss-openhands-home-"' in oh)
ok('OpenHands runtime cleanup','shutil.rmtree(runtime_home' in oh)
ok('case-sensitive tournament root','queryCaseSensitiveInfo' in runp and 'SetCaseSensitiveInfo' in runp)
ok('clean baseline required','if baseline:' in runp)
ok('porcelain z parser','--porcelain=v1","-z"' in runp)
ok('worker delta vs baseline','worker_attributed_paths' in runp)
ok('canonical lowercase template', 'CANONICAL_PR_TEMPLATE=".github/pull_request_template.md"' in runp)
ok('legacy uppercase isolated to detector', 'LEGACY_PR_TEMPLATE=".github/PULL_REQUEST_TEMPLATE.md"' in runp)
ok('template cleanup deletes only legacy','git(w,"rm","--",LEGACY)' in hp)
ok('template cleanup requires canonical','if CANON not in paths' in hp)
ok('cleanup not published','"published":False' in hp)
server=(ROOT/'dashboard'/'server.py').read_text();html=(ROOT/'dashboard'/'index.html').read_text()
ok('dashboard hygiene endpoint','/api/hygiene/pr-template' in server)
ok('dashboard states no GitHub write','NO GitHub write is made' in html)
print(f"FORGEBOSS v0.3.1 SELFTEST PASS={p} FAIL={f}");raise SystemExit(2 if f else 0)
