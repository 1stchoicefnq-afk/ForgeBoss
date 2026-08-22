from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];p=f=0
def ok(n,v):
 global p,f;print(f"[{'PASS' if v else 'FAIL'}] {n}");p+=int(v);f+=int(not v)
server=(ROOT/'dashboard'/'server.py').read_text(encoding='utf-8');html=(ROOT/'dashboard'/'index.html').read_text(encoding='utf-8')
ok('local-only dashboard bind','("127.0.0.1",8765)' in server)
ok('duration control','duration_minutes' in server and 'Duration' in html)
ok('budget control','budget_usd' in server and 'Maximum API spend' in html)
ok('one writer enforced','workers=1' in server)
ok('safe stop','/api/stop' in server)
ok('zero-cost bakeoff','model_calls":0' in server and '/api/bakeoff' in server)
ok('merge off visible','<span>Merge</span><b class="bad">OFF</b>' in html)
ok('deploy off visible','<span>Deploy</span><b class="bad">OFF</b>' in html)
ok('draft gate env','SITEBOSS_ALLOW_DRAFT_PUBLISH' in server)
ok('paid gate env','SITEBOSS_ALLOW_PAID_REPAIR' in server)
ok('session budget env','SITEBOSS_RUN_BUDGET_USD' in server)
ok('Repair Rat remains default','executor":"repair-rat"' in server)
print(f"FORGEBOSS DASHBOARD SELFTEST PASS={p} FAIL={f}");raise SystemExit(2 if f else 0)
