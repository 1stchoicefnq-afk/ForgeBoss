import importlib.metadata as m, json, os
wanted={
 "openhands-sdk":"1.22.1",
 "openhands-tools":"1.22.1",
 "openhands-workspace":"1.22.1",
 "mini-swe-agent":"2.4.6",
 "deepagents":"0.7.6",
}
results=[]
bad=0
for pkg,expected in wanted.items():
    try:
        actual=m.version(pkg);ok=(actual==expected)
    except Exception as e:
        actual=f"MISSING: {e}";ok=False
    print(f"[{'PASS' if ok else 'FAIL'}] {pkg}: {actual}")
    results.append({"package":pkg,"expected":expected,"actual":actual,"ok":ok})
    bad+=0 if ok else 1
root=os.path.join(os.path.expanduser('~'),'.forgeboss','runtime')
os.makedirs(root,exist_ok=True)
open(os.path.join(root,'python-upstreams.json'),'w',encoding='utf-8').write(json.dumps(results,indent=2))
raise SystemExit(2 if bad else 0)
