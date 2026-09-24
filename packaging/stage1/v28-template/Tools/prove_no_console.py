from __future__ import annotations
import ctypes, json, os, subprocess, sys
if os.name!="nt":
    raise SystemExit("Windows-only proof")
flags=getattr(subprocess,"CREATE_NO_WINDOW",0)
if not flags:
    raise SystemExit("CREATE_NO_WINDOW unavailable")
code="import ctypes;print(int(bool(ctypes.windll.kernel32.GetConsoleWindow())))"
cp=subprocess.run([sys.executable,"-I","-S","-c",code],capture_output=True,text=True,creationflags=flags,check=True)
ok=cp.stdout.strip()=="0"
print(json.dumps({"ok":ok,"childConsoleWindow":cp.stdout.strip(),"creationflags":flags},sort_keys=True))
raise SystemExit(0 if ok else 13)
