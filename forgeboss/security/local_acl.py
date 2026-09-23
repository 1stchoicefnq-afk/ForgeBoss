from __future__ import annotations
import getpass,os,stat,subprocess
from pathlib import Path
CREATE_NO_WINDOW=getattr(subprocess,"CREATE_NO_WINDOW",0)
class LocalAclError(RuntimeError):pass
def _user():return os.environ.get("USERNAME") or getpass.getuser()
def harden_private_path(path:Path):
    p=Path(path)
    if not p.exists():return p
    if os.name=="nt":
        cp=subprocess.run(["icacls.exe",str(p),"/inheritance:r","/grant:r",f"{_user()}:(F)","/grant:r","SYSTEM:(F)","/grant:r","Administrators:(F)"],
                          capture_output=True,text=True,timeout=20,creationflags=CREATE_NO_WINDOW)
        if cp.returncode:raise LocalAclError("Windows ACL hardening failed: "+(cp.stderr or cp.stdout).strip())
    else:os.chmod(p,stat.S_IRUSR|stat.S_IWUSR)
    return p
def harden_private_dir(path:Path):
    p=Path(path);p.mkdir(parents=True,exist_ok=True)
    if os.name=="nt":
        cp=subprocess.run(["icacls.exe",str(p),"/inheritance:r","/grant:r",f"{_user()}:(OI)(CI)(F)","/grant:r","SYSTEM:(OI)(CI)(F)","/grant:r","Administrators:(OI)(CI)(F)"],
                          capture_output=True,text=True,timeout=20,creationflags=CREATE_NO_WINDOW)
        if cp.returncode:raise LocalAclError("Windows directory ACL hardening failed: "+(cp.stderr or cp.stdout).strip())
    else:os.chmod(p,0o700)
    return p
