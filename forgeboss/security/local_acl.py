from __future__ import annotations
import getpass,os,re,stat,subprocess
from pathlib import Path
class LocalAclError(RuntimeError):pass

# Well-known SIDs rather than display names: "SYSTEM" and "Administrators" do not
# exist under those names on a localized Windows, and a name is resolved through a
# lookup an attacker on the box may influence. SIDs are stable and unambiguous.
SID_SYSTEM="*S-1-5-18"
SID_ADMINISTRATORS="*S-1-5-32-544"

# Windows account names may contain interior spaces, but never the icacls grant
# metacharacters ( ) : , * " / \ or a leading/trailing space.
_PART=r"[A-Za-z0-9._-](?:[A-Za-z0-9._ -]{0,62}[A-Za-z0-9._-])?"
_NAME_OK=re.compile(rf"^(?:{_PART}\\)?{_PART}$")
# Principals that would turn "harden" into "publish". %USERNAME% is attacker-writable
# environment, so the resolved principal must never be a broad or well-known group.
BROAD_PRINCIPALS={
    "everyone","users","authenticated users","guest","guests","anonymous logon",
    "interactive","network","batch","service","world","domain users","everybody",
    "all application packages","creator owner","creator group","null sid",
    # localized "Everyone"
    "jeder","todos","tout le monde","iedereen","alle","tutti",
}

def _user():
    """Resolve the account to grant. Fail closed rather than granting a broad SID."""
    name=None
    try:name=getpass.getuser()
    except Exception:name=None
    if not name:name=os.environ.get("USERNAME") or os.environ.get("USER")
    if not isinstance(name,str) or not name.strip():
        raise LocalAclError("cannot resolve the current account for ACL hardening")
    name=name.strip()
    if name.split("\\")[-1].casefold() in BROAD_PRINCIPALS or name.casefold() in BROAD_PRINCIPALS:
        raise LocalAclError("refusing to grant private ACL to broad principal: "+name)
    if not _NAME_OK.match(name):
        raise LocalAclError("refusing to grant private ACL to malformed principal: "+name)
    return name

def _icacls():
    # Bare "icacls.exe" is resolved against the current directory before PATH by
    # CreateProcess; pin it to System32 so a planted binary cannot be run instead.
    root=os.environ.get("SystemRoot") or r"C:\Windows"
    exe=os.path.join(root,"System32","icacls.exe")
    if not os.path.isfile(exe):raise LocalAclError("icacls.exe not found at "+exe)
    return exe

def _run_icacls(args):
    cp=subprocess.run([_icacls(),*args],capture_output=True,text=True,timeout=20)
    if cp.returncode:raise LocalAclError("Windows ACL hardening failed: "+(cp.stderr or cp.stdout).strip())

def _assert_not_link(p:Path):
    # os.chmod and mkdir(exist_ok=True) both follow links: without this, hardening a
    # planted link would re-permission whatever it points at, anywhere on the disk.
    if p.is_symlink() or (hasattr(p,"is_junction") and p.is_junction()):
        raise LocalAclError("refusing to harden a symlink/junction: "+str(p))

def _chmod(p:Path,mode:int):
    if os.chmod in getattr(os,"supports_follow_symlinks",set()):
        os.chmod(p,mode,follow_symlinks=False)
    else:
        os.chmod(p,mode)

def harden_private_path(path:Path):
    p=Path(path)
    _assert_not_link(p)
    if not p.exists():return p
    if os.name=="nt":
        _run_icacls([str(p),"/inheritance:r","/grant:r",f"{_user()}:(F)",
                     "/grant:r",f"{SID_SYSTEM}:(F)","/grant:r",f"{SID_ADMINISTRATORS}:(F)"])
    else:_chmod(p,stat.S_IRUSR|stat.S_IWUSR)
    return p

def harden_private_dir(path:Path):
    p=Path(path)
    # Create each level 0700 up front. mkdir(parents=True) applies the process umask,
    # leaving a world-readable window between creation and the chmod that follows.
    missing=[]
    cur=p
    while not cur.exists() and cur!=cur.parent:
        missing.append(cur);cur=cur.parent
    for d in reversed(missing):
        try:os.mkdir(d,0o700)
        except FileExistsError:pass
    _assert_not_link(p)
    if not p.is_dir():raise LocalAclError("private path exists and is not a directory: "+str(p))
    if os.name=="nt":
        _run_icacls([str(p),"/inheritance:r","/grant:r",f"{_user()}:(OI)(CI)(F)",
                     "/grant:r",f"{SID_SYSTEM}:(OI)(CI)(F)","/grant:r",f"{SID_ADMINISTRATORS}:(OI)(CI)(F)"])
    else:
        for d in reversed(missing):
            if d.is_dir() and not d.is_symlink():_chmod(d,0o700)
        _chmod(p,0o700)
    return p
