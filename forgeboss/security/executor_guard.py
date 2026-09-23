from __future__ import annotations
import argparse,hashlib,json,math,os,re,secrets,shutil,subprocess,time
from contextlib import contextmanager
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[2]

def _runtime_state_root()->Path:
    return Path(os.environ.get("FORGEBOSS_STATE_ROOT") or (ROOT/"state")).expanduser().resolve()

def _state_dir()->Path:
    path=_runtime_state_root()/"executor-security"
    path.mkdir(parents=True,exist_ok=True)
    return path

CNW=getattr(subprocess,"CREATE_NO_WINDOW",0)
class SecurityError(RuntimeError):pass

FORBIDDEN_PREFIXES=(".git/",".github/workflows/",".github/actions/","secrets/","appdata/",".openhands/",".circleci/","ci/credentials/","build/credentials/",".vscode/","devcontainer/",".devcontainer/","state/forgebossd/","state/learning/")
FORBIDDEN_EXACT={".git",".env",".env.local",".env.production",".npmrc",".pypirc","package.json","dockerfile","docker-compose.yml","docker-compose.yaml","compose.yml","compose.yaml",".pre-commit-config.yaml",".gitlab-ci.yml","jenkinsfile","azure-pipelines.yml","bitbucket-pipelines.yml","requirements.txt","requirements-dev.txt","requirements-test.txt","pyproject.toml","setup.py","setup.cfg","tox.ini","makefile","gnumakefile","pipfile","pipfile.lock","poetry.lock","cargo.toml","cargo.lock","go.mod","go.sum"}
GIT_META_EXACT=("config","config.worktree","HEAD","packed-refs","shallow","info/attributes","info/exclude","objects/info/alternates")
GIT_META_TREES=("refs","hooks")
EXEC_CONFIG_EXACT={"core.askpass","core.editor","core.gitproxy","core.pager","core.sshcommand","diff.external","gpg.program","interactive.difffilter","sequence.editor"}
EXEC_CONFIG_PATTERNS=(re.compile(r"^filter\..+\.(?:clean|smudge|process)$",re.I),re.compile(r"^diff\..+\.(?:command|textconv)$",re.I),re.compile(r"^merge\..+\.driver$",re.I),re.compile(r"^(?:diff|merge)tool\..+\.cmd$",re.I),re.compile(r"^gpg\..+\.program$",re.I),re.compile(r"^(?:pager|browser|man)\..+\.cmd$",re.I))
TRUSTED_SYSTEM_EXEC_PATTERNS=(re.compile(r"^filter\..+\.(?:clean|smudge|process)$",re.I),re.compile(r"^diff\..+\.textconv$",re.I))
_LOCAL_GIT_EXACT={
    ("rev-parse","--git-dir"),("rev-parse","--git-common-dir"),("rev-parse","--show-toplevel"),("rev-parse","HEAD"),("rev-parse","--git-path","hooks"),
    ("config","--includes","--name-only","--list"),("config","--includes","--show-origin","--show-scope","-z","--list"),
    ("ls-files","--stage","-z"),("remote",),
}
_WIN_GIT_REGISTRY_KEY=r"SOFTWARE\GitForWindows"
_WIN_TRUSTED_OWNER_SIDS={"s-1-5-18","s-1-5-32-544"}
_WIN_TRUSTED_INSTALLER_ACCOUNT=r"NT SERVICE\TrustedInstaller"
_WIN_TRUSTED_INSTALLER_SID="s-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_WIN_BROAD_WRITE_SIDS=("S-1-1-0","S-1-5-11","S-1-5-32-545")
_WIN_WRITE_RIGHTS=0x500D0156
_WIN_PARENT_REPLACE_RIGHTS=0x000C0040
_WIN_ALLOW_ACE_TYPES=frozenset((0,5,9,11))
_WIN_DENY_ACE_TYPES=frozenset((1,6,10,12))
_WIN_OBJECT_ACE_TYPES=frozenset((5,6,11,12))

def norm(p):
    if not isinstance(p,str) or not p.strip():raise SecurityError("empty path")
    x=p.replace("\\","/").strip()
    if (len(x)>=2 and x[1]==":") or x.startswith(("/","//","~")):raise SecurityError("absolute/home path denied")
    pp=PurePosixPath(x)
    if ".." in pp.parts:raise SecurityError("parent traversal denied")
    y=pp.as_posix()
    while y.startswith("./"):y=y[2:]
    if not y:raise SecurityError("empty normalized path")
    return y

def key(p):return norm(p).casefold()
def sensitive(p):
    k=key(p);return k in FORBIDDEN_EXACT or any(k.startswith(x) for x in FORBIDDEN_PREFIXES)
def phash(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def fhash(p):
    h=hashlib.sha256()
    with Path(p).open("rb") as f:
        for c in iter(lambda:f.read(1024*1024),b""):h.update(c)
    return h.hexdigest()
def is_linklike(p:Path):
    try:
        if p.is_symlink():return True
    except OSError:return True
    try:
        if hasattr(p,"is_junction") and p.is_junction():return True
    except OSError:return True
    return False
def assert_no_link_escape(work:Path):
    work=work.resolve()
    for p in work.rglob("*"):
        if is_linklike(p):raise SecurityError("baseline symlink/junction denied: "+str(p.relative_to(work)).replace("\\","/"))
def assert_paths_contained(work:Path,paths):
    work=work.resolve()
    for rel in paths:
        p=work/norm(rel);cur=p
        while cur!=work and cur.exists():
            if is_linklike(cur):raise SecurityError("symlink/junction path denied: "+norm(rel))
            cur=cur.parent
        try:
            resolved=p.resolve(strict=False)
            if os.path.commonpath([str(work),str(resolved)])!=str(work):raise SecurityError("resolved path escapes workspace: "+norm(rel))
        except ValueError:raise SecurityError("resolved path escapes workspace: "+norm(rel))
def _metadata_entry(p:Path,label:str):
    try:
        if is_linklike(p):raise SecurityError("linklike Git metadata denied: "+label)
        if not p.is_file():raise SecurityError("Git metadata is not a regular file: "+label)
        return {"kind":"file","sha256":fhash(p),"size":p.stat().st_size}
    except SecurityError:raise
    except Exception as e:raise SecurityError("unable to read Git metadata "+label+": "+str(e)) from e
def _assert_local_git_args(args):
    a=tuple(str(x) for x in args)
    if a in _LOCAL_GIT_EXACT:return
    if len(a)==4 and a[:3]==("config","--includes","--get-all") and a[3] and not any(c in a[3] for c in ("\x00","\r","\n")):return
    raise SecurityError("non-local/transport-capable Git command denied: "+" ".join(a))
def _assert_posix_git_trust(resolved:Path):
    cur=resolved
    while True:
        try:st=cur.stat()
        except Exception as e:raise SecurityError("unable to inspect Git trust path: "+str(cur)) from e
        if st.st_uid!=0:raise SecurityError("untrusted Git path owner: "+str(cur))
        if st.st_mode & 0o022:raise SecurityError("writable Git trust path denied: "+str(cur))
        if cur.parent==cur:break
        cur=cur.parent
def _windows_reparse(p:Path):
    try:return bool(int(getattr(os.lstat(p),"st_file_attributes",0)) & 0x400)
    except OSError:return True
def _windows_trusted_roots(registry=None):
    try:
        if registry is None:
            import winreg as registry
        views=[]
        for flag in (getattr(registry,"KEY_WOW64_64KEY",0),getattr(registry,"KEY_WOW64_32KEY",0)):
            if flag not in views:views.append(flag)
        roots=[];seen=set()
        for view in views:
            try:
                with registry.OpenKey(registry.HKEY_LOCAL_MACHINE,_WIN_GIT_REGISTRY_KEY,0,registry.KEY_READ|view) as key:
                    raw,typ=registry.QueryValueEx(key,"InstallPath")
            except OSError:
                continue
            if typ!=registry.REG_SZ or not isinstance(raw,str) or not raw or raw.strip()!=raw:
                raise SecurityError("Git-for-Windows HKLM InstallPath is invalid")
            p=Path(raw)
            if not p.is_absolute():raise SecurityError("Git-for-Windows HKLM InstallPath is not absolute")
            if is_linklike(p) or _windows_reparse(p):raise SecurityError("linklike Git-for-Windows install root denied: "+str(p))
            try:resolved=p.resolve(strict=True)
            except Exception as e:raise SecurityError("unable to resolve Git-for-Windows HKLM InstallPath: "+str(e)) from e
            if not resolved.is_dir() or is_linklike(resolved) or _windows_reparse(resolved):raise SecurityError("Git-for-Windows HKLM InstallPath is not a trusted directory")
            k=os.path.normcase(os.path.normpath(str(resolved)))
            if k not in seen:seen.add(k);roots.append(resolved)
        if not roots:raise SecurityError("trusted Git-for-Windows HKLM install root unavailable")
        return roots
    except SecurityError:raise
    except Exception as e:raise SecurityError("trusted Git-for-Windows HKLM install root unavailable") from e
def _windows_allow_ace_sid_offset(ace_type:int,object_flags:int=0):
    if ace_type in (0,9):return 8
    if ace_type in (5,11):return 12+(16 if object_flags & 0x1 else 0)+(16 if object_flags & 0x2 else 0)
    return None
def _windows_checked_ace_sid_offset(ace_type:int,ace_size:int,object_flags:int=0):
    if ace_type not in _WIN_ALLOW_ACE_TYPES|_WIN_DENY_ACE_TYPES:raise SecurityError("unsupported Windows DACL ACE type: "+str(ace_type))
    if not isinstance(ace_size,int) or ace_size<16 or ace_size%4:raise SecurityError("malformed Windows DACL ACE size")
    if ace_type in _WIN_OBJECT_ACE_TYPES:
        if object_flags & ~0x3:raise SecurityError("malformed Windows object ACE flags")
        offset=12+(16 if object_flags & 0x1 else 0)+(16 if object_flags & 0x2 else 0)
    else:offset=8
    if offset+8>ace_size:raise SecurityError("malformed Windows DACL ACE layout")
    return offset
def _windows_lookup_account_sid(account:str):
    try:
        import ctypes
        from ctypes import wintypes
        adv=ctypes.WinDLL("advapi32",use_last_error=True);kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        V=wintypes.LPVOID;D=wintypes.DWORD
        adv.LookupAccountNameW.argtypes=[wintypes.LPCWSTR,wintypes.LPCWSTR,V,ctypes.POINTER(D),wintypes.LPWSTR,ctypes.POINTER(D),ctypes.POINTER(ctypes.c_int)];adv.LookupAccountNameW.restype=wintypes.BOOL
        adv.ConvertSidToStringSidW.argtypes=[V,ctypes.POINTER(wintypes.LPWSTR)];adv.ConvertSidToStringSidW.restype=wintypes.BOOL
        kernel.LocalFree.argtypes=[V];kernel.LocalFree.restype=V
        sid_size=D(0);domain_size=D(0);sid_use=ctypes.c_int(0)
        ctypes.set_last_error(0)
        ok=adv.LookupAccountNameW(None,account,None,ctypes.byref(sid_size),None,ctypes.byref(domain_size),ctypes.byref(sid_use))
        err=ctypes.get_last_error()
        if ok or err!=122 or int(sid_size.value)<=0:raise SecurityError("unable to resolve protected Windows service SID: "+account)
        sid_buf=ctypes.create_string_buffer(int(sid_size.value));domain=ctypes.create_unicode_buffer(max(1,int(domain_size.value)))
        if not adv.LookupAccountNameW(None,account,ctypes.cast(sid_buf,V),ctypes.byref(sid_size),domain,ctypes.byref(domain_size),ctypes.byref(sid_use)):
            raise SecurityError("unable to resolve protected Windows service SID: "+account)
        out=wintypes.LPWSTR()
        if not adv.ConvertSidToStringSidW(ctypes.cast(sid_buf,V),ctypes.byref(out)):raise SecurityError("unable to stringify protected Windows service SID: "+account)
        try:return ctypes.wstring_at(out)
        finally:kernel.LocalFree(out)
    except SecurityError:raise
    except Exception as e:raise SecurityError("unable to resolve protected Windows service SID: "+account) from e
def _windows_trusted_principal_sids():
    trusted=set(_WIN_TRUSTED_OWNER_SIDS)
    if os.name!="nt":return frozenset(trusted)
    resolved=_windows_lookup_account_sid(_WIN_TRUSTED_INSTALLER_ACCOUNT).casefold()
    if resolved!=_WIN_TRUSTED_INSTALLER_SID:raise SecurityError("TrustedInstaller SID identity mismatch")
    trusted.add(resolved);return frozenset(trusted)
def _windows_acl_facts(path:Path):
    try:
        import ctypes
        from ctypes import wintypes
        adv=ctypes.WinDLL("advapi32",use_last_error=True);kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        V=wintypes.LPVOID;D=wintypes.DWORD
        class ACL_SIZE_INFORMATION(ctypes.Structure):
            _fields_=[("AceCount",D),("AclBytesInUse",D),("AclBytesFree",D)]
        class ACE_HEADER(ctypes.Structure):
            _fields_=[("AceType",ctypes.c_ubyte),("AceFlags",ctypes.c_ubyte),("AceSize",wintypes.WORD)]
        class TRUSTEE(ctypes.Structure):pass
        PTRUSTEE=ctypes.POINTER(TRUSTEE)
        TRUSTEE._fields_=[("pMultipleTrustee",PTRUSTEE),("MultipleTrusteeOperation",ctypes.c_int),("TrusteeForm",ctypes.c_int),("TrusteeType",ctypes.c_int),("ptstrName",wintypes.LPWSTR)]
        adv.GetNamedSecurityInfoW.argtypes=[wintypes.LPWSTR,D,D,ctypes.POINTER(V),ctypes.POINTER(V),ctypes.POINTER(V),ctypes.POINTER(V),ctypes.POINTER(V)];adv.GetNamedSecurityInfoW.restype=D
        adv.ConvertSidToStringSidW.argtypes=[V,ctypes.POINTER(wintypes.LPWSTR)];adv.ConvertSidToStringSidW.restype=wintypes.BOOL
        adv.BuildTrusteeWithSidW.argtypes=[ctypes.POINTER(TRUSTEE),V];adv.BuildTrusteeWithSidW.restype=None
        adv.GetEffectiveRightsFromAclW.argtypes=[V,ctypes.POINTER(TRUSTEE),ctypes.POINTER(D)];adv.GetEffectiveRightsFromAclW.restype=D
        adv.GetAclInformation.argtypes=[V,V,D,D];adv.GetAclInformation.restype=wintypes.BOOL
        adv.GetAce.argtypes=[V,D,ctypes.POINTER(V)];adv.GetAce.restype=wintypes.BOOL
        adv.IsValidSid.argtypes=[V];adv.IsValidSid.restype=wintypes.BOOL
        adv.GetLengthSid.argtypes=[V];adv.GetLengthSid.restype=D
        kernel.LocalFree.argtypes=[V];kernel.LocalFree.restype=V
        owner=V();dacl=V();sd=V()
        rc=adv.GetNamedSecurityInfoW(str(path),1,0x1|0x4,ctypes.byref(owner),None,ctypes.byref(dacl),None,ctypes.byref(sd))
        if rc!=0 or not owner.value or not dacl.value:raise SecurityError("unable to read Windows owner/DACL: "+str(path))
        def sid_text(sid_ptr):
            text=wintypes.LPWSTR()
            if not adv.ConvertSidToStringSidW(sid_ptr,ctypes.byref(text)):raise SecurityError("unable to read Windows SID: "+str(path))
            try:return ctypes.wstring_at(text)
            finally:kernel.LocalFree(text)
        owner_sid=sid_text(owner)
        info=ACL_SIZE_INFORMATION()
        if not adv.GetAclInformation(dacl,ctypes.byref(info),ctypes.sizeof(info),2):raise SecurityError("unable to enumerate Windows DACL: "+str(path))
        trustee_sids={}
        for i in range(int(info.AceCount)):
            ace=V()
            if not adv.GetAce(dacl,i,ctypes.byref(ace)) or not ace.value:raise SecurityError("unable to read Windows DACL ACE: "+str(path))
            header=ctypes.cast(ace,ctypes.POINTER(ACE_HEADER)).contents
            ace_type=int(header.AceType);ace_size=int(header.AceSize);base=int(ace.value)
            if ace_size<16 or ace_size%4:raise SecurityError("malformed Windows DACL ACE size: "+str(path))
            object_flags=ctypes.c_uint32.from_address(base+8).value if ace_type in _WIN_OBJECT_ACE_TYPES else 0
            offset=_windows_checked_ace_sid_offset(ace_type,ace_size,object_flags)
            sid_addr=base+offset
            subauth_count=int(ctypes.c_ubyte.from_address(sid_addr+1).value);sid_len=8+4*subauth_count
            if sid_len<8 or offset+sid_len>ace_size:raise SecurityError("malformed Windows DACL SID bounds: "+str(path))
            sid=V(sid_addr)
            if not adv.IsValidSid(sid) or int(adv.GetLengthSid(sid))!=sid_len:raise SecurityError("invalid Windows DACL SID: "+str(path))
            if ace_type in _WIN_DENY_ACE_TYPES:continue
            text=sid_text(sid);trustee_sids[text.casefold()]=(text,sid_addr)
        rights={}
        for _,(text,sid_addr) in sorted(trustee_sids.items()):
            trustee=TRUSTEE();adv.BuildTrusteeWithSidW(ctypes.byref(trustee),V(sid_addr));mask=D(0)
            rc=adv.GetEffectiveRightsFromAclW(dacl,ctypes.byref(trustee),ctypes.byref(mask))
            if rc!=0:raise SecurityError("unable to evaluate Windows DACL: "+str(path))
            rights[text]=int(mask.value)
        return owner_sid,rights
    except SecurityError:raise
    except Exception as e:raise SecurityError("unable to inspect Windows Git ACL: "+str(path)) from e
    finally:
        try:
            if 'sd' in locals() and sd.value:kernel.LocalFree(sd)
        except Exception:pass
def _assert_windows_acl_mask(path:Path,deny_mask:int,reason:str):
    owner,rights=_windows_acl_facts(path);trusted=_windows_trusted_principal_sids()
    if str(owner).casefold() not in trusted:raise SecurityError("untrusted Windows Git path owner: "+str(path))
    for sid,mask in rights.items():
        if str(sid).casefold() not in trusted and int(mask) & int(deny_mask):
            raise SecurityError(reason+str(sid)+" -> "+str(path))
def _assert_windows_acl_trust(path:Path):
    return _assert_windows_acl_mask(path,_WIN_WRITE_RIGHTS,"untrusted principal has write-capable Git path rights: ")
def _assert_windows_parent_replacement_trust(path:Path):
    return _assert_windows_acl_mask(path,_WIN_PARENT_REPLACE_RIGHTS,"untrusted principal has replacement-capable parent rights: ")
def _windows_path_key(p:Path):return os.path.normcase(os.path.normpath(str(p)))
def _windows_within(path:Path,root:Path):
    try:return os.path.commonpath([_windows_path_key(path),_windows_path_key(root)])==_windows_path_key(root)
    except ValueError:return False
def _assert_windows_git_trust(resolved:Path):
    roots=_windows_trusted_roots();matches=[r for r in roots if _windows_within(resolved,r)]
    if not matches:raise SecurityError("untrusted Git-for-Windows install path: "+str(resolved))
    root=max(matches,key=lambda x:len(_windows_path_key(x)));cur=resolved
    while True:
        if is_linklike(cur) or _windows_reparse(cur):raise SecurityError("linklike Git trust path denied: "+str(cur))
        _assert_windows_acl_trust(cur)
        if _windows_path_key(cur)==_windows_path_key(root):break
        if cur.parent==cur:raise SecurityError("Git executable escaped trusted install root")
        cur=cur.parent
    if os.name=="nt":
        anchor=str(root.anchor)
        if not re.fullmatch(r"[A-Za-z]:\\",anchor):raise SecurityError("Git-for-Windows trust root is not on a local drive")
    volume=Path(root.anchor) if root.anchor else root
    ancestor=root.parent
    while True:
        if is_linklike(ancestor) or _windows_reparse(ancestor):raise SecurityError("linklike Git ancestor trust path denied: "+str(ancestor))
        if _windows_path_key(ancestor)==_windows_path_key(volume):
            _assert_windows_parent_replacement_trust(ancestor);break
        _assert_windows_acl_trust(ancestor)
        if ancestor.parent==ancestor:raise SecurityError("Git trust chain has no stable volume boundary")
        ancestor=ancestor.parent
def _resolve_git_executable():
    name="git.exe" if os.name=="nt" else "git"
    raw=shutil.which(name)
    if not raw:raise SecurityError("Git executable unavailable: "+name)
    p=Path(raw)
    try:
        if not p.is_absolute():raise SecurityError("Git executable resolution is not absolute: "+str(p))
        if is_linklike(p):raise SecurityError("linklike Git executable denied: "+str(p))
        resolved=p.resolve(strict=True)
        if is_linklike(resolved):raise SecurityError("linklike Git executable denied: "+str(resolved))
        if not resolved.is_file():raise SecurityError("Git executable is not a regular file: "+str(resolved))
        if os.name!="nt" and not os.access(resolved,os.X_OK):raise SecurityError("Git executable is not executable: "+str(resolved))
        if os.name=="nt":_assert_windows_git_trust(resolved)
        else:_assert_posix_git_trust(resolved)
    except SecurityError:raise
    except Exception as e:raise SecurityError("unable to resolve Git executable: "+str(e)) from e
    return resolved
def _git_executable_identity():
    p=_resolve_git_executable()
    try:return {"kind":"executable","path":str(p),"sha256":fhash(p),"size":p.stat().st_size}
    except Exception as e:raise SecurityError("unable to bind Git executable identity: "+str(e)) from e
def git(work,*args):
    _assert_local_git_args(args);exe=_resolve_git_executable()
    p=subprocess.run([str(exe),*args],cwd=work,capture_output=True,text=True,timeout=60,creationflags=CNW)
    if p.returncode:raise SecurityError((p.stdout+p.stderr).strip() or "git failed")
    return p.stdout.strip()
def _resolve_git_dir(work:Path,flag:str):
    raw=git(work,"rev-parse",flag)
    if not raw:raise SecurityError("empty Git metadata resolution for "+flag)
    p=Path(raw)
    if not p.is_absolute():p=work/p
    try:resolved=p.resolve(strict=True)
    except Exception as e:raise SecurityError("unable to resolve Git metadata "+flag+": "+str(e)) from e
    if not resolved.is_dir():raise SecurityError("resolved Git metadata is not directory: "+flag)
    return resolved
def _snapshot_metadata_root(root:Path,prefix:str,out:dict):
    for rel in GIT_META_EXACT:
        p=root/rel
        try:exists=p.exists() or is_linklike(p)
        except OSError as e:raise SecurityError("unable to inspect Git metadata "+prefix+rel+": "+str(e)) from e
        if exists:out[prefix+rel]=_metadata_entry(p,prefix+rel)
    for tree in GIT_META_TREES:
        base=root/tree
        try:
            if not base.exists():continue
            if is_linklike(base):raise SecurityError("linklike Git metadata denied: "+prefix+tree)
            entries=list(base.rglob("*"))
        except SecurityError:raise
        except Exception as e:raise SecurityError("unable to enumerate Git metadata "+prefix+tree+": "+str(e)) from e
        for p in entries:
            rel=str(p.relative_to(root)).replace("\\","/")
            if p.is_dir() and not is_linklike(p):continue
            out[prefix+rel]=_metadata_entry(p,prefix+rel)
def _config_names(work:Path):
    raw=git(work,"config","--includes","--name-only","--list")
    return {line.strip().casefold() for line in raw.splitlines() if line.strip()}
def _config_values(work:Path,name:str):return [x.strip() for x in git(work,"config","--includes","--get-all",name).splitlines() if x.strip()]
def _parse_effective_config(raw:str):
    if not isinstance(raw,str):raise SecurityError("effective Git config is not text")
    parts=raw.split("\x00")
    if parts and parts[-1]=="":parts.pop()
    if len(parts)%3:raise SecurityError("effective Git config record framing invalid")
    out=[]
    for i in range(0,len(parts),3):
        scope=parts[i].strip().casefold();origin=parts[i+1];record=parts[i+2]
        name,sep,value=record.partition("\n")
        name=name.strip().casefold()
        if not scope or not origin or not name or not sep:raise SecurityError("effective Git config record invalid")
        out.append({"scope":scope,"origin":origin,"name":name,"value":value})
    return tuple(out)
def _entry_values(entries,name):return [e["value"].strip() for e in entries if e["name"]==name and e["value"].strip()]
def _assert_trusted_system_config_origin(entry):
    if entry.get("scope")!="system":raise SecurityError("untrusted Git execution config scope: "+str(entry.get("scope") or ""))
    origin=str(entry.get("origin") or "")
    if not origin.startswith("file:"):raise SecurityError("untrusted Git execution config origin: "+origin)
    p=Path(origin[5:])
    try:
        if not p.is_absolute():raise SecurityError("untrusted Git execution config origin: "+origin)
        if is_linklike(p):raise SecurityError("linklike Git execution config origin denied: "+origin)
        resolved=p.resolve(strict=True)
        if not resolved.is_file() or is_linklike(resolved):raise SecurityError("Git execution config origin is not a trusted regular file: "+origin)
        if os.name=="nt":_assert_windows_git_trust(resolved)
        else:_assert_posix_git_trust(resolved)
        return resolved
    except SecurityError:raise
    except Exception as e:raise SecurityError("unable to trust Git execution config origin: "+origin) from e
def _resolve_effective_git_path(work:Path,*args):
    raw=git(work,*args)
    if not raw:raise SecurityError("empty Git execution target resolution")
    p=Path(raw)
    if not p.is_absolute():p=work/p
    try:return p.resolve(strict=False)
    except Exception as e:raise SecurityError("unable to resolve Git execution target: "+str(e)) from e
def _assert_effective_worktree(work:Path):
    try:
        raw=git(work,"rev-parse","--show-toplevel")
        if not raw:raise SecurityError("empty effective Git worktree identity")
        effective=Path(raw)
        if not effective.is_absolute():effective=work/effective
        effective=effective.resolve(strict=True);leased=work.resolve(strict=True)
    except SecurityError:raise
    except Exception as e:raise SecurityError("unable to resolve effective Git worktree identity: "+str(e)) from e
    if effective!=leased:raise SecurityError("effective Git worktree escapes leased workspace: "+str(effective))
def _assert_safe_execution_config(work:Path,gitdir:Path,common:Path,entries):
    _assert_effective_worktree(work);names={e["name"] for e in entries}
    if "core.hookspath" in names:
        target=_resolve_effective_git_path(work,"rev-parse","--git-path","hooks");trusted={(gitdir/"hooks").resolve(strict=False),(common/"hooks").resolve(strict=False)}
        if target not in trusted:raise SecurityError("external Git execution target denied: core.hooksPath -> "+str(target))
    if "core.fsmonitor" in names:
        vals=[v.casefold() for v in _entry_values(entries,"core.fsmonitor")]
        if any(v not in ("true","false") for v in vals):raise SecurityError("external Git execution target denied: core.fsmonitor")
    if "protocol.ext.allow" in names:
        vals=[v.casefold() for v in _entry_values(entries,"protocol.ext.allow")]
        if not vals or any(v!="never" for v in vals):raise SecurityError("execution-capable Git transport denied: protocol.ext.allow")
    elif "protocol.allow" in names:
        vals=[v.casefold() for v in _entry_values(entries,"protocol.allow")]
        if not vals or any(v!="never" for v in vals):raise SecurityError("execution-capable Git transport denied: protocol.allow")
    for entry in sorted(entries,key=lambda e:(e["name"],e["scope"],e["origin"],e["value"])):
        name=entry["name"];value=entry["value"]
        if name in EXEC_CONFIG_EXACT:raise SecurityError("execution-capable Git config denied: "+name)
        matched=any(rx.match(name) for rx in EXEC_CONFIG_PATTERNS)
        if matched:
            if any(rx.match(name) for rx in TRUSTED_SYSTEM_EXEC_PATTERNS):
                if entry.get("scope")!="system":raise SecurityError("execution-capable Git config denied: "+name+" from "+str(entry.get("scope") or ""))
                try:_assert_trusted_system_config_origin(entry)
                except SecurityError as e:raise SecurityError("execution-capable Git config denied: "+name+" from "+entry["scope"]+" "+entry["origin"]+" ("+str(e)+")") from e
                continue
            raise SecurityError("execution-capable Git config denied: "+name)
        if name.startswith("alias.") and value.lstrip().startswith("!"):raise SecurityError("execution-capable Git config denied: "+name)
        if name.startswith("submodule.") and name.endswith(".update") and value.lstrip().startswith("!"):raise SecurityError("execution-capable Git config denied: "+name)
def git_metadata_snapshot(work):
    work=Path(work).resolve();dotgit=work/".git";out={};git_exe_before=_git_executable_identity()
    if not dotgit.exists() and not is_linklike(dotgit):return out
    if is_linklike(dotgit):raise SecurityError("linklike workspace .git denied")
    if dotgit.is_file():out[".git"]=_metadata_entry(dotgit,".git")
    elif not dotgit.is_dir():raise SecurityError("workspace .git is not file/directory")
    gitdir=_resolve_git_dir(work,"--git-dir");common=_resolve_git_dir(work,"--git-common-dir")
    _snapshot_metadata_root(gitdir,"gitdir/",out)
    if common!=gitdir:_snapshot_metadata_root(common,"common/",out)
    effective=git(work,"config","--includes","--show-origin","--show-scope","-z","--list");entries=_parse_effective_config(effective)
    _assert_safe_execution_config(work,gitdir,common,entries)
    out["git:effective-config"]={"kind":"semantic","sha256":hashlib.sha256(effective.encode("utf-8")).hexdigest()}
    staged=git(work,"ls-files","--stage","-z")
    out["git:index:stage"]={"kind":"semantic","sha256":hashlib.sha256(staged.encode("utf-8")).hexdigest()}
    git_exe_after=_git_executable_identity()
    if git_exe_before!=git_exe_after:raise SecurityError("Git executable identity changed during metadata snapshot")
    out["git:executable"]=git_exe_before
    return out
def snapshot(work):
    work=Path(work).resolve();out={}
    for p in work.rglob("*"):
        try:r=norm(str(p.relative_to(work)))
        except Exception:continue
        rk=r.casefold()
        if rk==".git" or rk.startswith(".git/"):continue
        if is_linklike(p):out[r]={"kind":"link","target":os.readlink(p) if p.is_symlink() else "<junction>"}
        elif p.is_file():out[r]={"kind":"file","sha256":fhash(p),"size":p.stat().st_size}
    return out
def changed(a,b):return sorted(k for k in set(a)|set(b) if a.get(k)!=b.get(k))
def validate_packet(packet):
    allowed=[norm(x) for x in packet.get("allowed_files",[])];context=[norm(x) for x in packet.get("context_files",[])]
    if not allowed:raise SecurityError("packet has no allowed_files")
    if len({x.casefold() for x in allowed})!=len(allowed):raise SecurityError("duplicate allowed_files after Windows casefold")
    for p in allowed:
        if sensitive(p):raise SecurityError("sensitive/high-impact write path denied: "+p)
    for p in context:
        k=p.casefold()
        if k==".git" or k.startswith(".git/"):raise SecurityError("Git metadata read denied")
    return allowed,context
def exact_head(work,packet):
    exp=packet.get("expected_head_revision") or packet.get("exact_head")
    if exp and (Path(work)/".git").exists():
        got=git(work,"rev-parse","HEAD")
        if got!=exp:raise SecurityError(f"exact HEAD mismatch {got} != {exp}")
def no_remotes(work):
    if (Path(work)/".git").exists() and git(work,"remote").strip():raise SecurityError("Git remotes present in executor workspace")
def isolation_ok(executor):
    if executor=="mini-swe":return True
    return os.environ.get("FORGEBOSS_OS_ISOLATION_VERIFIED")=="YES"
def _positive_budget(raw):
    if isinstance(raw,bool):raise SecurityError("paid budget must be a finite positive number")
    try:v=float(raw)
    except (TypeError,ValueError,OverflowError) as e:raise SecurityError("paid budget must be a finite positive number") from e
    if not math.isfinite(v) or v<=0:raise SecurityError("paid budget must be a finite positive number")
    return v
def _atomic_write_json(path,obj):
    path=Path(path);tmp=path.with_name(path.name+f".tmp-{os.getpid()}-{secrets.token_hex(4)}")
    data=json.dumps(obj,sort_keys=True,indent=2).encode("utf-8");fd=os.open(str(tmp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as f:f.write(data);f.flush();os.fsync(f.fileno())
    finally:
        try:os.close(fd)
        except OSError:pass
    os.replace(tmp,path)
class _WorkspaceFence:
    def __init__(self,workspace):self.path=_state_dir()/("paid-start-"+hashlib.sha256(str(Path(workspace).resolve()).encode()).hexdigest()+".lock");self.f=None
    def __enter__(self):
        self.f=self.path.open("a+b");self.f.seek(0,2)
        if self.f.tell()==0:self.f.write(b"\0");self.f.flush()
        self.f.seek(0)
        if os.name=="nt":
            import msvcrt;msvcrt.locking(self.f.fileno(),msvcrt.LK_LOCK,1)
        else:
            import fcntl;fcntl.flock(self.f.fileno(),fcntl.LOCK_EX)
        return self
    def __exit__(self,*_):
        try:
            self.f.seek(0)
            if os.name=="nt":
                import msvcrt;msvcrt.locking(self.f.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl;fcntl.flock(self.f.fileno(),fcntl.LOCK_UN)
        finally:self.f.close();self.f=None
def _load_control_envelope(raw):
    if not isinstance(raw,str) or not raw.strip():raise SecurityError("signed control envelope missing")
    text=raw.strip();p=Path(text)
    if not text.startswith("{") and p.exists():text=p.read_text(encoding="utf-8")
    try:payload=json.loads(text)
    except Exception as e:raise SecurityError("signed control envelope is invalid JSON") from e
    try:
        from forgeboss.control.envelope import secret_file,verify_envelope
        _,secret=secret_file(ROOT);return verify_envelope(payload,secret)
    except Exception as e:raise SecurityError("signed control envelope verification failed: "+str(e)) from e
def _protected_launch_bundle(raw):
    if not isinstance(raw,str) or not raw.strip():raise SecurityError("protected launch bundle missing")
    p=Path(raw)
    try:obj=json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:raise SecurityError("protected launch bundle is invalid") from e
    if not isinstance(obj,dict) or set(obj)!={"schema","launch","authorityResponse"} or obj.get("schema")!=2:
        raise SecurityError("protected launch bundle schema invalid")
    if not isinstance(obj.get("launch"),dict):
        raise SecurityError("protected launch payload invalid")
    return obj

def _protected_control_authority(raw,lease,packet,workspace,executor,cli_budget=None):
    bundle=_protected_launch_bundle(raw);authority=packet.get("self_build_authority")
    if not isinstance(authority,dict):raise SecurityError("self-build protected authority packet missing")
    required={"repository","control_revision","task_id","run_id","owner_epoch","builder_id","assignment_generation","assignment_sha256",
              "branch","budget_usd","global_budget_run_id","global_budget_reservation_id","receipt_public_key_b64"}
    if set(authority)!=required:raise SecurityError("self-build protected authority packet shape invalid")
    signed=bundle["launch"]
    from forgeboss.protected_authority.protocol import canonical_digest
    from forgeboss.protected_authority.signing import verify_signed_receipt
    digest=canonical_digest(signed);response=bundle["authorityResponse"]
    pin=authority["receipt_public_key_b64"]
    if not verify_signed_receipt(response,pin):raise SecurityError("protected authority service receipt invalid")
    receipt=response["receipt"];result=response["result"]
    if receipt.get("operation")!="authorize_self_build_launch":raise SecurityError("protected authority receipt operation mismatch")
    if str(receipt.get("repository","")).casefold()!=str(authority["repository"]).casefold():raise SecurityError("protected authority receipt repository mismatch")
    if int(receipt.get("controlRevision",0))!=int(authority["control_revision"]):raise SecurityError("protected authority control revision mismatch")
    if result.get("verified") is not True or result.get("launchDigest")!=digest:raise SecurityError("protected launch authority not verified")
    source=result.get("sourceIdentity")
    if not isinstance(source,dict):raise SecurityError("protected launch source identity missing")
    expected_head=str(packet.get("expected_head_revision") or "").lower()
    if not expected_head or str(source.get("revision") or "").lower()!=expected_head:
        raise SecurityError("protected launch source revision mismatch")
    if result.get("trustGrade")!="OWNER_DECLARED_TRUSTED_LOCAL_BOOTSTRAP":
        raise SecurityError("protected launch trust grade mismatch")
    work=Path(workspace).resolve();allowed=[norm(x) for x in lease.get("allowed_files",[])]
    expected={
        "schema":1,
        "repository":authority["repository"],
        "controlRevision":int(authority["control_revision"]),
        "taskId":authority["task_id"],
        "runId":authority["run_id"],
        "ownerEpoch":int(authority["owner_epoch"]),
        "builderId":authority["builder_id"],
        "assignmentGeneration":int(authority["assignment_generation"]),
        "assignmentSha256":authority["assignment_sha256"],
        "branch":authority["branch"],
        "worktreePath":str(work),
        "runtimeId":executor,
        "allowedPaths":allowed,
        "packetSha256":lease.get("packet_sha256"),
        "budgetUsd":str(authority["budget_usd"]),
        "globalBudgetRunId":authority["global_budget_run_id"],
        "globalBudgetReservationId":authority["global_budget_reservation_id"],
    }
    expires=signed.get("expiresAt")
    if isinstance(expires,bool):
        raise SecurityError("protected launch expiry invalid")
    try:expires=float(expires)
    except Exception as e:raise SecurityError("protected launch expiry invalid") from e
    if not math.isfinite(expires) or expires<=time.time():raise SecurityError("protected launch authority expired")
    actual=dict(signed);actual.pop("expiresAt",None)
    if actual!=expected:raise SecurityError("protected launch envelope binding mismatch")
    budget=_positive_budget(authority["budget_usd"])
    if cli_budget is not None and _positive_budget(cli_budget)!=budget:raise SecurityError("runner budget differs from protected launch authority")
    return {"taskId":authority["task_id"],"runId":authority["run_id"],"ownerEpoch":int(authority["owner_epoch"]),
            "budgetUsd":budget,"worktreePath":str(work),"runtime":{"adapter":executor},"expiresAt":expires,
            "allowedPaths":allowed,"envelopeSha256":digest,"protected":True,
            "globalBudgetRunId":authority["global_budget_run_id"],"globalBudgetReservationId":authority["global_budget_reservation_id"]}

def consume_protected_paid_start(lease_path,token,packet_path,workspace,executor,launch_bundle,cli_budget=None):
    lease_path=Path(lease_path);pp=Path(packet_path)
    with _WorkspaceFence(workspace):
        lease=_verify_unlocked(lease_path,token,pp,workspace,executor)
        if lease.get("paid_consumed") is True:raise SecurityError("paid executor authority already consumed")
        packet=json.loads(pp.read_text(encoding="utf-8"))
        authority=_protected_control_authority(launch_bundle,lease,packet,workspace,executor,cli_budget)
        ch=changed(lease.get("git_metadata"),git_metadata_snapshot(Path(workspace).resolve()))
        if ch:raise SecurityError("Git metadata changed at protected paid-start boundary: "+json.dumps(ch))
        lease["paid_consumed"]=True;lease["paid_consumed_at"]=time.time();lease["paid_authority"]=authority
        _atomic_write_json(lease_path,lease)
        return authority

def _control_authority(raw,lease,workspace,executor):
    env=_load_control_envelope(raw);work=Path(workspace).resolve()
    if Path(env.get("worktreePath","")).resolve()!=work:raise SecurityError("control envelope workspace mismatch")
    task=str(env.get("taskId") or "").strip();run=str(env.get("runId") or "").strip()
    if not task or not run:raise SecurityError("control envelope task/run identity missing")
    try:epoch=int(env.get("ownerEpoch"))
    except Exception as e:raise SecurityError("control envelope ownerEpoch invalid") from e
    if epoch<=0:raise SecurityError("control envelope ownerEpoch invalid")
    runtime=env.get("runtime")
    if not isinstance(runtime,dict) or str(runtime.get("adapter") or "")!=executor:raise SecurityError("control envelope runtime differs from executor")
    budget=_positive_budget(env.get("budgetUsd"));ea=[norm(x) for x in env.get("allowedPaths",[])];la=[norm(x) for x in lease.get("allowed_files",[])]
    if [x.casefold() for x in ea]!=[x.casefold() for x in la]:raise SecurityError("control envelope allowedPaths differ from executor lease")
    unsigned=json.dumps(env,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    return {"taskId":task,"runId":run,"ownerEpoch":epoch,"budgetUsd":budget,"worktreePath":str(work),"runtime":runtime,"expiresAt":float(env["expiresAt"]),"allowedPaths":ea,"envelopeSha256":hashlib.sha256(unsigned).hexdigest()}
def issue_lease(packet_path,workspace,executor,ttl=1200):
    pp=Path(packet_path);work=Path(workspace).resolve();packet=json.loads(pp.read_text(encoding="utf-8"));allowed,context=validate_packet(packet)
    if executor in ("openhands","opencode") and not isolation_ok(executor):raise SecurityError(f"{executor} write-capable execution is quarantined until OS/network isolation is verified")
    with _WorkspaceFence(work):
        assert_no_link_escape(work);assert_paths_contained(work,allowed+context);exact_head(work,packet);no_remotes(work);token=secrets.token_urlsafe(32)
        lease={"schema":3,"executor":executor,"workspace":str(work),"packet_sha256":phash(pp),"allowed_files":allowed,"allowed_keys":[x.casefold() for x in allowed],"issued_at":time.time(),"expires_at":time.time()+ttl,"token_sha256":hashlib.sha256(token.encode()).hexdigest(),"baseline":snapshot(work),"git_metadata":git_metadata_snapshot(work),"isolation_verified":isolation_ok(executor),"paid_consumed":False,"paid_authority":None}
        lp=_state_dir()/f"lease-{int(time.time()*1000)}-{secrets.token_hex(4)}.json";_atomic_write_json(lp,lease)
    return {"ok":True,"lease":str(lp),"token":token}

def issue(packet_path,workspace,executor,ttl=1200):
    print(json.dumps(issue_lease(packet_path,workspace,executor,ttl)));return 0

def _verify_unlocked(lease_path,token,packet_path,workspace,executor):
    lease=json.loads(Path(lease_path).read_text(encoding="utf-8"));work=Path(workspace).resolve();pp=Path(packet_path)
    if time.time()>float(lease.get("expires_at",0)):raise SecurityError("executor lease expired")
    if lease.get("executor")!=executor:raise SecurityError("executor identity mismatch")
    if Path(lease.get("workspace","")).resolve()!=work:raise SecurityError("workspace mismatch")
    if lease.get("packet_sha256")!=phash(pp):raise SecurityError("packet changed after lease")
    if not secrets.compare_digest(lease.get("token_sha256",""),hashlib.sha256(token.encode()).hexdigest()):raise SecurityError("lease token mismatch")
    packet=json.loads(pp.read_text(encoding="utf-8"));allowed,context=validate_packet(packet);assert_no_link_escape(work);assert_paths_contained(work,allowed+context);exact_head(work,packet);no_remotes(work)
    if executor in ("openhands","opencode") and not isolation_ok(executor):raise SecurityError(f"{executor} isolation proof disappeared after lease")
    before=lease.get("git_metadata")
    if not isinstance(before,dict):raise SecurityError("executor lease missing Git metadata baseline")
    ch=changed(before,git_metadata_snapshot(work))
    if ch:raise SecurityError("Git metadata changed after lease before execution: "+json.dumps(ch))
    return lease
def verify(lease_path,token,packet_path,workspace,executor):
    with _WorkspaceFence(workspace):return _verify_unlocked(lease_path,token,packet_path,workspace,executor)
@contextmanager
def paid_start_authority(lease_path,token,packet_path,workspace,executor,control_envelope,cli_budget=None):
    lease_path=Path(lease_path)
    with _WorkspaceFence(workspace):
        lease=_verify_unlocked(lease_path,token,packet_path,workspace,executor)
        if lease.get("paid_consumed") is True:raise SecurityError("paid executor authority already consumed")
        authority=_control_authority(control_envelope,lease,workspace,executor);budget=authority["budgetUsd"]
        if cli_budget is not None and _positive_budget(cli_budget)!=budget:raise SecurityError("runner budget differs from signed control authority")
        ch=changed(lease.get("git_metadata"),git_metadata_snapshot(Path(workspace).resolve()))
        if ch:raise SecurityError("Git metadata changed at paid-start boundary: "+json.dumps(ch))
        lease["paid_consumed"]=True;lease["paid_consumed_at"]=time.time();lease["paid_authority"]=authority;_atomic_write_json(lease_path,lease)
        yield authority
def postflight(lease_path,token,packet_path,workspace,executor):
    lease=verify(lease_path,token,packet_path,workspace,executor)
    with _WorkspaceFence(workspace):
        before=lease.get("git_metadata")
        if not isinstance(before,dict):raise SecurityError("executor lease missing Git metadata baseline")
        gc=changed(before,git_metadata_snapshot(workspace))
        if gc:raise SecurityError("Git metadata changed during executor run: "+json.dumps(gc))
        after=snapshot(workspace);ch=changed(lease.get("baseline") or {},after);allowed={x.casefold() for x in (lease.get("allowed_files") or [])};bad=[p for p in ch if p.casefold() not in allowed];links=[p for p in ch if (after.get(p) or {}).get("kind")=="link"]
        if bad:raise SecurityError("out-of-scope changes: "+json.dumps(bad))
        if links:raise SecurityError("symlink/junction changes denied: "+json.dumps(links))
        no_remotes(Path(workspace))
    print(json.dumps({"ok":True,"changed_paths":ch,"scope_ok":True,"isolation_verified":lease.get("isolation_verified"),"paid_consumed":lease.get("paid_consumed") is True}));return 0
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True);x=sp.add_parser("issue");x.add_argument("--packet",required=True);x.add_argument("--workspace",required=True);x.add_argument("--executor",required=True);x.add_argument("--ttl",type=int,default=1200)
    for n in ("verify","postflight"):
        x=sp.add_parser(n);x.add_argument("--lease",required=True);x.add_argument("--token",required=True);x.add_argument("--packet",required=True);x.add_argument("--workspace",required=True);x.add_argument("--executor",required=True)
    x=sp.add_parser("protected-paid-start");x.add_argument("--lease",required=True);x.add_argument("--token",required=True);x.add_argument("--packet",required=True);x.add_argument("--workspace",required=True);x.add_argument("--executor",required=True);x.add_argument("--launch-bundle",required=True);x.add_argument("--budget",required=True)
    ns=ap.parse_args()
    try:
        if ns.cmd=="issue":return issue(ns.packet,ns.workspace,ns.executor,ns.ttl)
        if ns.cmd=="verify":verify(ns.lease,ns.token,ns.packet,ns.workspace,ns.executor);print(json.dumps({"ok":True}));return 0
        if ns.cmd=="protected-paid-start":
            a=consume_protected_paid_start(ns.lease,ns.token,ns.packet,ns.workspace,ns.executor,ns.launch_bundle,ns.budget);print(json.dumps({"ok":True,"authority":a}));return 0
        return postflight(ns.lease,ns.token,ns.packet,ns.workspace,ns.executor)
    except Exception as e:print(json.dumps({"ok":False,"error":f"{type(e).__name__}: {e}"}));return 13
if __name__=="__main__":raise SystemExit(main())
