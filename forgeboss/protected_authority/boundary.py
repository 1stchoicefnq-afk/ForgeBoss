from __future__ import annotations

import base64,os,socket,stat
from dataclasses import dataclass
from pathlib import Path
from .protocol import AuthorityError

_WIN_TRUSTED_DEFAULT={'s-1-5-18','s-1-5-32-544'}
_WIN_WRITE_RIGHTS=0x00040000|0x00080000|0x00010000|0x00000002|0x00000004|0x00000040|0x00000100|0x40000000|0x10000000
_WIN_SECRET_RIGHTS=_WIN_WRITE_RIGHTS|0x00000001|0x00000008|0x00000080|0x00020000|0x80000000

@dataclass(frozen=True)
class PeerContext:
    platform:str
    principal:str

def _ed25519_verify(public_key_b64:str,digest_hex:str,signature_b64:str)->bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key=Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64,validate=True));sig=base64.b64decode(signature_b64,validate=True);key.verify(sig,bytes.fromhex(digest_hex));return True
    except Exception:return False

def unix_peer_context(sock:socket.socket)->PeerContext:
    if os.name=='nt' or not hasattr(socket,'SO_PEERCRED'):raise AuthorityError('PEER_CONTEXT_UNAVAILABLE')
    import struct
    try:_pid,uid,_gid=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
    except Exception as e:raise AuthorityError('PEER_CONTEXT_UNAVAILABLE') from e
    return PeerContext('posix',f'uid:{uid}')

def _windows_sid_text(sid_ptr)->str:
    import ctypes
    from ctypes import wintypes
    adv=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True);text=wintypes.LPWSTR()
    if not adv.ConvertSidToStringSidW(sid_ptr,ctypes.byref(text)):raise AuthorityError('WINDOWS_SID_INVALID')
    try:return ctypes.wstring_at(text)
    finally:kernel.LocalFree(text)

def _windows_token_sid(token)->str:
    import ctypes
    from ctypes import wintypes
    adv=ctypes.WinDLL('advapi32',use_last_error=True);needed=wintypes.DWORD(0);adv.GetTokenInformation(token,1,None,0,ctypes.byref(needed))
    if not needed.value:raise AuthorityError('WINDOWS_TOKEN_INVALID')
    buf=ctypes.create_string_buffer(needed.value)
    if not adv.GetTokenInformation(token,1,buf,needed,ctypes.byref(needed)):raise AuthorityError('WINDOWS_TOKEN_INVALID')
    return _windows_sid_text(ctypes.c_void_p.from_buffer(buf).value)

def windows_pipe_peer_context(pipe_handle:int)->PeerContext:
    if os.name!='nt':raise AuthorityError('PEER_CONTEXT_UNAVAILABLE')
    import ctypes
    from ctypes import wintypes
    adv=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    if not adv.ImpersonateNamedPipeClient(wintypes.HANDLE(pipe_handle)):raise AuthorityError('PEER_CONTEXT_UNAVAILABLE')
    token=wintypes.HANDLE()
    try:
        if not adv.OpenThreadToken(kernel.GetCurrentThread(),0x0008,True,ctypes.byref(token)):raise AuthorityError('PEER_CONTEXT_UNAVAILABLE')
        return PeerContext('windows',_windows_token_sid(token).casefold())
    finally:
        if token:kernel.CloseHandle(token)
        adv.RevertToSelf()

def _windows_acl_facts(path:Path):
    import ctypes
    from ctypes import wintypes
    adv=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True);V=wintypes.LPVOID;D=wintypes.DWORD
    class ACLINFO(ctypes.Structure):_fields_=[('AceCount',D),('AclBytesInUse',D),('AclBytesFree',D)]
    class ACEHDR(ctypes.Structure):_fields_=[('AceType',ctypes.c_ubyte),('AceFlags',ctypes.c_ubyte),('AceSize',wintypes.WORD)]
    class TRUSTEE(ctypes.Structure):pass
    PTR=ctypes.POINTER(TRUSTEE);TRUSTEE._fields_=[('pMultipleTrustee',PTR),('MultipleTrusteeOperation',ctypes.c_int),('TrusteeForm',ctypes.c_int),('TrusteeType',ctypes.c_int),('ptstrName',wintypes.LPWSTR)]
    owner=V();dacl=V();sd=V();rc=adv.GetNamedSecurityInfoW(str(path),1,0x1|0x4,ctypes.byref(owner),None,ctypes.byref(dacl),None,ctypes.byref(sd))
    if rc!=0 or not owner.value or not dacl.value:raise AuthorityError('PROTECTED_PATH_PERMISSIONS')
    try:
        owner_sid=_windows_sid_text(owner).casefold();info=ACLINFO()
        if not adv.GetAclInformation(dacl,ctypes.byref(info),ctypes.sizeof(info),2):raise AuthorityError('PROTECTED_PATH_PERMISSIONS')
        trustees={}
        for i in range(int(info.AceCount)):
            ace=V()
            if not adv.GetAce(dacl,i,ctypes.byref(ace)) or not ace.value:raise AuthorityError('PROTECTED_PATH_PERMISSIONS')
            h=ctypes.cast(ace,ctypes.POINTER(ACEHDR)).contents
            if int(h.AceSize)<8:raise AuthorityError('PROTECTED_PATH_ACL_UNKNOWN')
            t=int(h.AceType);base=int(ace.value)
            if t in (0,9):off=8
            elif t in (5,11):
                if int(h.AceSize)<12:raise AuthorityError('PROTECTED_PATH_ACL_UNKNOWN')
                flags=ctypes.c_uint32.from_address(base+8).value;off=12+(16 if flags&1 else 0)+(16 if flags&2 else 0)
            elif t in (1,2,3,4,6,7,8,10,12,13,14,15,16,17):continue
            else:raise AuthorityError('PROTECTED_PATH_ACL_UNKNOWN')
            if off>=int(h.AceSize):raise AuthorityError('PROTECTED_PATH_ACL_UNKNOWN')
            sid_addr=base+off;sid=_windows_sid_text(V(sid_addr));trustees[sid.casefold()]=(sid,sid_addr)
        rights={}
        for k,(text,addr) in trustees.items():
            tr=TRUSTEE();adv.BuildTrusteeWithSidW(ctypes.byref(tr),V(addr));mask=D(0)
            if adv.GetEffectiveRightsFromAclW(dacl,ctypes.byref(tr),ctypes.byref(mask))!=0:raise AuthorityError('PROTECTED_PATH_PERMISSIONS')
            rights[k]=int(mask.value)
        return owner_sid,rights
    finally:
        if sd.value:kernel.LocalFree(sd)

class PlatformMachineBoundary:
    def __init__(self,*,expected_service_principal:str,peer_principals:dict[str,str],peer_public_keys:dict[str,str],trusted_storage_principals:set[str]|None=None):
        if not expected_service_principal or not peer_principals or set(peer_principals)!=set(peer_public_keys):raise AuthorityError('BOUNDARY_CONFIG_INVALID')
        self.expected=expected_service_principal.casefold();self.peer_principals={k:v.casefold() for k,v in peer_principals.items()};self.peer_keys=dict(peer_public_keys);self.trusted_storage={x.casefold() for x in (trusted_storage_principals or set())}|{self.expected}|_WIN_TRUSTED_DEFAULT
    def _service_uid(self):
        if not self.expected.startswith('uid:') or not self.expected[4:].isdigit():raise AuthorityError('SERVICE_PRINCIPAL_INVALID')
        return int(self.expected[4:])
    def _assert_posix_component(self,path:Path,*,root_component=False,secret=False):
        uid=self._service_uid();st=path.stat();mode=stat.S_IMODE(st.st_mode)
        if st.st_uid not in ({uid} if (root_component or secret) else {0,uid}):raise AuthorityError('PROTECTED_PATH_PERMISSIONS')
        if mode&0o022:raise AuthorityError('PROTECTED_PATH_PERMISSIONS')
        if (root_component or secret) and mode&0o077:raise AuthorityError('PROTECTED_PATH_PERMISSIONS')
    def _current_windows_sid(self)->str:
        import ctypes
        from ctypes import wintypes
        adv=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True);token=wintypes.HANDLE()
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(),0x0008,ctypes.byref(token)):raise AuthorityError('SERVICE_PRINCIPAL_INVALID')
        try:return _windows_token_sid(token).casefold()
        finally:kernel.CloseHandle(token)
    def _assert_windows_component(self,path:Path,*,secret=False):
        owner,rights=_windows_acl_facts(path)
        if owner not in self.trusted_storage:raise AuthorityError('PROTECTED_PATH_PERMISSIONS')
        forbidden=_WIN_SECRET_RIGHTS if secret else _WIN_WRITE_RIGHTS
        for sid,mask in rights.items():
            if sid not in self.trusted_storage and mask&forbidden:raise AuthorityError('PROTECTED_PATH_PERMISSIONS')
    def assert_protected_path(self,path:Path,*,protected_root:Path|None=None,secret=False)->None:
        target=Path(path)
        if target.is_symlink() or not target.exists():raise AuthorityError('PROTECTED_PATH_INVALID')
        chain=[];cur=target;stop=Path(protected_root).resolve(strict=True) if protected_root is not None else target.resolve(strict=True)
        while True:
            chain.append(cur)
            if cur.resolve(strict=True)==stop:break
            parent=cur.parent
            if parent==cur:raise AuthorityError('PROTECTED_PATH_INVALID')
            cur=parent
        for component in reversed(chain):
            if component.is_symlink():raise AuthorityError('PROTECTED_PATH_INVALID')
            is_target=component.resolve(strict=True)==target.resolve(strict=True)
            is_root=component.resolve(strict=True)==stop
            if os.name=='nt':self._assert_windows_component(component,secret=(secret and is_target))
            else:self._assert_posix_component(component,root_component=is_root,secret=(secret and is_target))
    def assert_service_principal(self,protected_root:Path)->str:
        root=Path(protected_root)
        if root.is_symlink() or not root.is_dir():raise AuthorityError('PROTECTED_ROOT_INVALID')
        if os.name!='nt':
            uid=self._service_uid()
            if not hasattr(os,'geteuid') or os.geteuid()!=uid:raise AuthorityError('SERVICE_PRINCIPAL_MISMATCH')
            self.assert_protected_path(root,protected_root=root);return f'uid:{uid}'
        sid=self._current_windows_sid()
        if sid!=self.expected:raise AuthorityError('SERVICE_PRINCIPAL_MISMATCH')
        self.assert_protected_path(root,protected_root=root);return sid
    def verify_peer(self,peer_id:str,request_digest:str,signature:str,peer_context:PeerContext|None=None)->bool:
        if peer_context is None or peer_id not in self.peer_principals:return False
        if peer_context.platform!=('windows' if os.name=='nt' else 'posix') or peer_context.principal.casefold()!=self.peer_principals[peer_id]:return False
        return _ed25519_verify(self.peer_keys[peer_id],request_digest,signature)

class FileSecretProvider:
    def __init__(self,*,root:Path,private_key_path:Path,launch_trust_path:Path,boundary:PlatformMachineBoundary):self.root=root.resolve(strict=True);self.private_key_path=private_key_path;self.launch_trust_path=launch_trust_path;self.boundary=boundary
    def _read(self,path:Path)->bytes:
        raw=Path(path)
        if raw.is_symlink():raise AuthorityError('SECRET_PATH_INVALID')
        target=raw.resolve(strict=True)
        try:common=Path(os.path.commonpath([str(self.root),str(target)]))
        except ValueError as e:raise AuthorityError('SECRET_PATH_INVALID') from e
        if common!=self.root or target==self.root or not stat.S_ISREG(target.stat().st_mode):raise AuthorityError('SECRET_PATH_INVALID')
        self.boundary.assert_protected_path(target,protected_root=self.root,secret=True)
        flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0);fd=None
        try:
            fd=os.open(str(target),flags);before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):raise AuthorityError('SECRET_PATH_INVALID')
            chunks=[];total=0
            while True:
                b=os.read(fd,65536)
                if not b:break
                total+=len(b)
                if total>1024*1024:raise AuthorityError('SECRET_SIZE_INVALID')
                chunks.append(b)
            after=os.fstat(fd)
            if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):raise AuthorityError('SECRET_IDENTITY_CHANGED')
            return b''.join(chunks)
        except AuthorityError:raise
        except Exception as e:raise AuthorityError('SECRET_READ_FAILED') from e
        finally:
            if fd is not None:os.close(fd)
    def github_app_private_key(self)->bytes:return self._read(self.private_key_path)
    def launch_trust_root(self)->bytes:return self._read(self.launch_trust_path)
