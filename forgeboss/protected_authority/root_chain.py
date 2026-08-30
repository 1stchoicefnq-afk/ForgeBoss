from __future__ import annotations

import os,stat
from pathlib import Path

from .protocol import AuthorityError

_TRUSTED_INSTALLER_SID='s-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
# Rights that can replace/redirection-control the protected next component or
# retarget the ancestor itself. FILE_ADD_SUBDIRECTORY alone is deliberately not
# included: it cannot replace an already-existing protected next component.
_WIN_ANCESTOR_REPLACE_RIGHTS=(
    0x00010000 |  # DELETE
    0x00000040 |  # FILE_DELETE_CHILD
    0x00000002 |  # FILE_WRITE_DATA / directory write-data (reparse risk)
    0x00040000 |  # WRITE_DAC
    0x00080000 |  # WRITE_OWNER
    0x40000000 |  # GENERIC_WRITE
    0x10000000    # GENERIC_ALL
)
_INHERIT_ONLY_ACE=0x08


def _is_reparse(path:Path)->bool:
    try:st=path.lstat()
    except OSError as e:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_INVALID') from e
    return bool(getattr(st,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0))

def _service_uid(boundary)->int:
    expected=str(getattr(boundary,'expected',''))
    if not expected.startswith('uid:') or not expected[4:].isdigit():raise AuthorityError('SERVICE_PRINCIPAL_INVALID')
    return int(expected[4:])

def _windows_current_object_allows(path:Path):
    """Return owner SID and conservative direct allow masks for this object.

    Inherit-only ACEs are intentionally excluded: they govern descendants and
    do not grant authority over the ancestor currently being validated. Deny
    ACEs are not subtracted from allow masks, which is conservative/fail-closed.
    """
    import ctypes
    from ctypes import wintypes
    from .boundary import _windows_sid_text
    from .win32_ffi import load_win32
    api=load_win32();V=wintypes.LPVOID;D=wintypes.DWORD
    class ACLINFO(ctypes.Structure):_fields_=[('AceCount',D),('AclBytesInUse',D),('AclBytesFree',D)]
    class ACEHDR(ctypes.Structure):_fields_=[('AceType',ctypes.c_ubyte),('AceFlags',ctypes.c_ubyte),('AceSize',wintypes.WORD)]
    owner=V();dacl=V();sd=V()
    rc=api.advapi32.GetNamedSecurityInfoW(str(path),1,0x1|0x4,ctypes.byref(owner),None,ctypes.byref(dacl),None,ctypes.byref(sd))
    if rc!=0 or not owner.value or not dacl.value:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_PERMISSIONS')
    try:
        owner_sid=_windows_sid_text(owner).casefold();info=ACLINFO()
        if not api.advapi32.GetAclInformation(dacl,ctypes.byref(info),ctypes.sizeof(info),2):raise AuthorityError('PROTECTED_ROOT_ANCESTOR_PERMISSIONS')
        allows={}
        for i in range(int(info.AceCount)):
            ace=V()
            if not api.advapi32.GetAce(dacl,i,ctypes.byref(ace)) or not ace.value:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_PERMISSIONS')
            h=ctypes.cast(ace,ctypes.POINTER(ACEHDR)).contents;size=int(h.AceSize);t=int(h.AceType);flags=int(h.AceFlags);base=int(ace.value)
            if size<8:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_ACL_UNKNOWN')
            if flags&_INHERIT_ONLY_ACE:continue
            if t in (0,9):off=8
            elif t in (5,11):
                if size<12:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_ACL_UNKNOWN')
                obj_flags=ctypes.c_uint32.from_address(base+8).value;off=12+(16 if obj_flags&1 else 0)+(16 if obj_flags&2 else 0)
            elif t in (1,2,3,4,6,7,8,10,12,13,14,15,16,17):
                # Deny/audit/mandatory/resource ACEs do not add authority. Deny
                # masks are deliberately not used to reduce an allow mask.
                continue
            else:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_ACL_UNKNOWN')
            if off>=size:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_ACL_UNKNOWN')
            sid=_windows_sid_text(V(base+off)).casefold();mask=ctypes.c_uint32.from_address(base+4).value
            allows[sid]=allows.get(sid,0)|int(mask)
        return owner_sid,allows
    finally:
        if sd.value:api.kernel32.LocalFree(sd)

def _assert_windows_ancestor(boundary,path:Path)->None:
    if not hasattr(boundary,'trusted_storage'):
        boundary.assert_protected_path(path,protected_root=path);return
    owner,rights=_windows_current_object_allows(path)
    trusted=set(boundary.trusted_storage)|{_TRUSTED_INSTALLER_SID}
    if owner not in trusted:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_PERMISSIONS')
    for sid,mask in rights.items():
        if sid not in trusted and mask&_WIN_ANCESTOR_REPLACE_RIGHTS:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_PERMISSIONS')

def assert_machine_anchored_root(boundary,protected_root:Path)->Path:
    root=Path(protected_root)
    if not root.is_absolute() or root.is_symlink() or _is_reparse(root):raise AuthorityError('PROTECTED_ROOT_ANCESTOR_INVALID')
    try:resolved=root.resolve(strict=True)
    except Exception as e:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_INVALID') from e
    boundary.assert_service_principal(resolved)
    chain=[];cur=resolved
    while True:
        chain.append(cur)
        if cur.parent==cur:break
        cur=cur.parent
    if os.name!='nt':
        uid=_service_uid(boundary)
        for component in chain:
            try:st=component.lstat()
            except OSError as e:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_INVALID') from e
            if stat.S_ISLNK(st.st_mode):raise AuthorityError('PROTECTED_ROOT_ANCESTOR_INVALID')
            mode=stat.S_IMODE(st.st_mode)
            if component==resolved:
                if st.st_uid!=uid or mode&0o077:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_PERMISSIONS')
            else:
                if st.st_uid not in {0,uid} or mode&0o022:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_PERMISSIONS')
        if chain[-1]!=Path('/'):raise AuthorityError('PROTECTED_ROOT_ANCESTOR_INVALID')
    else:
        anchor=Path(resolved.anchor)
        if not anchor or chain[-1]!=anchor:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_INVALID')
        for component in chain:
            if component.is_symlink() or _is_reparse(component):raise AuthorityError('PROTECTED_ROOT_ANCESTOR_INVALID')
            if component!=resolved:_assert_windows_ancestor(boundary,component)
    return resolved
