from __future__ import annotations

import os,stat
from pathlib import Path

from .protocol import AuthorityError


def _is_reparse(path:Path)->bool:
    try:st=path.lstat()
    except OSError as e:raise AuthorityError('PROTECTED_ROOT_ANCESTOR_INVALID') from e
    return bool(getattr(st,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0))

def _service_uid(boundary)->int:
    expected=str(getattr(boundary,'expected',''))
    if not expected.startswith('uid:') or not expected[4:].isdigit():raise AuthorityError('SERVICE_PRINCIPAL_INVALID')
    return int(expected[4:])

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
            boundary.assert_protected_path(component,protected_root=component)
    return resolved
