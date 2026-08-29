from __future__ import annotations
import os
from pathlib import Path

READONLY=0x1; DIRECTORY=0x10; REPARSE=0x400
class WindowsCleanupError(RuntimeError): pass

if os.name=="nt":
    import ctypes
    from ctypes import wintypes as W
    class ATTR(ctypes.Structure): _fields_=[("FileAttributes",W.DWORD),("ReparseTag",W.DWORD)]
    class ID128(ctypes.Structure): _fields_=[("Identifier",ctypes.c_ubyte*16)]
    class IDINFO(ctypes.Structure): _fields_=[("VolumeSerialNumber",ctypes.c_ulonglong),("FileId",ID128)]
    class BHFI(ctypes.Structure): _fields_=[("a",W.DWORD),("b",W.FILETIME),("c",W.FILETIME),("d",W.FILETIME),("vol",W.DWORD),("sz1",W.DWORD),("sz2",W.DWORD),("links",W.DWORD),("hi",W.DWORD),("lo",W.DWORD)]
    class BASIC(ctypes.Structure): _fields_=[("c",ctypes.c_longlong),("a",ctypes.c_longlong),("w",ctypes.c_longlong),("chg",ctypes.c_longlong),("attrs",W.DWORD)]
    class DISP(ctypes.Structure): _fields_=[("delete",W.BOOL)]
    class USTR(ctypes.Structure): _fields_=[("Length",W.USHORT),("MaximumLength",W.USHORT),("Buffer",W.LPWSTR)]
    class OBJ(ctypes.Structure): _fields_=[("Length",W.ULONG),("RootDirectory",W.HANDLE),("ObjectName",ctypes.POINTER(USTR)),("Attributes",W.ULONG),("SecurityDescriptor",W.LPVOID),("SecurityQualityOfService",W.LPVOID)]
    class IOSU(ctypes.Union): _fields_=[("Status",W.LONG),("Pointer",W.LPVOID)]
    class IOS(ctypes.Structure): _anonymous_=("u",);_fields_=[("u",IOSU),("Information",ctypes.c_size_t)]
    class DIRINFO(ctypes.Structure):
        _fields_=[("Next",W.DWORD),("Index",W.DWORD),("ct",ctypes.c_longlong),("at",ctypes.c_longlong),("wt",ctypes.c_longlong),("cht",ctypes.c_longlong),("eof",ctypes.c_longlong),("alloc",ctypes.c_longlong),("attrs",W.DWORD),("name_len",W.DWORD),("ea",W.DWORD),("short_len",ctypes.c_ubyte),("reserved",ctypes.c_ubyte),("short",W.WCHAR*12),("file_id",ctypes.c_longlong),("name",W.WCHAR*1)]
    K=ctypes.WinDLL("kernel32",use_last_error=True); N=ctypes.WinDLL("ntdll",use_last_error=True)
    K.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,W.LPVOID,W.DWORD,W.DWORD,W.HANDLE];K.CreateFileW.restype=W.HANDLE
    K.CloseHandle.argtypes=[W.HANDLE];K.CloseHandle.restype=W.BOOL
    K.GetFileInformationByHandle.argtypes=[W.HANDLE,ctypes.POINTER(BHFI)];K.GetFileInformationByHandle.restype=W.BOOL
    K.GetFileInformationByHandleEx.argtypes=[W.HANDLE,ctypes.c_int,W.LPVOID,W.DWORD];K.GetFileInformationByHandleEx.restype=W.BOOL
    K.SetFileInformationByHandle.argtypes=[W.HANDLE,ctypes.c_int,W.LPVOID,W.DWORD];K.SetFileInformationByHandle.restype=W.BOOL
    N.NtCreateFile.argtypes=[ctypes.POINTER(W.HANDLE),W.DWORD,ctypes.POINTER(OBJ),ctypes.POINTER(IOS),W.LPVOID,W.ULONG,W.ULONG,W.ULONG,W.ULONG,W.LPVOID,W.ULONG];N.NtCreateFile.restype=W.LONG

def _win():
    if os.name!="nt": raise WindowsCleanupError("Windows native cleanup unavailable")
def _hv(h): return int(getattr(h,"value",h) or 0)
def _err(msg):
    e=ctypes.get_last_error();raise WindowsCleanupError(f"{msg} (WinError {e})")
def _close(h):
    if _hv(h): K.CloseHandle(h)
def _open_root(path,access):
    h=K.CreateFileW(str(path),access,7,None,3,0x02000000|0x00200000,None);bad=W.HANDLE(-1).value
    if _hv(h) in (0,int(bad)): _err(f"cannot open cleanup root: {path}")
    return h
def _attrs(h):
    x=ATTR()
    if not K.GetFileInformationByHandleEx(h,9,ctypes.byref(x),ctypes.sizeof(x)): _err("cannot read handle attributes")
    return int(x.FileAttributes)
def _id(h):
    x=IDINFO()
    if not K.GetFileInformationByHandleEx(h,18,ctypes.byref(x),ctypes.sizeof(x)): _err("cannot read handle identity")
    return {"volumeSerial":int(x.VolumeSerialNumber),"fileId":bytes(x.FileId.Identifier).hex()}
def _id64(h):
    x=BHFI()
    if not K.GetFileInformationByHandle(h,ctypes.byref(x)): _err("cannot read handle index")
    return int(x.vol),(int(x.hi)<<32)|int(x.lo)

def native_identity(path:str|os.PathLike[str])->dict:
    _win();h=_open_root(Path(path),0x80)
    try:
        if _attrs(h)&REPARSE: raise WindowsCleanupError("reparse cleanup root denied")
        return _id(h)
    finally:_close(h)

def _open_relative(parent,name):
    if not isinstance(name,str) or not name or name in (".","..") or any(x in name for x in ("\\","/","\x00")): raise WindowsCleanupError("unsafe cleanup child name")
    buf=ctypes.create_unicode_buffer(name);n=len(name.encode("utf-16-le"));u=USTR(n,n+2,ctypes.cast(buf,W.LPWSTR));o=OBJ(ctypes.sizeof(OBJ),parent,ctypes.pointer(u),0x40,None,None);io=IOS();out=W.HANDLE()
    access=0x10000|0x100000|0x1|0x80|0x100;opts=0x20|0x4000|0x00200000
    s=int(N.NtCreateFile(ctypes.byref(out),access,ctypes.byref(o),ctypes.byref(io),None,0,7,1,opts,None,0))
    if s<0 or not _hv(out): raise WindowsCleanupError(f"cannot open cleanup child {name!r} (NTSTATUS 0x{s&0xffffffff:08x})")
    return out

def _entries(h):
    out=[];klass=11
    while True:
        b=ctypes.create_string_buffer(65536);ctypes.set_last_error(0)
        if not K.GetFileInformationByHandleEx(h,klass,b,len(b)):
            e=ctypes.get_last_error()
            if e==18: break
            raise WindowsCleanupError(f"cannot enumerate cleanup directory (WinError {e})")
        klass=10;off=0
        while True:
            base=ctypes.addressof(b)+off;r=ctypes.cast(base,ctypes.POINTER(DIRINFO)).contents;n=int(r.name_len)
            if n<0 or n%2 or n>32768: raise WindowsCleanupError("malformed cleanup directory entry")
            name=ctypes.wstring_at(base+DIRINFO.name.offset,n//2)
            if name not in (".",".."):
                if not name or any(x in name for x in ("\\","/","\x00")): raise WindowsCleanupError("unsafe cleanup directory entry")
                fid=int(r.file_id)&((1<<64)-1)
                if not fid: raise WindowsCleanupError("cleanup directory entry lacks identity")
                out.append((name,fid,int(r.attrs)))
            nxt=int(r.Next)
            if not nxt: break
            if nxt<DIRINFO.name.offset or off+nxt>=len(b): raise WindowsCleanupError("malformed cleanup directory chain")
            off+=nxt
    return out

def _clear_ro(h):
    x=BASIC()
    if not K.GetFileInformationByHandleEx(h,0,ctypes.byref(x),ctypes.sizeof(x)): _err("cannot read basic cleanup info")
    if int(x.attrs)&READONLY:
        x.attrs=int(x.attrs)&~READONLY
        if not K.SetFileInformationByHandle(h,0,ctypes.byref(x),ctypes.sizeof(x)): _err("cannot clear read-only attribute through handle")
def _delete(h):
    x=DISP(1)
    if not K.SetFileInformationByHandle(h,4,ctypes.byref(x),ctypes.sizeof(x)): _err("cannot delete verified cleanup object through handle")
def _delete_children(parent):
    pvol,_=_id64(parent)
    for name,fid,listed in _entries(parent):
        if listed&REPARSE: raise WindowsCleanupError(f"reparse child denied: {name}")
        h=_open_relative(parent,name)
        try:
            attrs=_attrs(h);vol,opened=_id64(h)
            if attrs&REPARSE: raise WindowsCleanupError(f"reparse child denied: {name}")
            if vol!=pvol or opened!=fid: raise WindowsCleanupError(f"cleanup child identity changed: {name}")
            if bool(listed&DIRECTORY)!=bool(attrs&DIRECTORY): raise WindowsCleanupError(f"cleanup child type changed: {name}")
            if attrs&DIRECTORY:_delete_children(h)
            _clear_ro(h);_delete(h)
        finally:_close(h)

def delete_tree_exact(path:str|os.PathLike[str],expected_native:dict)->None:
    _win()
    if not isinstance(expected_native,dict) or set(expected_native)!={"volumeSerial","fileId"}: raise WindowsCleanupError("missing native generation identity")
    try:vol=int(expected_native["volumeSerial"]);fid=str(expected_native["fileId"]).lower()
    except Exception as e: raise WindowsCleanupError("invalid native generation identity") from e
    if vol<0 or len(fid)!=32 or any(c not in "0123456789abcdef" for c in fid): raise WindowsCleanupError("invalid native generation identity")
    h=_open_root(Path(path),0x10000|0x100000|0x1|0x80|0x100)
    try:
        attrs=_attrs(h);obs=_id(h)
        if attrs&REPARSE: raise WindowsCleanupError("reparse cleanup root denied")
        if obs!={"volumeSerial":vol,"fileId":fid}: raise WindowsCleanupError("workspace generation identity changed before cleanup")
        if not attrs&DIRECTORY: raise WindowsCleanupError("cleanup root is not a directory")
        _delete_children(h);_clear_ro(h);_delete(h)
    finally:_close(h)
