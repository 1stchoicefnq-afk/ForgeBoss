from __future__ import annotations
import ctypes,os
from dataclasses import dataclass
from ctypes import wintypes
from .protocol import AuthorityError
SC_HANDLE=wintypes.HANDLE
SERVICE_STATUS_HANDLE=wintypes.HANDLE
INVALID_HANDLE_VALUE=ctypes.c_void_p(-1).value
@dataclass(frozen=True)
class Win32API:
    advapi32:object
    kernel32:object
def load_win32()->Win32API:
    if os.name!='nt':raise AuthorityError('IPC_PLATFORM_INVALID')
    adv=ctypes.WinDLL('advapi32',use_last_error=True);ker=ctypes.WinDLL('kernel32',use_last_error=True)
    ker.GetCurrentProcess.argtypes=[];ker.GetCurrentProcess.restype=wintypes.HANDLE
    ker.GetCurrentThread.argtypes=[];ker.GetCurrentThread.restype=wintypes.HANDLE
    ker.CloseHandle.argtypes=[wintypes.HANDLE];ker.CloseHandle.restype=wintypes.BOOL
    ker.LocalFree.argtypes=[wintypes.HLOCAL];ker.LocalFree.restype=wintypes.HLOCAL
    ker.CreateNamedPipeW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID];ker.CreateNamedPipeW.restype=wintypes.HANDLE
    ker.ConnectNamedPipe.argtypes=[wintypes.HANDLE,wintypes.LPVOID];ker.ConnectNamedPipe.restype=wintypes.BOOL
    ker.ReadFile.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID];ker.ReadFile.restype=wintypes.BOOL
    ker.WriteFile.argtypes=[wintypes.HANDLE,wintypes.LPCVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID];ker.WriteFile.restype=wintypes.BOOL
    ker.DisconnectNamedPipe.argtypes=[wintypes.HANDLE];ker.DisconnectNamedPipe.restype=wintypes.BOOL
    ker.SetNamedPipeHandleState.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(wintypes.DWORD)];ker.SetNamedPipeHandleState.restype=wintypes.BOOL
    ker.WaitNamedPipeW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD];ker.WaitNamedPipeW.restype=wintypes.BOOL
    ker.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE];ker.CreateFileW.restype=wintypes.HANDLE
    adv.ConvertSidToStringSidW.argtypes=[wintypes.LPVOID,ctypes.POINTER(wintypes.LPWSTR)];adv.ConvertSidToStringSidW.restype=wintypes.BOOL
    adv.GetTokenInformation.argtypes=[wintypes.HANDLE,ctypes.c_int,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)];adv.GetTokenInformation.restype=wintypes.BOOL
    adv.ImpersonateNamedPipeClient.argtypes=[wintypes.HANDLE];adv.ImpersonateNamedPipeClient.restype=wintypes.BOOL
    adv.OpenThreadToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.BOOL,ctypes.POINTER(wintypes.HANDLE)];adv.OpenThreadToken.restype=wintypes.BOOL
    adv.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)];adv.OpenProcessToken.restype=wintypes.BOOL
    adv.RevertToSelf.argtypes=[];adv.RevertToSelf.restype=wintypes.BOOL
    adv.GetNamedSecurityInfoW.argtypes=[wintypes.LPWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(wintypes.LPVOID),ctypes.POINTER(wintypes.LPVOID),ctypes.POINTER(wintypes.LPVOID),ctypes.POINTER(wintypes.LPVOID),ctypes.POINTER(wintypes.LPVOID)];adv.GetNamedSecurityInfoW.restype=wintypes.DWORD
    adv.GetAclInformation.argtypes=[wintypes.LPVOID,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD];adv.GetAclInformation.restype=wintypes.BOOL
    adv.GetAce.argtypes=[wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.LPVOID)];adv.GetAce.restype=wintypes.BOOL
    adv.BuildTrusteeWithSidW.argtypes=[wintypes.LPVOID,wintypes.LPVOID];adv.BuildTrusteeWithSidW.restype=None
    adv.GetEffectiveRightsFromAclW.argtypes=[wintypes.LPVOID,wintypes.LPVOID,ctypes.POINTER(wintypes.DWORD)];adv.GetEffectiveRightsFromAclW.restype=wintypes.DWORD
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(wintypes.LPVOID),ctypes.POINTER(wintypes.DWORD)];adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=wintypes.BOOL
    adv.OpenSCManagerW.argtypes=[wintypes.LPCWSTR,wintypes.LPCWSTR,wintypes.DWORD];adv.OpenSCManagerW.restype=SC_HANDLE
    adv.OpenServiceW.argtypes=[SC_HANDLE,wintypes.LPCWSTR,wintypes.DWORD];adv.OpenServiceW.restype=SC_HANDLE
    adv.CloseServiceHandle.argtypes=[SC_HANDLE];adv.CloseServiceHandle.restype=wintypes.BOOL
    adv.QueryServiceConfigW.argtypes=[SC_HANDLE,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)];adv.QueryServiceConfigW.restype=wintypes.BOOL
    adv.RegisterServiceCtrlHandlerW.argtypes=[wintypes.LPCWSTR,wintypes.LPVOID];adv.RegisterServiceCtrlHandlerW.restype=SERVICE_STATUS_HANDLE
    adv.SetServiceStatus.argtypes=[SERVICE_STATUS_HANDLE,wintypes.LPVOID];adv.SetServiceStatus.restype=wintypes.BOOL
    adv.StartServiceCtrlDispatcherW.argtypes=[wintypes.LPVOID];adv.StartServiceCtrlDispatcherW.restype=wintypes.BOOL
    return Win32API(adv,ker)
def handle_value(handle)->int:
    if handle is None:return 0
    if isinstance(handle,int):return handle
    return int(ctypes.cast(handle,ctypes.c_void_p).value or 0)
def is_invalid_handle(handle)->bool:return handle_value(handle) in (0,INVALID_HANDLE_VALUE)
