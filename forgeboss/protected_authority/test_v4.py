from __future__ import annotations
import os,tempfile,unittest
from ctypes import wintypes
from pathlib import Path
from forgeboss.protected_authority.lifecycle import WindowsNamedPipeServer
from forgeboss.protected_authority.win32_ffi import is_invalid_handle,load_win32
class _Boundary:
    expected='test'
    def assert_service_principal(self,_root):return 'test'
    def assert_protected_path(self,_path,**_kw):return None
class _Service:pass
@unittest.skipUnless(os.name=='nt','native Windows FFI test')
class ProtectedAuthorityWin32V4Tests(unittest.TestCase):
    def test_pointer_sized_handle_prototypes(self):
        api=load_win32()
        self.assertIs(api.kernel32.CreateNamedPipeW.restype,wintypes.HANDLE)
        self.assertIs(api.advapi32.OpenSCManagerW.restype,wintypes.HANDLE)
        self.assertIs(api.advapi32.OpenServiceW.restype,wintypes.HANDLE)
        self.assertIs(api.advapi32.RegisterServiceCtrlHandlerW.restype,wintypes.HANDLE)
        self.assertIs(api.kernel32.GetCurrentProcess.restype,wintypes.HANDLE)
        self.assertIs(api.kernel32.GetCurrentThread.restype,wintypes.HANDLE)
        for fn in (api.kernel32.CreateNamedPipeW,api.kernel32.ConnectNamedPipe,api.kernel32.ReadFile,api.kernel32.WriteFile,api.kernel32.DisconnectNamedPipe,api.kernel32.CloseHandle,api.advapi32.OpenSCManagerW,api.advapi32.OpenServiceW,api.advapi32.CloseServiceHandle,api.advapi32.QueryServiceConfigW,api.advapi32.RegisterServiceCtrlHandlerW,api.advapi32.SetServiceStatus,api.advapi32.StartServiceCtrlDispatcherW,api.advapi32.OpenThreadToken,api.advapi32.OpenProcessToken,api.advapi32.ImpersonateNamedPipeClient,api.advapi32.GetTokenInformation):
            self.assertIsNotNone(fn.argtypes,fn.__name__);self.assertIsNotNone(fn.restype,fn.__name__)
    def test_native_named_pipe_create_and_close(self):
        with tempfile.TemporaryDirectory() as td:
            server=WindowsNamedPipeServer(service=_Service(),boundary=_Boundary(),protected_root=Path(td),allowed_peer_sids={'S-1-1-0'})
            handle=server.start();self.assertFalse(is_invalid_handle(handle));self.assertIsNotNone(server.handle);server.close();self.assertIsNone(server.handle)
    def test_native_scm_open_close_handle(self):
        api=load_win32();scm=api.advapi32.OpenSCManagerW(None,None,0x0001);self.assertFalse(is_invalid_handle(scm));self.assertTrue(api.advapi32.CloseServiceHandle(scm))
if __name__=='__main__':unittest.main()
