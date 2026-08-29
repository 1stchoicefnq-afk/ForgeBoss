from __future__ import annotations
import ctypes,os,tempfile,threading,unittest
from ctypes import wintypes
from pathlib import Path
from forgeboss.protected_authority.boundary import windows_pipe_peer_context
from forgeboss.protected_authority.lifecycle import FIXED_PIPE_NAME,WindowsNamedPipeServer
from forgeboss.protected_authority.protocol import AuthorityError
from forgeboss.protected_authority.win32_ffi import handle_value,is_invalid_handle,load_win32
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
        self.assertIs(api.kernel32.CreateFileW.restype,wintypes.HANDLE)
        self.assertIs(api.advapi32.OpenSCManagerW.restype,wintypes.HANDLE)
        self.assertIs(api.advapi32.OpenServiceW.restype,wintypes.HANDLE)
        self.assertIs(api.advapi32.RegisterServiceCtrlHandlerW.restype,wintypes.HANDLE)
        self.assertIs(api.kernel32.GetCurrentProcess.restype,wintypes.HANDLE)
        self.assertIs(api.kernel32.GetCurrentThread.restype,wintypes.HANDLE)
        for fn in (api.kernel32.CreateNamedPipeW,api.kernel32.ConnectNamedPipe,api.kernel32.ReadFile,api.kernel32.WriteFile,api.kernel32.DisconnectNamedPipe,api.kernel32.WaitNamedPipeW,api.kernel32.CreateFileW,api.kernel32.CloseHandle,api.advapi32.OpenSCManagerW,api.advapi32.OpenServiceW,api.advapi32.CloseServiceHandle,api.advapi32.QueryServiceConfigW,api.advapi32.RegisterServiceCtrlHandlerW,api.advapi32.SetServiceStatus,api.advapi32.StartServiceCtrlDispatcherW,api.advapi32.OpenThreadToken,api.advapi32.OpenProcessToken,api.advapi32.ImpersonateNamedPipeClient,api.advapi32.GetTokenInformation):
            self.assertIsNotNone(fn.argtypes,fn.__name__);self.assertIsNotNone(fn.restype,fn.__name__)
    def _server(self,td):return WindowsNamedPipeServer(service=_Service(),boundary=_Boundary(),protected_root=Path(td),allowed_peer_sids={'S-1-1-0'})
    def test_native_named_pipe_create_and_close(self):
        with tempfile.TemporaryDirectory() as td:
            server=self._server(td);handle=server.start();self.assertFalse(is_invalid_handle(handle));self.assertIsNotNone(server.handle);server.close();self.assertIsNone(server.handle)
    def test_native_named_pipe_peer_context_path(self):
        with tempfile.TemporaryDirectory() as td:
            api=load_win32();server=self._server(td);server.start();result={}
            def accept():
                try:
                    ok=api.kernel32.ConnectNamedPipe(server.handle,None);err=ctypes.get_last_error()
                    if not ok and err!=535:raise OSError(err,'ConnectNamedPipe')
                    result['ctx']=windows_pipe_peer_context(handle_value(server.handle))
                except BaseException as exc:result['error']=exc
                finally:
                    api.kernel32.DisconnectNamedPipe(server.handle)
            t=threading.Thread(target=accept);t.start()
            try:
                self.assertTrue(api.kernel32.WaitNamedPipeW(FIXED_PIPE_NAME,5000))
                client=api.kernel32.CreateFileW(FIXED_PIPE_NAME,0xC0000000,0,None,3,0,None)
                self.assertFalse(is_invalid_handle(client))
                try:
                    t.join(5);self.assertFalse(t.is_alive());self.assertNotIn('error',result);ctx=result['ctx'];self.assertEqual(ctx.platform,'windows');self.assertTrue(ctx.principal.startswith('s-1-'))
                finally:api.kernel32.CloseHandle(client)
            finally:
                server.close();t.join(1)
    def test_native_named_pipe_duplicate_start_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as td1,tempfile.TemporaryDirectory() as td2:
            first=self._server(td1);second=self._server(td2);first.start()
            try:
                with self.assertRaises(AuthorityError):second.start()
                self.assertIsNone(second.handle);self.assertIsNone(second._sd)
            finally:first.close();second.close()
    def test_native_scm_open_close_handle(self):
        api=load_win32();scm=api.advapi32.OpenSCManagerW(None,None,0x0001);self.assertFalse(is_invalid_handle(scm));self.assertTrue(api.advapi32.CloseServiceHandle(scm))
if __name__=='__main__':unittest.main()
