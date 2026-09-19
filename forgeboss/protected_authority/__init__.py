from __future__ import annotations

import importlib

from .boundary import FileSecretProvider,PeerContext,PlatformMachineBoundary,unix_peer_context,windows_pipe_peer_context
from .github_backend import GitHubAppBackend
from .lifecycle import FIXED_PIPE_NAME,FIXED_SERVICE_NAME,FIXED_SOCKET_NAME,LinuxAuthorityDaemon,WindowsNamedPipeServer,assert_windows_scm_registration,run_windows_scm_service
from .protocol import AuthorityError,build_request,canonical_digest,canonical_json,strict_loads
from .root_chain import assert_machine_anchored_root
from .signing import ReceiptSigner,verify_signed_receipt

_LAZY_SERVICE_EXPORTS=frozenset({
    'ProtectedAuthorityService',
    'ReplayJournal',
    'create_production_service',
})

__all__=['AuthorityError','build_request','canonical_digest','canonical_json','strict_loads','ProtectedAuthorityService','ReplayJournal','create_production_service','FileSecretProvider','PeerContext','PlatformMachineBoundary','unix_peer_context','windows_pipe_peer_context','GitHubAppBackend','ReceiptSigner','verify_signed_receipt','assert_machine_anchored_root','LinuxAuthorityDaemon','WindowsNamedPipeServer','assert_windows_scm_registration','run_windows_scm_service','FIXED_PIPE_NAME','FIXED_SOCKET_NAME','FIXED_SERVICE_NAME']


def __getattr__(name:str):
    """Preserve package-level service exports without importing the service eagerly.

    The protected authority service depends on self-build runtime/coordinator code.
    Eagerly importing it here makes a low-level boundary import pull the controller
    back in while the controller is still initializing. Keep the public package API,
    but only load service authority when a caller explicitly asks for it.
    """
    if name in _LAZY_SERVICE_EXPORTS:
        module=importlib.import_module(f'{__name__}.service')
        value=getattr(module,name)
        globals()[name]=value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals())|set(__all__))
