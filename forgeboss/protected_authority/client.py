from __future__ import annotations

import base64, ctypes, os, socket, time, uuid
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable, Mapping

from .lifecycle import FIXED_PIPE_NAME, FIXED_SOCKET_NAME
from .protocol import AuthorityError, MAX_REQUEST_BYTES, build_request, canonical_digest, canonical_json, strict_loads
from .signing import verify_signed_receipt


def _load_private_key(path: str | os.PathLike[str]):
    raw=Path(path).read_bytes()
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if len(raw)==32:
            return Ed25519PrivateKey.from_private_bytes(raw)
        key=serialization.load_pem_private_key(raw,password=None)
        if not isinstance(key,Ed25519PrivateKey):
            raise AuthorityError("PEER_SIGNING_KEY_INVALID")
        return key
    except AuthorityError:
        raise
    except Exception as ex:
        raise AuthorityError("PEER_SIGNING_KEY_INVALID") from ex


class ProtectedAuthorityClient:
    def __init__(self,*,peer_id:str,repository:str,control_revision:int,peer_private_key,
                 receipt_public_key_b64:str,unix_socket_path:str|os.PathLike[str]|None=None,
                 pipe_name:str=FIXED_PIPE_NAME,timeout:float=5.0,transport:Callable[[bytes],bytes]|None=None):
        if not isinstance(peer_id,str) or not peer_id.strip(): raise AuthorityError("PEER_ID_INVALID")
        if not isinstance(repository,str) or "/" not in repository: raise AuthorityError("REPOSITORY_INVALID")
        if isinstance(control_revision,bool) or not isinstance(control_revision,int) or control_revision<1: raise AuthorityError("CONTROL_REVISION_INVALID")
        if not isinstance(receipt_public_key_b64,str) or not receipt_public_key_b64.strip(): raise AuthorityError("RECEIPT_PUBLIC_KEY_INVALID")
        if not isinstance(timeout,(int,float)) or not 0.1<=float(timeout)<=30: raise AuthorityError("IPC_TIMEOUT_INVALID")
        self.peer_id=peer_id.strip();self.repository=repository.strip();self.control_revision=control_revision
        self.peer_private_key=peer_private_key;self.receipt_public_key_b64=receipt_public_key_b64.strip()
        self.unix_socket_path=Path(unix_socket_path) if unix_socket_path is not None else None
        self.pipe_name=pipe_name;self.timeout=float(timeout);self.transport=transport

    @classmethod
    def from_files(cls,*,peer_id:str,repository:str,control_revision:int,peer_private_key_file:str,
                   receipt_public_key_file:str,unix_socket_path:str|None=None,pipe_name:str=FIXED_PIPE_NAME,
                   timeout:float=5.0):
        key=_load_private_key(peer_private_key_file)
        pin=Path(receipt_public_key_file).read_text(encoding="ascii").strip()
        return cls(peer_id=peer_id,repository=repository,control_revision=control_revision,
                   peer_private_key=key,receipt_public_key_b64=pin,unix_socket_path=unix_socket_path,
                   pipe_name=pipe_name,timeout=timeout)

    @classmethod
    def from_environment(cls,env:Mapping[str,str]|None=None,*,repository:str="1stchoicefnq-afk/ForgeBoss",timeout:float=5.0):
        env=dict(os.environ if env is None else env)
        peer_key=env.get("FORGEBOSS_AUTHORITY_PEER_KEY")
        receipt_pin=env.get("FORGEBOSS_AUTHORITY_RECEIPT_PUBLIC_KEY")
        if not peer_key or not receipt_pin:
            raise AuthorityError("AUTHORITY_CLIENT_CONFIG_MISSING")
        peer_id=env.get("FORGEBOSS_AUTHORITY_PEER_ID") or "controller-a"
        try:revision=int(env.get("FORGEBOSS_CONTROL_REVISION") or "1")
        except Exception as ex:raise AuthorityError("CONTROL_REVISION_INVALID") from ex
        unix_socket=None
        if os.name!="nt":
            endpoint=env.get("FORGEBOSS_AUTHORITY_ENDPOINT_DIR")
            if not endpoint:raise AuthorityError("IPC_ENDPOINT_MISSING")
            unix_socket=str(Path(endpoint)/FIXED_SOCKET_NAME)
        return cls.from_files(
            peer_id=peer_id,repository=repository,control_revision=revision,
            peer_private_key_file=peer_key,receipt_public_key_file=receipt_pin,
            unix_socket_path=unix_socket,timeout=timeout,
        )

    def _request(self,operation:str,payload:Mapping[str,Any])->tuple[dict,str]:
        request_id=str(uuid.uuid4())
        # Let the protocol perform its exact canonicalization first (including
        # repository case normalization), then sign that exact request digest.
        provisional=build_request(
            operation=operation,request_id=request_id,peer_id=self.peer_id,
            repository=self.repository,control_revision=self.control_revision,
            payload=payload,signature="unsigned-placeholder",
        )
        digest=provisional["requestDigest"]
        try:
            signature=base64.b64encode(
                self.peer_private_key.sign(bytes.fromhex(digest))
            ).decode("ascii")
        except Exception as ex:
            raise AuthorityError("PEER_SIGNING_FAILED") from ex
        request=build_request(
            operation=operation,request_id=request_id,peer_id=self.peer_id,
            repository=self.repository,control_revision=self.control_revision,
            payload=payload,signature=signature,
        )
        if request["requestDigest"]!=digest:
            raise AuthorityError("REQUEST_DIGEST_MISMATCH")
        return request,digest

    def call(self,operation:str,payload:Mapping[str,Any])->dict:
        request,request_digest=self._request(operation,payload)
        raw=canonical_json(request)
        response_raw=self.transport(raw) if self.transport is not None else self._exchange(raw)
        response=strict_loads(response_raw)
        if not verify_signed_receipt(response,self.receipt_public_key_b64):
            raise AuthorityError("SERVICE_RECEIPT_INVALID")
        receipt=response["receipt"]
        checks={
            "operation":operation,
            "requestId":request["requestId"],
            "peerId":self.peer_id,
            "repository":self.repository,
            "controlRevision":self.control_revision,
            "requestDigest":request_digest,
        }
        for name,want in checks.items():
            got=receipt.get(name)
            if name=="repository":
                if str(got).casefold()!=str(want).casefold(): raise AuthorityError("SERVICE_RECEIPT_BINDING_MISMATCH")
            elif got!=want: raise AuthorityError("SERVICE_RECEIPT_BINDING_MISMATCH")
        return response

    def verify_launch_authority(self,*,envelope:Mapping[str,Any],envelope_digest:str)->dict:
        response=self.call("verify_launch_authority",{"envelope":dict(envelope),"envelopeDigest":envelope_digest})
        result=response.get("result") or {}
        if result.get("verified") is not True or result.get("envelopeDigest")!=envelope_digest:
            raise AuthorityError("LAUNCH_AUTHORITY_NOT_VERIFIED")
        return response

    def attest_launch_payload(self,signed_payload:Mapping[str,Any])->dict:
        """Sign an exact launch payload, have the protected service verify it,
        and return the service-attested bundle consumed by executor_guard."""
        signed=dict(signed_payload)
        digest=canonical_digest(signed)
        try:
            signature=base64.b64encode(
                self.peer_private_key.sign(bytes.fromhex(digest))
            ).decode("ascii")
        except Exception as ex:
            raise AuthorityError("LAUNCH_SIGNING_FAILED") from ex
        envelope={"signed":signed,"signature":signature}
        response=self.verify_launch_authority(envelope=envelope,envelope_digest=digest)
        return {"schema":1,"envelope":envelope,"authorityResponse":response}

    def prepare_self_build(self,*,source_root:str,base_sha:str,run_id:str)->dict:
        return self.call("prepare_self_build",{"sourceRoot":source_root,"baseSha":base_sha,"runId":run_id})

    def prepare_self_build_replacement(self,*,run_id:str)->dict:
        return self.call("prepare_self_build_replacement",{"runId":run_id})

    def compose_self_build_successor(self,*,run_id:str)->dict:
        return self.call("compose_self_build_successor",{"runId":run_id})

    def self_build_status(self,*,run_id:str)->dict:
        return self.call("self_build_status",{"runId":run_id})

    def revoke_self_build_worker(self,*,run_id:str,task_id:str,worker_run_id:str,owner_epoch:int,reason:str)->dict:
        return self.call("revoke_self_build_worker",{
            "runId":run_id,"taskId":task_id,"workerRunId":worker_run_id,
            "ownerEpoch":int(owner_epoch),"reason":reason,
        })

    def record_self_build_handoff(self,*,run_id:str,task_id:str,worker_run_id:str,owner_epoch:int,evidence:Mapping[str,Any])->dict:
        return self.call("record_self_build_handoff",{
            "runId":run_id,"taskId":task_id,"workerRunId":worker_run_id,
            "ownerEpoch":int(owner_epoch),"evidence":dict(evidence),
        })

    def record_self_build_review(self,*,run_id:str,task_id:str,worker_run_id:str,owner_epoch:int,review:Mapping[str,Any])->dict:
        return self.call("record_self_build_review",{
            "runId":run_id,"taskId":task_id,"workerRunId":worker_run_id,
            "ownerEpoch":int(owner_epoch),"review":dict(review),
        })

    def accept_self_build_candidate(self,*,run_id:str,task_id:str,worker_run_id:str,owner_epoch:int)->dict:
        return self.call("accept_self_build_candidate",{
            "runId":run_id,"taskId":task_id,"workerRunId":worker_run_id,
            "ownerEpoch":int(owner_epoch),
        })

    def _exchange(self,raw:bytes)->bytes:
        if os.name=="nt": return self._exchange_windows(raw)
        path=self.unix_socket_path
        if path is None:
            root=os.environ.get("FORGEBOSS_AUTHORITY_ENDPOINT_DIR")
            if not root: raise AuthorityError("IPC_ENDPOINT_MISSING")
            path=Path(root)/FIXED_SOCKET_NAME
        if not path.is_absolute(): raise AuthorityError("IPC_ENDPOINT_INVALID")
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(self.timeout)
        try:
            s.connect(str(path));s.sendall(raw);s.shutdown(socket.SHUT_WR)
            chunks=[];total=0
            while True:
                part=s.recv(65536)
                if not part: break
                total+=len(part)
                if total>MAX_REQUEST_BYTES: raise AuthorityError("IPC_RESPONSE_TOO_LARGE")
                chunks.append(part)
            if not chunks: raise AuthorityError("IPC_EMPTY_RESPONSE")
            return b"".join(chunks)
        except AuthorityError: raise
        except Exception as ex: raise AuthorityError("IPC_CLIENT_FAILED") from ex
        finally:
            try:s.close()
            except OSError:pass

    def _exchange_windows(self,raw:bytes)->bytes:
        if not isinstance(self.pipe_name,str) or not self.pipe_name.startswith("\\\\.\\pipe\\"):
            raise AuthorityError("IPC_ENDPOINT_INVALID")
        k=ctypes.WinDLL("kernel32",use_last_error=True)
        k.WaitNamedPipeW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD];k.WaitNamedPipeW.restype=wintypes.BOOL
        k.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
        k.CreateFileW.restype=wintypes.HANDLE
        k.WriteFile.argtypes=[wintypes.HANDLE,wintypes.LPCVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID];k.WriteFile.restype=wintypes.BOOL
        k.ReadFile.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID];k.ReadFile.restype=wintypes.BOOL
        k.CloseHandle.argtypes=[wintypes.HANDLE];k.CloseHandle.restype=wintypes.BOOL
        timeout_ms=max(100,int(self.timeout*1000))
        if not k.WaitNamedPipeW(self.pipe_name,timeout_ms): raise AuthorityError("IPC_CONNECT_FAILED")
        h=k.CreateFileW(self.pipe_name,0xC0000000,0,None,3,0,None)
        invalid=ctypes.c_void_p(-1).value
        if not h or int(h)==invalid: raise AuthorityError("IPC_CONNECT_FAILED")
        try:
            written=wintypes.DWORD(0);buf=ctypes.create_string_buffer(raw)
            if not k.WriteFile(h,buf,len(raw),ctypes.byref(written),None) or written.value!=len(raw):
                raise AuthorityError("IPC_WRITE_FAILED")
            out=[];total=0
            while True:
                b=ctypes.create_string_buffer(65536);got=wintypes.DWORD(0);ctypes.set_last_error(0)
                ok=k.ReadFile(h,b,len(b),ctypes.byref(got),None);err=ctypes.get_last_error()
                if got.value:
                    total+=got.value
                    if total>MAX_REQUEST_BYTES: raise AuthorityError("IPC_RESPONSE_TOO_LARGE")
                    out.append(b.raw[:got.value])
                if ok: break
                if err==234: continue
                raise AuthorityError("IPC_READ_FAILED")
            if not out: raise AuthorityError("IPC_EMPTY_RESPONSE")
            return b"".join(out)
        finally:
            k.CloseHandle(h)
