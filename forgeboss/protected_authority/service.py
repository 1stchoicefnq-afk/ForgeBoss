from __future__ import annotations

import base64,re,sqlite3
from pathlib import Path
from typing import Any,Mapping
from .boundary import FileSecretProvider,PeerContext,PlatformMachineBoundary
from .github_backend import GitHubAppBackend
from .protocol import AuthorityError,assert_public_result,canonical_digest,canonical_json,strict_loads,unsigned_request
from .root_chain import assert_machine_anchored_root
from .signing import ReceiptSigner
from forgeboss.control.self_build_runtime import SelfBuildRuntime,SelfBuildRuntimeError
_REPO_RE=re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')

def _canonical_repository_map(values)->dict[str,str]:
    if not values:raise AuthorityError('REPOSITORY_ALLOWLIST_INVALID')
    out={}
    for value in values:
        if not isinstance(value,str) or not _REPO_RE.fullmatch(value):raise AuthorityError('REPOSITORY_ALLOWLIST_INVALID')
        key=value.casefold()
        if key in out and out[key]!=value:raise AuthorityError('REPOSITORY_ALLOWLIST_INVALID')
        out[key]=value
    if not out:raise AuthorityError('REPOSITORY_ALLOWLIST_INVALID')
    return out

class ReplayJournal:
    def __init__(self,root:Path):
        self.path=root/'replay.sqlite3'
        try:
            db=sqlite3.connect(self.path,timeout=30,isolation_level=None);db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL');db.execute('CREATE TABLE IF NOT EXISTS consumed(request_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, consumed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');db.close()
        except Exception as e:raise AuthorityError('REPLAY_STATE_INVALID') from e
    def consume(self,request_id:str,request_digest:str)->None:
        db=sqlite3.connect(self.path,timeout=30,isolation_level=None);begun=False
        try:
            db.execute('BEGIN IMMEDIATE');begun=True
            try:db.execute('INSERT INTO consumed(request_id,request_digest) VALUES(?,?)',(request_id,request_digest))
            except sqlite3.IntegrityError as e:raise AuthorityError('REQUEST_REPLAYED') from e
            db.execute('COMMIT');begun=False
        except AuthorityError:
            if begun:db.execute('ROLLBACK')
            raise
        except Exception as e:
            if begun:
                try:db.execute('ROLLBACK')
                except Exception:pass
            raise AuthorityError('REPLAY_STATE_WRITE_FAILED') from e
        finally:db.close()

class ProtectedAuthorityService:
    def __init__(self,*,protected_root:Path,boundary:PlatformMachineBoundary,secrets_provider:FileSecretProvider,backend:GitHubAppBackend,receipt_signer:ReceiptSigner,allowed_repositories,self_build_runtime=None,github_enabled:bool=True):
        root=Path(protected_root)
        if not root.is_absolute():raise AuthorityError('PROTECTED_ROOT_INVALID')
        resolved=assert_machine_anchored_root(boundary,root)
        if receipt_signer is None:raise AuthorityError('RECEIPT_SIGNER_REQUIRED')
        self.root=resolved;self.boundary=boundary;self.secrets_provider=secrets_provider;self.backend=backend;self.receipt_signer=receipt_signer;self.allowed_repositories=_canonical_repository_map(allowed_repositories);self.service_principal=boundary.assert_service_principal(resolved);self.journal=ReplayJournal(resolved);self.self_build_runtime=self_build_runtime;self.github_enabled=bool(github_enabled)
    def handle_json(self,raw:str|bytes,*,peer_context:PeerContext)->bytes:return canonical_json(self.handle(unsigned_request(strict_loads(raw)),peer_context=peer_context))
    def handle(self,raw_request:Mapping[str,Any],*,peer_context:PeerContext)->dict:
        r=unsigned_request(raw_request)
        if not self.boundary.verify_peer(r['peerId'],r['requestDigest'],r['signature'],peer_context):raise AuthorityError('PEER_AUTH_DENIED')
        canonical_repo=self.allowed_repositories.get(r['repository'].casefold())
        if canonical_repo is None:raise AuthorityError('REPOSITORY_DENIED')
        r=dict(r);r['repository']=canonical_repo
        self.journal.consume(r['requestId'],r['requestDigest']);private=[]
        try:
            op=r['operation']
            if op in {'authorize_self_build_launch','prepare_self_build','prepare_self_build_replacement','compose_self_build_successor','activate_self_build_successor','prove_self_build_activation_rollback','self_build_current_known_good','self_build_status','revoke_self_build_worker','record_self_build_handoff','review_self_build_candidate','accept_self_build_candidate'}:
                if self.self_build_runtime is None:raise AuthorityError('SELF_BUILD_RUNTIME_UNAVAILABLE')
                try:
                    if op=='authorize_self_build_launch':result=self.self_build_runtime.authorize_launch(r['payload']['launch'],repository=r['repository'],control_revision=r['controlRevision'])
                    elif op=='prepare_self_build':result=self.self_build_runtime.prepare(r['payload'])
                    elif op=='prepare_self_build_replacement':result=self.self_build_runtime.prepare_replacement(r['payload'])
                    elif op=='compose_self_build_successor':result=self.self_build_runtime.compose_successor(r['payload'])
                    elif op=='activate_self_build_successor':result=self.self_build_runtime.activate_successor(r['payload'])
                    elif op=='prove_self_build_activation_rollback':result=self.self_build_runtime.prove_activation_rollback(r['payload'])
                    elif op=='self_build_current_known_good':result=self.self_build_runtime.current_known_good(r['payload'])
                    elif op=='revoke_self_build_worker':result=self.self_build_runtime.revoke_worker(r['payload'])
                    elif op=='record_self_build_handoff':result=self.self_build_runtime.record_handoff(r['payload'])
                    elif op=='review_self_build_candidate':result=self.self_build_runtime.record_review(r['payload'])
                    elif op=='accept_self_build_candidate':result=self.self_build_runtime.accept_candidate(r['payload'],controller_id=r['peerId'])
                    else:result=self.self_build_runtime.status(r['payload'])
                except SelfBuildRuntimeError as ex:
                    raise AuthorityError(ex.code,str(ex)) from ex
            else:
                if not getattr(self,'github_enabled',True):raise AuthorityError('GITHUB_NOT_CONFIGURED')
                key=self.secrets_provider.github_app_private_key();private.append(key);kw={'repository':r['repository'],'control_revision':r['controlRevision'],'payload':r['payload'],'private_key':key}
                if op=='read_github_control':result=self.backend.read_github_control(**kw)
                elif op=='publish_report_comment':result=self.backend.publish_report_comment(**kw)
                elif op=='publish_reviewed_draft_pr':result=self.backend.publish_reviewed_draft_pr(**kw)
                else:raise AuthorityError('OPERATION_DENIED')
            public=assert_public_result(result,tuple(private))
        except AuthorityError:raise
        except Exception:raise AuthorityError('BACKEND_OPERATION_FAILED')
        receipt={'schema':3,'operation':r['operation'],'requestId':r['requestId'],'peerId':r['peerId'],'peerPrincipal':peer_context.principal,'repository':r['repository'],'controlRevision':r['controlRevision'],'requestDigest':r['requestDigest'],'resultDigest':canonical_digest(public),'servicePrincipal':self.service_principal}
        signed=self.receipt_signer.sign(receipt);return {**signed,'result':public}

def create_production_service(*,protected_root:str,expected_service_principal:str,peer_principals:dict[str,str],peer_public_keys:dict[str,str],github_app_id:int,github_installation_id:int,github_private_key_file:str,receipt_signing_key_file:str,allowed_repositories,trusted_storage_principals:set[str]|None=None,github_enabled:bool=True)->ProtectedAuthorityService:
    root=Path(protected_root);boundary=PlatformMachineBoundary(expected_service_principal=expected_service_principal,peer_principals=peer_principals,peer_public_keys=peer_public_keys,trusted_storage_principals=trusted_storage_principals);root=assert_machine_anchored_root(boundary,root)
    repos=_canonical_repository_map(allowed_repositories)
    secrets=FileSecretProvider(root=root,private_key_path=Path(github_private_key_file),boundary=boundary);signer=ReceiptSigner.from_file(root=root,path=Path(receipt_signing_key_file),boundary=boundary);backend=GitHubAppBackend(app_id=github_app_id,installation_id=github_installation_id)
    receipt_pin=base64.b64encode(signer.public_raw).decode('ascii')
    runtime=SelfBuildRuntime(protected_root=root,boundary=boundary,receipt_public_key_b64=receipt_pin)
    return ProtectedAuthorityService(protected_root=root,boundary=boundary,secrets_provider=secrets,backend=backend,receipt_signer=signer,allowed_repositories=repos.values(),self_build_runtime=runtime,github_enabled=github_enabled)