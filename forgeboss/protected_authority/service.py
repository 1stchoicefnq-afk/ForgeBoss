from __future__ import annotations

import os, sqlite3
from pathlib import Path
from typing import Any,Mapping

from .boundary import FileSecretProvider,PeerContext,PlatformMachineBoundary
from .github_backend import GitHubAppBackend
from .protocol import AuthorityError,assert_public_result,canonical_digest,canonical_json,strict_loads,unsigned_request


class ReplayJournal:
    def __init__(self,root:Path):
        self.path=root/'replay.sqlite3'
        try:
            db=sqlite3.connect(self.path,timeout=30,isolation_level=None);db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL');db.execute('CREATE TABLE IF NOT EXISTS consumed(request_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, consumed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');db.close()
        except Exception as e:raise AuthorityError('REPLAY_STATE_INVALID') from e
    def consume(self,request_id:str,request_digest:str)->None:
        db=sqlite3.connect(self.path,timeout=30,isolation_level=None)
        begun=False
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
    def __init__(self,*,protected_root:Path,boundary:PlatformMachineBoundary,secrets_provider:FileSecretProvider,backend:GitHubAppBackend):
        root=Path(protected_root)
        if not root.is_absolute():raise AuthorityError('PROTECTED_ROOT_INVALID')
        try:
            if root.is_symlink() or not root.is_dir():raise AuthorityError('PROTECTED_ROOT_INVALID')
            resolved=root.resolve(strict=True)
        except AuthorityError:raise
        except Exception as e:raise AuthorityError('PROTECTED_ROOT_INVALID') from e
        principal=boundary.assert_service_principal(resolved)
        if not principal:raise AuthorityError('SERVICE_PRINCIPAL_INVALID')
        self.root=resolved;self.boundary=boundary;self.secrets_provider=secrets_provider;self.backend=backend;self.service_principal=principal;self.journal=ReplayJournal(resolved)
    def handle_json(self,raw:str|bytes,*,peer_context:PeerContext)->bytes:return canonical_json(self.handle(unsigned_request(strict_loads(raw)),peer_context=peer_context))
    def handle(self,raw_request:Mapping[str,Any],*,peer_context:PeerContext)->dict:
        r=unsigned_request(raw_request)
        if not self.boundary.verify_peer(r['peerId'],r['requestDigest'],r['signature'],peer_context):raise AuthorityError('PEER_AUTH_DENIED')
        self.journal.consume(r['requestId'],r['requestDigest'])
        private=[]
        try:
            if r['operation']=='verify_launch_authority':
                trust=self.secrets_provider.launch_trust_root();private.append(trust);result=self.backend.verify_launch_authority(repository=r['repository'],control_revision=r['controlRevision'],payload=r['payload'],trust_root=trust)
            else:
                key=self.secrets_provider.github_app_private_key();private.append(key);kw={'repository':r['repository'],'control_revision':r['controlRevision'],'payload':r['payload'],'private_key':key}
                if r['operation']=='read_github_control':result=self.backend.read_github_control(**kw)
                elif r['operation']=='publish_report_comment':result=self.backend.publish_report_comment(**kw)
                elif r['operation']=='publish_reviewed_draft_pr':result=self.backend.publish_reviewed_draft_pr(**kw)
                else:raise AuthorityError('OPERATION_DENIED')
            public=assert_public_result(result,tuple(private))
        except AuthorityError:raise
        except Exception:raise AuthorityError('BACKEND_OPERATION_FAILED')
        receipt={'schema':2,'operation':r['operation'],'requestId':r['requestId'],'peerId':r['peerId'],'peerPrincipal':peer_context.principal,'repository':r['repository'],'controlRevision':r['controlRevision'],'requestDigest':r['requestDigest'],'resultDigest':canonical_digest(public),'servicePrincipal':self.service_principal}
        return {'receipt':receipt,'receiptDigest':canonical_digest(receipt),'result':public}


def create_production_service(*,protected_root:str,expected_service_principal:str,peer_principals:dict[str,str],peer_public_keys:dict[str,str],github_app_id:int,github_installation_id:int,github_private_key_file:str,launch_trust_file:str)->ProtectedAuthorityService:
    root=Path(protected_root).resolve(strict=True);boundary=PlatformMachineBoundary(expected_service_principal=expected_service_principal,peer_principals=peer_principals,peer_public_keys=peer_public_keys);boundary.assert_service_principal(root)
    secrets=FileSecretProvider(root=root,private_key_path=Path(github_private_key_file),launch_trust_path=Path(launch_trust_file),boundary=boundary);backend=GitHubAppBackend(app_id=github_app_id,installation_id=github_installation_id)
    return ProtectedAuthorityService(protected_root=root,boundary=boundary,secrets_provider=secrets,backend=backend)
