from __future__ import annotations

import base64, hashlib, json, math, re, time
from dataclasses import dataclass
from typing import Any, Mapping

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    Ed25519PublicKey=None

COMMAND_VERSION=1
DOMAIN='forgeboss/controller-command/v1'
_ID=re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$')
_SHA256=re.compile(r'^[0-9a-f]{64}$')
_ALLOWED={
    'budget.run.create','budget.run.close','worker.revoke','worker.reassign',
    'task.retry','candidate.freeze','candidate.accept','workspace.quarantine.reconcile'
}

class ControllerCommandError(ValueError): pass

def _strict_json(value:Any)->bytes:
    def conv(v):
        if isinstance(v,Mapping):
            out={}
            for k,x in v.items():
                if not isinstance(k,str) or k in out: raise ControllerCommandError('object key invalid')
                out[k]=conv(x)
            return out
        if isinstance(v,(list,tuple)): return [conv(x) for x in v]
        if isinstance(v,(str,int,bool)) or v is None:return v
        raise ControllerCommandError(f'non-canonical value type: {type(v).__name__}')
    return json.dumps(conv(value),sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def _text(v,name,pat=_ID,max_len=256):
    if not isinstance(v,str) or not v or v!=v.strip() or len(v)>max_len or any(ord(c)<32 or ord(c)==127 for c in v): raise ControllerCommandError(f'{name} invalid')
    if pat and not pat.fullmatch(v):raise ControllerCommandError(f'{name} invalid')
    return v

def _int(v,name,minv=1):
    if not isinstance(v,int) or isinstance(v,bool) or v<minv:raise ControllerCommandError(f'{name} invalid')
    return v

def _time(v,name):
    if not isinstance(v,int) or isinstance(v,bool) or v<0:raise ControllerCommandError(f'{name} invalid')
    return v

def payload_digest(payload:Any)->str:return hashlib.sha256(_strict_json(payload)).hexdigest()

@dataclass(frozen=True)
class ControllerKey:
    controller_id:str
    key_id:str
    public_key_b64:str
    generation:int
    active_from:int
    cutoff_at:int|None=None
    def __post_init__(self):
        _text(self.controller_id,'controllerId');_text(self.key_id,'keyId');_int(self.generation,'generation');_time(self.active_from,'activeFrom')
        if self.cutoff_at is not None and _time(self.cutoff_at,'cutoffAt')<=self.active_from:raise ControllerCommandError('cutoffAt invalid')
        try:raw=base64.b64decode(self.public_key_b64,validate=True)
        except Exception as ex:raise ControllerCommandError('public key encoding invalid') from ex
        if len(raw)!=32:raise ControllerCommandError('public key length invalid')

@dataclass(frozen=True)
class CommandTrust:
    minimum_generation:int
    keys:tuple[ControllerKey,...]
    def __post_init__(self):
        _int(self.minimum_generation,'minimumGeneration')
        if not self.keys or any(not isinstance(k,ControllerKey) for k in self.keys):raise ControllerCommandError('keys invalid')
        ids=[k.key_id.casefold() for k in self.keys]
        if len(ids)!=len(set(ids)):raise ControllerCommandError('duplicate key id')
    def key(self,controller_id,key_id,generation,now):
        _text(controller_id,'controllerId');_text(key_id,'keyId');_int(generation,'generation');now=_time(now,'now')
        if generation<self.minimum_generation:raise PermissionError('stale controller generation')
        match=[k for k in self.keys if k.controller_id==controller_id and k.key_id==key_id and k.generation==generation]
        if len(match)!=1:raise PermissionError('controller key/generation unknown')
        k=match[0]
        if now<k.active_from:raise PermissionError('controller key not active')
        if k.cutoff_at is not None and now>=k.cutoff_at:raise PermissionError('controller key cutoff reached')
        return k

@dataclass(frozen=True)
class VerifiedControllerCommand:
    command_id:str; method:str; controller_id:str; key_id:str; generation:int
    issued_at:int; expires_at:int; nonce:str; payload_sha256:str; payload:Any
    def material(self):
        return {'domain':DOMAIN,'version':COMMAND_VERSION,'commandId':self.command_id,'method':self.method,
                'controllerId':self.controller_id,'keyId':self.key_id,'generation':self.generation,
                'issuedAt':self.issued_at,'expiresAt':self.expires_at,'nonce':self.nonce,
                'payloadSha256':self.payload_sha256,'payload':self.payload}
    @property
    def digest(self):return hashlib.sha256(_strict_json(self.material())).hexdigest()

class NonceLedger:
    def __init__(self):self._seen=set()
    def consume(self,controller_id,generation,nonce):
        key=(controller_id.casefold(),int(generation),nonce)
        if key in self._seen:raise PermissionError('controller command replay')
        self._seen.add(key)

def verify_controller_command(record:Mapping[str,Any],trust:CommandTrust,*,nonce_ledger,now=None,max_lifetime=60)->VerifiedControllerCommand:
    if not isinstance(record,Mapping):raise ControllerCommandError('command record invalid')
    required={'domain','version','commandId','method','controllerId','keyId','generation','issuedAt','expiresAt','nonce','payloadSha256','payload','signature'}
    if set(record)!=required:raise ControllerCommandError('command keys invalid')
    if record['domain']!=DOMAIN or record['version']!=COMMAND_VERSION:raise PermissionError('controller command domain/version invalid')
    method=_text(record['method'],'method',None,128)
    if method not in _ALLOWED:raise PermissionError('controller method not allowed')
    command_id=_text(record['commandId'],'commandId');controller_id=_text(record['controllerId'],'controllerId');key_id=_text(record['keyId'],'keyId')
    generation=_int(record['generation'],'generation');issued=_time(record['issuedAt'],'issuedAt');expires=_time(record['expiresAt'],'expiresAt');current=int(time.time()) if now is None else _time(now,'now')
    if expires<=issued or expires-issued>int(max_lifetime):raise ControllerCommandError('command lifetime invalid')
    if current<issued-5 or current>=expires:raise PermissionError('controller command expired/not-yet-valid')
    nonce=_text(record['nonce'],'nonce',re.compile(r'^[0-9a-f]{32,128}$'),128)
    psha=_text(record['payloadSha256'],'payloadSha256',_SHA256,64)
    if payload_digest(record['payload'])!=psha:raise PermissionError('controller command payload digest mismatch')
    key=trust.key(controller_id,key_id,generation,current)
    material={k:record[k] for k in required if k!='signature'}
    try:sig=base64.b64decode(record['signature'],validate=True)
    except Exception as ex:raise ControllerCommandError('signature encoding invalid') from ex
    if len(sig)!=64:raise ControllerCommandError('signature length invalid')
    if Ed25519PublicKey is None:raise RuntimeError('Ed25519 verifier unavailable')
    try:Ed25519PublicKey.from_public_bytes(base64.b64decode(key.public_key_b64)).verify(sig,_strict_json(material))
    except Exception as ex:raise PermissionError('controller command signature invalid') from ex
    if nonce_ledger is None or not hasattr(nonce_ledger,'consume'):raise ControllerCommandError('durable nonce consumer required')
    nonce_ledger.consume(controller_id,generation,nonce)
    return VerifiedControllerCommand(command_id,method,controller_id,key_id,generation,issued,expires,nonce,psha,record['payload'])
