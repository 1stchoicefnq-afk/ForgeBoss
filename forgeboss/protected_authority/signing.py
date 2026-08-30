from __future__ import annotations

import base64,hashlib,os,stat
from pathlib import Path
from typing import Any,Mapping

from .protocol import AuthorityError,canonical_digest


def _load_private(raw:bytes):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key=serialization.load_pem_private_key(raw,password=None)
        if not isinstance(key,Ed25519PrivateKey):raise AuthorityError('RECEIPT_SIGNING_KEY_INVALID')
        return key
    except AuthorityError:raise
    except Exception as e:raise AuthorityError('RECEIPT_SIGNING_KEY_INVALID') from e

def _public_raw(key)->bytes:
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)

def _read_secret(root:Path,path:Path,boundary)->bytes:
    root=root.resolve(strict=True);raw=Path(path)
    if raw.is_symlink():raise AuthorityError('RECEIPT_SIGNING_KEY_PATH_INVALID')
    target=raw.resolve(strict=True)
    try:common=Path(os.path.commonpath([str(root),str(target)]))
    except ValueError as e:raise AuthorityError('RECEIPT_SIGNING_KEY_PATH_INVALID') from e
    if common!=root or target==root or not stat.S_ISREG(target.stat().st_mode):raise AuthorityError('RECEIPT_SIGNING_KEY_PATH_INVALID')
    boundary.assert_protected_path(target,protected_root=root,secret=True)
    fd=None
    try:
        fd=os.open(str(target),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):raise AuthorityError('RECEIPT_SIGNING_KEY_PATH_INVALID')
        data=b''
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            data+=chunk
            if len(data)>1024*1024:raise AuthorityError('RECEIPT_SIGNING_KEY_INVALID')
        after=os.fstat(fd)
        if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):raise AuthorityError('RECEIPT_SIGNING_KEY_CHANGED')
        return data
    except AuthorityError:raise
    except Exception as e:raise AuthorityError('RECEIPT_SIGNING_KEY_READ_FAILED') from e
    finally:
        if fd is not None:os.close(fd)

class ReceiptSigner:
    def __init__(self,key):
        self._key=key;self.public_raw=_public_raw(key);self.public_key_id=hashlib.sha256(self.public_raw).hexdigest()
    @classmethod
    def from_file(cls,*,root:Path,path:Path,boundary):return cls(_load_private(_read_secret(root,path,boundary)))
    @classmethod
    def from_private_key(cls,key):return cls(key)
    def sign(self,receipt:Mapping[str,Any])->dict:
        digest=canonical_digest(receipt);sig=self._key.sign(bytes.fromhex(digest))
        return {'receipt':dict(receipt),'receiptDigest':digest,'receiptPublicKeyId':self.public_key_id,'receiptSignature':base64.b64encode(sig).decode('ascii')}

def verify_signed_receipt(response:Mapping[str,Any],pinned_public_key_b64:str)->bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if not isinstance(response,Mapping) or set(response)!={'receipt','receiptDigest','receiptPublicKeyId','receiptSignature','result'}:return False
        receipt=response['receipt'];digest=response['receiptDigest']
        if canonical_digest(receipt)!=digest:return False
        if not isinstance(receipt,Mapping) or receipt.get('resultDigest')!=canonical_digest(response['result']):return False
        raw=base64.b64decode(pinned_public_key_b64,validate=True)
        if len(raw)!=32 or hashlib.sha256(raw).hexdigest()!=response['receiptPublicKeyId']:return False
        sig=base64.b64decode(response['receiptSignature'],validate=True)
        Ed25519PublicKey.from_public_bytes(raw).verify(sig,bytes.fromhex(digest));return True
    except Exception:return False
