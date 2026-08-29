from __future__ import annotations

import base64, json, time, urllib.error, urllib.request
from typing import Any, Mapping

from .protocol import AuthorityError, canonical_digest


class GitHubAppBackend:
    def __init__(self, *, app_id:int, installation_id:int, api_base:str='https://api.github.com'):
        if not isinstance(app_id,int) or app_id<=0 or not isinstance(installation_id,int) or installation_id<=0: raise AuthorityError('GITHUB_APP_CONFIG_INVALID')
        if api_base!='https://api.github.com': raise AuthorityError('GITHUB_API_BASE_DENIED')
        self.app_id=app_id;self.installation_id=installation_id;self.api_base=api_base

    def _jwt(self,pem:bytes)->str:
        try:
            from cryptography.hazmat.primitives import hashes,serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            now=int(time.time());header={'alg':'RS256','typ':'JWT'};payload={'iat':now-30,'exp':now+540,'iss':str(self.app_id)}
            enc=lambda x:base64.urlsafe_b64encode(json.dumps(x,separators=(',',':'),sort_keys=True).encode()).rstrip(b'=')
            unsigned=enc(header)+b'.'+enc(payload)
            key=serialization.load_pem_private_key(pem,password=None);sig=key.sign(unsigned,padding.PKCS1v15(),hashes.SHA256())
            return (unsigned+b'.'+base64.urlsafe_b64encode(sig).rstrip(b'=')).decode()
        except Exception as exc: raise AuthorityError('GITHUB_APP_KEY_INVALID') from exc

    def _request(self,method:str,path:str,*,token:str|None=None,body:Mapping[str,Any]|None=None)->Any:
        if not path.startswith('/') or '://' in path or '..' in path: raise AuthorityError('GITHUB_PATH_DENIED')
        headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'ForgeBossAuthority'}
        if token:headers['Authorization']='Bearer '+token
        data=None if body is None else json.dumps(body,separators=(',',':')).encode()
        req=urllib.request.Request(self.api_base+path,data=data,headers=headers,method=method)
        try:
            with urllib.request.urlopen(req,timeout=30) as r:return json.loads(r.read().decode())
        except (urllib.error.URLError,ValueError) as exc: raise AuthorityError('GITHUB_OPERATION_FAILED') from exc

    def _token(self,pem:bytes)->str:
        obj=self._request('POST',f'/app/installations/{self.installation_id}/access_tokens',token=self._jwt(pem),body={})
        token=obj.get('token') if isinstance(obj,dict) else None
        if not isinstance(token,str) or not token: raise AuthorityError('GITHUB_TOKEN_INVALID')
        return token

    @staticmethod
    def _repo_path(repository:str)->str:return '/repos/'+repository

    def read_github_control(self,*,repository:str,control_revision:int,payload:Mapping[str,Any],private_key:bytes)->Any:
        token=self._token(private_key);root=int(payload['rootPr']);preferred=int(payload['preferredRepairPr'])
        root_pr=self._request('GET',self._repo_path(repository)+f'/pulls/{root}',token=token)
        repair=None
        if preferred: repair=self._request('GET',self._repo_path(repository)+f'/pulls/{preferred}',token=token)
        return {'repository':repository,'controlRevision':control_revision,'rootPr':{'number':root_pr.get('number'),'state':root_pr.get('state'),'headSha':root_pr.get('head',{}).get('sha'),'baseSha':root_pr.get('base',{}).get('sha')},'repairPr':None if repair is None else {'number':repair.get('number'),'state':repair.get('state'),'headSha':repair.get('head',{}).get('sha'),'baseSha':repair.get('base',{}).get('sha')}}

    def publish_report_comment(self,*,repository:str,control_revision:int,payload:Mapping[str,Any],private_key:bytes)->Any:
        token=self._token(private_key);obj=self._request('POST',self._repo_path(repository)+f"/issues/{int(payload['issue'])}/comments",token=token,body={'body':payload['body']})
        return {'repository':repository,'controlRevision':control_revision,'commentId':obj.get('id'),'reportDigest':payload['reportDigest']}

    def publish_reviewed_draft_pr(self,*,repository:str,control_revision:int,payload:Mapping[str,Any],private_key:bytes)->Any:
        token=self._token(private_key);base_ref=payload['baseRef'];head_ref=payload['headRef']
        base=self._request('GET',self._repo_path(repository)+f'/git/ref/heads/{base_ref}',token=token);head=self._request('GET',self._repo_path(repository)+f'/git/ref/heads/{head_ref}',token=token)
        if base.get('object',{}).get('sha','').lower()!=payload['baseSha'] or head.get('object',{}).get('sha','').lower()!=payload['headSha']: raise AuthorityError('PR_REF_SHA_MISMATCH')
        obj=self._request('POST',self._repo_path(repository)+'/pulls',token=token,body={'title':payload['title'],'body':payload['body'],'head':head_ref,'base':base_ref,'draft':True})
        return {'repository':repository,'controlRevision':control_revision,'prNumber':obj.get('number'),'draft':obj.get('draft') is True,'headSha':payload['headSha'],'baseSha':payload['baseSha'],'reviewDigest':payload['reviewDigest']}

    def verify_launch_authority(self,*,repository:str,control_revision:int,payload:Mapping[str,Any],trust_root:bytes)->Any:
        env=payload['envelope'];signature=env.get('signature');signed=env.get('signed')
        if not isinstance(signature,str) or not isinstance(signed,Mapping): raise AuthorityError('LAUNCH_ENVELOPE_INVALID')
        if canonical_digest(signed)!=payload['envelopeDigest']: raise AuthorityError('ENVELOPE_DIGEST_MISMATCH')
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            key=Ed25519PublicKey.from_public_bytes(base64.b64decode(trust_root,validate=True));key.verify(base64.b64decode(signature,validate=True),bytes.fromhex(payload['envelopeDigest']))
        except Exception as exc: raise AuthorityError('LAUNCH_AUTHORITY_INVALID') from exc
        return {'repository':repository,'controlRevision':control_revision,'verified':True,'envelopeDigest':payload['envelopeDigest']}
