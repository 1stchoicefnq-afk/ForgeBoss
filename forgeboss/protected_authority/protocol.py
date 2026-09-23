from __future__ import annotations

import hashlib,json,math,re,uuid
from typing import Any,Mapping

MAX_REQUEST_BYTES=128*1024;MAX_TEXT=64*1024;SCHEMA=2
OPERATIONS={'read_github_control','publish_report_comment','publish_reviewed_draft_pr','verify_launch_authority','prepare_self_build','prepare_self_build_replacement','compose_self_build_successor','activate_self_build_successor','prove_self_build_activation_rollback','self_build_current_known_good','self_build_status','revoke_self_build_worker','record_self_build_handoff','review_self_build_candidate','accept_self_build_candidate'}
_REPO=re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$');_HEX64=re.compile(r'^[0-9a-f]{64}$');_OID=re.compile(r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$');_MONEY=re.compile(r'^[0-9]{1,6}(?:\\.[0-9]{1,6})?$');_PEER=re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$');_REF=re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,199})$');_SECRET_KEY=re.compile(r'(?:token|secret|private[_-]?key|pem|jwt|credential|password)',re.I);_RUN_ID=re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
class AuthorityError(RuntimeError):
    def __init__(self,code:str,message:str='protected authority request denied'):
        super().__init__(f"{message} [{code}]");self.code=code

def _jsonable(v):
    if v is None or isinstance(v,(str,bool,int)):return v
    if isinstance(v,float):
        if not math.isfinite(v):raise AuthorityError('NONFINITE_JSON')
        return v
    if isinstance(v,Mapping):
        out={}
        for k,x in v.items():
            if not isinstance(k,str):raise AuthorityError('JSON_KEY_INVALID')
            out[k]=_jsonable(x)
        return out
    if isinstance(v,(list,tuple)):return [_jsonable(x) for x in v]
    raise AuthorityError('JSON_TYPE_INVALID')
def canonical_json(v):
    try:return json.dumps(_jsonable(v),sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
    except AuthorityError:raise
    except Exception as e:raise AuthorityError('JSON_INVALID') from e
def canonical_digest(v):return hashlib.sha256(canonical_json(v)).hexdigest()
def strict_loads(raw):
    if isinstance(raw,bytes):
        data=raw
        try:text=raw.decode()
        except UnicodeDecodeError as e:raise AuthorityError('JSON_INVALID') from e
    elif isinstance(raw,str):text=raw;data=raw.encode()
    else:raise AuthorityError('JSON_INVALID')
    if not data or len(data)>MAX_REQUEST_BYTES:raise AuthorityError('REQUEST_SIZE_INVALID')
    def pairs(xs):
        out={}
        for k,v in xs:
            if k in out:raise AuthorityError('DUPLICATE_JSON_KEY')
            out[k]=v
        return out
    def constant(_):raise AuthorityError('NONFINITE_JSON')
    try:return json.loads(text,object_pairs_hook=pairs,parse_constant=constant)
    except AuthorityError:raise
    except Exception as e:raise AuthorityError('JSON_INVALID') from e
def _exact(v,keys,code):
    if not isinstance(v,Mapping) or set(v)!=set(keys):raise AuthorityError(code)
    return dict(v)
def _text(v,code,max_len=MAX_TEXT,pattern=None,lower=False):
    if not isinstance(v,str) or not v or v!=v.strip() or len(v)>max_len or any(ord(c)<32 or ord(c)==127 for c in v):raise AuthorityError(code)
    out=v.lower() if lower else v
    if pattern is not None and not pattern.fullmatch(out):raise AuthorityError(code)
    return out
def _int(v,code,zero=False):
    if isinstance(v,bool) or not isinstance(v,int) or v<(0 if zero else 1) or v>2**63-1:raise AuthorityError(code)
    return v
def _rid(v):
    t=_text(v,'REQUEST_ID_INVALID',36)
    try:p=uuid.UUID(t)
    except ValueError as e:raise AuthorityError('REQUEST_ID_INVALID') from e
    if p.version!=4 or str(p)!=t.lower():raise AuthorityError('REQUEST_ID_INVALID')
    return t.lower()
def _ref(v,code):
    t=_text(v,code,200,_REF)
    if t.startswith('/') or t.endswith('/') or '..' in t.split('/') or '@{' in t or '\\' in t:raise AuthorityError(code)
    return t
def _payload(op,raw):
    if op=='read_github_control':
        o=_exact(raw,('rootPr','preferredRepairPr'),'PAYLOAD_INVALID');o['rootPr']=_int(o['rootPr'],'ROOT_PR_INVALID');o['preferredRepairPr']=_int(o['preferredRepairPr'],'REPAIR_PR_INVALID',True);return o
    if op=='publish_report_comment':
        o=_exact(raw,('issue','body','reportDigest'),'PAYLOAD_INVALID');o['issue']=_int(o['issue'],'ISSUE_INVALID');o['body']=_text(o['body'],'COMMENT_BODY_INVALID');o['reportDigest']=_text(o['reportDigest'],'REPORT_DIGEST_INVALID',64,_HEX64,True);return o
    if op=='publish_reviewed_draft_pr':
        o=_exact(raw,('baseSha','headSha','baseRef','headRef','title','body','reviewDigest'),'PAYLOAD_INVALID');o['baseSha']=_text(o['baseSha'],'BASE_SHA_INVALID',64,_OID,True);o['headSha']=_text(o['headSha'],'HEAD_SHA_INVALID',64,_OID,True)
        if len(o['baseSha'])!=len(o['headSha']):raise AuthorityError('OBJECT_FORMAT_MISMATCH')
        if o['baseSha']==o['headSha']:raise AuthorityError('DRAFT_PR_EMPTY_DIFF')
        o['baseRef']=_ref(o['baseRef'],'BASE_REF_INVALID');o['headRef']=_ref(o['headRef'],'HEAD_REF_INVALID')
        if o['baseRef']==o['headRef']:raise AuthorityError('PR_REF_COLLISION')
        o['title']=_text(o['title'],'PR_TITLE_INVALID',256);o['body']=_text(o['body'],'PR_BODY_INVALID');o['reviewDigest']=_text(o['reviewDigest'],'REVIEW_DIGEST_INVALID',64,_HEX64,True);return o
    if op=='verify_launch_authority':
        o=_exact(raw,('envelope','envelopeDigest'),'PAYLOAD_INVALID')
        if not isinstance(o['envelope'],Mapping):raise AuthorityError('LAUNCH_ENVELOPE_INVALID')
        o['envelope']=_jsonable(o['envelope']);o['envelopeDigest']=_text(o['envelopeDigest'],'ENVELOPE_DIGEST_INVALID',64,_HEX64,True);return o
    if op=='prepare_self_build':
        o=_exact(raw,('sourceRoot','baseSha','runId'),'PAYLOAD_INVALID')
        o['sourceRoot']=_text(o['sourceRoot'],'SOURCE_ROOT_INVALID',4096)
        o['baseSha']=_text(o['baseSha'],'BASE_SHA_INVALID',64,_OID,True)
        o['runId']=_text(o['runId'],'RUN_ID_INVALID',64,_RUN_ID)
        return o
    if op=='self_build_current_known_good':
        o=_exact(raw,(),'PAYLOAD_INVALID')
        return o
    if op in {'prepare_self_build_replacement','compose_self_build_successor','activate_self_build_successor','prove_self_build_activation_rollback','self_build_status'}:
        o=_exact(raw,('runId',),'PAYLOAD_INVALID')
        o['runId']=_text(o['runId'],'RUN_ID_INVALID',64,_RUN_ID)
        return o
    if op=='revoke_self_build_worker':
        o=_exact(raw,('runId','taskId','workerRunId','ownerEpoch','reason'),'PAYLOAD_INVALID')
        o['runId']=_text(o['runId'],'RUN_ID_INVALID',64,_RUN_ID)
        o['taskId']=_text(o['taskId'],'TASK_ID_INVALID',128,_PEER)
        o['workerRunId']=_text(o['workerRunId'],'WORKER_RUN_ID_INVALID',128,_PEER)
        o['ownerEpoch']=_int(o['ownerEpoch'],'OWNER_EPOCH_INVALID')
        o['reason']=_text(o['reason'],'REVOKE_REASON_INVALID',512)
        return o
    if op=='record_self_build_handoff':
        o=_exact(raw,('runId','taskId','workerRunId','ownerEpoch','evidence'),'PAYLOAD_INVALID')
        o['runId']=_text(o['runId'],'RUN_ID_INVALID',64,_RUN_ID)
        o['taskId']=_text(o['taskId'],'TASK_ID_INVALID',128,_PEER)
        o['workerRunId']=_text(o['workerRunId'],'WORKER_RUN_ID_INVALID',128,_PEER)
        o['ownerEpoch']=_int(o['ownerEpoch'],'OWNER_EPOCH_INVALID')
        if not isinstance(o['evidence'],Mapping):raise AuthorityError('HANDOFF_EVIDENCE_INVALID')
        o['evidence']=_jsonable(o['evidence'])
        return o
    if op=='review_self_build_candidate':
        o=_exact(raw,('runId','taskId','workerRunId','ownerEpoch'),'PAYLOAD_INVALID')
        o['runId']=_text(o['runId'],'RUN_ID_INVALID',64,_RUN_ID)
        o['taskId']=_text(o['taskId'],'TASK_ID_INVALID',128,_PEER)
        o['workerRunId']=_text(o['workerRunId'],'WORKER_RUN_ID_INVALID',128,_PEER)
        o['ownerEpoch']=_int(o['ownerEpoch'],'OWNER_EPOCH_INVALID')
        return o
    if op=='accept_self_build_candidate':
        o=_exact(raw,('runId','taskId','workerRunId','ownerEpoch'),'PAYLOAD_INVALID')
        o['runId']=_text(o['runId'],'RUN_ID_INVALID',64,_RUN_ID)
        o['taskId']=_text(o['taskId'],'TASK_ID_INVALID',128,_PEER)
        o['workerRunId']=_text(o['workerRunId'],'WORKER_RUN_ID_INVALID',128,_PEER)
        o['ownerEpoch']=_int(o['ownerEpoch'],'OWNER_EPOCH_INVALID')
        return o
    raise AuthorityError('OPERATION_DENIED')
def _canonical_unsigned(raw):
    o=_exact(raw,('schema','operation','requestId','peerId','repository','controlRevision','payload'),'REQUEST_FIELDS_INVALID')
    if o['schema']!=SCHEMA:raise AuthorityError('SCHEMA_INVALID')
    op=_text(o['operation'],'OPERATION_INVALID',64)
    if op not in OPERATIONS:raise AuthorityError('OPERATION_DENIED')
    repo=_text(o['repository'],'REPOSITORY_INVALID',201,_REPO,True);rev=_int(o['controlRevision'],'CONTROL_REVISION_INVALID');rid=_rid(o['requestId']);peer=_text(o['peerId'],'PEER_ID_INVALID',128,_PEER);payload=_payload(op,o['payload'])
    return {'schema':SCHEMA,'operation':op,'requestId':rid,'peerId':peer,'repository':repo,'controlRevision':rev,'payload':payload}
def unsigned_request(raw):
    o=_exact(raw,('schema','operation','requestId','peerId','repository','controlRevision','requestDigest','signature','payload'),'REQUEST_FIELDS_INVALID')
    u=_canonical_unsigned({k:o[k] for k in ('schema','operation','requestId','peerId','repository','controlRevision','payload')});dig=_text(o['requestDigest'],'REQUEST_DIGEST_INVALID',64,_HEX64,True);sig=_text(o['signature'],'SIGNATURE_INVALID',4096)
    if canonical_digest(u)!=dig:raise AuthorityError('REQUEST_DIGEST_MISMATCH')
    return {**u,'requestDigest':dig,'signature':sig}
def build_request(*,operation,request_id,peer_id,repository,control_revision,payload,signature):
    u=_canonical_unsigned({'schema':SCHEMA,'operation':operation,'requestId':request_id,'peerId':peer_id,'repository':repository,'controlRevision':control_revision,'payload':dict(payload)})
    return unsigned_request({**u,'requestDigest':canonical_digest(u),'signature':signature})
def assert_public_result(value,private_values=()):
    clean=_jsonable(value);texts=[]
    for item in private_values:
        if isinstance(item,bytes):
            try:texts.append(item.decode())
            except UnicodeDecodeError:pass
        elif isinstance(item,str):texts.append(item)
    def walk(n):
        if isinstance(n,Mapping):
            for k,v in n.items():
                if _SECRET_KEY.search(str(k)):raise AuthorityError('SECRET_FIELD_DENIED')
                walk(v)
        elif isinstance(n,list):
            for v in n:walk(v)
        elif isinstance(n,str):
            for s in texts:
                if s and s in n:raise AuthorityError('SECRET_VALUE_DENIED')
    walk(clean);return clean
