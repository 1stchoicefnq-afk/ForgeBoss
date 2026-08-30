from __future__ import annotations

import hashlib, json, math, re, uuid
from typing import Any, Mapping

MAX_REQUEST_BYTES = 128 * 1024
MAX_TEXT = 64 * 1024
SCHEMA = 2
OPERATIONS = {'read_github_control', 'publish_report_comment', 'publish_reviewed_draft_pr', 'verify_launch_authority'}
_REPO = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_OID = re.compile(r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')
_PEER = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$')
_REF = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,199})$')
_SECRET_KEY = re.compile(r'(?:token|secret|private[_-]?key|pem|jwt|credential|password)', re.I)


class AuthorityError(RuntimeError):
    def __init__(self, code: str, message: str = 'protected authority request denied'):
        super().__init__(message); self.code = code


def _jsonable(value):
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AuthorityError('NONFINITE_JSON')
        return value
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuthorityError('JSON_KEY_INVALID')
            out[key] = _jsonable(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    raise AuthorityError('JSON_TYPE_INVALID')


def canonical_json(value):
    try:
        return json.dumps(_jsonable(value), sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    except AuthorityError:
        raise
    except Exception as exc:
        raise AuthorityError('JSON_INVALID') from exc


def canonical_digest(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def strict_loads(raw):
    if isinstance(raw, bytes):
        data = raw
        try:
            text = raw.decode()
        except UnicodeDecodeError as exc:
            raise AuthorityError('JSON_INVALID') from exc
    elif isinstance(raw, str):
        text = raw; data = raw.encode()
    else:
        raise AuthorityError('JSON_INVALID')
    if not data or len(data) > MAX_REQUEST_BYTES:
        raise AuthorityError('REQUEST_SIZE_INVALID')

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise AuthorityError('DUPLICATE_JSON_KEY')
            out[key] = value
        return out

    def constant(_):
        raise AuthorityError('NONFINITE_JSON')

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except AuthorityError:
        raise
    except Exception as exc:
        raise AuthorityError('JSON_INVALID') from exc


def _exact(value, keys, code):
    if not isinstance(value, Mapping) or set(value) != set(keys):
        raise AuthorityError(code)
    return dict(value)


def _text(value, code, max_len=MAX_TEXT, pattern=None, lower=False):
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > max_len or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise AuthorityError(code)
    out = value.lower() if lower else value
    if pattern is not None and not pattern.fullmatch(out):
        raise AuthorityError(code)
    return out


def _int(value, code, zero=False):
    if isinstance(value, bool) or not isinstance(value, int) or value < (0 if zero else 1) or value > 2**63 - 1:
        raise AuthorityError(code)
    return value


def _rid(value):
    text = _text(value, 'REQUEST_ID_INVALID', 36)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise AuthorityError('REQUEST_ID_INVALID') from exc
    if parsed.version != 4 or str(parsed) != text.lower():
        raise AuthorityError('REQUEST_ID_INVALID')
    return text.lower()


def _ref(value, code):
    text = _text(value, code, 200, _REF)
    parts = text.split('/')
    if (
        text.startswith('/') or text.endswith('/') or '@{' in text or '\\' in text
        or any(not part or part in {'.', '..'} or part.startswith('.') or part.endswith('.lock') or part.endswith('.') for part in parts)
    ):
        raise AuthorityError(code)
    return text


def _payload(operation, raw):
    if operation == 'read_github_control':
        out = _exact(raw, ('rootPr', 'preferredRepairPr'), 'PAYLOAD_INVALID')
        out['rootPr'] = _int(out['rootPr'], 'ROOT_PR_INVALID')
        out['preferredRepairPr'] = _int(out['preferredRepairPr'], 'REPAIR_PR_INVALID', True)
        return out
    if operation == 'publish_report_comment':
        out = _exact(raw, ('issue', 'body', 'reportDigest'), 'PAYLOAD_INVALID')
        out['issue'] = _int(out['issue'], 'ISSUE_INVALID')
        out['body'] = _text(out['body'], 'COMMENT_BODY_INVALID')
        out['reportDigest'] = _text(out['reportDigest'], 'REPORT_DIGEST_INVALID', 64, _HEX64, True)
        return out
    if operation == 'publish_reviewed_draft_pr':
        out = _exact(raw, ('baseSha', 'headSha', 'baseRef', 'headRef', 'title', 'body', 'reviewDigest'), 'PAYLOAD_INVALID')
        out['baseSha'] = _text(out['baseSha'], 'BASE_SHA_INVALID', 64, _OID, True)
        out['headSha'] = _text(out['headSha'], 'HEAD_SHA_INVALID', 64, _OID, True)
        if len(out['baseSha']) != len(out['headSha']):
            raise AuthorityError('OBJECT_FORMAT_MISMATCH')
        if out['baseSha'] == out['headSha']:
            raise AuthorityError('DRAFT_PR_EMPTY_DIFF')
        out['baseRef'] = _ref(out['baseRef'], 'BASE_REF_INVALID')
        out['headRef'] = _ref(out['headRef'], 'HEAD_REF_INVALID')
        if out['baseRef'] == out['headRef']:
            raise AuthorityError('PR_REF_COLLISION')
        out['title'] = _text(out['title'], 'PR_TITLE_INVALID', 256)
        out['body'] = _text(out['body'], 'PR_BODY_INVALID')
        out['reviewDigest'] = _text(out['reviewDigest'], 'REVIEW_DIGEST_INVALID', 64, _HEX64, True)
        return out
    if operation == 'verify_launch_authority':
        out = _exact(raw, ('envelope', 'envelopeDigest'), 'PAYLOAD_INVALID')
        if not isinstance(out['envelope'], Mapping):
            raise AuthorityError('LAUNCH_ENVELOPE_INVALID')
        out['envelope'] = _jsonable(out['envelope'])
        out['envelopeDigest'] = _text(out['envelopeDigest'], 'ENVELOPE_DIGEST_INVALID', 64, _HEX64, True)
        return out
    raise AuthorityError('OPERATION_DENIED')


def unsigned_request(raw):
    out = _exact(raw, ('schema', 'operation', 'requestId', 'peerId', 'repository', 'controlRevision', 'requestDigest', 'signature', 'payload'), 'REQUEST_FIELDS_INVALID')
    if out['schema'] != SCHEMA:
        raise AuthorityError('SCHEMA_INVALID')
    operation = _text(out['operation'], 'OPERATION_INVALID', 64)
    if operation not in OPERATIONS:
        raise AuthorityError('OPERATION_DENIED')
    repository = _text(out['repository'], 'REPOSITORY_INVALID', 201, _REPO, True)
    revision = _int(out['controlRevision'], 'CONTROL_REVISION_INVALID')
    request_id = _rid(out['requestId'])
    peer_id = _text(out['peerId'], 'PEER_ID_INVALID', 128, _PEER)
    payload = _payload(operation, out['payload'])
    digest = _text(out['requestDigest'], 'REQUEST_DIGEST_INVALID', 64, _HEX64, True)
    signature = _text(out['signature'], 'SIGNATURE_INVALID', 4096)
    unsigned = {'schema': SCHEMA, 'operation': operation, 'requestId': request_id, 'peerId': peer_id, 'repository': repository, 'controlRevision': revision, 'payload': payload}
    if canonical_digest(unsigned) != digest:
        raise AuthorityError('REQUEST_DIGEST_MISMATCH')
    return {**unsigned, 'requestDigest': digest, 'signature': signature}


def build_request(*, operation, request_id, peer_id, repository, control_revision, payload, signature):
    operation = _text(operation, 'OPERATION_INVALID', 64)
    if operation not in OPERATIONS:
        raise AuthorityError('OPERATION_DENIED')
    normalized = {
        'schema': SCHEMA,
        'operation': operation,
        'requestId': _rid(request_id),
        'peerId': _text(peer_id, 'PEER_ID_INVALID', 128, _PEER),
        'repository': _text(repository, 'REPOSITORY_INVALID', 201, _REPO, True),
        'controlRevision': _int(control_revision, 'CONTROL_REVISION_INVALID'),
        'payload': _payload(operation, payload),
    }
    return unsigned_request({**normalized, 'requestDigest': canonical_digest(normalized), 'signature': _text(signature, 'SIGNATURE_INVALID', 4096)})


def assert_public_result(value, private_values=()):
    clean = _jsonable(value); texts = []
    for item in private_values:
        if isinstance(item, bytes):
            try:
                texts.append(item.decode())
            except UnicodeDecodeError:
                pass
        elif isinstance(item, str):
            texts.append(item)

    def walk(node):
        if isinstance(node, Mapping):
            for key, value in node.items():
                if _SECRET_KEY.search(str(key)):
                    raise AuthorityError('SECRET_FIELD_DENIED')
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str):
            for secret in texts:
                if secret and secret in node:
                    raise AuthorityError('SECRET_VALUE_DENIED')

    walk(clean)
    return clean
