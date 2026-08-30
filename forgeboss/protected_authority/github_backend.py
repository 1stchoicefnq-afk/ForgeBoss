from __future__ import annotations

import base64, json, re, time, urllib.error, urllib.parse, urllib.request
from typing import Any, Mapping

from .protocol import AuthorityError, canonical_digest

_TOKEN_PERMISSIONS = {
    'read_github_control': {'contents': 'read', 'pull_requests': 'read'},
    'publish_report_comment': {'issues': 'write'},
    'publish_reviewed_draft_pr': {'contents': 'read', 'pull_requests': 'write'},
}
_OID = re.compile(r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')
_REF = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,199})$')


def _authority_oid(value, code='CONTROL_OBJECT_INVALID') -> str:
    if not isinstance(value, str):
        raise AuthorityError(code)
    value = value.lower()
    if not _OID.fullmatch(value):
        raise AuthorityError(code)
    return value


def _authority_ref(value, code='CONTROL_REF_INVALID') -> str:
    if not isinstance(value, str) or not value or value != value.strip() or not _REF.fullmatch(value):
        raise AuthorityError(code)
    parts = value.split('/')
    if any(not p or p in {'.', '..'} or p.startswith('.') or p.endswith('.lock') for p in parts):
        raise AuthorityError(code)
    if '@{' in value or '\\' in value or value.endswith('.'):
        raise AuthorityError(code)
    return value


def _pr_summary(pr: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(pr, Mapping):
        raise AuthorityError('CONTROL_PR_INVALID')
    head = pr.get('head'); base = pr.get('base')
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        raise AuthorityError('CONTROL_PR_INVALID')
    head_repo = head.get('repo')
    if not isinstance(head_repo, Mapping):
        raise AuthorityError('CONTROL_PR_INVALID')
    number = pr.get('number')
    if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
        raise AuthorityError('CONTROL_PR_INVALID')
    state = pr.get('state')
    if not isinstance(state, str) or not state:
        raise AuthorityError('CONTROL_PR_INVALID')
    title = pr.get('title')
    if title is None:
        title = ''
    if not isinstance(title, str):
        raise AuthorityError('CONTROL_PR_INVALID')
    updated = pr.get('updated_at')
    if updated is None:
        updated = ''
    if not isinstance(updated, str):
        raise AuthorityError('CONTROL_PR_INVALID')
    repo = head_repo.get('full_name')
    if not isinstance(repo, str) or not repo:
        raise AuthorityError('CONTROL_PR_INVALID')
    return {
        'number': number,
        'state': state,
        'title': title,
        'head_sha': _authority_oid(head.get('sha')),
        'head_ref': _authority_ref(head.get('ref')),
        'base_sha': _authority_oid(base.get('sha')),
        'base_ref': _authority_ref(base.get('ref')),
        'repo': repo,
        'updated_at': updated,
    }


def _looks_like_repair_child(pr: Mapping[str, Any], parent_number: int) -> bool:
    head = pr.get('head') if isinstance(pr, Mapping) else None
    head_ref = head.get('ref', '') if isinstance(head, Mapping) else ''
    title = pr.get('title', '') if isinstance(pr, Mapping) else ''
    body = pr.get('body', '') if isinstance(pr, Mapping) else ''
    head_ref = head_ref if isinstance(head_ref, str) else ''
    title = title if isinstance(title, str) else ''
    body = body if isinstance(body, str) else ''
    prefix = f'autopilot/repair-pr{parent_number}-'
    if head_ref.casefold().startswith(prefix.casefold()):
        return True
    ref_pat = re.compile(rf'#{parent_number}\b', re.I)
    if re.search(r'\brepair\b', title, re.I) and (ref_pat.search(title) or ref_pat.search(body)):
        return True
    if re.search(rf'(parent|target|integration)\s+PR\s*:?\s*#{parent_number}\b', body, re.I):
        return True
    return False


class GitHubAppBackend:
    def __init__(self, *, app_id: int, installation_id: int, api_base: str = 'https://api.github.com'):
        if not isinstance(app_id, int) or app_id <= 0 or not isinstance(installation_id, int) or installation_id <= 0:
            raise AuthorityError('GITHUB_APP_CONFIG_INVALID')
        if api_base != 'https://api.github.com':
            raise AuthorityError('GITHUB_API_BASE_DENIED')
        self.app_id = app_id; self.installation_id = installation_id; self.api_base = api_base

    def _jwt(self, pem: bytes) -> str:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            now = int(time.time()); header = {'alg': 'RS256', 'typ': 'JWT'}; payload = {'iat': now - 30, 'exp': now + 540, 'iss': str(self.app_id)}
            enc = lambda x: base64.urlsafe_b64encode(json.dumps(x, separators=(',', ':'), sort_keys=True).encode()).rstrip(b'=')
            unsigned = enc(header) + b'.' + enc(payload)
            key = serialization.load_pem_private_key(pem, password=None)
            sig = key.sign(unsigned, padding.PKCS1v15(), hashes.SHA256())
            return (unsigned + b'.' + base64.urlsafe_b64encode(sig).rstrip(b'=')).decode()
        except Exception as exc:
            raise AuthorityError('GITHUB_APP_KEY_INVALID') from exc

    def _request(self, method: str, path: str, *, token: str | None = None, body: Mapping[str, Any] | None = None) -> Any:
        if not path.startswith('/') or '://' in path or '..' in path:
            raise AuthorityError('GITHUB_PATH_DENIED')
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'ForgeBossAuthority'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        data = None if body is None else json.dumps(body, separators=(',', ':')).encode()
        req = urllib.request.Request(self.api_base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode())
        except (urllib.error.URLError, ValueError) as exc:
            raise AuthorityError('GITHUB_OPERATION_FAILED') from exc

    def _token(self, pem: bytes, repository: str, operation: str) -> str:
        perms = _TOKEN_PERMISSIONS.get(operation)
        if perms is None:
            raise AuthorityError('GITHUB_TOKEN_SCOPE_DENIED')
        owner, sep, name = repository.partition('/')
        if not sep or not owner or not name:
            raise AuthorityError('GITHUB_REPOSITORY_INVALID')
        body = {'repositories': [name], 'permissions': dict(perms)}
        obj = self._request('POST', f'/app/installations/{self.installation_id}/access_tokens', token=self._jwt(pem), body=body)
        token = obj.get('token') if isinstance(obj, dict) else None
        if not isinstance(token, str) or not token:
            raise AuthorityError('GITHUB_TOKEN_INVALID')
        return token

    @staticmethod
    def _repo_path(repository: str) -> str:
        return '/repos/' + repository

    def _open_prs_on_base(self, repository: str, base_ref: str, token: str) -> list[Mapping[str, Any]]:
        encoded = urllib.parse.quote(base_ref, safe='')
        out = []
        for page in range(1, 6):
            path = self._repo_path(repository) + f'/pulls?state=open&base={encoded}&per_page=100&sort=updated&direction=desc&page={page}'
            batch = self._request('GET', path, token=token)
            if not isinstance(batch, list):
                raise AuthorityError('CONTROL_DISCOVERY_INVALID')
            if len(batch) > 100:
                raise AuthorityError('CONTROL_DISCOVERY_INVALID')
            out.extend(batch)
            if len(batch) < 100:
                return out
        raise AuthorityError('CONTROL_DISCOVERY_BOUNDS')

    def read_github_control(self, *, repository: str, control_revision: int, payload: Mapping[str, Any], private_key: bytes) -> Any:
        token = self._token(private_key, repository, 'read_github_control')
        root_number = int(payload['rootPr']); preferred_number = int(payload['preferredRepairPr'])
        root_raw = self._request('GET', self._repo_path(repository) + f'/pulls/{root_number}', token=token)
        root = _pr_summary(root_raw)
        if root['number'] != root_number or root['state'] != 'open':
            raise AuthorityError('CONTROL_ROOT_INVALID')
        if root['repo'].casefold() != repository.casefold():
            raise AuthorityError('CONTROL_ROOT_REPOSITORY_MISMATCH')

        preferred_raw = None; preferred = None
        if preferred_number:
            try:
                preferred_raw = self._request('GET', self._repo_path(repository) + f'/pulls/{preferred_number}', token=token)
                preferred = _pr_summary(preferred_raw)
            except AuthorityError:
                preferred_raw = None; preferred = None

        discovered_raw = self._open_prs_on_base(repository, root['head_ref'], token)
        exact_raw = []
        exact = []
        for pr in discovered_raw:
            try:
                summary = _pr_summary(pr)
            except AuthorityError:
                raise AuthorityError('CONTROL_DISCOVERY_INVALID')
            if summary['state'] != 'open':
                continue
            if summary['repo'].casefold() != repository.casefold():
                continue
            if summary['base_sha'] != root['head_sha'] or summary['base_ref'] != root['head_ref']:
                continue
            if not _looks_like_repair_child(pr, root_number):
                continue
            exact_raw.append(pr); exact.append(summary)

        selected = None; reason = None
        if preferred is not None:
            if (
                preferred['number'] == preferred_number and preferred['state'] == 'open'
                and preferred['repo'].casefold() == repository.casefold()
                and preferred['base_sha'] == root['head_sha']
                and preferred['base_ref'] == root['head_ref']
            ):
                selected = preferred; reason = 'preferred-exact'
        if selected is None:
            if len(exact) == 1:
                selected = exact[0]; reason = 'discovered-exact'
            elif len(exact) > 1:
                raise AuthorityError('CONTROL_REPAIR_AMBIGUOUS')

        owner, _, repo_name = repository.partition('/')
        result = {
            'schema': 2,
            'controlRevision': control_revision,
            'owner': owner,
            'repo': repo_name,
            'root_pr': {k: root[k] for k in ('number', 'state', 'head_sha', 'head_ref', 'base_sha', 'base_ref')},
            'repair_pr': selected,
            'preferred_repair_pr': preferred,
            'exact_repair_candidates': exact,
        }
        if selected is None:
            result['binding'] = {
                'status': 'NO_CURRENT_EXACT_REPAIR_CHILD',
                'repair_base_equals_root_head': False,
                'repository': repository,
                'stale_preferred': preferred_number > 0,
                'preferred_state': '' if preferred is None else preferred['state'],
                'preferred_base_sha': '' if preferred is None else preferred['base_sha'],
            }
        else:
            result['binding'] = {
                'status': 'EXACT_REPAIR_CHILD_BOUND',
                'repair_base_equals_root_head': True,
                'repository': repository,
                'selection_reason': reason,
            }
        return result

    def publish_report_comment(self, *, repository: str, control_revision: int, payload: Mapping[str, Any], private_key: bytes) -> Any:
        token = self._token(private_key, repository, 'publish_report_comment')
        obj = self._request('POST', self._repo_path(repository) + f"/issues/{int(payload['issue'])}/comments", token=token, body={'body': payload['body']})
        return {'repository': repository, 'controlRevision': control_revision, 'commentId': obj.get('id'), 'reportDigest': payload['reportDigest']}

    def publish_reviewed_draft_pr(self, *, repository: str, control_revision: int, payload: Mapping[str, Any], private_key: bytes) -> Any:
        token = self._token(private_key, repository, 'publish_reviewed_draft_pr'); base_ref = payload['baseRef']; head_ref = payload['headRef']
        base = self._request('GET', self._repo_path(repository) + f'/git/ref/heads/{base_ref}', token=token)
        head = self._request('GET', self._repo_path(repository) + f'/git/ref/heads/{head_ref}', token=token)
        if base.get('object', {}).get('sha', '').lower() != payload['baseSha'] or head.get('object', {}).get('sha', '').lower() != payload['headSha']:
            raise AuthorityError('PR_REF_SHA_MISMATCH')
        obj = self._request('POST', self._repo_path(repository) + '/pulls', token=token, body={'title': payload['title'], 'body': payload['body'], 'head': head_ref, 'base': base_ref, 'draft': True})
        return {'repository': repository, 'controlRevision': control_revision, 'prNumber': obj.get('number'), 'draft': obj.get('draft') is True, 'headSha': payload['headSha'], 'baseSha': payload['baseSha'], 'reviewDigest': payload['reviewDigest']}

    def verify_launch_authority(self, *, repository: str, control_revision: int, payload: Mapping[str, Any], trust_root: bytes) -> Any:
        env = payload['envelope']; signature = env.get('signature'); signed = env.get('signed')
        if not isinstance(signature, str) or not isinstance(signed, Mapping):
            raise AuthorityError('LAUNCH_ENVELOPE_INVALID')
        if canonical_digest(signed) != payload['envelopeDigest']:
            raise AuthorityError('ENVELOPE_DIGEST_MISMATCH')
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(trust_root, validate=True))
            key.verify(base64.b64decode(signature, validate=True), bytes.fromhex(payload['envelopeDigest']))
        except Exception as exc:
            raise AuthorityError('LAUNCH_AUTHORITY_INVALID') from exc
        return {'repository': repository, 'controlRevision': control_revision, 'verified': True, 'envelopeDigest': payload['envelopeDigest']}
