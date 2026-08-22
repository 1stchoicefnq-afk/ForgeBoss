'use strict';

function classify(packet) {
  const text = JSON.stringify(packet || {}).toLowerCase();

  let domain = 'general';
  if (/postgres|postgresql|sql|database|serializable|40001|40p01|migration/.test(text)) domain = 'database';
  else if (/auth|authentication|authorization|oidc|oauth|permission|session|identity/.test(text)) domain = 'identity';
  else if (/openai|llm|agent|prompt|model|orchestration/.test(text)) domain = 'ai';
  else if (/react|frontend|css|html|browser|ui|accessibility/.test(text)) domain = 'frontend';
  else if (/docker|ci|workflow|github actions|powershell|build pipeline/.test(text)) domain = 'devops';

  const risk =
    /auth|permission|payment|security|migration|database|production|secret/.test(text)
      ? 'HIGH'
      : /architecture|multi-agent|cross-functional|release/.test(text)
      ? 'MEDIUM'
      : 'LOW';

  const contextCount = (packet?.context_files || []).length;
  const writeCount = (packet?.allowed_files || []).length;
  const complexity =
    contextCount > 30 || writeCount > 12 || /architecture|multi-agent|cross-functional|end-to-end/.test(text)
      ? 'HIGH'
      : 'MEDIUM';

  return { domain, risk, complexity };
}

function route(packet, config = {}) {
  const classification = classify(packet);
  const localReady = Boolean(config?.local?.enabled && config?.local?.endpoint);
  const requiresStrong =
    classification.risk === 'HIGH' || classification.complexity === 'HIGH';

  const provider = (!requiresStrong && localReady) ? 'local' : 'openai';

  return {
    schema: 1,
    classification,
    provider,
    fallback: provider === 'local' ? 'openai' : null,
    reason:
      provider === 'local'
        ? 'Low-risk bounded task and local provider is configured.'
        : 'Strong-model escalation required, or local provider is unavailable.',
    authority:
      'Routing only. This result cannot alter SiteBoss packet scope, permissions, leases, branch authority, review independence, merge, or deployment authority.'
  };
}

module.exports = { classify, route };
