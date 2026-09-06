import type { Check, CorsProbe, Evidence, FindingInput } from '../../types.js';

const REFERENCE = {
  title: 'PortSwigger: Exploiting CORS misconfigurations',
  url: 'https://portswigger.net/web-security/cors',
};
const MDN = {
  title: 'MDN: Cross-Origin Resource Sharing',
  url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
};

/**
 * Severity here hinges on Access-Control-Allow-Credentials. Reflecting an
 * arbitrary origin without credentials exposes only what an unauthenticated
 * client could already fetch. Reflecting it *with* credentials lets any site a
 * logged-in user visits read authenticated responses from this origin, which is
 * a cross-origin data disclosure rather than a hardening gap.
 */
export const corsMisconfigurationCheck: Check = {
  id: 'cors/misconfiguration',
  title: 'CORS policy',
  category: 'cors',
  description: 'Evaluates how the origin responds to untrusted Origin headers.',
  requires: ['cors'],

  run(ctx) {
    const { probes } = ctx.evidence('cors');
    const findings: FindingInput[] = [];

    for (const probe of probes) {
      const allowOrigin = probe.allowOrigin;
      if (allowOrigin === undefined) continue;

      const credentialed = probe.allowCredentials?.trim().toLowerCase() === 'true';
      const reflected = allowOrigin === probe.sentOrigin;
      const wildcard = allowOrigin.trim() === '*';

      if (wildcard && credentialed) {
        findings.push({
          id: 'cors/misconfiguration/wildcard-with-credentials',
          title: 'CORS sends a wildcard origin together with credentials',
          severity: 'low',
          confidence: 'confirmed',
          summary:
            'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: ' +
            'true is an invalid combination that browsers reject, so cross-origin credentialed ' +
            'requests fail. It signals that the CORS policy is not doing what its author ' +
            'intended, and is often corrected by reflecting the Origin instead -- which would ' +
            'be considerably worse.',
          evidence: describe(probe),
          remediation:
            'Decide which case is intended. For public data, drop ' +
            'Access-Control-Allow-Credentials. For authenticated cross-origin access, reflect ' +
            'only origins on an explicit allowlist.',
          references: [MDN],
        });
        continue;
      }

      if (!reflected && !wildcard) continue;

      if (probe.label === 'null') {
        findings.push({
          id: 'cors/misconfiguration/null-origin',
          title: `The null origin is allowed${credentialed ? ' with credentials' : ''}`,
          severity: credentialed ? 'high' : 'medium',
          confidence: 'confirmed',
          summary:
            'A null Origin is what sandboxed iframes, redirects and data: documents send. It ' +
            'is trivially produced from any attacker-controlled page, so allowlisting it is ' +
            'equivalent to allowing any origin' +
            (credentialed
              ? ' -- and because credentials are permitted, authenticated responses can be read.'
              : '.'),
          evidence: describe(probe),
          remediation:
            'Remove null from the allowlist. There is no configuration in which trusting it ' +
            'is safer than naming the real origins.',
          references: [REFERENCE],
        });
        continue;
      }

      if (probe.label === 'subdomain-suffix') {
        findings.push({
          id: 'cors/misconfiguration/allowlist-bypass',
          title: 'CORS allowlist can be bypassed by a lookalike origin',
          severity: credentialed ? 'high' : 'medium',
          confidence: 'confirmed',
          summary:
            `The origin ${probe.sentOrigin} was accepted. It is not related to the target -- ` +
            'the match succeeded because the allowlist is comparing with a prefix, suffix or ' +
            'substring test rather than an exact comparison. Any domain the attacker registers ' +
            'can be shaped to pass the same test.',
          evidence: describe(probe),
          remediation:
            'Compare the Origin header against a fixed set of permitted origins with an exact ' +
            'string equality test. Never build the comparison out of startsWith, endsWith, ' +
            'includes or a regular expression with an unanchored hostname.',
          references: [REFERENCE],
        });
        continue;
      }

      findings.push({
        id:
          probe.label === 'preflight'
            ? 'cors/misconfiguration/preflight-reflects-origin'
            : 'cors/misconfiguration/reflects-origin',
        title: `Arbitrary origins are allowed${credentialed ? ' with credentials' : ''}`,
        severity: credentialed ? 'high' : 'medium',
        confidence: 'confirmed',
        summary: credentialed
          ? 'The origin reflects any Origin it is given and permits credentials. Any website ' +
            'a logged-in user visits can issue a request to this origin with their cookies ' +
            'attached and read the response, which makes every authenticated endpoint here ' +
            'readable cross-origin.'
          : 'The origin reflects any Origin it is given. Credentials are not permitted, so ' +
            'this exposes only what an unauthenticated client could already retrieve -- but ' +
            'it also removes CORS as a control if authentication is added later, and it can ' +
            'be used to read responses that are gated by network position rather than by ' +
            'credentials.',
        evidence: describe(probe),
        remediation: credentialed
          ? 'Replace the reflection with an exact-match allowlist, and confirm that every ' +
            'origin on it needs credentialed access.'
          : 'Reflect only origins on an explicit allowlist, even where credentials are not used.',
        references: [REFERENCE],
      });
    }

    return dedupe(findings);
  },
};

function describe(probe: CorsProbe): Evidence[] {
  const responseHeaders: Record<string, string> = {};
  if (probe.allowOrigin !== undefined) {
    responseHeaders['access-control-allow-origin'] = probe.allowOrigin;
  }
  if (probe.allowCredentials !== undefined) {
    responseHeaders['access-control-allow-credentials'] = probe.allowCredentials;
  }
  if (probe.allowMethods !== undefined) {
    responseHeaders['access-control-allow-methods'] = probe.allowMethods;
  }
  if (probe.allowHeaders !== undefined) {
    responseHeaders['access-control-allow-headers'] = probe.allowHeaders;
  }

  return [
    {
      kind: 'exchange',
      method: probe.label === 'preflight' ? 'OPTIONS' : 'GET',
      url: '(scanned document)',
      status: probe.status,
      requestHeaders: { origin: probe.sentOrigin },
      responseHeaders,
    },
  ];
}

/** The arbitrary-origin and preflight probes often produce the same verdict. */
function dedupe(findings: readonly FindingInput[]): FindingInput[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    if (seen.has(finding.id)) return false;
    seen.add(finding.id);
    return true;
  });
}
