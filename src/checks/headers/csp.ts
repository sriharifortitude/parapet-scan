import {
  effectiveSources,
  hasKeyword,
  hasNonceOrHash,
  hasStrictDynamic,
  parsePolicies,
  permitsAnyOrigin,
  type CspPolicy,
} from '../../core/csp.js';
import type { Check, FindingInput } from '../../types.js';

const MDN_CSP = {
  title: 'MDN: Content-Security-Policy',
  url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
};
const CSP_CHEAT_SHEET = {
  title: 'OWASP Content Security Policy Cheat Sheet',
  url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
};

export const cspCheck: Check = {
  id: 'headers/csp',
  title: 'Content-Security-Policy',
  category: 'headers',
  description:
    'Evaluates the enforced Content-Security-Policy for script execution weaknesses ' +
    'and for the directives that do not inherit from default-src.',
  requires: ['baseline'],

  run(ctx) {
    const { response } = ctx.evidence('baseline');
    const enforced = response.headers.getAll('content-security-policy');
    const reportOnly = response.headers.getAll('content-security-policy-report-only');

    if (enforced.length === 0) {
      return [
        reportOnly.length > 0
          ? {
              id: 'headers/csp/report-only',
              title: 'Content-Security-Policy is report-only',
              severity: 'low',
              confidence: 'firm',
              summary:
                'A policy is present but only as Content-Security-Policy-Report-Only, which ' +
                'reports violations without blocking them. It provides no mitigation until ' +
                'it is served as an enforcing header.',
              evidence: [
                { kind: 'header', name: 'content-security-policy-report-only', value: reportOnly[0] ?? '' },
                { kind: 'missing-header', name: 'content-security-policy' },
              ],
              remediation:
                'Once the report stream is clean, serve the same policy in the ' +
                'Content-Security-Policy header. Both may be sent together during a rollout.',
              references: [MDN_CSP],
            }
          : {
              id: 'headers/csp/missing',
              title: 'No Content-Security-Policy',
              severity: 'medium',
              confidence: 'firm',
              summary:
                'The response carries no Content-Security-Policy. An injection flaw anywhere ' +
                'in the application therefore has no second line of defence: injected script ' +
                'runs with the full privileges of the origin.',
              evidence: [{ kind: 'missing-header', name: 'content-security-policy' }],
              remediation:
                "Introduce a nonce-based policy, starting with default-src 'self' and " +
                "object-src 'none'. Deploy it in report-only mode first to find violations.",
              references: [MDN_CSP, CSP_CHEAT_SHEET],
            },
      ];
    }

    const policies = parsePolicies(enforced);
    const findings: FindingInput[] = [];

    // Multiple policies are enforced as an intersection, so a weakness only
    // matters when every policy permits it.
    if (policies.every((policy) => scriptSrcAllowsInline(policy))) {
      findings.push({
        id: 'headers/csp/unsafe-inline-script',
        title: "Script sources permit 'unsafe-inline'",
        severity: 'medium',
        confidence: 'firm',
        summary:
          "The effective script source list contains 'unsafe-inline' without a nonce or " +
          'hash to supersede it. Browsers that support CSP Level 2 or later ignore ' +
          "'unsafe-inline' only when a nonce or hash is also present, so injected inline " +
          'script executes and the policy provides no XSS mitigation.',
        evidence: enforced.map((value) => ({
          kind: 'header' as const,
          name: 'content-security-policy',
          value,
        })),
        remediation:
          "Remove 'unsafe-inline' and attach a per-response nonce to legitimate inline " +
          "scripts, or move them to files. Adding 'strict-dynamic' alongside the nonce lets " +
          'trusted scripts load their own dependencies without an allowlist.',
        references: [CSP_CHEAT_SHEET],
      });
    }

    if (policies.every((policy) => hasKeyword(effectiveSources(policy, 'script-src'), 'unsafe-eval'))) {
      findings.push({
        id: 'headers/csp/unsafe-eval',
        title: "Script sources permit 'unsafe-eval'",
        severity: 'low',
        confidence: 'firm',
        summary:
          "'unsafe-eval' re-enables eval, new Function and string-argument timers. It widens " +
          'the set of injection sinks that reach script execution, though on its own it does ' +
          'not permit arbitrary inline script.',
        evidence: enforced.map((value) => ({
          kind: 'header' as const,
          name: 'content-security-policy',
          value,
        })),
        remediation:
          "Identify the dependency requiring eval -- most often a templating or schema " +
          "library -- and replace it or switch to its CSP-compatible build, then drop the keyword.",
        references: [MDN_CSP],
      });
    }

    if (policies.every((policy) => scriptSrcIsWildcard(policy))) {
      findings.push({
        id: 'headers/csp/wildcard-script-src',
        title: 'Script sources allow any origin',
        severity: 'medium',
        confidence: 'firm',
        summary:
          'The effective script source list contains a wildcard or a bare scheme, so script ' +
          'may be loaded from any host. The policy still blocks inline script but places no ' +
          'restriction on where external script comes from.',
        evidence: enforced.map((value) => ({
          kind: 'header' as const,
          name: 'content-security-policy',
          value,
        })),
        remediation:
          'Replace the wildcard with the specific origins the application loads script from, ' +
          "or adopt a nonce with 'strict-dynamic', which makes host allowlisting unnecessary.",
        references: [CSP_CHEAT_SHEET],
      });
    }

    // object-src and base-uri fall back to default-src, but a policy that sets a
    // permissive default-src leaves both open, so they are checked explicitly.
    if (policies.every((policy) => permitsAnyOrigin(effectiveSources(policy, 'object-src')) ||
        effectiveSources(policy, 'object-src') === undefined)) {
      findings.push({
        id: 'headers/csp/object-src-unrestricted',
        title: 'object-src is unrestricted',
        severity: 'low',
        confidence: 'firm',
        summary:
          'Plugin content is not restricted. Legacy plugin embeds are a script execution ' +
          'vector that the script-src directive does not cover.',
        evidence: enforced.map((value) => ({
          kind: 'header' as const,
          name: 'content-security-policy',
          value,
        })),
        remediation: "Add object-src 'none' unless the application genuinely embeds plugin content.",
        references: [CSP_CHEAT_SHEET],
      });
    }

    if (policies.every((policy) => policy.directives.get('base-uri') === undefined)) {
      findings.push({
        id: 'headers/csp/base-uri-missing',
        title: 'base-uri is not set',
        severity: 'low',
        confidence: 'firm',
        summary:
          'base-uri does not inherit from default-src. Without it, an injected <base> tag can ' +
          'repoint every relative script and form URL on the page to an attacker-controlled ' +
          'origin, which also defeats a nonce-based policy.',
        evidence: enforced.map((value) => ({
          kind: 'header' as const,
          name: 'content-security-policy',
          value,
        })),
        remediation: "Add base-uri 'self' (or 'none' if the application sets no base element).",
        references: [CSP_CHEAT_SHEET],
      });
    }

    return findings;
  },
};

function scriptSrcAllowsInline(policy: CspPolicy): boolean {
  const sources = effectiveSources(policy, 'script-src');
  if (sources === undefined) return false;
  if (!hasKeyword(sources, 'unsafe-inline')) return false;
  // A nonce or hash in the same list makes browsers ignore 'unsafe-inline'.
  return !hasNonceOrHash(sources);
}

function scriptSrcIsWildcard(policy: CspPolicy): boolean {
  const sources = effectiveSources(policy, 'script-src');
  if (sources === undefined) return false;
  // strict-dynamic discards host expressions entirely, wildcard included.
  if (hasStrictDynamic(sources)) return false;
  return permitsAnyOrigin(sources);
}
