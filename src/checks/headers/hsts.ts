import type { Check, FindingInput } from '../../types.js';

/** Six months. Below this the browser's protection window is short enough to be worth flagging. */
const RECOMMENDED_MAX_AGE = 15_552_000;
const MINIMAL_MAX_AGE = 86_400;

const REFERENCE = {
  title: 'RFC 6797: HTTP Strict Transport Security',
  url: 'https://datatracker.ietf.org/doc/html/rfc6797',
};

export const hstsCheck: Check = {
  id: 'headers/hsts',
  title: 'HTTP Strict Transport Security',
  category: 'headers',
  description: 'Checks for HSTS and the strength of its max-age and scope.',
  requires: ['baseline'],

  run(ctx) {
    // Browsers ignore the header over plaintext, so reporting on it there would
    // be noise. Whether http is served at all is the transport check's job.
    if (!ctx.target.isHttps) return [];

    const { response } = ctx.evidence('baseline');
    const header = response.headers.get('strict-transport-security');

    if (header === undefined) {
      return [
        {
          id: 'headers/hsts/missing',
          title: 'No Strict-Transport-Security header',
          severity: 'medium',
          confidence: 'firm',
          summary:
            'The origin does not instruct browsers to use https exclusively. A first visit ' +
            'typed as a bare hostname, or any link written as http, is sent in plaintext and ' +
            'can be intercepted and downgraded before the redirect to https is ever seen.',
          evidence: [{ kind: 'missing-header', name: 'strict-transport-security' }],
          remediation:
            'Send Strict-Transport-Security: max-age=31536000; includeSubDomains on https ' +
            'responses. Roll the max-age up gradually, and confirm every subdomain serves ' +
            'https before adding includeSubDomains.',
          references: [REFERENCE],
        },
      ];
    }

    const findings: FindingInput[] = [];
    const maxAge = parseMaxAge(header);
    const evidence = [
      { kind: 'header' as const, name: 'strict-transport-security', value: header },
    ];

    if (maxAge === undefined) {
      findings.push({
        id: 'headers/hsts/invalid',
        title: 'Strict-Transport-Security has no valid max-age',
        severity: 'medium',
        confidence: 'firm',
        summary:
          'max-age is required. Without a parseable value the entire header is ignored, so ' +
          'the origin has no HSTS protection despite appearing to send it.',
        evidence,
        remediation: 'Set an explicit max-age in seconds, for example max-age=31536000.',
        references: [REFERENCE],
      });
    } else if (maxAge === 0) {
      findings.push({
        id: 'headers/hsts/disabled',
        title: 'Strict-Transport-Security is disabled by max-age=0',
        severity: 'medium',
        confidence: 'confirmed',
        summary:
          'max-age=0 instructs browsers to forget any existing HSTS entry for this host. ' +
          'This is the correct way to retire HSTS, and a mistake if it is not intentional.',
        evidence,
        remediation:
          'If HSTS is being deliberately withdrawn, no action is needed. Otherwise restore a ' +
          'positive max-age.',
        references: [REFERENCE],
      });
    } else if (maxAge < MINIMAL_MAX_AGE) {
      findings.push({
        id: 'headers/hsts/short-max-age',
        title: `Strict-Transport-Security max-age is ${maxAge} seconds`,
        severity: 'low',
        confidence: 'firm',
        summary:
          'The policy expires in under a day. A client that has not visited recently is ' +
          'unprotected, which removes most of the value of the header.',
        evidence,
        remediation: `Raise max-age to at least ${RECOMMENDED_MAX_AGE} (six months).`,
        references: [REFERENCE],
      });
    } else if (maxAge < RECOMMENDED_MAX_AGE) {
      findings.push({
        id: 'headers/hsts/low-max-age',
        title: `Strict-Transport-Security max-age is below six months`,
        severity: 'info',
        confidence: 'firm',
        summary:
          `max-age is ${maxAge} seconds. This is a working policy, but a longer window is ` +
          'usual once the deployment has been stable, and preload submission requires a year.',
        evidence,
        remediation: 'Raise max-age to 31536000 once you are confident https will not be withdrawn.',
        references: [REFERENCE],
      });
    }

    if (maxAge !== undefined && maxAge > 0 && !/;\s*includeSubDomains/i.test(header)) {
      findings.push({
        id: 'headers/hsts/no-subdomains',
        title: 'Strict-Transport-Security does not cover subdomains',
        severity: 'low',
        confidence: 'firm',
        summary:
          'Without includeSubDomains the policy applies only to this exact host. A subdomain ' +
          'reachable over plaintext can be used to set cookies for the parent domain, which ' +
          'undermines the protection on the host that does have HSTS.',
        evidence,
        remediation:
          'Add includeSubDomains once every subdomain, including internal and legacy ones, ' +
          'is confirmed to serve https.',
        references: [REFERENCE],
      });
    }

    return findings;
  },
};

/** Returns undefined when max-age is absent or not a valid non-negative integer. */
function parseMaxAge(header: string): number | undefined {
  const match = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?/i.exec(header);
  if (match?.[1] === undefined) return undefined;
  const value = Number(match[1]);
  return Number.isSafeInteger(value) ? value : undefined;
}
