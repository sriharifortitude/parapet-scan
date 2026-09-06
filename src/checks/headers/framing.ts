import { parsePolicies } from '../../core/csp.js';
import type { Check, Evidence, FindingInput } from '../../types.js';

const REFERENCE = {
  title: 'OWASP Clickjacking Defense Cheat Sheet',
  url: 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
};

/**
 * Framing protection can come from either CSP frame-ancestors or the older
 * X-Frame-Options, and frame-ancestors wins wherever both are understood. The
 * two are therefore evaluated together rather than as separate header checks --
 * flagging a missing X-Frame-Options on an origin that sets frame-ancestors
 * would be a false positive.
 */
export const framingCheck: Check = {
  id: 'headers/framing',
  title: 'Clickjacking protection',
  category: 'headers',
  description: 'Checks CSP frame-ancestors and X-Frame-Options for framing restrictions.',
  requires: ['baseline'],

  run(ctx) {
    const { response } = ctx.evidence('baseline');
    const policies = parsePolicies(response.headers.getAll('content-security-policy'));
    const frameAncestors = policies
      .map((policy) => policy.directives.get('frame-ancestors'))
      .find((sources) => sources !== undefined);
    const xfo = response.headers.get('x-frame-options');

    const findings: FindingInput[] = [];
    const evidence: Evidence[] = [];
    if (frameAncestors !== undefined) {
      evidence.push({
        kind: 'header',
        name: 'content-security-policy',
        value: `frame-ancestors ${frameAncestors.join(' ')}`,
      });
    }
    if (xfo !== undefined) {
      evidence.push({ kind: 'header', name: 'x-frame-options', value: xfo });
    }

    if (frameAncestors !== undefined) {
      if (frameAncestors.includes('*')) {
        findings.push({
          id: 'headers/framing/ancestors-wildcard',
          title: 'frame-ancestors allows any origin',
          severity: 'medium',
          confidence: 'firm',
          summary:
            'frame-ancestors * permits any site to embed this page in a frame, which is ' +
            'equivalent to setting no framing restriction at all.',
          evidence,
          remediation:
            "Restrict frame-ancestors to 'none', 'self', or the specific origins that are " +
            'meant to embed the application.',
          references: [REFERENCE],
        });
      }
      // A valid frame-ancestors supersedes X-Frame-Options; nothing further to report.
      return findings;
    }

    const normalisedXfo = xfo?.trim().toUpperCase();

    if (normalisedXfo === undefined) {
      return [
        {
          id: 'headers/framing/missing',
          title: 'No clickjacking protection',
          severity: 'medium',
          confidence: 'firm',
          summary:
            'Neither CSP frame-ancestors nor X-Frame-Options is set, so any site may embed ' +
            'this page in a frame and overlay it. Where the page performs a state-changing ' +
            'action on click, that action can be induced from a third-party site.',
          evidence: [
            { kind: 'missing-header', name: 'x-frame-options' },
            { kind: 'note', text: 'No frame-ancestors directive in Content-Security-Policy.' },
          ],
          remediation:
            "Add frame-ancestors 'none' to the CSP (or 'self' if the application frames its " +
            'own pages). Send X-Frame-Options: DENY alongside it only if you still support ' +
            'browsers that predate CSP Level 2.',
          references: [REFERENCE],
        },
      ];
    }

    if (normalisedXfo.startsWith('ALLOW-FROM')) {
      findings.push({
        id: 'headers/framing/allow-from-obsolete',
        title: 'X-Frame-Options uses the obsolete ALLOW-FROM directive',
        severity: 'medium',
        confidence: 'firm',
        summary:
          'No current browser implements ALLOW-FROM. Browsers that do not recognise the value ' +
          'ignore the header entirely, so the page is framable by any origin.',
        evidence,
        remediation:
          'Replace it with a CSP frame-ancestors directive naming the permitted origins.',
        references: [REFERENCE],
      });
    } else if (normalisedXfo !== 'DENY' && normalisedXfo !== 'SAMEORIGIN') {
      findings.push({
        id: 'headers/framing/invalid-value',
        title: `X-Frame-Options value "${xfo}" is not valid`,
        severity: 'medium',
        confidence: 'firm',
        summary:
          'Only DENY and SAMEORIGIN are honoured. An unrecognised value causes the header to ' +
          'be ignored, leaving the page framable.',
        evidence,
        remediation: "Use frame-ancestors in the CSP, or set X-Frame-Options to DENY or SAMEORIGIN.",
        references: [REFERENCE],
      });
    } else {
      findings.push({
        id: 'headers/framing/xfo-only',
        title: 'Framing is restricted by X-Frame-Options alone',
        severity: 'info',
        confidence: 'firm',
        summary:
          'X-Frame-Options is set and honoured, but it has been superseded by CSP ' +
          'frame-ancestors, which is more expressive and is the directive browsers consult ' +
          'first where both are present.',
        evidence,
        remediation:
          `Add frame-ancestors ${normalisedXfo === 'DENY' ? "'none'" : "'self'"} to the CSP ` +
          'and keep the existing header for legacy clients.',
        references: [REFERENCE],
      });
    }

    return findings;
  },
};
