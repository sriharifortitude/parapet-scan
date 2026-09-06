import type { Check, FindingInput } from '../../types.js';

export const insecureFormCheck: Check = {
  id: 'content/insecure-form',
  title: 'Form submission over plaintext',
  category: 'content',
  description: 'Finds forms whose action targets http, especially those collecting passwords.',
  requires: ['document'],

  run(ctx) {
    const document = ctx.evidence('document');
    if (!document.isHtml) return [];

    const insecure = document.forms.filter((form) => form.action.startsWith('http://'));
    if (insecure.length === 0) return [];

    const withPassword = insecure.filter((form) => form.hasPasswordField);
    const findings: FindingInput[] = [];

    if (withPassword.length > 0) {
      findings.push({
        id: 'content/insecure-form/password-over-http',
        title: 'Password field submits over plaintext http',
        severity: 'high',
        confidence: 'confirmed',
        summary:
          'A form containing a password input posts to an http URL, so the credential is sent ' +
          'unencrypted regardless of how the page itself was loaded. Browsers warn on these ' +
          'fields, but the submission still happens if the user proceeds.',
        evidence: withPassword.map((form) => ({
          kind: 'markup' as const,
          snippet: `<form method="${form.method}" action="${form.action}">`,
        })),
        remediation: 'Change the form action to https. There is no configuration where this is acceptable.',
        references: [
          {
            title: 'OWASP Transport Layer Security Cheat Sheet',
            url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
          },
        ],
      });
    }

    const withoutPassword = insecure.filter((form) => !form.hasPasswordField);
    if (withoutPassword.length > 0) {
      findings.push({
        id: 'content/insecure-form/action-over-http',
        title: `${withoutPassword.length} form${withoutPassword.length === 1 ? '' : 's'} submit over plaintext http`,
        severity: 'medium',
        confidence: 'confirmed',
        summary:
          'Form data is sent unencrypted and can be read and modified in transit. Even where ' +
          'the fields look innocuous, the request carries any cookie scoped to that host.',
        evidence: withoutPassword.slice(0, 10).map((form) => ({
          kind: 'markup' as const,
          snippet: `<form method="${form.method}" action="${form.action}">`,
        })),
        remediation: 'Change the form action to https.',
        references: [],
      });
    }

    return findings;
  },
};

/**
 * Reported at info, not low. Browsers have implied rel=noopener for
 * target=_blank since 2021, so on current clients this is a compatibility note
 * rather than a live exposure -- saying otherwise would be inflating a finding.
 */
export const targetBlankCheck: Check = {
  id: 'content/target-blank',
  title: 'Reverse tabnabbing',
  category: 'content',
  description: 'Finds cross-origin target=_blank links without rel=noopener.',
  requires: ['document'],

  run(ctx) {
    const document = ctx.evidence('document');
    if (!document.isHtml) return [];

    const base = ctx.target.url.origin;
    const risky = document.links.filter((link) => {
      if (link.target?.toLowerCase() !== '_blank') return false;
      if (link.relTokens.includes('noopener') || link.relTokens.includes('noreferrer')) return false;
      return isCrossOrigin(link.href, base);
    });
    if (risky.length === 0) return [];

    return [
      {
        id: 'content/target-blank/missing-noopener',
        title: `${risky.length} cross-origin link${risky.length === 1 ? '' : 's'} open a new tab without rel=noopener`,
        severity: 'info',
        confidence: 'firm',
        summary:
          'Links opening a cross-origin destination in a new tab do not set rel=noopener. ' +
          'Current browsers imply it, so this is not exploitable on an up-to-date client; on ' +
          'older ones the opened page receives a window.opener handle and can navigate the ' +
          'original tab to a phishing page.',
        evidence: risky.slice(0, 10).map((link) => ({
          kind: 'markup' as const,
          snippet: `<a target="_blank" href="${link.href}">`,
        })),
        remediation: 'Add rel="noopener noreferrer" to outbound target=_blank links.',
        references: [
          {
            title: 'OWASP: Reverse tabnabbing',
            url: 'https://owasp.org/www-community/attacks/Reverse_Tabnabbing',
          },
        ],
      },
    ];
  },
};

function isCrossOrigin(href: string, base: string): boolean {
  try {
    return new URL(href).origin !== base;
  } catch {
    return false;
  }
}
