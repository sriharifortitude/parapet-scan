import type { Check } from '../../types.js';

/**
 * Reported at info because it is a process gap rather than a technical one:
 * without a published contact, someone who finds a flaw here has no route to
 * report it and is more likely to disclose it publicly or not at all.
 */
export const securityTxtCheck: Check = {
  id: 'disclosure/security-txt',
  title: 'Vulnerability disclosure contact',
  category: 'disclosure',
  description: 'Checks for a security.txt file as defined by RFC 9116.',
  requires: ['well-known'],

  run(ctx) {
    const { securityTxt } = ctx.evidence('well-known');
    if (securityTxt !== undefined && securityTxt.status === 200) return [];

    return [
      {
        id: 'disclosure/security-txt/missing',
        title: 'No security.txt published',
        severity: 'info',
        confidence: 'firm',
        summary:
          'There is no /.well-known/security.txt, so a researcher who finds a vulnerability ' +
          'has no documented way to report it. In practice reports then arrive through ' +
          'support channels that are not equipped to triage them, or not at all.',
        evidence: [
          {
            kind: 'note',
            text:
              securityTxt === undefined
                ? 'The request for /.well-known/security.txt did not complete.'
                : `/.well-known/security.txt returned ${securityTxt.status}.`,
          },
        ],
        remediation:
          'Publish /.well-known/security.txt with at least a Contact field and an Expires ' +
          'timestamp, per RFC 9116.',
        references: [
          {
            title: 'RFC 9116: A File Format to Aid in Security Vulnerability Disclosure',
            url: 'https://datatracker.ietf.org/doc/html/rfc9116',
          },
        ],
      },
    ];
  },
};
