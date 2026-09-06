import type { Check, CertificateSummary, Evidence, FindingInput } from '../../types.js';

const EXPIRY_WARNING_DAYS = 30;
const EXPIRY_URGENT_DAYS = 7;
const MIN_RSA_BITS = 2048;
/** NIST SP 800-57 puts the floor for elliptic curve keys at 224 bits. */
const MIN_EC_BITS = 224;

const REFERENCE = {
  title: 'RFC 6125: Service identity in TLS',
  url: 'https://datatracker.ietf.org/doc/html/rfc6125',
};

export const tlsCertificateCheck: Check = {
  id: 'tls/certificate',
  title: 'TLS certificate',
  category: 'tls',
  description: 'Checks certificate validity, hostname coverage and key strength.',
  requires: ['tls'],

  run(ctx) {
    const tls = ctx.evidence('tls');
    const certificate = tls.certificate;
    if (!ctx.target.isHttps || certificate === undefined) return [];

    const evidence: Evidence[] = [
      {
        kind: 'certificate',
        detail: {
          subject: certificate.subject,
          issuer: certificate.issuer,
          validFrom: certificate.validFrom,
          validTo: certificate.validTo,
          subjectAltNames: certificate.subjectAltNames.join(', ') || '(none)',
          ...(certificate.keyBits === undefined ? {} : { keyBits: String(certificate.keyBits) }),
        },
      },
    ];

    const findings: FindingInput[] = [];

    if (certificate.daysUntilExpiry < 0) {
      findings.push({
        id: 'tls/certificate/expired',
        title: `Certificate expired ${Math.abs(certificate.daysUntilExpiry)} days ago`,
        severity: 'critical',
        confidence: 'confirmed',
        summary:
          `The certificate expired on ${certificate.validTo}. Browsers present a full-page ` +
          'interstitial for an expired certificate, so the site is effectively unreachable, ' +
          'and users trained to click through such warnings lose the protection entirely.',
        evidence,
        remediation:
          'Renew immediately, then automate renewal and add expiry monitoring so the next one ' +
          'is not found by a visitor.',
        references: [REFERENCE],
      });
    } else if (certificate.daysUntilExpiry <= EXPIRY_URGENT_DAYS) {
      findings.push({
        id: 'tls/certificate/expiring-urgent',
        title: `Certificate expires in ${certificate.daysUntilExpiry} days`,
        severity: 'high',
        confidence: 'confirmed',
        summary:
          `The certificate is valid until ${certificate.validTo}. At this range an unnoticed ` +
          'renewal failure becomes an outage within the week.',
        evidence,
        remediation: 'Renew now and confirm the automated renewal path is actually running.',
        references: [REFERENCE],
      });
    } else if (certificate.daysUntilExpiry <= EXPIRY_WARNING_DAYS) {
      findings.push({
        id: 'tls/certificate/expiring-soon',
        title: `Certificate expires in ${certificate.daysUntilExpiry} days`,
        severity: 'low',
        confidence: 'confirmed',
        summary: `The certificate is valid until ${certificate.validTo}.`,
        evidence,
        remediation: 'Confirm automated renewal is configured and has succeeded at least once.',
        references: [REFERENCE],
      });
    }

    if (isSelfSigned(certificate)) {
      findings.push({
        id: 'tls/certificate/self-signed',
        title: 'Certificate is self-signed',
        severity: 'high',
        confidence: 'confirmed',
        summary:
          'Subject and issuer are identical, so no certificate authority vouches for this ' +
          'identity. Clients cannot distinguish the real server from an interceptor, which ' +
          'removes the authentication half of TLS while leaving the encryption in place.',
        evidence,
        remediation:
          'Issue a certificate from a CA the clients trust. For internal services that means ' +
          'an internal CA distributed to those clients, not a self-signed leaf.',
        references: [REFERENCE],
      });
    }

    if (!coversHostname(certificate, ctx.target.hostname)) {
      findings.push({
        id: 'tls/certificate/hostname-mismatch',
        title: `Certificate does not cover ${ctx.target.hostname}`,
        severity: 'high',
        confidence: 'confirmed',
        summary:
          `None of the subject alternative names match ${ctx.target.hostname}. Browsers refuse ` +
          'the connection, and the mismatch usually means requests are landing on a different ' +
          'virtual host than intended.',
        evidence,
        remediation:
          `Reissue the certificate with ${ctx.target.hostname} in the subject alternative ` +
          'name list, or correct the routing so the request reaches the intended host.',
        references: [REFERENCE],
      });
    }

    const weakKey = describeWeakKey(certificate);
    if (weakKey !== undefined) {
      findings.push({
        id: 'tls/certificate/weak-key',
        title: `Certificate public key is ${certificate.keyBits ?? '?'} bits`,
        severity: 'high',
        confidence: 'firm',
        summary: weakKey,
        evidence,
        remediation: 'Reissue with a 2048-bit or larger RSA key, or an ECDSA P-256 key.',
        references: [
          {
            title: 'NIST SP 800-57 Part 1: Key management recommendations',
            url: 'https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final',
          },
        ],
      });
    }

    return findings;
  },
};

/**
 * Key sizes are only comparable within an algorithm family. A 256-bit ECDSA key
 * offers roughly the strength of a 3072-bit RSA key, so applying the RSA floor
 * to every certificate would flag a modern P-256 deployment -- which is what
 * most CAs now issue by default -- as a high-severity weakness.
 */
function describeWeakKey(certificate: CertificateSummary): string | undefined {
  const bits = certificate.keyBits;
  if (bits === undefined) return undefined;

  if (certificate.keyType === 'rsa') {
    return bits < MIN_RSA_BITS
      ? `A ${bits}-bit RSA key is below the ${MIN_RSA_BITS}-bit floor that public CAs and ` +
          'every current baseline require. Factoring effort against keys this size is within ' +
          'reach of a well-resourced attacker.'
      : undefined;
  }

  if (certificate.keyType === 'ec') {
    return bits < MIN_EC_BITS
      ? `A ${bits}-bit elliptic curve key (${certificate.curve ?? 'unnamed curve'}) is below ` +
          `the ${MIN_EC_BITS}-bit minimum. Note that EC key sizes are not comparable to RSA: ` +
          '256 bits here is the common, and adequate, choice.'
      : undefined;
  }

  // An unrecognised algorithm is not evidence of weakness, so it is not reported.
  return undefined;
}

function isSelfSigned(certificate: CertificateSummary): boolean {
  return (
    certificate.subject !== '(unavailable)' && certificate.subject === certificate.issuer
  );
}

/**
 * RFC 6125 name matching, restricted to the parts that matter in practice: a
 * wildcard is valid only in the leftmost label and matches exactly one label.
 */
function coversHostname(certificate: CertificateSummary, hostname: string): boolean {
  const names = certificate.subjectAltNames
    .map((entry) => entry.replace(/^DNS:/i, '').trim().toLowerCase())
    .filter((entry) => entry !== '');

  // Certificates without a SAN extension are rejected by every current browser,
  // so falling back to the subject CN would report a pass the clients disagree with.
  if (names.length === 0) return false;

  const host = hostname.toLowerCase();
  return names.some((name) => {
    if (name === host) return true;
    if (!name.startsWith('*.')) return false;
    const suffix = name.slice(1);
    if (!host.endsWith(suffix)) return false;
    const remainder = host.slice(0, host.length - suffix.length);
    return remainder !== '' && !remainder.includes('.');
  });
}
