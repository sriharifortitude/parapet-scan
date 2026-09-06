import type { Check, FindingInput } from '../../types.js';

const DEPRECATED = new Set(['TLSv1', 'TLSv1.1']);

const RFC_8996 = {
  title: 'RFC 8996: Deprecating TLS 1.0 and TLS 1.1',
  url: 'https://datatracker.ietf.org/doc/html/rfc8996',
};

export const tlsProtocolsCheck: Check = {
  id: 'tls/protocols',
  title: 'TLS protocol versions',
  category: 'tls',
  description: 'Reports which TLS versions the server will negotiate.',
  requires: ['tls'],

  run(ctx) {
    const tls = ctx.evidence('tls');
    if (!ctx.target.isHttps) return [];

    const findings: FindingInput[] = [];
    const deprecated = tls.acceptedProtocols.filter((protocol) => DEPRECATED.has(protocol));

    if (deprecated.length > 0) {
      findings.push({
        id: 'tls/protocols/deprecated',
        title: `Server negotiates ${deprecated.join(' and ')}`,
        severity: 'medium',
        confidence: 'confirmed',
        summary:
          `${deprecated.join(' and ')} ${deprecated.length > 1 ? 'are' : 'is'} deprecated by ` +
          'RFC 8996. They rely on MD5 and SHA-1 in the handshake and lack modern cipher ' +
          'constructions, and their availability lets a network attacker negotiate a weaker ' +
          'connection than both parties are capable of. Accepting them also fails PCI DSS.',
        evidence: [
          {
            kind: 'note',
            text: `Accepted protocol versions: ${tls.acceptedProtocols.join(', ') || 'none observed'}`,
          },
        ],
        remediation:
          'Set the minimum protocol version to TLS 1.2 at the terminating server or load ' +
          'balancer. Check client analytics first if you support long-tail legacy devices.',
        references: [RFC_8996],
      });
    }

    if (tls.acceptedProtocols.length > 0 && !tls.acceptedProtocols.includes('TLSv1.3')) {
      findings.push({
        id: 'tls/protocols/no-tls13',
        title: 'TLS 1.3 is not offered',
        severity: 'info',
        confidence: 'firm',
        summary:
          'The server negotiates TLS 1.2 but not 1.3. This is not a weakness; TLS 1.3 removes ' +
          'the remaining legacy key exchanges, forces forward secrecy and completes the ' +
          'handshake in one round trip.',
        evidence: [
          { kind: 'note', text: `Accepted protocol versions: ${tls.acceptedProtocols.join(', ')}` },
        ],
        remediation: 'Enable TLS 1.3 alongside 1.2 when the terminating software supports it.',
        references: [
          {
            title: 'RFC 8446: TLS 1.3',
            url: 'https://datatracker.ietf.org/doc/html/rfc8446',
          },
        ],
      });
    }

    return findings;
  },
};
