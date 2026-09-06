import { describe, expect, it } from 'vitest';

import { tlsCertificateCheck } from '../../src/checks/tls/certificate.js';
import { tlsProtocolsCheck } from '../../src/checks/tls/protocols.js';
import { makeContext, runCheck } from '../helpers/context.js';
import type { CertificateSummary, TlsEvidence } from '../../src/types.js';

function certificate(overrides: Partial<CertificateSummary> = {}): CertificateSummary {
  return {
    subject: 'CN=target.test',
    issuer: 'CN=Test CA, O=Test',
    validFrom: 'Jan 1 00:00:00 2026 GMT',
    validTo: 'Jan 1 00:00:00 2027 GMT',
    daysUntilExpiry: 200,
    subjectAltNames: ['DNS:target.test'],
    keyType: 'rsa',
    keyBits: 2048,
    ...overrides,
  };
}

function scanCertificate(overrides: Partial<CertificateSummary> = {}, target?: string) {
  const tls: TlsEvidence = {
    acceptedProtocols: ['TLSv1.2', 'TLSv1.3'],
    errors: [],
    certificate: certificate(overrides),
  };
  return runCheck(
    tlsCertificateCheck,
    makeContext({ tls }, target === undefined ? {} : { target }),
  );
}

describe('tlsCertificateCheck', () => {
  it('says nothing about a healthy certificate', async () => {
    expect(await scanCertificate()).toEqual([]);
  });

  it.each([
    [-5, 'tls/certificate/expired'],
    [3, 'tls/certificate/expiring-urgent'],
    [20, 'tls/certificate/expiring-soon'],
  ])('grades %d days until expiry as %s', async (days, expected) => {
    expect(await scanCertificate({ daysUntilExpiry: days })).toContain(expected);
  });

  it('detects a self-signed certificate', async () => {
    expect(await scanCertificate({ issuer: 'CN=target.test' })).toContain(
      'tls/certificate/self-signed',
    );
  });

  describe('hostname matching', () => {
    it('accepts an exact subject alternative name', async () => {
      expect(await scanCertificate({ subjectAltNames: ['DNS:target.test'] })).not.toContain(
        'tls/certificate/hostname-mismatch',
      );
    });

    it('accepts a wildcard covering one label', async () => {
      const ids = await scanCertificate(
        { subjectAltNames: ['DNS:*.target.test'] },
        'https://app.target.test/',
      );
      expect(ids).not.toContain('tls/certificate/hostname-mismatch');
    });

    // RFC 6125: a wildcard matches exactly one label, never a bare domain and
    // never across a dot.
    it('rejects a wildcard against the bare domain', async () => {
      const ids = await scanCertificate(
        { subjectAltNames: ['DNS:*.target.test'] },
        'https://target.test/',
      );
      expect(ids).toContain('tls/certificate/hostname-mismatch');
    });

    it('rejects a wildcard spanning more than one label', async () => {
      const ids = await scanCertificate(
        { subjectAltNames: ['DNS:*.target.test'] },
        'https://a.b.target.test/',
      );
      expect(ids).toContain('tls/certificate/hostname-mismatch');
    });

    it('rejects a certificate with no subject alternative names', async () => {
      expect(await scanCertificate({ subjectAltNames: [] })).toContain(
        'tls/certificate/hostname-mismatch',
      );
    });
  });

  describe('key strength', () => {
    it('reports an undersized RSA key', async () => {
      expect(await scanCertificate({ keyType: 'rsa', keyBits: 1024 })).toContain(
        'tls/certificate/weak-key',
      );
    });

    // The regression this exists for: a 256-bit EC key is roughly equivalent to
    // 3072-bit RSA, and is what most CAs issue by default.
    it('accepts a 256-bit elliptic curve key', async () => {
      const ids = await scanCertificate({ keyType: 'ec', keyBits: 256, curve: 'prime256v1' });
      expect(ids).not.toContain('tls/certificate/weak-key');
    });

    it('reports an undersized elliptic curve key', async () => {
      expect(await scanCertificate({ keyType: 'ec', keyBits: 192 })).toContain(
        'tls/certificate/weak-key',
      );
    });

    it('says nothing when the algorithm is unrecognised', async () => {
      expect(await scanCertificate({ keyType: 'other', keyBits: 256 })).not.toContain(
        'tls/certificate/weak-key',
      );
    });
  });
});

describe('tlsProtocolsCheck', () => {
  it('reports deprecated protocol versions', async () => {
    const ids = await runCheck(
      tlsProtocolsCheck,
      makeContext({
        tls: { acceptedProtocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2'], errors: [] },
      }),
    );
    expect(ids).toContain('tls/protocols/deprecated');
  });

  it('accepts a modern protocol set', async () => {
    const ids = await runCheck(
      tlsProtocolsCheck,
      makeContext({ tls: { acceptedProtocols: ['TLSv1.2', 'TLSv1.3'], errors: [] } }),
    );
    expect(ids).toEqual([]);
  });

  it('notes the absence of TLS 1.3 without calling it a weakness', async () => {
    const ids = await runCheck(
      tlsProtocolsCheck,
      makeContext({ tls: { acceptedProtocols: ['TLSv1.2'], errors: [] } }),
    );
    expect(ids).toEqual(['tls/protocols/no-tls13']);
  });
});
