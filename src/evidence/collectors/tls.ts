import { connect, type ConnectionOptions, type PeerCertificate, type TLSSocket } from 'node:tls';

import { describeError } from '../../core/errors.js';
import type { CertificateSummary, Collector, TlsEvidence } from '../../types.js';

const PROBED_PROTOCOLS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] as const;
type ProbedProtocol = (typeof PROBED_PROTOCOLS)[number];

/**
 * Certificate verification is disabled for these handshakes on purpose.
 *
 * The collector's job is to describe the certificate a server presents,
 * including expired, self-signed and hostname-mismatched ones -- exactly the
 * cases a verifying client refuses to complete. Rejecting them would mean the
 * tool goes silent precisely when it has something to report. Nothing is sent
 * over these sockets and no response body is trusted; they carry a handshake
 * and are then destroyed.
 */
const INSPECTION_ONLY: ConnectionOptions = { rejectUnauthorized: false };

export const tlsCollector: Collector<'tls'> = {
  id: 'tls',
  description: 'Inspects the certificate and negotiates each TLS version in isolation.',
  dependsOn: [],

  async collect(ctx): Promise<TlsEvidence> {
    if (!ctx.target.isHttps) {
      return { acceptedProtocols: [], errors: ['Target is not https; TLS was not inspected.'] };
    }

    const { hostname, port } = ctx.target;
    const errors: string[] = [];

    let negotiated: { protocol?: string; cipher?: string; certificate?: CertificateSummary };
    try {
      negotiated = await describeHandshake(hostname, port, ctx.config.timeoutMs);
    } catch (error) {
      return {
        acceptedProtocols: [],
        errors: [`Handshake failed: ${describeError(error)}`],
      };
    }

    const accepted: string[] = [];
    for (const protocol of PROBED_PROTOCOLS) {
      const result = await probeProtocol(hostname, port, protocol, ctx.config.timeoutMs);
      if (result.accepted) accepted.push(protocol);
      else if (result.error !== undefined) errors.push(`${protocol}: ${result.error}`);
    }

    return {
      ...(negotiated.protocol === undefined ? {} : { negotiatedProtocol: negotiated.protocol }),
      ...(negotiated.cipher === undefined ? {} : { negotiatedCipher: negotiated.cipher }),
      ...(negotiated.certificate === undefined ? {} : { certificate: negotiated.certificate }),
      acceptedProtocols: accepted,
      errors,
    };
  },
};

function handshake(options: ConnectionOptions, timeoutMs: number): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = connect({ ...options, ...INSPECTION_ONLY });

    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };

    socket.setTimeout(timeoutMs, () => fail(new Error(`handshake timed out after ${timeoutMs}ms`)));
    socket.once('error', fail);
    socket.once('secureConnect', () => {
      if (settled) return;
      settled = true;
      socket.setTimeout(0);
      resolve(socket);
    });
  });
}

async function describeHandshake(
  hostname: string,
  port: number,
  timeoutMs: number,
): Promise<{ protocol?: string; cipher?: string; certificate?: CertificateSummary }> {
  const socket = await handshake({ host: hostname, port, servername: sniFor(hostname) }, timeoutMs);
  try {
    const protocol = socket.getProtocol() ?? undefined;
    const cipher = socket.getCipher()?.name;
    const peer = socket.getPeerCertificate(false);
    const certificate = isPopulated(peer) ? summarise(peer) : undefined;

    return {
      ...(protocol === undefined ? {} : { protocol }),
      ...(cipher === undefined ? {} : { cipher }),
      ...(certificate === undefined ? {} : { certificate }),
    };
  } finally {
    socket.destroy();
  }
}

async function probeProtocol(
  hostname: string,
  port: number,
  protocol: ProbedProtocol,
  timeoutMs: number,
): Promise<{ accepted: boolean; error?: string }> {
  try {
    const socket = await handshake(
      {
        host: hostname,
        port,
        servername: sniFor(hostname),
        minVersion: protocol,
        maxVersion: protocol,
        // TLS 1.0/1.1 need the legacy security level to be offered at all; without
        // this OpenSSL 3 refuses locally and the probe would report a false absence.
        ...(protocol === 'TLSv1' || protocol === 'TLSv1.1'
          ? { ciphers: 'DEFAULT:@SECLEVEL=0' }
          : {}),
      },
      timeoutMs,
    );
    socket.destroy();
    return { accepted: true };
  } catch (error) {
    const message = describeError(error);
    // A protocol the local OpenSSL build cannot offer is a gap in our coverage,
    // not evidence about the server, so it is reported separately.
    if (/no protocols available|unsupported protocol|invalid protocol/i.test(message)) {
      return { accepted: false, error: `not offered by the local TLS stack (${message})` };
    }
    return { accepted: false };
  }
}

/** SNI is a hostname extension; IP literals must not be sent in it. */
function sniFor(hostname: string): string | undefined {
  return /^[\d.]+$/.test(hostname) || hostname.includes(':') ? undefined : hostname;
}

function isPopulated(certificate: PeerCertificate): boolean {
  return Object.keys(certificate).length > 0 && certificate.valid_to !== undefined;
}

function summarise(certificate: PeerCertificate): CertificateSummary {
  const curve = curveOf(certificate);
  const validTo = new Date(certificate.valid_to);
  const msPerDay = 86_400_000;
  const daysUntilExpiry = Math.floor((validTo.getTime() - Date.now()) / msPerDay);

  return {
    subject: formatName(certificate.subject),
    issuer: formatName(certificate.issuer),
    validFrom: certificate.valid_from,
    validTo: certificate.valid_to,
    daysUntilExpiry: Number.isFinite(daysUntilExpiry) ? daysUntilExpiry : 0,
    subjectAltNames: parseSubjectAltNames(certificate.subjectaltname),
    ...(typeof certificate.bits === 'number' ? { keyBits: certificate.bits } : {}),
    keyType: keyTypeOf(certificate),
    ...(curve === undefined ? {} : { curve }),
  };
}

/**
 * OpenSSL populates modulus/exponent for RSA keys and a curve name for EC keys,
 * so the algorithm is inferred from which fields are present rather than parsed
 * out of the DER.
 */
function keyTypeOf(certificate: PeerCertificate): 'rsa' | 'ec' | 'other' {
  if (typeof certificate.modulus === 'string' && certificate.modulus !== '') return 'rsa';
  if (curveOf(certificate) !== undefined) return 'ec';
  return 'other';
}

function curveOf(certificate: PeerCertificate): string | undefined {
  const curve = certificate.nistCurve ?? certificate.asn1Curve;
  return typeof curve === 'string' && curve !== '' ? curve : undefined;
}

function formatName(name: PeerCertificate['subject'] | undefined): string {
  if (name === undefined) return '(unavailable)';
  const parts = Object.entries(name)
    .filter(([, value]) => typeof value === 'string' || Array.isArray(value))
    .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join('+') : String(value)}`);
  return parts.length > 0 ? parts.join(', ') : '(unavailable)';
}

function parseSubjectAltNames(raw: string | undefined): string[] {
  if (raw === undefined || raw === '') return [];
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '');
}
