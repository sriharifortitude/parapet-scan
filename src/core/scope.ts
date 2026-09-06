import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

import { TargetRejectedError } from './errors.js';
import type { TargetDescriptor } from '../types.js';

/**
 * Targets are resolved and screened before the first request.
 *
 * The scanner takes a hostname from a CLI flag or a config file that may itself
 * have come from a CI variable, then issues requests from wherever it runs --
 * frequently a build agent inside a private network. That is the shape of an
 * SSRF primitive, so name resolution happens here and the resulting addresses
 * are screened against reserved ranges. `--allow-private` is the deliberate
 * opt-out, and it exists mainly so the bundled lab in lab/ can be scanned.
 */

const IPV4_BLOCKS: ReadonlyArray<readonly [string, number, string]> = [
  ['0.0.0.0', 8, 'this network'],
  ['10.0.0.0', 8, 'private use'],
  ['100.64.0.0', 10, 'carrier-grade NAT'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local'],
  ['172.16.0.0', 12, 'private use'],
  ['192.0.0.0', 24, 'IETF protocol assignments'],
  ['192.0.2.0', 24, 'documentation'],
  ['192.168.0.0', 16, 'private use'],
  ['198.18.0.0', 15, 'benchmarking'],
  ['198.51.100.0', 24, 'documentation'],
  ['203.0.113.0', 24, 'documentation'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
];

const IPV6_BLOCKS: ReadonlyArray<readonly [string, number, string]> = [
  ['::', 128, 'unspecified'],
  ['::1', 128, 'loopback'],
  ['fc00::', 7, 'unique local'],
  ['fe80::', 10, 'link-local'],
  ['ff00::', 8, 'multicast'],
];

function ipv4ToInt(address: string): number {
  const octets = address.split('.');
  if (octets.length !== 4) throw new TypeError(`not an IPv4 address: ${address}`);
  let value = 0;
  for (const octet of octets) {
    const n = Number(octet);
    if (!Number.isInteger(n) || n < 0 || n > 255) {
      throw new TypeError(`not an IPv4 address: ${address}`);
    }
    value = value * 256 + n;
  }
  return value;
}

function expandIpv6(address: string): bigint {
  const zoneless = address.split('%')[0] ?? address;

  // ::ffff:192.0.2.1 style addresses carry a v4 address in the low 32 bits.
  const embeddedV4 = /^(.*:)((?:\d{1,3}\.){3}\d{1,3})$/.exec(zoneless);
  let text = zoneless;
  if (embeddedV4?.[1] !== undefined && embeddedV4[2] !== undefined) {
    const v4 = ipv4ToInt(embeddedV4[2]);
    const high = (v4 >>> 16) & 0xffff;
    const low = v4 & 0xffff;
    text = `${embeddedV4[1]}${high.toString(16)}:${low.toString(16)}`;
  }

  const halves = text.split('::');
  if (halves.length > 2) throw new TypeError(`not an IPv6 address: ${address}`);

  const headText = halves[0] ?? '';
  const head = headText === '' ? [] : headText.split(':');

  let groups: string[];
  if (halves.length === 1) {
    groups = head;
  } else {
    const tailText = halves[1] ?? '';
    const tail = tailText === '' ? [] : tailText.split(':');
    const fill = 8 - head.length - tail.length;
    if (fill < 0) throw new TypeError(`not an IPv6 address: ${address}`);
    groups = [...head, ...Array<string>(fill).fill('0'), ...tail];
  }
  if (groups.length !== 8) throw new TypeError(`not an IPv6 address: ${address}`);

  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) throw new TypeError(`not an IPv6 address: ${address}`);
    value = (value << 16n) | BigInt(parseInt(group, 16));
  }
  return value;
}

function inV4Block(address: string, base: string, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (-1 << (32 - prefix)) >>> 0;
  return (ipv4ToInt(address) & mask) >>> 0 === (ipv4ToInt(base) & mask) >>> 0;
}

function inV6Block(address: string, base: string, prefix: number): boolean {
  const shift = BigInt(128 - prefix);
  return expandIpv6(address) >> shift === expandIpv6(base) >> shift;
}

/** Returns a human-readable reason when the address is reserved, otherwise undefined. */
export function reservedRangeFor(address: string): string | undefined {
  const family = isIP(address);
  try {
    if (family === 4) {
      for (const [base, prefix, label] of IPV4_BLOCKS) {
        if (inV4Block(address, base, prefix)) return label;
      }
      if (address === '255.255.255.255') return 'broadcast';
      return undefined;
    }
    if (family === 6) {
      const mapped = /^::ffff:((?:\d{1,3}\.){3}\d{1,3})$/i.exec(address);
      if (mapped?.[1] !== undefined) return reservedRangeFor(mapped[1]);
      for (const [base, prefix, label] of IPV6_BLOCKS) {
        if (inV6Block(address, base, prefix)) return label;
      }
      return undefined;
    }
  } catch {
    // Unparseable input is treated as unresolvable rather than allowed.
    return 'unparseable address';
  }
  return 'unparseable address';
}

/** Accepts bare hostnames and normalises them to an absolute https URL. */
export function parseTarget(raw: string): URL {
  const trimmed = raw.trim();
  if (trimmed === '') throw new TargetRejectedError('Target is empty.');

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new TargetRejectedError(`Target is not a valid URL: ${raw}`);
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new TargetRejectedError(
      `Unsupported scheme "${url.protocol}" in target ${raw}.`,
      'Only http:// and https:// targets can be scanned.',
    );
  }

  if (url.username !== '' || url.password !== '') {
    throw new TargetRejectedError(
      'Target URL contains embedded credentials.',
      'Pass authentication with --header instead so it can be redacted from reports.',
    );
  }

  return url;
}

export function describeTarget(url: URL): TargetDescriptor {
  const isHttps = url.protocol === 'https:';
  const port = url.port === '' ? (isHttps ? 443 : 80) : Number(url.port);
  return { url, origin: url.origin, hostname: url.hostname, port, isHttps };
}

export interface ScopeOptions {
  readonly allowPrivateTargets: boolean;
}

/**
 * Resolves the hostname and rejects reserved addresses unless explicitly allowed.
 *
 * Known limitation: this screens the addresses seen at resolution time. A DNS
 * record that changes between this check and the request (a rebinding attack)
 * is not defended against here -- doing so requires pinning the resolved
 * address into the connection, which is tracked in docs/adr/0003-scope-guard.md.
 */
export async function assertTargetInScope(url: URL, options: ScopeOptions): Promise<void> {
  const literal = isIP(url.hostname) !== 0;
  const addresses = literal
    ? [url.hostname]
    : await resolveOrThrow(url.hostname).then((records) => records.map((r) => r.address));

  if (addresses.length === 0) {
    throw new TargetRejectedError(`Hostname ${url.hostname} did not resolve to any address.`);
  }

  if (options.allowPrivateTargets) return;

  for (const address of addresses) {
    const reason = reservedRangeFor(address);
    if (reason !== undefined) {
      throw new TargetRejectedError(
        `${url.hostname} resolves to ${address}, which is in a reserved range (${reason}).`,
        'Pass --allow-private if you intend to scan a host on your own network, such as the bundled lab.',
      );
    }
  }
}

async function resolveOrThrow(hostname: string): Promise<Array<{ address: string }>> {
  try {
    return await lookup(hostname, { all: true });
  } catch (error) {
    throw new TargetRejectedError(
      `Could not resolve ${hostname}.`,
      error instanceof Error ? error.message : undefined,
    );
  }
}
