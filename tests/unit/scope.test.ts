import { describe, expect, it } from 'vitest';

import { parseTarget, reservedRangeFor } from '../../src/core/scope.js';
import { TargetRejectedError } from '../../src/core/errors.js';

describe('reservedRangeFor', () => {
  it.each([
    ['127.0.0.1', 'loopback'],
    ['10.1.2.3', 'private use'],
    ['172.16.0.1', 'private use'],
    ['172.31.255.255', 'private use'],
    ['192.168.1.1', 'private use'],
    ['169.254.169.254', 'link-local'],
    ['100.64.0.1', 'carrier-grade NAT'],
    ['0.0.0.0', 'this network'],
    ['224.0.0.1', 'multicast'],
  ])('rejects %s as %s', (address, label) => {
    expect(reservedRangeFor(address)).toBe(label);
  });

  it.each(['8.8.8.8', '1.1.1.1', '93.184.215.14', '172.32.0.1', '172.15.255.255'])(
    'allows the public address %s',
    (address) => {
      expect(reservedRangeFor(address)).toBeUndefined();
    },
  );

  // 169.254.169.254 is the cloud metadata endpoint, so the IPv6 forms of these
  // ranges have to be blocked too or the guard is trivially sidestepped.
  it.each([
    ['::1', 'loopback'],
    ['::', 'unspecified'],
    ['fc00::1', 'unique local'],
    ['fd12:3456::1', 'unique local'],
    ['fe80::1', 'link-local'],
    ['ff02::1', 'multicast'],
  ])('rejects the IPv6 address %s as %s', (address, label) => {
    expect(reservedRangeFor(address)).toBe(label);
  });

  it('resolves IPv4-mapped IPv6 addresses to the underlying v4 range', () => {
    expect(reservedRangeFor('::ffff:127.0.0.1')).toBe('loopback');
    expect(reservedRangeFor('::ffff:169.254.169.254')).toBe('link-local');
    expect(reservedRangeFor('::ffff:8.8.8.8')).toBeUndefined();
  });

  it.each(['2606:4700::1111', '2001:4860:4860::8888'])(
    'allows the public IPv6 address %s',
    (address) => {
      expect(reservedRangeFor(address)).toBeUndefined();
    },
  );

  it('treats unparseable input as reserved rather than allowed', () => {
    expect(reservedRangeFor('not-an-address')).toBe('unparseable address');
    expect(reservedRangeFor('999.1.1.1')).toBe('unparseable address');
  });
});

describe('parseTarget', () => {
  it('defaults a bare hostname to https', () => {
    expect(parseTarget('example.com').href).toBe('https://example.com/');
  });

  it('preserves an explicit scheme, path and port', () => {
    const url = parseTarget('http://example.com:8080/app');
    expect(url.protocol).toBe('http:');
    expect(url.port).toBe('8080');
    expect(url.pathname).toBe('/app');
  });

  it.each(['file:///etc/passwd', 'ftp://example.com', 'gopher://example.com'])(
    'rejects the non-http scheme in %s',
    (target) => {
      expect(() => parseTarget(target)).toThrow(TargetRejectedError);
    },
  );

  // Credentials in the URL would end up in the report and in shell history.
  it('rejects embedded credentials', () => {
    expect(() => parseTarget('https://user:secret@example.com')).toThrow(TargetRejectedError);
  });

  it('rejects empty input', () => {
    expect(() => parseTarget('   ')).toThrow(TargetRejectedError);
  });
});
