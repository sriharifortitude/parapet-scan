import { describe, expect, it } from 'vitest';

import {
  isScopeWiderThanHost,
  parseSetCookie,
  prefixRequirementViolation,
} from '../../src/core/cookies.js';
import { cookieAttributesCheck } from '../../src/checks/cookies/attributes.js';
import { makeContext, makeResponse } from '../helpers/context.js';

function scan(cookies: string[], target = 'https://target.test/') {
  const headers = cookies.map((cookie) => ['set-cookie', cookie] as const);
  return cookieAttributesCheck.run(
    makeContext({ baseline: { response: makeResponse([...headers]) } }, { target }),
  );
}

describe('parseSetCookie', () => {
  it('parses the name, value and attributes', () => {
    const cookie = parseSetCookie('sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax');
    expect(cookie).toMatchObject({
      name: 'sid',
      value: 'abc123',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
    });
  });

  it('is case-insensitive on attribute names and values', () => {
    expect(parseSetCookie('a=b; SECURE; httponly; samesite=STRICT')).toMatchObject({
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
    });
  });

  // Expires contains a comma, which is why Set-Cookie headers are never joined.
  it('keeps an Expires value containing a comma intact', () => {
    expect(parseSetCookie('a=b; Expires=Wed, 21 Oct 2026 07:28:00 GMT')?.expires).toBe(
      'Wed, 21 Oct 2026 07:28:00 GMT',
    );
  });

  it('handles a value containing an equals sign', () => {
    expect(parseSetCookie('token=eyJhbGc=.payload=; Path=/')?.value).toBe('eyJhbGc=.payload=');
  });

  it('strips a leading dot from Domain', () => {
    expect(parseSetCookie('a=b; Domain=.example.com')?.domain).toBe('example.com');
  });

  it('returns undefined for input with no name', () => {
    expect(parseSetCookie('=value')).toBeUndefined();
    expect(parseSetCookie('novalue')).toBeUndefined();
  });

  it('treats an empty value as valid', () => {
    expect(parseSetCookie('a=; Path=/')).toMatchObject({ name: 'a', value: '' });
  });
});

describe('prefixRequirementViolation', () => {
  it('requires Secure for __Secure-', () => {
    expect(prefixRequirementViolation(parseSetCookie('__Secure-a=b')!)).toMatch(/Secure/);
    expect(prefixRequirementViolation(parseSetCookie('__Secure-a=b; Secure')!)).toBeUndefined();
  });

  it('requires Secure, Path=/ and no Domain for __Host-', () => {
    expect(prefixRequirementViolation(parseSetCookie('__Host-a=b; Path=/')!)).toMatch(/Secure/);
    expect(
      prefixRequirementViolation(parseSetCookie('__Host-a=b; Secure; Path=/settings')!),
    ).toMatch(/Path=\//);
    expect(
      prefixRequirementViolation(parseSetCookie('__Host-a=b; Secure; Path=/; Domain=x.test')!),
    ).toMatch(/Domain/);
    expect(prefixRequirementViolation(parseSetCookie('__Host-a=b; Secure; Path=/')!)).toBeUndefined();
  });

  it('ignores cookies without a prefix', () => {
    expect(prefixRequirementViolation(parseSetCookie('plain=b')!)).toBeUndefined();
  });
});

describe('isScopeWiderThanHost', () => {
  it('detects a cookie scoped to a parent domain', () => {
    expect(isScopeWiderThanHost(parseSetCookie('a=b; Domain=example.com')!, 'app.example.com')).toBe(
      true,
    );
  });

  it('does not flag a host-only cookie or an exact match', () => {
    expect(isScopeWiderThanHost(parseSetCookie('a=b')!, 'app.example.com')).toBe(false);
    expect(
      isScopeWiderThanHost(parseSetCookie('a=b; Domain=app.example.com')!, 'app.example.com'),
    ).toBe(false);
  });

  // "notexample.com" must not be treated as a parent of "example.com".
  it('does not treat a suffix without a label boundary as a parent', () => {
    expect(isScopeWiderThanHost(parseSetCookie('a=b; Domain=example.com')!, 'notexample.com')).toBe(
      false,
    );
  });
});

describe('cookieAttributesCheck', () => {
  it('escalates a session cookie missing Secure over https', async () => {
    const findings = await scan(['sessionid=x; Path=/']);
    const secure = findings.find((f) => f.id.startsWith('cookies/attributes/no-secure'));
    expect(secure?.severity).toBe('high');
  });

  it('does not report a missing Secure attribute over plaintext http', async () => {
    const findings = await scan(['sessionid=x; Path=/'], 'http://target.test/');
    expect(findings.map((f) => f.id)).not.toContainEqual(
      expect.stringContaining('no-secure'),
    );
  });

  it('rates HttpOnly by whether the name suggests session state', async () => {
    const session = await scan(['auth_token=x; Secure']);
    const benign = await scan(['theme=dark; Secure']);
    expect(session.find((f) => f.id.includes('no-httponly'))?.severity).toBe('medium');
    expect(benign.find((f) => f.id.includes('no-httponly'))?.severity).toBe('info');
  });

  it('reports SameSite=None sent without Secure', async () => {
    const findings = await scan(['a=b; SameSite=None']);
    expect(findings.map((f) => f.id)).toContain('cookies/attributes/samesite-none-insecure:a');
  });

  it('stays quiet on a correctly configured cookie', async () => {
    const findings = await scan(['__Host-session=x; Secure; HttpOnly; SameSite=Strict; Path=/']);
    expect(findings).toEqual([]);
  });

  // The cookie value may be a live session token, so it must not reach a report.
  it('redacts the cookie value from the evidence', async () => {
    const findings = await scan(['sessionid=super-secret-value; Path=/']);
    const serialised = JSON.stringify(findings);
    expect(serialised).not.toContain('super-secret-value');
    expect(serialised).toContain('redacted');
  });
});
