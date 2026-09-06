import { describe, expect, it } from 'vitest';

import { effectiveSources, parsePolicy } from '../../src/core/csp.js';
import { cspCheck } from '../../src/checks/headers/csp.js';
import { makeContext, makeResponse, runCheck } from '../helpers/context.js';

function scan(...policies: string[]): Promise<string[]> {
  const headers = policies.map((policy) => ['content-security-policy', policy] as const);
  return runCheck(cspCheck, makeContext({ baseline: { response: makeResponse([...headers]) } }));
}

describe('parsePolicy', () => {
  it('lower-cases directive names and keeps source expressions verbatim', () => {
    const policy = parsePolicy("Default-Src 'SELF' https://CDN.example");
    expect([...policy.directives.keys()]).toEqual(['default-src']);
    expect(policy.directives.get('default-src')).toEqual(["'SELF'", 'https://CDN.example']);
  });

  it('keeps the first occurrence when a directive is repeated in one policy', () => {
    const policy = parsePolicy("script-src 'self'; script-src 'none'");
    expect(policy.directives.get('script-src')).toEqual(["'self'"]);
  });

  it('ignores empty segments produced by trailing semicolons', () => {
    expect([...parsePolicy("default-src 'self';;").directives.keys()]).toEqual(['default-src']);
  });
});

describe('effectiveSources', () => {
  it('falls back to default-src for fetch directives', () => {
    const policy = parsePolicy("default-src 'self'");
    expect(effectiveSources(policy, 'script-src')).toEqual(["'self'"]);
  });

  // The distinction that makes the framing and base-uri checks correct.
  it.each(['frame-ancestors', 'base-uri', 'form-action'])(
    'does not fall back to default-src for %s',
    (directive) => {
      const policy = parsePolicy("default-src 'self'");
      expect(effectiveSources(policy, directive)).toBeUndefined();
    },
  );
});

describe('cspCheck', () => {
  it('reports a missing policy', async () => {
    const ids = await runCheck(cspCheck, makeContext({ baseline: { response: makeResponse([]) } }));
    expect(ids).toContain('headers/csp/missing');
  });

  it('reports a report-only policy as unenforced', async () => {
    const ids = await runCheck(
      cspCheck,
      makeContext({
        baseline: {
          response: makeResponse([['content-security-policy-report-only', "default-src 'self'"]]),
        },
      }),
    );
    expect(ids).toEqual(['headers/csp/report-only']);
  });

  it("flags 'unsafe-inline' when no nonce or hash supersedes it", async () => {
    expect(await scan("script-src 'self' 'unsafe-inline'")).toContain(
      'headers/csp/unsafe-inline-script',
    );
  });

  // Browsers ignore 'unsafe-inline' when a nonce is present, so reporting it
  // there would be a false positive on a correctly built strict policy.
  it("does not flag 'unsafe-inline' alongside a nonce", async () => {
    const ids = await scan("script-src 'self' 'unsafe-inline' 'nonce-abc123'");
    expect(ids).not.toContain('headers/csp/unsafe-inline-script');
  });

  it("does not flag 'unsafe-inline' alongside a hash", async () => {
    const ids = await scan("script-src 'unsafe-inline' 'sha256-abc123='");
    expect(ids).not.toContain('headers/csp/unsafe-inline-script');
  });

  it('flags a wildcard script source', async () => {
    expect(await scan('script-src *')).toContain('headers/csp/wildcard-script-src');
  });

  it("does not flag a wildcard that 'strict-dynamic' renders inert", async () => {
    const ids = await scan("script-src 'nonce-abc' 'strict-dynamic' https:");
    expect(ids).not.toContain('headers/csp/wildcard-script-src');
  });

  it('reports base-uri only when it is absent', async () => {
    expect(await scan("default-src 'self'")).toContain('headers/csp/base-uri-missing');
    expect(await scan("default-src 'self'; base-uri 'none'")).not.toContain(
      'headers/csp/base-uri-missing',
    );
  });

  it("does not report object-src when it is set to 'none'", async () => {
    expect(await scan("default-src 'self'; object-src 'none'")).not.toContain(
      'headers/csp/object-src-unrestricted',
    );
  });

  // Multiple policies are enforced as an intersection: a weakness only survives
  // if every policy permits it.
  it('does not flag a weakness that a second policy constrains', async () => {
    const ids = await scan("script-src 'unsafe-inline'", "script-src 'self'");
    expect(ids).not.toContain('headers/csp/unsafe-inline-script');
  });

  it('flags a weakness that every policy permits', async () => {
    const ids = await scan("script-src 'unsafe-inline'", "script-src 'unsafe-inline' 'self'");
    expect(ids).toContain('headers/csp/unsafe-inline-script');
  });
});
