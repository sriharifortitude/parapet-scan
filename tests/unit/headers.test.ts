import { describe, expect, it } from 'vitest';

import { framingCheck } from '../../src/checks/headers/framing.js';
import { hstsCheck } from '../../src/checks/headers/hsts.js';
import {
  contentTypeOptionsCheck,
  referrerPolicyCheck,
} from '../../src/checks/headers/directives.js';
import { makeContext, makeResponse, runCheck } from '../helpers/context.js';
import type { Check } from '../../src/types.js';

function scan(check: Check, headers: Array<readonly [string, string]>, target?: string) {
  return runCheck(
    check,
    makeContext(
      { baseline: { response: makeResponse(headers) } },
      target === undefined ? {} : { target },
    ),
  );
}

describe('hstsCheck', () => {
  it('reports a missing header on https', async () => {
    expect(await scan(hstsCheck, [])).toEqual(['headers/hsts/missing']);
  });

  // Browsers ignore HSTS over plaintext, so reporting it there is noise.
  it('says nothing on an http target', async () => {
    expect(await scan(hstsCheck, [], 'http://target.test/')).toEqual([]);
  });

  it('accepts a long max-age with includeSubDomains', async () => {
    const ids = await scan(hstsCheck, [
      ['strict-transport-security', 'max-age=31536000; includeSubDomains'],
    ]);
    expect(ids).toEqual([]);
  });

  it('reports a header with no parseable max-age', async () => {
    expect(await scan(hstsCheck, [['strict-transport-security', 'includeSubDomains']])).toContain(
      'headers/hsts/invalid',
    );
  });

  it('recognises max-age=0 as a withdrawal rather than a short policy', async () => {
    expect(await scan(hstsCheck, [['strict-transport-security', 'max-age=0']])).toContain(
      'headers/hsts/disabled',
    );
  });

  it.each([
    ['max-age=600', 'headers/hsts/short-max-age'],
    ['max-age=2592000', 'headers/hsts/low-max-age'],
  ])('grades %s as %s', async (value, expected) => {
    expect(await scan(hstsCheck, [['strict-transport-security', value]])).toContain(expected);
  });

  it('reports a missing includeSubDomains separately', async () => {
    expect(await scan(hstsCheck, [['strict-transport-security', 'max-age=31536000']])).toContain(
      'headers/hsts/no-subdomains',
    );
  });
});

describe('framingCheck', () => {
  it('reports when neither mechanism is present', async () => {
    expect(await scan(framingCheck, [])).toEqual(['headers/framing/missing']);
  });

  // frame-ancestors supersedes X-Frame-Options, so requiring both is a false positive.
  it('accepts frame-ancestors without X-Frame-Options', async () => {
    expect(
      await scan(framingCheck, [['content-security-policy', "frame-ancestors 'none'"]]),
    ).toEqual([]);
  });

  it('reports a wildcard frame-ancestors', async () => {
    expect(await scan(framingCheck, [['content-security-policy', 'frame-ancestors *']])).toEqual([
      'headers/framing/ancestors-wildcard',
    ]);
  });

  // A restrictive default-src does not cover framing.
  it('still reports when only default-src is set', async () => {
    expect(await scan(framingCheck, [['content-security-policy', "default-src 'none'"]])).toEqual([
      'headers/framing/missing',
    ]);
  });

  it.each(['DENY', 'sameorigin'])('accepts X-Frame-Options: %s as protection', async (value) => {
    expect(await scan(framingCheck, [['x-frame-options', value]])).toEqual([
      'headers/framing/xfo-only',
    ]);
  });

  it.each([
    ['ALLOW-FROM https://example.com', 'headers/framing/allow-from-obsolete'],
    ['ALLOWALL', 'headers/framing/invalid-value'],
  ])('reports the unusable value %s', async (value, expected) => {
    expect(await scan(framingCheck, [['x-frame-options', value]])).toEqual([expected]);
  });
});

describe('directive checks', () => {
  it('reports a missing nosniff and accepts a correct one', async () => {
    expect(await scan(contentTypeOptionsCheck, [])).toEqual([
      'headers/content-type-options/missing',
    ]);
    expect(await scan(contentTypeOptionsCheck, [['x-content-type-options', 'nosniff']])).toEqual([]);
  });

  it('reports an unrecognised nosniff value', async () => {
    expect(await scan(contentTypeOptionsCheck, [['x-content-type-options', 'none']])).toEqual([
      'headers/content-type-options/invalid',
    ]);
  });

  it('accepts a strict referrer policy and reports a permissive one', async () => {
    expect(
      await scan(referrerPolicyCheck, [['referrer-policy', 'strict-origin-when-cross-origin']]),
    ).toEqual([]);
    expect(await scan(referrerPolicyCheck, [['referrer-policy', 'unsafe-url']])).toEqual([
      'headers/referrer-policy/permissive',
    ]);
  });
});
