import { beforeAll, describe, expect, it } from 'vitest';

import { scanTarget } from '../../src/core/engine.js';
import { selectChecks } from '../../src/checks/index.js';
import { toHtml } from '../../src/reporting/html.js';
import { makeConfig } from '../helpers/context.js';
import type { TargetResult } from '../../src/types.js';

const LAB = 'http://127.0.0.1:8080';

/**
 * These run the real engine over real HTTP against the container in lab/.
 * Nothing here is mocked, so a break in the HTTP client, the collectors or the
 * check wiring shows up as a failure rather than passing against a stub.
 */
async function scan(path: string): Promise<TargetResult> {
  const config = makeConfig({ allowPrivateTargets: true, requestDelayMs: 0 });
  return scanTarget(`${LAB}${path}`, {
    checks: selectChecks({ disabled: [], categories: [] }),
    config,
  });
}

beforeAll(async () => {
  const response = await fetch(`${LAB}/healthz`).catch(() => undefined);
  if (response === undefined || !response.ok) {
    throw new Error(
      `The lab target is not reachable at ${LAB}. Start it with: npm run lab:up`,
    );
  }
});

describe('scanning the vulnerable endpoint', () => {
  let result: TargetResult;
  let ids: string[];

  beforeAll(async () => {
    result = await scan('/');
    ids = result.findings.map((finding) => finding.id);
  });

  it('completes without collector or check errors', () => {
    expect(result.collectorErrors).toEqual([]);
    expect(result.checkErrors).toEqual([]);
    expect(result.skippedChecks).toEqual([]);
  });

  it.each([
    'headers/csp/missing',
    'headers/framing/missing',
    'headers/content-type-options/missing',
    'headers/referrer-policy/missing',
    'headers/cross-origin-opener/missing',
    'headers/permissions-policy/missing',
  ])('reports the missing header finding %s', (id) => {
    expect(ids).toContain(id);
  });

  it('reports the cookie attribute weaknesses', () => {
    expect(ids).toContain('cookies/attributes/no-httponly:sessionid');
    expect(ids).toContain('cookies/attributes/no-samesite:sessionid');
    expect(ids).toContain('cookies/attributes/prefix-violation:__Host-pref');
  });

  it('reports the credentialed CORS reflection exactly once', () => {
    expect(ids).toContain('cors/misconfiguration/reflects-origin');
    expect(ids).toContain('cors/misconfiguration/null-origin');
    expect(ids).toContain('cors/misconfiguration/allowlist-bypass');
    expect(ids.filter((id) => id === 'cors/misconfiguration/reflects-origin')).toHaveLength(1);
    expect(ids).not.toContain('cors/misconfiguration/preflight-reflects-origin');
  });

  it('reports the files that are readable from the web root', () => {
    expect(ids).toContain('disclosure/exposed-paths/git-head-file');
    expect(ids).toContain('disclosure/exposed-paths/git-config-file');
    expect(ids).toContain('disclosure/exposed-paths/dotenv-file');
    expect(ids).toContain('disclosure/exposed-paths/javascript-source-map');
  });

  /**
   * The lab answers every unknown path with a 200 and an HTML body. A scanner
   * keying on status codes would report all of these as exposed; the content
   * signatures are what keep the result honest.
   */
  it.each([
    'disclosure/exposed-paths/subversion-entries-file',
    'disclosure/exposed-paths/macos-directory-index',
    'disclosure/exposed-paths/apache-mod_status-page',
    'disclosure/exposed-paths/phpinfo-output',
  ])('does not report %s against a 200-status soft 404', (id) => {
    expect(ids).not.toContain(id);
  });

  it('reports the markup findings', () => {
    expect(ids).toContain('content/subresource-integrity/missing');
    expect(ids).toContain('content/insecure-form/password-over-http');
    expect(ids).toContain('content/target-blank/missing-noopener');
  });

  it('reports plaintext transport and the versioned banners', () => {
    expect(ids).toContain('tls/plaintext-transport/http-target');
    expect(ids).toContain('disclosure/server-banner/versioned');
  });

  it('says nothing about HSTS or certificates on a plaintext target', () => {
    expect(ids.filter((id) => id.startsWith('headers/hsts'))).toEqual([]);
    expect(ids.filter((id) => id.startsWith('tls/certificate'))).toEqual([]);
  });

  it('orders findings by descending severity', () => {
    const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const ranks = result.findings.map((finding) => rank[finding.severity]);
    expect(ranks).toEqual([...ranks].sort((a, b) => b - a));
  });

  it('stays within a proportionate request budget', () => {
    // One document, one CORS set, the well-known pair and the fixed path list.
    expect(result.requestCount).toBeLessThanOrEqual(20);
  });

  it('never puts a cookie value in the report', () => {
    expect(JSON.stringify(result)).not.toContain('lab-session-value');
  });

  it('renders the findings to HTML without unescaped markup from the target', () => {
    const html = toHtml({
      tool: { name: 'parapet-scan', version: 'test' },
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      results: [result],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    });
    expect(html).not.toMatch(/<form method="POST"/);
    expect(html).toContain('&lt;form');
  });
});

describe('scanning the hardened endpoint', () => {
  let ids: string[];

  beforeAll(async () => {
    ids = (await scan('/hardened')).findings.map((finding) => finding.id);
  });

  // The other half of the assertion: checks must go quiet when the
  // configuration is correct, or they are just noise generators.
  it.each([
    'headers/csp/missing',
    'headers/csp/unsafe-inline-script',
    'headers/csp/base-uri-missing',
    'headers/csp/object-src-unrestricted',
    'headers/framing/missing',
    'headers/content-type-options/missing',
    'headers/referrer-policy/missing',
    'headers/cross-origin-opener/missing',
    'headers/permissions-policy/missing',
  ])('does not report %s', (id) => {
    expect(ids).not.toContain(id);
  });

  it('reports no cookie or subresource findings when none are present', () => {
    expect(ids.filter((id) => id.startsWith('cookies/'))).toEqual([]);
    expect(ids.filter((id) => id.startsWith('content/subresource-integrity'))).toEqual([]);
  });
});

describe('scope enforcement', () => {
  it('refuses a loopback target unless private addresses are allowed', async () => {
    await expect(
      scanTarget(LAB, {
        checks: selectChecks({ disabled: [], categories: [] }),
        config: makeConfig({ allowPrivateTargets: false }),
      }),
    ).rejects.toThrow(/reserved range/i);
  });
});
