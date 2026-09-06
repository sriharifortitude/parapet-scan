import { describe, expect, it } from 'vitest';

import { escapeHtml, toHtml } from '../../src/reporting/html.js';
import { toSarif } from '../../src/reporting/sarif.js';
import { redactFinding } from '../../src/reporting/redact.js';
import { meetsThreshold, toSarifLevel } from '../../src/core/severity.js';
import type { Check, Finding, ScanReport } from '../../src/types.js';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'headers/csp/missing',
    checkId: 'headers/csp',
    title: 'No Content-Security-Policy',
    category: 'headers',
    severity: 'medium',
    confidence: 'firm',
    target: 'https://target.test/',
    summary: 'The response carries no Content-Security-Policy.',
    evidence: [{ kind: 'missing-header', name: 'content-security-policy' }],
    remediation: 'Introduce a nonce-based policy.',
    references: [{ title: 'MDN', url: 'https://developer.mozilla.org/' }],
    ...overrides,
  };
}

function report(findings: Finding[]): ScanReport {
  return {
    tool: { name: 'bastion-scan', version: '0.1.0' },
    startedAt: '2026-01-01T00:00:00.000Z',
    finishedAt: '2026-01-01T00:00:05.000Z',
    results: [
      {
        target: 'https://target.test/',
        findings,
        suppressed: [],
        collectorErrors: [],
        checkErrors: [],
        skippedChecks: [],
        requestCount: 12,
        elapsedMs: 5000,
      },
    ],
    summary: { critical: 0, high: 0, medium: findings.length, low: 0, info: 0 },
  };
}

describe('meetsThreshold', () => {
  it('includes the threshold itself and everything above it', () => {
    expect(meetsThreshold('high', 'high')).toBe(true);
    expect(meetsThreshold('critical', 'high')).toBe(true);
    expect(meetsThreshold('medium', 'high')).toBe(false);
    expect(meetsThreshold('info', 'info')).toBe(true);
  });
});

describe('toSarifLevel', () => {
  it('maps the five severities onto the three SARIF levels', () => {
    expect(toSarifLevel('critical')).toBe('error');
    expect(toSarifLevel('high')).toBe('error');
    expect(toSarifLevel('medium')).toBe('warning');
    expect(toSarifLevel('low')).toBe('note');
    expect(toSarifLevel('info')).toBe('note');
  });
});

describe('redactFinding', () => {
  it('replaces the value of a header on the redaction list', () => {
    const redacted = redactFinding(
      finding({ evidence: [{ kind: 'header', name: 'Authorization', value: 'Bearer secret' }] }),
      ['authorization'],
    );
    expect(JSON.stringify(redacted)).not.toContain('Bearer secret');
  });

  it('redacts inside an exchange on both request and response headers', () => {
    const redacted = redactFinding(
      finding({
        evidence: [
          {
            kind: 'exchange',
            method: 'GET',
            url: 'https://target.test/',
            status: 200,
            requestHeaders: { cookie: 'sid=secret-value' },
            responseHeaders: { 'set-cookie': 'sid=secret-value' },
          },
        ],
      }),
      ['cookie', 'set-cookie'],
    );
    expect(JSON.stringify(redacted)).not.toContain('secret-value');
  });

  it('leaves headers that are not on the list alone', () => {
    const redacted = redactFinding(
      finding({ evidence: [{ kind: 'header', name: 'server', value: 'nginx/1.2.3' }] }),
      ['authorization'],
    );
    expect(JSON.stringify(redacted)).toContain('nginx/1.2.3');
  });
});

describe('escapeHtml', () => {
  it('escapes every character that could break out of markup or an attribute', () => {
    expect(escapeHtml(`<script>alert('x' + "y")</script>&`)).toBe(
      '&lt;script&gt;alert(&#39;x&#39; + &quot;y&quot;)&lt;/script&gt;&amp;',
    );
  });
});

describe('toHtml', () => {
  // Report content comes from the scanned target, so it is attacker-controlled.
  it('escapes hostile content in a finding title', () => {
    const html = toHtml(report([finding({ title: '<img src=x onerror=alert(1)>' })]));
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('escapes hostile content in header evidence', () => {
    const html = toHtml(
      report([
        finding({
          evidence: [{ kind: 'header', name: 'server', value: '</pre><script>alert(1)</script>' }],
        }),
      ]),
    );
    expect(html).not.toContain('<script>alert(1)</script>');
  });

  it('escapes hostile content in a response body excerpt', () => {
    const html = toHtml(
      report([
        finding({
          evidence: [
            { kind: 'body', url: 'https://target.test/.env', excerpt: '"><svg onload=alert(1)>' },
          ],
        }),
      ]),
    );
    expect(html).not.toContain('<svg onload');
  });

  it('escapes the target URL', () => {
    const html = toHtml(report([finding({ target: 'https://target.test/"><script>x</script>' })]));
    expect(html).not.toContain('<script>x</script>');
  });

  it('renders a clean report when there are no findings', () => {
    const html = toHtml(report([]));
    expect(html).toContain('No findings');
  });
});

describe('toSarif', () => {
  const checks: Check[] = [
    {
      id: 'headers/csp',
      title: 'Content-Security-Policy',
      category: 'headers',
      description: 'Evaluates the enforced policy.',
      requires: ['baseline'],
      run: () => [],
    },
  ];

  it('emits a valid 2.1.0 envelope with the rule and result linked', () => {
    const parsed = JSON.parse(toSarif(report([finding()]), checks, 'bastion.yml')) as {
      version: string;
      runs: Array<{
        tool: { driver: { rules: Array<{ id: string }> } };
        results: Array<{ ruleId: string; level: string; partialFingerprints: unknown }>;
      }>;
    };

    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs[0]!.tool.driver.rules[0]!.id).toBe('headers/csp');
    expect(parsed.runs[0]!.results[0]!.ruleId).toBe('headers/csp');
    expect(parsed.runs[0]!.results[0]!.level).toBe('warning');
    expect(parsed.runs[0]!.results[0]!.partialFingerprints).toEqual({
      bastionFindingId: 'https://target.test/|headers/csp/missing',
    });
  });

  // A result whose ruleId is not in the rules array is rejected by consumers.
  it('omits results whose check is not in the rule set', () => {
    const parsed = JSON.parse(
      toSarif(report([finding({ checkId: 'not/registered' })]), checks, 'bastion.yml'),
    ) as { runs: Array<{ results: unknown[] }> };
    expect(parsed.runs[0]!.results).toEqual([]);
  });
});
