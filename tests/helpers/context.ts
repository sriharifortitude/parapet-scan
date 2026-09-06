import { HeaderBag } from '../../src/core/headers.js';
import { DEFAULTS } from '../../src/config/schema.js';
import { describeTarget, parseTarget } from '../../src/core/scope.js';
import type {
  Check,
  CollectorId,
  CollectorResultMap,
  FindingInput,
  HttpResponse,
  ResolvedConfig,
  ScanContext,
} from '../../src/types.js';

/**
 * Builds a response with the given headers so header checks can be exercised
 * without HTTP. Header entries are passed as tuples rather than an object so a
 * test can send the same header twice, which several checks treat as
 * significant.
 */
export function makeResponse(
  headers: Array<readonly [string, string]>,
  options: { url?: string; status?: number; body?: string } = {},
): HttpResponse {
  const url = options.url ?? 'https://target.test/';
  const body = options.body ?? '';

  return {
    url,
    requestedUrl: url,
    method: 'GET',
    status: options.status ?? 200,
    headers: new HeaderBag(headers),
    body,
    bodyBytes: Buffer.byteLength(body),
    truncated: false,
    redirects: [],
    elapsedMs: 1,
  };
}

export function makeConfig(overrides: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    targets: ['https://target.test/'],
    userAgent: 'bastion-scan/test',
    timeoutMs: DEFAULTS.timeoutMs,
    concurrency: DEFAULTS.concurrency,
    requestDelayMs: 0,
    maxBodyBytes: DEFAULTS.maxBodyBytes,
    maxRequests: DEFAULTS.maxRequests,
    failOn: 'high',
    allowPrivateTargets: false,
    disabledChecks: [],
    categories: [],
    baseline: [],
    extraHeaders: {},
    redactHeaders: [...DEFAULTS.redactHeaders],
    probeExposedPaths: true,
    ...overrides,
  };
}

export function makeContext(
  evidence: Partial<CollectorResultMap>,
  options: { target?: string; config?: Partial<ResolvedConfig> } = {},
): ScanContext {
  const target = describeTarget(parseTarget(options.target ?? 'https://target.test/'));
  const config = makeConfig(options.config);

  return {
    target,
    config,
    evidence<K extends CollectorId>(id: K): CollectorResultMap[K] {
      const value = evidence[id];
      if (value === undefined) throw new Error(`test context has no "${id}" evidence`);
      return value;
    },
    tryEvidence<K extends CollectorId>(id: K): CollectorResultMap[K] | undefined {
      return evidence[id];
    },
  };
}

/** Runs a check and returns the finding ids, which is what most assertions care about. */
export async function runCheck(check: Check, context: ScanContext): Promise<string[]> {
  const findings = await check.run(context);
  return findings.map((finding: FindingInput) => finding.id);
}
