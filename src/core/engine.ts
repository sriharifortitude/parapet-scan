import { COLLECTORS, collectorById } from '../evidence/index.js';
import { describeError } from './errors.js';
import { compareSeverityDesc } from './severity.js';
import { assertTargetInScope, describeTarget, parseTarget } from './scope.js';
import { UndiciHttpClient } from './http.js';
import type {
  Check,
  CheckError,
  Collector,
  CollectorError,
  CollectorId,
  CollectorResultMap,
  Finding,
  ResolvedConfig,
  ScanContext,
  TargetResult,
} from '../types.js';

export interface ScanTargetOptions {
  readonly checks: readonly Check[];
  readonly config: ResolvedConfig;
}

/**
 * Runs every collector required by the selected checks, then the checks.
 *
 * A collector failure is contained: the checks that required it are recorded as
 * skipped and the rest of the scan proceeds. A partial report that says which
 * parts are missing is more useful than an aborted one, and it matters in CI
 * where a single flaky TLS handshake should not fail a build on the strength of
 * findings that were never evaluated.
 */
export async function scanTarget(
  rawTarget: string,
  options: ScanTargetOptions,
): Promise<TargetResult> {
  const { config, checks } = options;
  const started = Date.now();

  const url = parseTarget(rawTarget);
  await assertTargetInScope(url, { allowPrivateTargets: config.allowPrivateTargets });
  const target = describeTarget(url);

  const http = new UndiciHttpClient({
    userAgent: config.userAgent,
    timeoutMs: config.timeoutMs,
    concurrency: config.concurrency,
    requestDelayMs: config.requestDelayMs,
    maxBodyBytes: config.maxBodyBytes,
    maxRequests: config.maxRequests,
    maxRedirects: 5,
    extraHeaders: config.extraHeaders,
  });

  const results = new Map<CollectorId, CollectorResultMap[CollectorId]>();
  const collectorErrors: CollectorError[] = [];

  const evidenceLookup = <K extends CollectorId>(id: K): CollectorResultMap[K] => {
    if (!results.has(id)) {
      throw new Error(`Evidence "${id}" was requested but the collector did not run.`);
    }
    return results.get(id) as CollectorResultMap[K];
  };

  try {
    for (const collector of orderCollectors(requiredCollectors(checks))) {
      const unmet = collector.dependsOn.filter((id) => !results.has(id));
      if (unmet.length > 0) {
        collectorErrors.push({
          collectorId: collector.id,
          message: `skipped: depends on ${unmet.join(', ')}, which did not complete`,
        });
        continue;
      }

      try {
        const value = await collector.collect({ target, http, config, evidence: evidenceLookup });
        results.set(collector.id, value);
      } catch (error) {
        collectorErrors.push({ collectorId: collector.id, message: describeError(error) });
      }
    }

    const context: ScanContext = {
      target,
      config,
      evidence: evidenceLookup,
      tryEvidence: <K extends CollectorId>(id: K): CollectorResultMap[K] | undefined =>
        results.has(id) ? (results.get(id) as CollectorResultMap[K]) : undefined,
    };

    const findings: Finding[] = [];
    const checkErrors: CheckError[] = [];
    const skippedChecks: string[] = [];

    for (const check of checks) {
      if (check.requires.some((id) => !results.has(id))) {
        skippedChecks.push(check.id);
        continue;
      }

      try {
        for (const input of await check.run(context)) {
          findings.push({
            ...input,
            checkId: check.id,
            category: check.category,
            target: input.target ?? target.url.href,
          });
        }
      } catch (error) {
        checkErrors.push({ checkId: check.id, message: describeError(error) });
      }
    }

    const suppressed = new Set(config.baseline);
    const reported = findings.filter((finding) => !suppressed.has(finding.id));

    return {
      target: target.url.href,
      findings: reported.sort(bySeverityThenId),
      suppressed: findings.filter((finding) => suppressed.has(finding.id)).sort(bySeverityThenId),
      collectorErrors,
      checkErrors,
      skippedChecks,
      requestCount: http.requestCount,
      elapsedMs: Date.now() - started,
    };
  } finally {
    await http.close();
  }
}

function bySeverityThenId(a: Finding, b: Finding): number {
  const bySeverity = compareSeverityDesc(a.severity, b.severity);
  return bySeverity !== 0 ? bySeverity : a.id.localeCompare(b.id);
}

/** Transitive closure of what the selected checks require. */
function requiredCollectors(checks: readonly Check[]): Set<CollectorId> {
  const needed = new Set<CollectorId>();

  const visit = (id: CollectorId): void => {
    if (needed.has(id)) return;
    needed.add(id);
    for (const dependency of collectorById(id).dependsOn) visit(dependency);
  };

  for (const check of checks) {
    for (const id of check.requires) visit(id);
  }
  return needed;
}

/**
 * Dependency order for the collectors in `needed`. The graph is declared in
 * code and is small, but a cycle would deadlock the run, so it is detected
 * rather than assumed away.
 */
function orderCollectors(needed: ReadonlySet<CollectorId>): Collector[] {
  const ordered: Collector[] = [];
  const state = new Map<CollectorId, 'visiting' | 'done'>();

  const visit = (id: CollectorId, path: readonly CollectorId[]): void => {
    if (state.get(id) === 'done') return;
    if (state.get(id) === 'visiting') {
      throw new Error(`Collector dependency cycle: ${[...path, id].join(' -> ')}`);
    }

    state.set(id, 'visiting');
    const collector = collectorById(id);
    for (const dependency of collector.dependsOn) visit(dependency, [...path, id]);
    state.set(id, 'done');
    ordered.push(collector as Collector);
  };

  // Iterating COLLECTORS rather than the set keeps the order deterministic.
  for (const collector of COLLECTORS) {
    if (needed.has(collector.id)) visit(collector.id, []);
  }
  return ordered;
}
