import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

import { loadConfig } from '../../config/load.js';
import { scanTarget } from '../../core/engine.js';
import { ParapetError, describeError } from '../../core/errors.js';
import { meetsThreshold } from '../../core/severity.js';
import { selectChecks } from '../../checks/index.js';
import { redactFinding } from '../../reporting/redact.js';
import { countBySeverity, renderTerminal } from '../../reporting/terminal.js';
import { toHtml } from '../../reporting/html.js';
import { toJson } from '../../reporting/json.js';
import { toSarif } from '../../reporting/sarif.js';
import { TOOL_NAME, TOOL_VERSION } from '../../version.js';
import type { Category, ScanReport, Severity, TargetResult } from '../../types.js';

export type OutputFormat = 'terminal' | 'json' | 'sarif' | 'html';

export interface ScanCommandOptions {
  readonly config?: string;
  readonly format: OutputFormat;
  readonly output?: string;
  readonly failOn?: Severity | 'never';
  readonly allowPrivate?: boolean;
  readonly probePaths?: boolean;
  readonly concurrency?: number;
  readonly timeout?: number;
  readonly disable?: readonly string[];
  readonly category?: readonly Category[];
  readonly header?: readonly string[];
  readonly quiet?: boolean;
  readonly evidence?: boolean;
}

/**
 * Exit codes are the CI contract:
 *   0  scan completed, nothing at or above the threshold
 *   1  scan completed, findings at or above the threshold
 *   2  the scan could not be completed
 *
 * Keeping "found problems" and "could not run" distinct is what stops a
 * misconfigured pipeline from reading as a clean bill of health.
 */
export async function runScan(targets: readonly string[], options: ScanCommandOptions): Promise<number> {
  const { config } = await loadConfig(
    { cwd: process.cwd(), ...(options.config === undefined ? {} : { explicitPath: options.config }) },
    {
      targets,
      ...(options.failOn === undefined ? {} : { failOn: options.failOn }),
      ...(options.allowPrivate === undefined ? {} : { allowPrivateTargets: options.allowPrivate }),
      ...(options.probePaths === undefined ? {} : { probeExposedPaths: options.probePaths }),
      ...(options.concurrency === undefined ? {} : { concurrency: options.concurrency }),
      ...(options.timeout === undefined ? {} : { timeoutMs: options.timeout }),
      ...(options.disable === undefined ? {} : { disabledChecks: options.disable }),
      ...(options.category === undefined ? {} : { categories: options.category }),
      headers: parseHeaders(options.header ?? []),
    },
  );

  const checks = selectChecks({
    disabled: config.disabledChecks,
    categories: config.categories,
  });
  if (checks.length === 0) {
    throw new ParapetError(
      'Every check was filtered out.',
      'Check the --category and --disable arguments.',
    );
  }

  const startedAt = new Date().toISOString();
  const results: TargetResult[] = [];
  let hardFailure = false;

  for (const target of config.targets) {
    try {
      const result = await scanTarget(target, { checks, config });
      results.push({
        ...result,
        findings: result.findings.map((finding) => redactFinding(finding, config.redactHeaders)),
        suppressed: result.suppressed.map((finding) =>
          redactFinding(finding, config.redactHeaders),
        ),
      });
    } catch (error) {
      hardFailure = true;
      process.stderr.write(`${TOOL_NAME}: ${target}: ${describeError(error)}\n`);
      if (error instanceof ParapetError && error.hint !== undefined) {
        process.stderr.write(`  ${error.hint}\n`);
      }
    }
  }

  if (results.length === 0) return 2;

  const report: ScanReport = {
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    startedAt,
    finishedAt: new Date().toISOString(),
    results,
    summary: countBySeverity(results),
  };

  await emit(report, options, checks);

  if (hardFailure) return 2;

  if (config.failOn === 'never') return 0;
  const breached = results.some((result) =>
    result.findings.some((finding) => meetsThreshold(finding.severity, config.failOn as Severity)),
  );
  return breached ? 1 : 0;
}

async function emit(
  report: ScanReport,
  options: ScanCommandOptions,
  checks: ReturnType<typeof selectChecks>,
): Promise<void> {
  const rendered =
    options.format === 'json'
      ? toJson(report)
      : options.format === 'sarif'
        ? toSarif(report, checks, options.config ?? 'parapet.yml')
        : options.format === 'html'
          ? toHtml(report)
          : renderTerminal(report, {
              quiet: options.quiet ?? false,
              showEvidence: options.evidence ?? false,
            });

  if (options.output === undefined) {
    process.stdout.write(rendered);
    return;
  }

  await mkdir(dirname(options.output), { recursive: true });
  await writeFile(options.output, rendered, 'utf8');
  process.stderr.write(`${TOOL_NAME}: report written to ${options.output}\n`);
}

/** `--header 'Name: value'`, split on the first colon so values may contain colons. */
function parseHeaders(entries: readonly string[]): Record<string, string> {
  const headers: Record<string, string> = {};

  for (const entry of entries) {
    const separator = entry.indexOf(':');
    if (separator <= 0) {
      throw new ParapetError(
        `Could not parse --header "${entry}".`,
        'Use the form --header "Name: value".',
      );
    }
    headers[entry.slice(0, separator).trim()] = entry.slice(separator + 1).trim();
  }

  return headers;
}
