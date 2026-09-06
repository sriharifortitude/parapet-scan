import pc from 'picocolors';

import { SEVERITY_ORDER } from '../core/severity.js';
import type { Evidence, Finding, ScanReport, Severity, TargetResult } from '../types.js';

const LABEL: Readonly<Record<Severity, (text: string) => string>> = {
  critical: (text) => pc.bgRed(pc.white(pc.bold(text))),
  high: (text) => pc.red(pc.bold(text)),
  medium: (text) => pc.yellow(pc.bold(text)),
  low: (text) => pc.cyan(text),
  info: (text) => pc.dim(text),
};

export interface TerminalOptions {
  /** Hide info-level findings, which are hardening notes rather than weaknesses. */
  readonly quiet: boolean;
  readonly showEvidence: boolean;
}

export function renderTerminal(report: ScanReport, options: TerminalOptions): string {
  const lines: string[] = [];

  for (const result of report.results) {
    lines.push('', pc.bold(pc.underline(result.target)), '');
    renderTarget(result, options, lines);
  }

  lines.push('', ...renderSummary(report), '');
  return lines.join('\n');
}

function renderTarget(result: TargetResult, options: TerminalOptions, lines: string[]): void {
  const visible = options.quiet
    ? result.findings.filter((finding) => finding.severity !== 'info')
    : result.findings;

  if (visible.length === 0) {
    lines.push(pc.green('  No findings at the selected severity levels.'));
  }

  for (const finding of visible) {
    lines.push(
      `  ${LABEL[finding.severity](finding.severity.toUpperCase().padEnd(8))} ${pc.bold(finding.title)}`,
      `           ${pc.dim(finding.id)} ${pc.dim(`(${finding.confidence})`)}`,
      ...wrap(finding.summary, 11),
      `${' '.repeat(11)}${pc.dim('Fix:')} ${wrap(finding.remediation, 11).join('\n').trimStart()}`,
    );

    if (options.showEvidence) {
      for (const item of finding.evidence.slice(0, 4)) {
        lines.push(`${' '.repeat(11)}${pc.dim(describeEvidence(item))}`);
      }
    }
    lines.push('');
  }

  if (result.suppressed.length > 0) {
    lines.push(pc.dim(`  ${result.suppressed.length} finding(s) suppressed by the baseline.`), '');
  }

  for (const error of result.collectorErrors) {
    lines.push(pc.yellow(`  ! evidence "${error.collectorId}" unavailable: ${error.message}`));
  }
  for (const error of result.checkErrors) {
    lines.push(pc.yellow(`  ! check "${error.checkId}" failed: ${error.message}`));
  }
  if (result.skippedChecks.length > 0) {
    lines.push(
      pc.yellow(
        `  ! ${result.skippedChecks.length} check(s) skipped for want of evidence: ` +
          result.skippedChecks.join(', '),
      ),
    );
  }
  if (
    result.collectorErrors.length > 0 ||
    result.checkErrors.length > 0 ||
    result.skippedChecks.length > 0
  ) {
    lines.push('');
  }

  lines.push(
    pc.dim(`  ${result.requestCount} requests in ${(result.elapsedMs / 1000).toFixed(1)}s`),
  );
}

function renderSummary(report: ScanReport): string[] {
  const counts = SEVERITY_ORDER.slice()
    .reverse()
    .filter((severity) => (report.summary[severity] ?? 0) > 0)
    .map((severity) => LABEL[severity](`${report.summary[severity]} ${severity}`));

  return [
    pc.bold('Summary'),
    counts.length === 0 ? pc.green('  Nothing reported.') : `  ${counts.join(pc.dim('  ·  '))}`,
  ];
}

function describeEvidence(evidence: Evidence): string {
  switch (evidence.kind) {
    case 'header':
      return `${evidence.name}: ${truncate(evidence.value, 120)}`;
    case 'missing-header':
      return `${evidence.name}: (absent)`;
    case 'exchange':
      return `${evidence.method} ${evidence.url} -> ${evidence.status}`;
    case 'body':
      return `${evidence.url} -> ${truncate(evidence.excerpt, 120)}`;
    case 'markup':
      return truncate(evidence.snippet, 120);
    case 'certificate':
      return Object.entries(evidence.detail)
        .map(([key, value]) => `${key}=${value}`)
        .join(' ');
    case 'note':
      return evidence.text;
  }
}

function truncate(value: string, limit: number): string {
  return value.length > limit ? `${value.slice(0, limit)}...` : value;
}

/** Wraps at 88 columns rather than reading the terminal width, so piped output is stable. */
function wrap(text: string, indent: number): string[] {
  const width = 88 - indent;
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    if (current === '') current = word;
    else if (current.length + 1 + word.length <= width) current += ` ${word}`;
    else {
      lines.push(current);
      current = word;
    }
  }
  if (current !== '') lines.push(current);

  return lines.map((line) => `${' '.repeat(indent)}${line}`);
}

export function countBySeverity(
  results: readonly TargetResult[],
): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const result of results) {
    for (const finding of result.findings) counts[finding.severity] += 1;
  }
  return counts;
}

export function highestSeverity(findings: readonly Finding[]): Severity | undefined {
  let highest: Severity | undefined;
  for (const finding of findings) {
    if (highest === undefined) highest = finding.severity;
    else if (SEVERITY_ORDER.indexOf(finding.severity) > SEVERITY_ORDER.indexOf(highest)) {
      highest = finding.severity;
    }
  }
  return highest;
}
