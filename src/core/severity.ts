import type { Severity } from '../types.js';

/**
 * Severities are assigned from the rubric in docs/severity-rubric.md, not from a
 * calculated CVSS vector. A configuration weakness observed from outside the
 * application has no reliable exploitability or scope input, so a numeric score
 * would imply precision the evidence does not support.
 */
export const SEVERITY_ORDER: readonly Severity[] = [
  'info',
  'low',
  'medium',
  'high',
  'critical',
] as const;

const RANK = new Map<Severity, number>(SEVERITY_ORDER.map((s, i) => [s, i]));

export function severityRank(severity: Severity): number {
  return RANK.get(severity) ?? 0;
}

/** True when `severity` is at or above `threshold`. Drives the CI exit code. */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) >= severityRank(threshold);
}

export function compareSeverityDesc(a: Severity, b: Severity): number {
  return severityRank(b) - severityRank(a);
}

/** SARIF has three levels plus "none"; this is the documented lossy mapping. */
export function toSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
  }
}
