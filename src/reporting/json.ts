import type { ScanReport } from '../types.js';

/**
 * The machine-readable form, and the contract other tooling depends on. Kept as
 * a straight serialisation of the report so the JSON shape and the TypeScript
 * types cannot drift apart.
 */
export function toJson(report: ScanReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}
