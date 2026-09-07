import { toSarifLevel } from '../core/severity.js';
import { TOOL_NAME, TOOL_URL, TOOL_VERSION } from '../version.js';
import type { Check, Finding, ScanReport } from '../types.js';

/**
 * SARIF 2.1.0, so results can be uploaded to GitHub code scanning.
 *
 * SARIF is built around findings that live at a file and line. These findings
 * live at a URL, so each result is anchored to the config file that requested
 * the scan and carries the real location in properties and in the message. That
 * is the conventional treatment for a dynamic scanner and it keeps the results
 * clickable in the GitHub UI rather than pointing at line 1 of nothing.
 */
export function toSarif(report: ScanReport, checks: readonly Check[], anchorPath: string): string {
  const rules = checks.map((check) => ({
    id: check.id,
    name: check.title,
    shortDescription: { text: check.title },
    fullDescription: { text: check.description },
    properties: { category: check.category },
  }));

  const knownRuleIds = new Set(rules.map((rule) => rule.id));
  const results = report.results.flatMap((result) =>
    result.findings
      .filter((finding) => knownRuleIds.has(finding.checkId))
      .map((finding) => toResult(finding, anchorPath)),
  );

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: TOOL_URL,
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: report.startedAt,
            endTimeUtc: report.finishedAt,
          },
        ],
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

function toResult(finding: Finding, anchorPath: string): unknown {
  return {
    ruleId: finding.checkId,
    level: toSarifLevel(finding.severity),
    message: { text: `${finding.target}: ${finding.title}. ${finding.summary}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: anchorPath },
          region: { startLine: 1 },
        },
        logicalLocations: [{ name: finding.target, kind: 'resource' }],
      },
    ],
    // Stable across runs so code scanning can track a finding rather than
    // reporting it as new every time the scan runs.
    partialFingerprints: { parapetFindingId: `${finding.target}|${finding.id}` },
    properties: {
      severity: finding.severity,
      confidence: finding.confidence,
      category: finding.category,
      target: finding.target,
      remediation: finding.remediation,
      references: finding.references.map((reference) => reference.url),
    },
  };
}
