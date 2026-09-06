import type { Evidence, Finding } from '../types.js';

const PLACEHOLDER = '<redacted>';

/**
 * Reports are the artefact that gets attached to a ticket or emailed to a
 * client, so anything that could be a live credential is removed before a
 * reporter ever sees it. Redaction happens once, here, rather than being left
 * to each output format to remember.
 */
export function redactFinding(finding: Finding, headerNames: readonly string[]): Finding {
  const redacted = new Set(headerNames.map((name) => name.toLowerCase()));
  return { ...finding, evidence: finding.evidence.map((item) => redactEvidence(item, redacted)) };
}

function redactEvidence(evidence: Evidence, redacted: ReadonlySet<string>): Evidence {
  switch (evidence.kind) {
    case 'header':
      return redacted.has(evidence.name.toLowerCase())
        ? { ...evidence, value: PLACEHOLDER }
        : evidence;

    case 'exchange':
      return {
        ...evidence,
        ...(evidence.requestHeaders === undefined
          ? {}
          : { requestHeaders: redactHeaderMap(evidence.requestHeaders, redacted) }),
        ...(evidence.responseHeaders === undefined
          ? {}
          : { responseHeaders: redactHeaderMap(evidence.responseHeaders, redacted) }),
      };

    default:
      return evidence;
  }
}

function redactHeaderMap(
  headers: Readonly<Record<string, string>>,
  redacted: ReadonlySet<string>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [
      name,
      redacted.has(name.toLowerCase()) ? PLACEHOLDER : value,
    ]),
  );
}
