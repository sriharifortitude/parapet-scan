import { SEVERITY_ORDER } from '../core/severity.js';
import { TOOL_NAME, TOOL_VERSION } from '../version.js';
import type { Evidence, Finding, ScanReport, Severity, TargetResult } from '../types.js';

/**
 * A single self-contained HTML file, with no external stylesheet or script.
 *
 * Everything interpolated here originates from the scanned target -- header
 * values, markup snippets, response excerpts -- so it is attacker-controlled by
 * definition. Every interpolation goes through escapeHtml, and there is no path
 * that writes raw markup into the document. A scanner that reports on injection
 * flaws by producing a page vulnerable to injection would be an embarrassment,
 * and tests/unit/reporting-html.test.ts asserts the escaping directly.
 */
export function toHtml(report: ScanReport): string {
  const generated = new Date(report.finishedAt).toISOString().replace('T', ' ').slice(0, 19);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security posture report</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #ffffff; --fg: #16181d; --muted: #5c6370; --line: #e2e5ea; --card: #f7f8fa;
    --critical: #7f1d1d; --high: #b91c1c; --medium: #b45309; --low: #0369a1; --info: #64748b;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #101215; --fg: #e6e8ec; --muted: #9aa2b1; --line: #262b33; --card: #171a1f;
      --critical: #fca5a5; --high: #f87171; --medium: #fbbf24; --low: #7dd3fc; --info: #94a3b8;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2.5rem 1.5rem; background: var(--bg); color: var(--fg);
    font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  main { max-width: 60rem; margin: 0 auto; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
  h2 { font-size: 1.05rem; margin: 2.5rem 0 .75rem; padding-bottom: .4rem; border-bottom: 1px solid var(--line); word-break: break-all; }
  .meta { color: var(--muted); font-size: .85rem; margin-bottom: 2rem; }
  .tallies { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: 1rem; }
  .tally { border: 1px solid var(--line); border-radius: 6px; padding: .4rem .7rem; font-size: .8rem; font-weight: 600; letter-spacing: .02em; }
  .finding { border: 1px solid var(--line); border-left-width: 4px; border-radius: 6px; background: var(--card); padding: 1rem 1.1rem; margin-bottom: .9rem; }
  .finding header { display: flex; flex-wrap: wrap; align-items: baseline; gap: .6rem; margin-bottom: .5rem; }
  .sev { font-size: .72rem; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; }
  .title { font-weight: 600; }
  .id { color: var(--muted); font-size: .75rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin-left: auto; }
  .summary { margin: 0 0 .7rem; }
  .fix { margin: 0 0 .7rem; font-size: .92rem; }
  .fix strong { font-weight: 600; }
  details { font-size: .85rem; }
  summary { cursor: pointer; color: var(--muted); }
  pre { overflow-x: auto; background: var(--bg); border: 1px solid var(--line); border-radius: 4px; padding: .6rem .7rem; margin: .5rem 0 0; font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
  .refs { margin: .6rem 0 0; padding-left: 1.1rem; font-size: .82rem; }
  .refs a { color: inherit; }
  .clean { color: var(--muted); }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .8rem; }
${SEVERITY_ORDER.map(
  (severity) =>
    `  .s-${severity} { border-left-color: var(--${severity}); } .s-${severity} .sev { color: var(--${severity}); }`,
).join('\n')}
</style>
</head>
<body>
<main>
<h1>Security posture report</h1>
<p class="meta">Generated ${escapeHtml(generated)} UTC by ${escapeHtml(TOOL_NAME)} ${escapeHtml(TOOL_VERSION)}</p>
<div class="tallies">${renderTallies(report.summary)}</div>
${report.results.map(renderTarget).join('\n')}
<footer>
Findings describe the configuration observed from outside the application at the time of the
scan. They are not a substitute for a manual review, and severity follows the project's own
documented rubric rather than a CVSS calculation.
</footer>
</main>
</body>
</html>
`;
}

function renderTallies(summary: Readonly<Record<Severity, number>>): string {
  const present = SEVERITY_ORDER.slice()
    .reverse()
    .filter((severity) => (summary[severity] ?? 0) > 0);

  if (present.length === 0) return '<span class="tally clean">No findings</span>';

  return present
    .map(
      (severity) =>
        `<span class="tally s-${severity}" style="color: var(--${severity})">${summary[severity]} ${severity}</span>`,
    )
    .join('');
}

function renderTarget(result: TargetResult): string {
  const body =
    result.findings.length === 0
      ? '<p class="clean">No findings.</p>'
      : result.findings.map(renderFinding).join('\n');

  const notes: string[] = [];
  if (result.suppressed.length > 0) {
    notes.push(`${result.suppressed.length} finding(s) suppressed by the baseline.`);
  }
  if (result.skippedChecks.length > 0) {
    notes.push(`${result.skippedChecks.length} check(s) skipped for want of evidence.`);
  }
  for (const error of result.collectorErrors) {
    notes.push(`Evidence "${error.collectorId}" unavailable: ${error.message}`);
  }

  return `<h2>${escapeHtml(result.target)}</h2>
${body}
${notes.length === 0 ? '' : `<p class="clean">${notes.map(escapeHtml).join('<br>')}</p>`}`;
}

function renderFinding(finding: Finding): string {
  const evidence = finding.evidence.map(describeEvidence).filter((line) => line !== '');

  return `<article class="finding s-${finding.severity}">
  <header>
    <span class="sev">${escapeHtml(finding.severity)}</span>
    <span class="title">${escapeHtml(finding.title)}</span>
    <span class="id">${escapeHtml(finding.id)}</span>
  </header>
  <p class="summary">${escapeHtml(finding.summary)}</p>
  <p class="fix"><strong>Remediation.</strong> ${escapeHtml(finding.remediation)}</p>
${
  evidence.length === 0
    ? ''
    : `  <details><summary>Evidence (${evidence.length})</summary><pre>${escapeHtml(evidence.join('\n'))}</pre></details>`
}
${
  finding.references.length === 0
    ? ''
    : `  <ul class="refs">${finding.references
        .map(
          (reference) =>
            `<li><a href="${escapeHtml(safeUrl(reference.url))}" rel="noopener noreferrer">${escapeHtml(reference.title)}</a></li>`,
        )
        .join('')}</ul>`
}
</article>`;
}

function describeEvidence(evidence: Evidence): string {
  switch (evidence.kind) {
    case 'header':
      return `${evidence.name}: ${evidence.value}`;
    case 'missing-header':
      return `${evidence.name}: (absent)`;
    case 'exchange':
      return [
        `${evidence.method} ${evidence.url} -> ${evidence.status}`,
        ...Object.entries(evidence.requestHeaders ?? {}).map(([k, v]) => `  > ${k}: ${v}`),
        ...Object.entries(evidence.responseHeaders ?? {}).map(([k, v]) => `  < ${k}: ${v}`),
      ].join('\n');
    case 'body':
      return `${evidence.url}\n  ${evidence.excerpt}`;
    case 'markup':
      return evidence.snippet;
    case 'certificate':
      return Object.entries(evidence.detail)
        .map(([key, value]) => `${key}: ${value}`)
        .join('\n');
    case 'note':
      return evidence.text;
  }
}

/**
 * Reference URLs are authored in this codebase rather than taken from the
 * target, but the check runs anyway: it costs nothing and it means adding a
 * reference can never introduce a javascript: URL into the report.
 */
function safeUrl(url: string): string {
  return /^https?:\/\//i.test(url) ? url : '#';
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
