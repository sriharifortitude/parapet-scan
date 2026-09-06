import type { Check, FindingInput, Severity } from '../../types.js';

/**
 * Severity is per signature rather than uniform. A readable .git directory or a
 * .env file is a direct route to source and credentials; a source map exposes
 * original source but no secret that was not already shipped to the browser.
 */
const SEVERITY_BY_SIGNATURE: Readonly<Record<string, Severity>> = {
  'git HEAD file': 'high',
  'git config file': 'high',
  'dotenv file': 'critical',
  'subversion entries file': 'high',
  'macOS directory index': 'low',
  'Apache mod_status page': 'medium',
  'phpinfo output': 'high',
  'JavaScript source map': 'low',
};

const IMPACT_BY_SIGNATURE: Readonly<Record<string, string>> = {
  'git HEAD file':
    'A readable .git directory usually means the whole repository is retrievable, including ' +
    'full history. Secrets that were committed and later removed remain in that history.',
  'git config file':
    'The git config often carries the remote URL, and where the remote was cloned over https ' +
    'with an embedded token, the credential itself.',
  'dotenv file':
    'Environment files hold database credentials, API keys and signing secrets in plaintext. ' +
    'Treat every value in the retrieved file as compromised.',
  'subversion entries file':
    'The .svn metadata allows reconstruction of the working copy, including files not intended ' +
    'to be served.',
  'macOS directory index':
    'A .DS_Store file lists the names of every file in the directory at the time it was ' +
    'created, including ones that are not linked from anywhere.',
  'Apache mod_status page':
    'The server status page lists active requests with their URLs and client addresses, which ' +
    'discloses application routes and user activity in real time.',
  'phpinfo output':
    'phpinfo lists the full configuration, loaded modules, filesystem paths and often ' +
    'environment variables, giving a precise map of the runtime.',
  'JavaScript source map':
    'The source map contains original, unminified source for the bundle. It exposes internal ' +
    'structure and comments, and occasionally values that were meant to stay in the build.',
};

const REFERENCE = {
  title: 'OWASP WSTG: Review Old Backup and Unreferenced Files',
  url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
};

export const exposedPathsCheck: Check = {
  id: 'disclosure/exposed-paths',
  title: 'Publicly readable sensitive files',
  category: 'disclosure',
  description: 'Reports files that responded with content matching a known sensitive format.',
  requires: ['exposure'],

  run(ctx) {
    const { exposed } = ctx.evidence('exposure');

    return exposed.map((hit): FindingInput => {
      const severity = SEVERITY_BY_SIGNATURE[hit.matchedSignature] ?? 'medium';
      const impact =
        IMPACT_BY_SIGNATURE[hit.matchedSignature] ??
        'The file is readable without authentication.';

      return {
        id: `disclosure/exposed-paths/${slug(hit.matchedSignature)}`,
        title: `${hit.matchedSignature} is publicly readable`,
        severity,
        confidence: 'confirmed',
        target: hit.url,
        summary:
          `${hit.url} returned content matching a ${hit.matchedSignature.toLowerCase()}. ${impact}`,
        evidence: [
          { kind: 'exchange', method: 'GET', url: hit.url, status: hit.status },
          { kind: 'body', url: hit.url, excerpt: hit.bodyExcerpt },
        ],
        remediation:
          'Stop serving the file: deny the path at the web server, and exclude it from the ' +
          'deployment artefact so it is not present to be served. ' +
          (severity === 'critical'
            ? 'Then rotate every credential the file contained -- removing access does not ' +
              'undo the disclosure.'
            : 'Then confirm no other metadata from the same tool is reachable.'),
        references: [REFERENCE],
      };
    });
  },
};

function slug(signature: string): string {
  return signature.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}
