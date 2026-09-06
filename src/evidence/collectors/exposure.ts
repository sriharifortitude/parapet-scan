import { describeError } from '../../core/errors.js';
import type { Collector, ExposedPath, ExposureEvidence } from '../../types.js';

interface Signature {
  readonly path: string;
  readonly name: string;
  /** Must match the body, not just the status code. See the note below. */
  readonly matches: (body: string, contentType: string) => boolean;
}

/**
 * A 200 alone proves nothing. Single-page apps answer every unknown path with
 * their index document, and plenty of hosts serve a styled 404 with a 200
 * status. Reporting on status codes would make this collector a false-positive
 * generator on exactly the modern stacks it is most often pointed at, so each
 * candidate has to produce content that matches a format signature.
 */
const SIGNATURES: readonly Signature[] = [
  {
    path: '/.git/HEAD',
    name: 'git HEAD file',
    matches: (body) => /^ref:\s+refs\//.test(body.trimStart()),
  },
  {
    path: '/.git/config',
    name: 'git config file',
    matches: (body) => /\[core\]/.test(body) && /repositoryformatversion/.test(body),
  },
  {
    path: '/.env',
    name: 'dotenv file',
    matches: (body, contentType) =>
      !/html/i.test(contentType) && /^[A-Z][A-Z0-9_]*=/m.test(body),
  },
  {
    path: '/.svn/entries',
    name: 'subversion entries file',
    matches: (body) => /^\d+\s*$/m.test(body.split('\n')[0] ?? ''),
  },
  {
    path: '/.DS_Store',
    name: 'macOS directory index',
    matches: (body) => body.includes('Bud1'),
  },
  {
    path: '/server-status',
    name: 'Apache mod_status page',
    matches: (body) => /Apache Server Status/i.test(body),
  },
  {
    path: '/phpinfo.php',
    name: 'phpinfo output',
    matches: (body) => /phpinfo\(\)/.test(body) || /PHP Version\s*</i.test(body),
  },
  {
    path: '/.well-known/../.env',
    name: 'dotenv file via path traversal',
    matches: (body, contentType) =>
      !/html/i.test(contentType) && /^[A-Z][A-Z0-9_]*=/m.test(body),
  },
];

const MAX_EXCERPT = 220;

/**
 * Requests a fixed list of paths that should never be publicly readable, plus
 * the source maps referenced by the page's own scripts.
 *
 * This is a fixed list, not a wordlist: the collector issues on the order of a
 * dozen requests, does not recurse, and never guesses application routes. It is
 * an audit of known-bad defaults, not directory brute-forcing.
 */
export const exposureCollector: Collector<'exposure'> = {
  id: 'exposure',
  description: 'Requests a fixed list of paths that should not be publicly readable.',
  dependsOn: ['baseline', 'document'],

  async collect(ctx): Promise<ExposureEvidence> {
    if (!ctx.config.probeExposedPaths) return { exposed: [], probedPaths: 0 };

    const base = new URL(ctx.evidence('baseline').response.url);
    const exposed: ExposedPath[] = [];
    let probedPaths = 0;

    for (const signature of SIGNATURES) {
      const url = new URL(signature.path, base);
      probedPaths += 1;
      const hit = await probe(ctx, url, signature);
      if (hit !== undefined) exposed.push(hit);
    }

    for (const url of sourceMapCandidates(ctx, base)) {
      probedPaths += 1;
      const hit = await probe(ctx, url, {
        path: url.pathname,
        name: 'JavaScript source map',
        matches: (body) => /"(?:sources|mappings)"\s*:/.test(body),
      });
      if (hit !== undefined) exposed.push(hit);
    }

    return { exposed, probedPaths };
  },
};

async function probe(
  ctx: Parameters<Collector<'exposure'>['collect']>[0],
  url: URL,
  signature: Signature,
): Promise<ExposedPath | undefined> {
  try {
    const response = await ctx.http.request(url, {
      followRedirects: false,
      maxBodyBytes: 8192,
    });
    if (response.status !== 200) return undefined;

    const contentType = response.headers.get('content-type') ?? '';
    if (!signature.matches(response.body, contentType)) return undefined;

    return {
      url: url.href,
      status: response.status,
      ...(contentType === '' ? {} : { contentType }),
      bodyExcerpt: excerpt(response.body),
      matchedSignature: signature.name,
    };
  } catch (error) {
    void describeError(error);
    return undefined;
  }
}

/** Only same-origin scripts; probing a CDN's source maps is not this target's business. */
function sourceMapCandidates(
  ctx: Parameters<Collector<'exposure'>['collect']>[0],
  base: URL,
): URL[] {
  const document = ctx.evidence('document');
  const candidates: URL[] = [];

  for (const script of document.scripts) {
    if (script.isCrossOrigin) continue;
    try {
      const url = new URL(script.src, base);
      if (url.origin !== base.origin || !url.pathname.endsWith('.js')) continue;
      url.pathname += '.map';
      url.search = '';
      candidates.push(url);
    } catch {
      continue;
    }
    if (candidates.length >= 3) break;
  }

  return candidates;
}

function excerpt(body: string): string {
  const collapsed = body.replace(/\s+/g, ' ').trim();
  return collapsed.length > MAX_EXCERPT ? `${collapsed.slice(0, MAX_EXCERPT)}...` : collapsed;
}
