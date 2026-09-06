/**
 * A Content-Security-Policy parser sufficient for auditing a served policy.
 *
 * Two behaviours here are easy to get wrong by matching on the raw string and
 * both change the verdict:
 *
 *  1. Only some directives fall back to default-src. script-src and style-src
 *     do; frame-ancestors, base-uri and form-action do not, so a policy with a
 *     restrictive default-src still has no clickjacking protection.
 *  2. When a header is sent more than once the policies are enforced together
 *     and the result is the intersection -- but a directive absent from one
 *     policy is not constrained by it. Each policy is therefore kept separate.
 */

export interface CspPolicy {
  readonly raw: string;
  readonly directives: ReadonlyMap<string, readonly string[]>;
}

/** Directives that inherit from default-src when absent (CSP Level 3, "fetch directives"). */
const FETCH_DIRECTIVES = new Set([
  'child-src',
  'connect-src',
  'font-src',
  'frame-src',
  'img-src',
  'manifest-src',
  'media-src',
  'object-src',
  'script-src',
  'script-src-attr',
  'script-src-elem',
  'style-src',
  'style-src-attr',
  'style-src-elem',
  'worker-src',
]);

export function parsePolicy(raw: string): CspPolicy {
  const directives = new Map<string, string[]>();

  for (const segment of raw.split(';')) {
    const tokens = segment.trim().split(/\s+/).filter((token) => token !== '');
    const name = tokens.shift()?.toLowerCase();
    if (name === undefined || name === '') continue;
    // A directive repeated inside one policy: the first occurrence wins.
    if (!directives.has(name)) directives.set(name, tokens);
  }

  return { raw, directives };
}

export function parsePolicies(values: readonly string[]): CspPolicy[] {
  return values.map(parsePolicy);
}

/**
 * Source list actually enforced for `directive`, applying default-src fallback
 * only where the specification allows it. Undefined means unconstrained.
 */
export function effectiveSources(
  policy: CspPolicy,
  directive: string,
): readonly string[] | undefined {
  const own = policy.directives.get(directive);
  if (own !== undefined) return own;
  if (!FETCH_DIRECTIVES.has(directive)) return undefined;
  return policy.directives.get('default-src');
}

export function hasKeyword(sources: readonly string[] | undefined, keyword: string): boolean {
  return sources?.some((source) => source.toLowerCase() === `'${keyword}'`) ?? false;
}

/** True when the list permits any origin, e.g. `*`, `https:` or `data:`. */
export function permitsAnyOrigin(sources: readonly string[] | undefined): boolean {
  return (
    sources?.some((source) => {
      const value = source.toLowerCase();
      return value === '*' || value === 'https:' || value === 'http:' || value === 'data:';
    }) ?? false
  );
}

export function hasNonceOrHash(sources: readonly string[] | undefined): boolean {
  return sources?.some((source) => /^'(nonce-|sha(256|384|512)-)/i.test(source)) ?? false;
}

/**
 * `strict-dynamic` makes host-source allowlist entries inert, so a policy that
 * pairs it with a nonce is not weakened by an accompanying wildcard.
 */
export function hasStrictDynamic(sources: readonly string[] | undefined): boolean {
  return hasKeyword(sources, 'strict-dynamic');
}
