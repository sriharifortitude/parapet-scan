/**
 * Set-Cookie parser. The header is not comma-separable (Expires contains a
 * comma), so each header value is parsed on its own and duplicates are kept
 * distinct by the HeaderBag rather than being joined.
 */

export interface ParsedCookie {
  readonly name: string;
  readonly value: string;
  readonly raw: string;
  readonly secure: boolean;
  readonly httpOnly: boolean;
  readonly sameSite?: 'strict' | 'lax' | 'none';
  /** Present verbatim when the cookie sets one; absent means host-only. */
  readonly domain?: string;
  readonly path?: string;
  readonly maxAge?: number;
  readonly expires?: string;
}

export function parseSetCookie(raw: string): ParsedCookie | undefined {
  const parts = raw.split(';');
  const pair = parts.shift();
  if (pair === undefined) return undefined;

  const equals = pair.indexOf('=');
  if (equals <= 0) return undefined;

  const name = pair.slice(0, equals).trim();
  const value = pair.slice(equals + 1).trim();
  if (name === '') return undefined;

  let secure = false;
  let httpOnly = false;
  let sameSite: ParsedCookie['sameSite'];
  let domain: string | undefined;
  let path: string | undefined;
  let maxAge: number | undefined;
  let expires: string | undefined;

  for (const attribute of parts) {
    const trimmed = attribute.trim();
    const splitAt = trimmed.indexOf('=');
    const key = (splitAt === -1 ? trimmed : trimmed.slice(0, splitAt)).toLowerCase();
    const attributeValue = splitAt === -1 ? '' : trimmed.slice(splitAt + 1).trim();

    switch (key) {
      case 'secure':
        secure = true;
        break;
      case 'httponly':
        httpOnly = true;
        break;
      case 'samesite': {
        const normalised = attributeValue.toLowerCase();
        if (normalised === 'strict' || normalised === 'lax' || normalised === 'none') {
          sameSite = normalised;
        }
        break;
      }
      case 'domain':
        domain = attributeValue.replace(/^\./, '');
        break;
      case 'path':
        path = attributeValue;
        break;
      case 'max-age': {
        const parsed = Number(attributeValue);
        if (Number.isFinite(parsed)) maxAge = parsed;
        break;
      }
      case 'expires':
        expires = attributeValue;
        break;
      default:
        break;
    }
  }

  return {
    name,
    value,
    raw,
    secure,
    httpOnly,
    ...(sameSite === undefined ? {} : { sameSite }),
    ...(domain === undefined || domain === '' ? {} : { domain }),
    ...(path === undefined || path === '' ? {} : { path }),
    ...(maxAge === undefined ? {} : { maxAge }),
    ...(expires === undefined || expires === '' ? {} : { expires }),
  };
}

/**
 * Cookie name prefixes are enforced by the browser rather than the server, so
 * a cookie carrying one has integrity guarantees a plain name cannot claim.
 * https://datatracker.ietf.org/doc/html/rfc6265bis
 */
export function prefixRequirementViolation(cookie: ParsedCookie): string | undefined {
  if (cookie.name.startsWith('__Secure-') && !cookie.secure) {
    return '__Secure- prefix requires the Secure attribute';
  }
  if (cookie.name.startsWith('__Host-')) {
    if (!cookie.secure) return '__Host- prefix requires the Secure attribute';
    if (cookie.domain !== undefined) return '__Host- prefix forbids the Domain attribute';
    if (cookie.path !== '/') return '__Host- prefix requires Path=/';
  }
  return undefined;
}

const SESSION_NAME = /(^|[_-])(sess|session|sid|auth|token|jwt|csrf|xsrf|remember|login)/i;

/** Heuristic, and reported as such: cookie naming is a convention, not a contract. */
export function looksSessionBearing(cookie: ParsedCookie): boolean {
  return SESSION_NAME.test(cookie.name);
}

/**
 * A cookie scoped to a registrable parent domain is readable by every sibling
 * host under it. Returns the parent domain when the scope is wider than the
 * host that set it.
 */
export function isScopeWiderThanHost(cookie: ParsedCookie, hostname: string): boolean {
  if (cookie.domain === undefined) return false;
  const scope = cookie.domain.toLowerCase();
  const host = hostname.toLowerCase();
  return scope !== host && host.endsWith(`.${scope}`);
}
