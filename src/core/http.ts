import { Agent, request as undiciRequest } from 'undici';

import { HeaderBag } from './headers.js';
import { RequestBudgetError, describeError } from './errors.js';
import type { HttpClient, HttpRequestOptions, HttpResponse, RedirectHop } from '../types.js';

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export interface HttpClientOptions {
  readonly userAgent: string;
  readonly timeoutMs: number;
  readonly concurrency: number;
  readonly requestDelayMs: number;
  readonly maxBodyBytes: number;
  readonly maxRequests: number;
  readonly maxRedirects: number;
  readonly extraHeaders: Readonly<Record<string, string>>;
}

/**
 * Serialises access so at most `limit` requests are in flight, and enforces a
 * minimum gap between request starts. Both matter: a scanner that opens thirty
 * sockets against a small production site is indistinguishable from an attack,
 * and several of the checks here are only meaningful against an origin that is
 * not simultaneously rate-limiting us.
 */
class RequestGate {
  #active = 0;
  #lastStart = 0;
  readonly #queue: Array<() => void> = [];

  constructor(
    private readonly limit: number,
    private readonly minGapMs: number,
  ) {}

  async acquire(): Promise<void> {
    if (this.#active >= this.limit) {
      await new Promise<void>((resolve) => this.#queue.push(resolve));
    }
    this.#active += 1;

    const wait = this.#lastStart + this.minGapMs - Date.now();
    if (wait > 0) await sleep(wait);
    this.#lastStart = Date.now();
  }

  release(): void {
    this.#active -= 1;
    this.#queue.shift()?.();
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class UndiciHttpClient implements HttpClient {
  #requestCount = 0;
  readonly #gate: RequestGate;
  readonly #agent: Agent;

  constructor(private readonly options: HttpClientOptions) {
    this.#gate = new RequestGate(options.concurrency, options.requestDelayMs);
    this.#agent = new Agent({
      connections: options.concurrency,
      headersTimeout: options.timeoutMs,
      bodyTimeout: options.timeoutMs,
      connectTimeout: options.timeoutMs,
      // Redirects are followed by hand so the chain can be reported on: an
      // http -> https upgrade is itself a finding input.
      maxRedirections: 0,
    });
  }

  get requestCount(): number {
    return this.#requestCount;
  }

  async close(): Promise<void> {
    await this.#agent.close();
  }

  async request(url: string | URL, options: HttpRequestOptions = {}): Promise<HttpResponse> {
    const requestedUrl = typeof url === 'string' ? url : url.href;
    const method = options.method ?? 'GET';
    const followRedirects = options.followRedirects ?? true;
    const maxBodyBytes = options.maxBodyBytes ?? this.options.maxBodyBytes;

    const redirects: RedirectHop[] = [];
    const started = Date.now();
    let currentUrl = requestedUrl;

    for (let hop = 0; ; hop += 1) {
      const single = await this.#send(currentUrl, method, options.headers ?? {}, maxBodyBytes);

      const location = single.headers.get('location');
      const isRedirect = REDIRECT_STATUSES.has(single.status) && location !== undefined;

      if (!followRedirects || !isRedirect || hop >= this.options.maxRedirects) {
        return {
          url: currentUrl,
          requestedUrl,
          method,
          status: single.status,
          headers: single.headers,
          body: single.body,
          bodyBytes: single.bodyBytes,
          truncated: single.truncated,
          redirects,
          elapsedMs: Date.now() - started,
        };
      }

      redirects.push({ url: currentUrl, status: single.status, location });

      let next: URL;
      try {
        next = new URL(location, currentUrl);
      } catch {
        // A malformed Location is worth surfacing, so stop here and let the
        // checks see the 3xx response rather than throwing the run away.
        return {
          url: currentUrl,
          requestedUrl,
          method,
          status: single.status,
          headers: single.headers,
          body: single.body,
          bodyBytes: single.bodyBytes,
          truncated: single.truncated,
          redirects,
          elapsedMs: Date.now() - started,
        };
      }
      currentUrl = next.href;
    }
  }

  async #send(
    url: string,
    method: string,
    headers: Readonly<Record<string, string>>,
    maxBodyBytes: number,
  ): Promise<{ status: number; headers: HeaderBag; body: string; bodyBytes: number; truncated: boolean }> {
    if (this.#requestCount >= this.options.maxRequests) {
      throw new RequestBudgetError(
        `Request budget of ${this.options.maxRequests} exhausted.`,
        'Raise maxRequests in the config if the scan legitimately needs more requests.',
      );
    }

    await this.#gate.acquire();
    this.#requestCount += 1;
    try {
      const response = await undiciRequest(url, {
        method: method as 'GET',
        dispatcher: this.#agent,
        headers: {
          'user-agent': this.options.userAgent,
          accept: '*/*',
          'accept-encoding': 'identity',
          ...this.options.extraHeaders,
          ...headers,
        },
      });

      const { text, bytes, truncated } = await readCapped(response.body, maxBodyBytes);
      return {
        status: response.statusCode,
        headers: HeaderBag.from(response.headers),
        body: text,
        bodyBytes: bytes,
        truncated,
      };
    } catch (error) {
      throw new Error(`${method} ${url} failed: ${describeError(error)}`, { cause: error });
    } finally {
      this.#gate.release();
    }
  }
}

/**
 * Reads at most `limit` bytes then abandons the rest. Responses are attacker
 * controlled, so an unbounded read is a denial-of-service against the scanner.
 */
async function readCapped(
  body: AsyncIterable<Buffer> & { destroy?: (error?: Error) => void },
  limit: number,
): Promise<{ text: string; bytes: number; truncated: boolean }> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  let truncated = false;

  for await (const chunk of body) {
    bytes += chunk.length;
    if (bytes >= limit) {
      chunks.push(chunk.subarray(0, chunk.length - (bytes - limit)));
      truncated = true;
      body.destroy?.();
      break;
    }
    chunks.push(chunk);
  }

  return {
    text: Buffer.concat(chunks).toString('utf8'),
    bytes: truncated ? limit : bytes,
    truncated,
  };
}
