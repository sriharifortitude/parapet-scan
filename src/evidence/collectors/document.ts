import { parse } from 'node-html-parser';

import type {
  Collector,
  DocumentEvidence,
  FormElement,
  LinkElement,
  ScriptElement,
} from '../../types.js';

const EMPTY: DocumentEvidence = {
  isHtml: false,
  scripts: [],
  stylesheets: [],
  links: [],
  forms: [],
  insecureSubresources: [],
};

/**
 * Parses the baseline document once so the content checks can share one DOM.
 *
 * Only markup that is present in the served HTML is visible here. Anything a
 * client-side framework injects after hydration is out of scope, which is
 * stated in the README rather than papered over with a headless browser.
 */
export const documentCollector: Collector<'document'> = {
  id: 'document',
  description: 'Parses the served HTML for subresources, links and forms.',
  dependsOn: ['baseline'],

  collect(ctx): Promise<DocumentEvidence> {
    const { response } = ctx.evidence('baseline');
    const contentType = response.headers.get('content-type') ?? '';
    if (!/^\s*(text\/html|application\/xhtml\+xml)/i.test(contentType)) {
      return Promise.resolve(EMPTY);
    }

    const root = parse(response.body, { comment: false });
    const base = new URL(response.url);
    const insecure = new Set<string>();

    const scripts: ScriptElement[] = [];
    for (const element of root.querySelectorAll('script[src]')) {
      const src = element.getAttribute('src');
      if (src === undefined || src === '') continue;
      const resolved = resolve(src, base);
      if (resolved !== undefined) noteInsecure(resolved, base, insecure);
      scripts.push({
        src: resolved?.href ?? src,
        ...attr(element.getAttribute('integrity'), 'integrity'),
        ...attr(element.getAttribute('crossorigin'), 'crossorigin'),
        isCrossOrigin: resolved !== undefined && resolved.origin !== base.origin,
      });
    }

    const stylesheets: ScriptElement[] = [];
    for (const element of root.querySelectorAll('link[rel~="stylesheet"][href]')) {
      const href = element.getAttribute('href');
      if (href === undefined || href === '') continue;
      const resolved = resolve(href, base);
      if (resolved !== undefined) noteInsecure(resolved, base, insecure);
      stylesheets.push({
        src: resolved?.href ?? href,
        ...attr(element.getAttribute('integrity'), 'integrity'),
        ...attr(element.getAttribute('crossorigin'), 'crossorigin'),
        isCrossOrigin: resolved !== undefined && resolved.origin !== base.origin,
      });
    }

    const links: LinkElement[] = [];
    for (const element of root.querySelectorAll('a[href]')) {
      const href = element.getAttribute('href');
      if (href === undefined || href === '') continue;
      const target = element.getAttribute('target');
      links.push({
        href: resolve(href, base)?.href ?? href,
        ...attr(target, 'target'),
        relTokens: tokenise(element.getAttribute('rel')),
      });
    }

    const forms: FormElement[] = [];
    for (const element of root.querySelectorAll('form')) {
      const action = element.getAttribute('action');
      const resolved = action === undefined || action === '' ? base : resolve(action, base);
      if (resolved !== undefined) noteInsecure(resolved, base, insecure);
      forms.push({
        action: resolved?.href ?? action ?? base.href,
        method: (element.getAttribute('method') ?? 'GET').toUpperCase(),
        hasPasswordField: element.querySelectorAll('input[type="password"]').length > 0,
      });
    }

    const generator = root.querySelector('meta[name="generator" i]')?.getAttribute('content');

    return Promise.resolve({
      isHtml: true,
      scripts,
      stylesheets,
      links,
      forms,
      insecureSubresources: [...insecure],
      ...(generator === undefined || generator === '' ? {} : { generatorMeta: generator }),
    });
  },
};

function resolve(value: string, base: URL): URL | undefined {
  try {
    return new URL(value, base);
  } catch {
    return undefined;
  }
}

function noteInsecure(resolved: URL, base: URL, sink: Set<string>): void {
  if (base.protocol === 'https:' && resolved.protocol === 'http:') sink.add(resolved.href);
}

function tokenise(value: string | undefined): string[] {
  return (value ?? '')
    .split(/\s+/)
    .map((token) => token.toLowerCase())
    .filter((token) => token !== '');
}

/** Keeps optional attributes absent rather than explicitly undefined. */
function attr<K extends string>(
  value: string | undefined,
  key: K,
): Partial<Record<K, string>> {
  return value === undefined || value === '' ? {} : ({ [key]: value } as Record<K, string>);
}
