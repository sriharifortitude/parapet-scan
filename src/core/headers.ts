/**
 * HTTP header names are case-insensitive and several headers of interest here
 * (Set-Cookie, Content-Security-Policy) may legitimately appear more than once.
 * Collapsing them into a plain object loses information that checks depend on,
 * so responses carry this instead.
 */
export class HeaderBag {
  readonly #entries: ReadonlyArray<readonly [string, string]>;
  readonly #index: ReadonlyMap<string, readonly string[]>;

  constructor(entries: Iterable<readonly [string, string]>) {
    const list = [...entries].map(([name, value]) => [name, value] as const);
    const index = new Map<string, string[]>();

    for (const [name, value] of list) {
      const key = name.toLowerCase();
      const bucket = index.get(key);
      if (bucket) bucket.push(value);
      else index.set(key, [value]);
    }

    this.#entries = list;
    this.#index = index;
  }

  static from(headers: Record<string, string | string[] | undefined>): HeaderBag {
    const entries: Array<readonly [string, string]> = [];
    for (const [name, value] of Object.entries(headers)) {
      if (value === undefined) continue;
      if (Array.isArray(value)) entries.push(...value.map((v) => [name, v] as const));
      else entries.push([name, value]);
    }
    return new HeaderBag(entries);
  }

  /** First value for `name`, or undefined. Use {@link getAll} when duplicates are meaningful. */
  get(name: string): string | undefined {
    return this.#index.get(name.toLowerCase())?.[0];
  }

  getAll(name: string): readonly string[] {
    return this.#index.get(name.toLowerCase()) ?? [];
  }

  has(name: string): boolean {
    return this.#index.has(name.toLowerCase());
  }

  /** Count of values for `name`; >1 means the origin sent the header more than once. */
  count(name: string): number {
    return this.getAll(name).length;
  }

  names(): readonly string[] {
    return [...this.#index.keys()];
  }

  entries(): ReadonlyArray<readonly [string, string]> {
    return this.#entries;
  }
}
