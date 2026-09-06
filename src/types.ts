import type { HeaderBag } from './core/headers.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * How much the evidence supports the finding.
 *  - confirmed: the observation is the weakness (e.g. CORS reflected an arbitrary origin)
 *  - firm:      the observation is definitive but impact depends on the app (e.g. missing HSTS)
 *  - tentative: the observation is suggestive and needs human confirmation
 */
export type Confidence = 'confirmed' | 'firm' | 'tentative';

export type Category = 'headers' | 'cookies' | 'cors' | 'tls' | 'disclosure' | 'content';

export interface Reference {
  readonly title: string;
  readonly url: string;
}

export type Evidence =
  | { readonly kind: 'header'; readonly name: string; readonly value: string }
  | { readonly kind: 'missing-header'; readonly name: string }
  | {
      readonly kind: 'exchange';
      readonly method: string;
      readonly url: string;
      readonly status: number;
      readonly requestHeaders?: Readonly<Record<string, string>>;
      readonly responseHeaders?: Readonly<Record<string, string>>;
    }
  | { readonly kind: 'body'; readonly url: string; readonly excerpt: string }
  | { readonly kind: 'markup'; readonly snippet: string; readonly location?: string }
  | { readonly kind: 'certificate'; readonly detail: Readonly<Record<string, string>> }
  | { readonly kind: 'note'; readonly text: string };

export interface Finding {
  /** Stable across runs and versions; used to suppress via the baseline file. */
  readonly id: string;
  readonly checkId: string;
  readonly title: string;
  readonly category: Category;
  readonly severity: Severity;
  readonly confidence: Confidence;
  /** The URL the finding is about, which is not always the scan target. */
  readonly target: string;
  readonly summary: string;
  readonly evidence: readonly Evidence[];
  readonly remediation: string;
  readonly references: readonly Reference[];
}

/** What a check returns; the engine stamps checkId, category and target. */
export type FindingInput = Omit<Finding, 'checkId' | 'category' | 'target'> & {
  readonly target?: string;
};

export interface RedirectHop {
  readonly url: string;
  readonly status: number;
  readonly location: string;
}

export interface HttpResponse {
  /** Final URL after redirects. */
  readonly url: string;
  readonly requestedUrl: string;
  readonly method: string;
  readonly status: number;
  readonly headers: HeaderBag;
  readonly body: string;
  readonly bodyBytes: number;
  /** True when the body exceeded the configured read limit and was cut short. */
  readonly truncated: boolean;
  readonly redirects: readonly RedirectHop[];
  readonly elapsedMs: number;
}

export interface TargetDescriptor {
  readonly url: URL;
  readonly origin: string;
  readonly hostname: string;
  readonly port: number;
  readonly isHttps: boolean;
}

// --- Evidence collectors -------------------------------------------------

export interface BaselineEvidence {
  readonly response: HttpResponse;
}

/** Result of asking for the http:// form of the target. */
export interface TransportEvidence {
  readonly httpProbed: boolean;
  readonly httpReachable: boolean;
  readonly redirectsToHttps: boolean;
  readonly firstHopStatus?: number;
  readonly firstHopLocation?: string;
}

export interface CertificateSummary {
  readonly subject: string;
  readonly issuer: string;
  readonly validFrom: string;
  readonly validTo: string;
  readonly daysUntilExpiry: number;
  readonly subjectAltNames: readonly string[];
  readonly keyBits?: number;
  readonly signatureAlgorithm?: string;
}

export interface TlsEvidence {
  readonly negotiatedProtocol?: string;
  readonly negotiatedCipher?: string;
  readonly certificate?: CertificateSummary;
  /** Protocols the server accepted when offered in isolation. */
  readonly acceptedProtocols: readonly string[];
  readonly errors: readonly string[];
}

export interface ScriptElement {
  readonly src: string;
  readonly integrity?: string;
  readonly crossorigin?: string;
  readonly isCrossOrigin: boolean;
}

export interface LinkElement {
  readonly href: string;
  readonly target?: string;
  readonly relTokens: readonly string[];
}

export interface FormElement {
  readonly action: string;
  readonly method: string;
  readonly hasPasswordField: boolean;
}

export interface DocumentEvidence {
  readonly isHtml: boolean;
  readonly scripts: readonly ScriptElement[];
  readonly stylesheets: readonly ScriptElement[];
  readonly links: readonly LinkElement[];
  readonly forms: readonly FormElement[];
  /** http:// subresources referenced from an https:// document. */
  readonly insecureSubresources: readonly string[];
  readonly generatorMeta?: string;
}

export interface CorsProbe {
  readonly sentOrigin: string;
  readonly label: 'arbitrary' | 'null' | 'subdomain-suffix' | 'preflight';
  readonly allowOrigin?: string;
  readonly allowCredentials?: string;
  readonly allowMethods?: string;
  readonly allowHeaders?: string;
  readonly status: number;
}

export interface CorsEvidence {
  readonly probes: readonly CorsProbe[];
}

export interface WellKnownEvidence {
  readonly securityTxt?: { readonly url: string; readonly status: number };
  readonly robotsTxt?: { readonly url: string; readonly status: number };
}

export interface ExposedPath {
  readonly url: string;
  readonly status: number;
  readonly contentType?: string;
  readonly bodyExcerpt: string;
  readonly matchedSignature: string;
}

export interface ExposureEvidence {
  readonly exposed: readonly ExposedPath[];
  readonly probedPaths: number;
}

export interface CollectorResultMap {
  baseline: BaselineEvidence;
  transport: TransportEvidence;
  tls: TlsEvidence;
  document: DocumentEvidence;
  cors: CorsEvidence;
  'well-known': WellKnownEvidence;
  exposure: ExposureEvidence;
}

export type CollectorId = keyof CollectorResultMap;

export interface CollectorContext {
  readonly target: TargetDescriptor;
  readonly http: HttpClient;
  readonly config: ResolvedConfig;
  /** Collectors may read earlier collectors; the engine fixes the order. */
  evidence<K extends CollectorId>(id: K): CollectorResultMap[K];
}

export interface Collector<K extends CollectorId = CollectorId> {
  readonly id: K;
  readonly description: string;
  /** Collectors this one reads from, so the engine can order and skip correctly. */
  readonly dependsOn: readonly CollectorId[];
  collect(ctx: CollectorContext): Promise<CollectorResultMap[K]>;
}

// --- Checks --------------------------------------------------------------

export interface ScanContext {
  readonly target: TargetDescriptor;
  readonly config: ResolvedConfig;
  /** Throws if the collector did not run; the engine only calls checks whose requires are met. */
  evidence<K extends CollectorId>(id: K): CollectorResultMap[K];
  tryEvidence<K extends CollectorId>(id: K): CollectorResultMap[K] | undefined;
}

export interface Check {
  readonly id: string;
  readonly title: string;
  readonly category: Category;
  readonly description: string;
  /** Collectors that must have succeeded before this check runs. */
  readonly requires: readonly CollectorId[];
  run(ctx: ScanContext): FindingInput[] | Promise<FindingInput[]>;
}

// --- HTTP ----------------------------------------------------------------

export interface HttpRequestOptions {
  readonly method?: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly followRedirects?: boolean;
  readonly maxBodyBytes?: number;
}

export interface HttpClient {
  request(url: string | URL, options?: HttpRequestOptions): Promise<HttpResponse>;
  /** Requests issued so far, for the run summary and the budget ceiling. */
  readonly requestCount: number;
}

// --- Configuration and results ------------------------------------------

export interface ResolvedConfig {
  readonly targets: readonly string[];
  readonly userAgent: string;
  readonly timeoutMs: number;
  readonly concurrency: number;
  readonly requestDelayMs: number;
  readonly maxBodyBytes: number;
  readonly maxRequests: number;
  readonly failOn: Severity | 'never';
  readonly allowPrivateTargets: boolean;
  readonly disabledChecks: readonly string[];
  readonly categories: readonly Category[];
  readonly baseline: readonly string[];
  readonly extraHeaders: Readonly<Record<string, string>>;
  readonly redactHeaders: readonly string[];
  readonly probeExposedPaths: boolean;
}

export interface CollectorError {
  readonly collectorId: CollectorId;
  readonly message: string;
}

export interface CheckError {
  readonly checkId: string;
  readonly message: string;
}

export interface TargetResult {
  readonly target: string;
  readonly findings: readonly Finding[];
  readonly suppressed: readonly Finding[];
  readonly collectorErrors: readonly CollectorError[];
  readonly checkErrors: readonly CheckError[];
  readonly skippedChecks: readonly string[];
  readonly requestCount: number;
  readonly elapsedMs: number;
}

export interface ScanReport {
  readonly tool: { readonly name: string; readonly version: string };
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly results: readonly TargetResult[];
  readonly summary: Readonly<Record<Severity, number>>;
}
