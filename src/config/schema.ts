import { z } from 'zod';

import { USER_AGENT } from '../version.js';

/**
 * Defaults are chosen to be safe against a production origin that has not
 * consented to load: four connections, a small inter-request delay, and a hard
 * ceiling on total requests. A scan that needs more than the budget should say
 * so in configuration rather than silently escalating.
 */
export const DEFAULTS = {
  timeoutMs: 10_000,
  concurrency: 4,
  requestDelayMs: 100,
  maxBodyBytes: 1_048_576,
  maxRequests: 80,
  failOn: 'high',
  allowPrivateTargets: false,
  probeExposedPaths: true,
  redactHeaders: ['authorization', 'cookie', 'set-cookie', 'proxy-authorization', 'x-api-key'],
} as const;

const severity = z.enum(['critical', 'high', 'medium', 'low', 'info']);
const category = z.enum(['headers', 'cookies', 'cors', 'tls', 'disclosure', 'content']);

/**
 * Header names are constrained to RFC 7230 token characters and values to
 * printable ASCII. Without this, a newline in a config-supplied header value
 * would be a request-splitting primitive against the target.
 */
const headerName = z
  .string()
  .regex(/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/, 'is not a valid HTTP header name');
const headerValue = z
  .string()
  .regex(/^[\x20-\x7E]*$/, 'contains characters that are not permitted in a header value');

export const configFileSchema = z
  .object({
    targets: z.array(z.string().min(1)).optional(),
    userAgent: z.string().min(1).optional(),
    timeoutMs: z.number().int().positive().max(120_000).optional(),
    concurrency: z.number().int().min(1).max(16).optional(),
    requestDelayMs: z.number().int().min(0).max(10_000).optional(),
    maxBodyBytes: z.number().int().min(1024).max(50_000_000).optional(),
    maxRequests: z.number().int().min(1).max(2000).optional(),
    failOn: z.union([severity, z.literal('never')]).optional(),
    allowPrivateTargets: z.boolean().optional(),
    probeExposedPaths: z.boolean().optional(),
    disabledChecks: z.array(z.string().min(1)).optional(),
    categories: z.array(category).optional(),
    baseline: z.array(z.string().min(1)).optional(),
    headers: z.record(headerName, headerValue).optional(),
    redactHeaders: z.array(headerName).optional(),
  })
  // Unknown keys are an error rather than being ignored: a typo in a security
  // setting that silently does nothing is worse than a failed startup.
  .strict();

export type ConfigFile = z.infer<typeof configFileSchema>;

export const DEFAULT_USER_AGENT = USER_AGENT;
