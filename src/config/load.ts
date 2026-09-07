import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { parse as parseYaml } from 'yaml';

import { ConfigError } from '../core/errors.js';
import { DEFAULTS, DEFAULT_USER_AGENT, configFileSchema, type ConfigFile } from './schema.js';
import type { Category, ResolvedConfig, Severity } from '../types.js';

const CANDIDATE_FILENAMES = ['parapet.yml', 'parapet.yaml'] as const;

export interface CliOverrides {
  readonly targets?: readonly string[];
  readonly failOn?: Severity | 'never';
  readonly allowPrivateTargets?: boolean;
  readonly probeExposedPaths?: boolean;
  readonly concurrency?: number;
  readonly timeoutMs?: number;
  readonly disabledChecks?: readonly string[];
  readonly categories?: readonly Category[];
  readonly headers?: Readonly<Record<string, string>>;
}

export interface LoadedConfig {
  readonly config: ResolvedConfig;
  /** Absolute path of the file that was used, or undefined when none was found. */
  readonly sourcePath?: string;
}

export async function loadConfig(
  options: { readonly explicitPath?: string; readonly cwd: string },
  overrides: CliOverrides,
): Promise<LoadedConfig> {
  const found = await readConfigFile(options);
  const file = found?.contents ?? {};

  const targets = overrides.targets?.length ? overrides.targets : (file.targets ?? []);
  if (targets.length === 0) {
    throw new ConfigError(
      'No target was given.',
      'Pass a URL as an argument, or list targets in parapet.yml.',
    );
  }

  const config: ResolvedConfig = {
    targets,
    userAgent: file.userAgent ?? DEFAULT_USER_AGENT,
    timeoutMs: overrides.timeoutMs ?? file.timeoutMs ?? DEFAULTS.timeoutMs,
    concurrency: overrides.concurrency ?? file.concurrency ?? DEFAULTS.concurrency,
    requestDelayMs: file.requestDelayMs ?? DEFAULTS.requestDelayMs,
    maxBodyBytes: file.maxBodyBytes ?? DEFAULTS.maxBodyBytes,
    maxRequests: file.maxRequests ?? DEFAULTS.maxRequests,
    failOn: overrides.failOn ?? file.failOn ?? DEFAULTS.failOn,
    allowPrivateTargets:
      overrides.allowPrivateTargets ?? file.allowPrivateTargets ?? DEFAULTS.allowPrivateTargets,
    probeExposedPaths:
      overrides.probeExposedPaths ?? file.probeExposedPaths ?? DEFAULTS.probeExposedPaths,
    disabledChecks: [...(file.disabledChecks ?? []), ...(overrides.disabledChecks ?? [])],
    categories: overrides.categories?.length ? overrides.categories : (file.categories ?? []),
    baseline: file.baseline ?? [],
    extraHeaders: { ...(file.headers ?? {}), ...(overrides.headers ?? {}) },
    redactHeaders: (file.redactHeaders ?? DEFAULTS.redactHeaders).map((name) =>
      name.toLowerCase(),
    ),
  };

  return found === undefined ? { config } : { config, sourcePath: found.path };
}

async function readConfigFile(options: {
  readonly explicitPath?: string;
  readonly cwd: string;
}): Promise<{ path: string; contents: ConfigFile } | undefined> {
  const candidates =
    options.explicitPath === undefined
      ? CANDIDATE_FILENAMES.map((name) => resolve(options.cwd, name))
      : [resolve(options.cwd, options.explicitPath)];

  for (const path of candidates) {
    let raw: string;
    try {
      raw = await readFile(path, 'utf8');
    } catch (error) {
      // An explicit path that does not exist is an error; a missing default is not.
      if (options.explicitPath !== undefined) {
        throw new ConfigError(
          `Could not read config file ${path}.`,
          error instanceof Error ? error.message : undefined,
        );
      }
      continue;
    }

    let parsed: unknown;
    try {
      parsed = parseYaml(raw);
    } catch (error) {
      throw new ConfigError(
        `${path} is not valid YAML.`,
        error instanceof Error ? error.message : undefined,
      );
    }

    const result = configFileSchema.safeParse(parsed ?? {});
    if (!result.success) {
      const issues = result.error.issues
        .map((issue) => `  ${issue.path.join('.') || '(root)'}: ${issue.message}`)
        .join('\n');
      throw new ConfigError(`${path} is not a valid configuration.`, `\n${issues}`);
    }

    return { path, contents: result.data };
  }

  return undefined;
}
