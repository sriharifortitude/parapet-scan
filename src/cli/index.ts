#!/usr/bin/env node
import { Command, InvalidArgumentError, Option } from 'commander';

import { CHECKS } from '../checks/index.js';
import { ParapetError, describeError } from '../core/errors.js';
import { TOOL_NAME, TOOL_VERSION } from '../version.js';
import { runScan, type OutputFormat } from './commands/scan.js';
import type { Category, Severity } from '../types.js';

const CATEGORIES = ['headers', 'cookies', 'cors', 'tls', 'disclosure', 'content'] as const;

const program = new Command();

program
  .name('parapet')
  .description(
    'Audits the externally observable security posture of a web application.\n\n' +
      'Only scan systems you own or have written permission to test.',
  )
  .version(TOOL_VERSION, '-v, --version');

program
  .command('scan', { isDefault: true })
  .description('Scan one or more targets')
  .argument('[targets...]', 'URLs or hostnames to scan')
  .option('-c, --config <path>', 'path to a parapet.yml configuration file')
  .addOption(
    new Option('-f, --format <format>', 'output format')
      .choices(['terminal', 'json', 'sarif', 'html'])
      .default('terminal'),
  )
  .option('-o, --output <path>', 'write the report to a file instead of stdout')
  .addOption(
    new Option('--fail-on <severity>', 'exit 1 when a finding at this severity or above is reported')
      .choices(['critical', 'high', 'medium', 'low', 'info', 'never']),
  )
  .option(
    '--allow-private',
    'permit targets that resolve to private or reserved addresses (required for the bundled lab)',
  )
  .option('--no-probe-paths', 'skip requests for commonly exposed files such as /.git/HEAD')
  .option('--concurrency <n>', 'maximum concurrent requests', parsePositiveInt)
  .option('--timeout <ms>', 'per-request timeout in milliseconds', parsePositiveInt)
  .option('--disable <checkId...>', 'check ids to skip')
  .addOption(new Option('--category <name...>', 'limit the scan to these categories').choices(CATEGORIES))
  .option('--header <header...>', 'extra request header, as "Name: value"')
  .option('-q, --quiet', 'hide info-level findings in terminal output')
  .option('-e, --evidence', 'show evidence lines in terminal output')
  .action(async (targets: string[], options: Record<string, unknown>) => {
    const exitCode = await runScan(targets, {
      format: options['format'] as OutputFormat,
      ...(options['config'] === undefined ? {} : { config: options['config'] as string }),
      ...(options['output'] === undefined ? {} : { output: options['output'] as string }),
      ...(options['failOn'] === undefined
        ? {}
        : { failOn: options['failOn'] as Severity | 'never' }),
      ...(options['allowPrivate'] === undefined
        ? {}
        : { allowPrivate: options['allowPrivate'] as boolean }),
      // commander sets probePaths to false only when --no-probe-paths is given.
      ...(options['probePaths'] === false ? { probePaths: false } : {}),
      ...(options['concurrency'] === undefined
        ? {}
        : { concurrency: options['concurrency'] as number }),
      ...(options['timeout'] === undefined ? {} : { timeout: options['timeout'] as number }),
      ...(options['disable'] === undefined ? {} : { disable: options['disable'] as string[] }),
      ...(options['category'] === undefined ? {} : { category: options['category'] as Category[] }),
      ...(options['header'] === undefined ? {} : { header: options['header'] as string[] }),
      ...(options['quiet'] === undefined ? {} : { quiet: options['quiet'] as boolean }),
      ...(options['evidence'] === undefined ? {} : { evidence: options['evidence'] as boolean }),
    });
    process.exitCode = exitCode;
  });

program
  .command('checks')
  .description('List the registered checks and their categories')
  .action(() => {
    const width = Math.max(...CHECKS.map((check) => check.id.length));
    for (const category of CATEGORIES) {
      const inCategory = CHECKS.filter((check) => check.category === category);
      if (inCategory.length === 0) continue;

      console.log(`\n${category}`);
      for (const check of inCategory) {
        console.log(`  ${check.id.padEnd(width)}  ${check.description}`);
      }
    }
    console.log('');
  });

function parsePositiveInt(value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new InvalidArgumentError('must be a positive integer');
  }
  return parsed;
}

try {
  await program.parseAsync(process.argv);
} catch (error) {
  process.stderr.write(`${TOOL_NAME}: ${describeError(error)}\n`);
  if (error instanceof ParapetError && error.hint !== undefined) {
    process.stderr.write(`  ${error.hint}\n`);
  }
  process.exitCode = 2;
}
