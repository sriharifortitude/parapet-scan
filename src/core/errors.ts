/** Base class so the CLI can distinguish expected failures from real crashes. */
export class BastionError extends Error {
  constructor(
    message: string,
    readonly hint?: string,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

/** The target was rejected before any request was sent. */
export class TargetRejectedError extends BastionError {}

/** Configuration file or CLI flags were invalid. */
export class ConfigError extends BastionError {}

/** The run exceeded its request budget. */
export class RequestBudgetError extends BastionError {}

export function describeError(error: unknown): string {
  if (error instanceof Error) {
    const cause = error.cause;
    if (cause instanceof Error && cause.message && cause.message !== error.message) {
      return `${error.message} (${cause.message})`;
    }
    return error.message;
  }
  return String(error);
}
