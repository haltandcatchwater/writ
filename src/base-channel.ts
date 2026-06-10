/**
 * Writ — Base Channel
 *
 * Abstract base class for all scoped channels. The scope is frozen
 * at construction time and cannot be modified — agents cannot widen
 * the scope because they cannot touch channel code.
 */

import type { ChannelScope, ChannelResult } from "./types";

export abstract class ScopedChannel<TScope extends ChannelScope = ChannelScope> {
  /** The channel's human-readable name. */
  public readonly name: string;

  /** The immutable scope, frozen at construction. */
  public readonly scope: Readonly<TScope>;

  /** Optional role identifier (e.g., "http", "payments"). */
  public readonly role?: string;

  constructor(name: string, scope: TScope, role?: string) {
    this.name = name;
    this.scope = Object.freeze({ ...scope });
    this.role = role;
  }

  /**
   * Execute the channel operation. Subclasses implement the actual I/O.
   * The base class guarantees scope is immutable before dispatch.
   */
  abstract execute(intent: unknown): Promise<ChannelResult>;

  /**
   * Validate that an intent is within scope before execution.
   * Returns null if valid, or an error message if out of scope.
   */
  abstract validateIntent(intent: unknown): string | null;

  /**
   * Async pre-flight hook. Default: pass-through. Subclasses can override
   * to add async checks (distributed rate limiting, prompt injection
   * guard) that don't fit in the sync validateIntent.
   */
  protected async preflight(_intent: unknown): Promise<string | null> {
    return null;
  }

  /**
   * Async request sanitizer. Default: identity. LLM-channel subclasses
   * override to wrap untrusted content in delimiters and detect
   * prompt-injection patterns before the request leaves the process.
   * Returns the (possibly-modified) intent; throw or return preflight
   * error to abort.
   */
  protected async sanitizeRequest(intent: unknown): Promise<unknown> {
    return intent;
  }

  /**
   * Safe execute: validates intent, runs preflight, sanitizes, then
   * executes if in scope.
   */
  async send(intent: unknown): Promise<ChannelResult> {
    const violation = this.validateIntent(intent);
    if (violation) {
      return { success: false, error: `Scope violation: ${violation}` };
    }
    const asyncViolation = await this.preflight(intent);
    if (asyncViolation) {
      return { success: false, error: `Scope violation: ${asyncViolation}` };
    }
    let sanitized: unknown;
    try {
      sanitized = await this.sanitizeRequest(intent);
    } catch (err) {
      return { success: false, error: `Sanitizer rejected: ${(err as Error).message}` };
    }
    return this.execute(sanitized);
  }
}
