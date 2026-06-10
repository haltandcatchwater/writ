/**
 * Writ — Type Definitions
 *
 * A scope is a writ: a typed, frozen permission grant. It is fixed at
 * channel construction time and cannot be widened afterward — not by
 * the agent, not by the tool call, not by anything downstream.
 */

/** Scope configuration for a channel. Immutable after creation. */
export interface ChannelScope {
  /** Human-readable description of what this scope permits. */
  description: string;
}

/** Result of a channel operation. */
export interface ChannelResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

// ── HTTP ─────────────────────────────────────────────────────────────

/** HTTP channel scope — restricts allowed hosts and methods. */
export interface HttpScope extends ChannelScope {
  allowedHosts: string[];
  allowedMethods: Array<"GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS">;
  /**
   * Headers the channel injects on every outbound request — typically auth
   * (Authorization, X-API-Key). The agent never sees these and cannot
   * override them: any agent-supplied header matching an injected name
   * (case-insensitive) is dropped before fetch(). This keeps API keys out
   * of agent context — the agent literally cannot read or leak them.
   *
   * Values may use ${ENV_VAR} placeholders that resolve at channel
   * construction time against process.env. Unresolved placeholders throw —
   * preferred to silently shipping a literal "${API_KEY}" upstream.
   */
  injectHeaders?: Record<string, string>;
}

// ── File ─────────────────────────────────────────────────────────────

/** File operations supported by FileChannel. */
export type FileOperation = "read" | "write" | "list" | "delete" | "rename" | "mkdir" | "rmdir";

/** File channel scope — restricts allowed directories and operations.
 *
 * `protectedPaths` is a deny-list that overrides `allowedPaths`: a path under
 * an allowed directory is still rejected if it falls under any protected path.
 * This lets you grant broad access (e.g., the entire repo) while carving out
 * non-negotiable safety zones (.git/, .env, secrets/) the agent can never reach.
 */
export interface FileScope extends ChannelScope {
  allowedPaths: string[];
  allowedOperations: FileOperation[];
  /** Paths that NEVER permit any operation, even if allowedPaths covers them. Optional. */
  protectedPaths?: string[];
  /** Hard cap on `delete` + `rmdir` operations per channel instance. Bulk-destruction throttle. */
  maxDeletesPerRun?: number;
  /** Hard cap on a single write's size in bytes. */
  maxFileSize?: number;
  /** Forbid writes/renames whose target has any of these extensions (e.g., lockfiles). */
  protectedExtensions?: string[];
}

// ── LLM (Anthropic) ──────────────────────────────────────────────────

/**
 * Pluggable response validator (zod-compatible shape). When set, provider
 * responses are schema-checked before they reach the caller — hallucinated
 * tool-call shapes or injected response fields fail closed.
 */
export interface LlmResponseSchema {
  safeParse(value: unknown): { success: true; data: unknown } | { success: false; error: unknown };
}

/** Anthropic API operations. */
export type AnthropicOperation = "createMessage" | "countTokens" | "listModels";

export interface AnthropicScope extends ChannelScope {
  apiKeyEnvVar: string;
  apiVersion: string;
  allowedOperations: AnthropicOperation[];
  allowedModels: string[];
  maxTokensPerCall: number;
  maxCallsPerMinute: number;
  timeoutMs: number;
  baseUrl?: string;
  /** Pluggable response validator. */
  responseSchema?: LlmResponseSchema;
  /** When true, suspicious user-role content is wrapped + flagged instead of rejected. */
  allowsUntrustedContent?: boolean;
}

// ── Slack ────────────────────────────────────────────────────────────

/** Slack API operations. */
export type SlackOperation = "postMessage" | "postReply" | "uploadFile" | "listChannels";

export interface SlackScope extends ChannelScope {
  botTokenEnvVar: string;
  allowedOperations: SlackOperation[];
  allowedChannels: string[];
  maxMessagesPerMinute: number;
  maxMessageLength: number;
  timeoutMs: number;
}

// ── Stripe ───────────────────────────────────────────────────────────

/** Stripe API operations. Note: payouts are not on this list and never will be by default. */
export type StripeOperation =
  | "createCheckoutSession"
  | "refundCharge"
  | "listCustomers"
  | "getCustomer"
  | "getInvoice"
  | "listSubscriptions"
  | "createCustomer";

export interface StripeScope extends ChannelScope {
  apiKeyEnvVar: string;
  /** Safety gate: reject if the API key is a live key (sk_live_) unless explicitly enabled. */
  livemodeAllowed: boolean;
  allowedOperations: StripeOperation[];
  /** Optional cap on refund amounts in cents. */
  maxRefundAmountCents?: number;
  maxOpsPerRun: number;
  maxOpsPerMinute: number;
  timeoutMs: number;
  baseUrl?: string;
}
