/**
 * Writ — typed, frozen permission grants for AI agent tools.
 *
 * MCP gives your agent tools. Writ gives them permissions.
 */

// Core
export { ScopedChannel } from "./base-channel";
export type {
  ChannelScope,
  ChannelResult,
  HttpScope,
  FileScope,
  FileOperation,
  AnthropicScope,
  AnthropicOperation,
  LlmResponseSchema,
  SlackScope,
  SlackOperation,
  StripeScope,
  StripeOperation,
} from "./types";

// Channels
export { HttpChannel, type HttpIntent } from "./http.channel";
export { FileChannel, type FileIntent } from "./file.channel";
export { AnthropicChannel, type AnthropicIntent, type AnthropicMessage, type AnthropicResult } from "./anthropic.channel";
export { SlackChannel, type SlackIntent, type SlackResult } from "./slack.channel";
export { StripeChannel, type StripeIntent, type StripeResult } from "./stripe.channel";

// Helpers
export { RateLimiter, resolveSecretFromEnv, postJson, getJson, jsonRequest } from "./api-helpers";

// Prompt-injection defense
export {
  containsJailbreakPattern,
  wrapUntrusted,
  scanAndAnnotate,
  type InjectionDetection,
} from "./lib/prompt-injection-guard";
export { sanitizeMessages, type SanitizerOptions, type SanitizedMessage } from "./lib/llm-sanitizer";

// MCP adapter
export { toMcpTools, type WritMcpTool } from "./mcp";
