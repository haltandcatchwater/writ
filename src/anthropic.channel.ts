/**
 * Writ — Anthropic Channel. Structured-intent access to the Claude API.
 *
 * The agent never sees the API key. validateIntent enforces:
 *   - operation is in scope.allowedOperations
 *   - model is in scope.allowedModels
 *   - max_tokens is within scope.maxTokensPerCall
 *   - rate limiter has capacity (per-minute cap)
 *
 * The caller issues Claude calls via:
 *   channel.send({ operation: "createMessage", model, messages, ... })
 * The channel hard-codes the URL and method per operation. There is no
 * `path` or `method` field on the intent — the agent cannot pivot to
 * non-Claude endpoints by tweaking the path.
 *
 * User-role message content is scanned for prompt-injection patterns
 * before the request leaves the process (see lib/llm-sanitizer).
 */

import { ScopedChannel } from "./base-channel";
import type { AnthropicScope, AnthropicOperation, ChannelResult } from "./types";
import { resolveSecretFromEnv, RateLimiter, postJson, getJson } from "./api-helpers";
import { sanitizeMessages } from "./lib/llm-sanitizer";

export interface AnthropicMessage {
  role: "user" | "assistant";
  content: string | Array<{ type: string; [k: string]: unknown }>;
}

export interface AnthropicIntent {
  operation: AnthropicOperation;
  // createMessage / countTokens
  model?: string;
  system?: string;
  messages?: AnthropicMessage[];
  max_tokens?: number;
  temperature?: number;
  top_p?: number;
  top_k?: number;
  stop_sequences?: string[];
  metadata?: Record<string, unknown>;
  tools?: Array<Record<string, unknown>>;
  tool_choice?: Record<string, unknown>;
}

export interface AnthropicResult {
  status: number;
  data: unknown;
}

const DEFAULT_BASE = "https://api.anthropic.com";

export class AnthropicChannel extends ScopedChannel<AnthropicScope> {
  private readonly apiKey: string;
  private readonly rateLimiter: RateLimiter;
  private readonly baseUrl: string;

  constructor(name: string, scope: AnthropicScope) {
    super(name, scope, "http");
    this.apiKey = resolveSecretFromEnv(scope.apiKeyEnvVar);
    this.rateLimiter = new RateLimiter(scope.maxCallsPerMinute);
    this.baseUrl = (scope.baseUrl ?? DEFAULT_BASE).replace(/\/$/, "");
  }

  /** Scan/wrap user-role messages for prompt-injection patterns. */
  protected async sanitizeRequest(intent: unknown): Promise<unknown> {
    const req = intent as { messages?: Array<{ role: string; content: unknown }>; system?: string } | undefined;
    if (!req || !Array.isArray(req.messages)) return intent;
    const { sanitized, prependedDirectives } = sanitizeMessages(req.messages, {
      allowsUntrustedContent: this.scope.allowsUntrustedContent,
    });
    if (prependedDirectives.length === 0 && sanitized === req.messages) return intent;
    const directiveBlock = prependedDirectives.join("\n\n");
    const newSystem = directiveBlock ? `${directiveBlock}${req.system ? "\n\n" + req.system : ""}` : req.system;
    return { ...req, messages: sanitized, system: newSystem };
  }

  validateIntent(intent: unknown): string | null {
    const req = intent as AnthropicIntent;
    if (!req || typeof req !== "object") return "Intent must be an AnthropicIntent object";
    if (!req.operation) return "Intent must include an operation";
    if (!this.scope.allowedOperations.includes(req.operation)) {
      return `Operation "${req.operation}" is not in allowedOperations`;
    }

    if (req.operation === "createMessage" || req.operation === "countTokens") {
      if (!req.model || typeof req.model !== "string") {
        return `Operation "${req.operation}" requires a model string`;
      }
      if (this.scope.allowedModels.length > 0 && !this.scope.allowedModels.includes(req.model)) {
        return `Model "${req.model}" is not in allowedModels`;
      }
      if (!Array.isArray(req.messages) || req.messages.length === 0) {
        return `Operation "${req.operation}" requires a non-empty messages array`;
      }
      for (const m of req.messages) {
        if (!m || (m.role !== "user" && m.role !== "assistant")) {
          return "Each message must have role 'user' or 'assistant'";
        }
      }
    }

    if (req.operation === "createMessage") {
      if (typeof req.max_tokens !== "number" || req.max_tokens <= 0) {
        return "createMessage requires max_tokens (positive integer)";
      }
      if (req.max_tokens > this.scope.maxTokensPerCall) {
        return `max_tokens ${req.max_tokens} exceeds scope.maxTokensPerCall ${this.scope.maxTokensPerCall}`;
      }
    }

    const rl = this.rateLimiter.tryConsume();
    if (rl) return rl;
    return null;
  }

  async execute(intent: unknown): Promise<ChannelResult<AnthropicResult>> {
    const req = intent as AnthropicIntent;
    const headers = {
      "x-api-key": this.apiKey,
      "anthropic-version": this.scope.apiVersion,
    };
    try {
      switch (req.operation) {
        case "createMessage": {
          const body: Record<string, unknown> = {
            model: req.model,
            messages: req.messages,
            max_tokens: req.max_tokens,
          };
          if (req.system !== undefined) body.system = req.system;
          if (req.temperature !== undefined) body.temperature = req.temperature;
          if (req.top_p !== undefined) body.top_p = req.top_p;
          if (req.top_k !== undefined) body.top_k = req.top_k;
          if (req.stop_sequences !== undefined) body.stop_sequences = req.stop_sequences;
          if (req.metadata !== undefined) body.metadata = req.metadata;
          if (req.tools !== undefined) body.tools = req.tools;
          if (req.tool_choice !== undefined) body.tool_choice = req.tool_choice;
          const r = await postJson(`${this.baseUrl}/v1/messages`, body, headers, this.scope.timeoutMs);
          if (!r.ok) {
            return { success: false, error: r.error ?? "createMessage failed", data: { status: r.status, data: r.data } };
          }
          // Optionally schema-validate the provider response: hallucinated
          // tool-call shapes / injected response fields fail closed.
          if (this.scope.responseSchema) {
            const parsed = this.scope.responseSchema.safeParse(r.data);
            if (!parsed.success) {
              return {
                success: false,
                error: "schema-violation: provider response failed responseSchema.safeParse",
                data: { status: r.status, data: r.data },
              };
            }
          }
          return { success: true, data: { status: r.status, data: r.data } };
        }
        case "countTokens": {
          const body: Record<string, unknown> = {
            model: req.model,
            messages: req.messages,
          };
          if (req.system !== undefined) body.system = req.system;
          const r = await postJson(`${this.baseUrl}/v1/messages/count_tokens`, body, headers, this.scope.timeoutMs);
          return r.ok
            ? { success: true, data: { status: r.status, data: r.data } }
            : { success: false, error: r.error ?? "countTokens failed", data: { status: r.status, data: r.data } };
        }
        case "listModels": {
          const r = await getJson(`${this.baseUrl}/v1/models`, headers, this.scope.timeoutMs);
          return r.ok
            ? { success: true, data: { status: r.status, data: r.data } }
            : { success: false, error: r.error ?? "listModels failed", data: { status: r.status, data: r.data } };
        }
      }
    } catch (err) {
      return { success: false, error: `Anthropic operation failed: ${(err as Error).message}` };
    }
  }
}
