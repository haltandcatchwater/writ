/**
 * Writ — Slack Channel. Structured-intent access to Slack's Web API.
 * Operations: postMessage, postReply (thread), uploadFile, listChannels.
 *
 * Scope: allowedChannels is a whitelist of channel IDs (e.g., "C0123ABC").
 * The bot can only post where you have explicitly granted access.
 * maxMessageLength caps individual message size; the rate limiter caps
 * messages per minute. The bot token never enters agent context.
 */

import { ScopedChannel } from "./base-channel";
import type { SlackScope, SlackOperation, ChannelResult } from "./types";
import { resolveSecretFromEnv, RateLimiter, postJson, getJson } from "./api-helpers";

export interface SlackIntent {
  operation: SlackOperation;
  channel?: string;
  text?: string;
  blocks?: Array<Record<string, unknown>>;
  thread_ts?: string;
  // upload
  file?: { content: string; filename: string; title?: string }; // base64
}

export interface SlackResult {
  status: number;
  data: unknown;
}

const BASE = "https://slack.com/api";

export class SlackChannel extends ScopedChannel<SlackScope> {
  private readonly botToken: string;
  private readonly rateLimiter: RateLimiter;

  constructor(name: string, scope: SlackScope) {
    super(name, scope, "http");
    this.botToken = resolveSecretFromEnv(scope.botTokenEnvVar);
    this.rateLimiter = new RateLimiter(scope.maxMessagesPerMinute);
  }

  private headers(): Record<string, string> {
    return { authorization: `Bearer ${this.botToken}` };
  }

  validateIntent(intent: unknown): string | null {
    const req = intent as SlackIntent;
    if (!req || typeof req !== "object") return "Intent must be a SlackIntent object";
    if (!req.operation) return "Intent must include an operation";
    if (!this.scope.allowedOperations.includes(req.operation)) {
      return `Operation "${req.operation}" is not in allowedOperations`;
    }
    if (req.operation !== "listChannels") {
      if (!req.channel || typeof req.channel !== "string") {
        return `Operation "${req.operation}" requires channel ID`;
      }
      if (!this.scope.allowedChannels.includes(req.channel)) {
        return `Channel "${req.channel}" is not in allowedChannels`;
      }
    }
    if (req.operation === "postMessage" || req.operation === "postReply") {
      if (typeof req.text !== "string" || req.text.length === 0) {
        return `${req.operation} requires text string`;
      }
      if (req.text.length > this.scope.maxMessageLength) {
        return `text length ${req.text.length} exceeds maxMessageLength ${this.scope.maxMessageLength}`;
      }
      if (req.operation === "postReply" && (!req.thread_ts || typeof req.thread_ts !== "string")) {
        return "postReply requires thread_ts";
      }
    }
    if (req.operation === "uploadFile" && !req.file) {
      return "uploadFile requires file payload";
    }
    const rl = this.rateLimiter.tryConsume();
    if (rl) return rl;
    return null;
  }

  async execute(intent: unknown): Promise<ChannelResult<SlackResult>> {
    const req = intent as SlackIntent;
    try {
      switch (req.operation) {
        case "postMessage": {
          const body: Record<string, unknown> = { channel: req.channel, text: req.text };
          if (req.blocks) body.blocks = req.blocks;
          const r = await postJson(`${BASE}/chat.postMessage`, body, this.headers(), this.scope.timeoutMs);
          return ret(r);
        }
        case "postReply": {
          const body: Record<string, unknown> = {
            channel: req.channel,
            text: req.text,
            thread_ts: req.thread_ts,
          };
          if (req.blocks) body.blocks = req.blocks;
          const r = await postJson(`${BASE}/chat.postMessage`, body, this.headers(), this.scope.timeoutMs);
          return ret(r);
        }
        case "uploadFile": {
          // Slack's files.upload is going away; real binary upload requires
          // multipart/form-data. Not yet wired.
          return {
            success: false,
            error: "uploadFile requires multipart/form-data; not yet implemented.",
          };
        }
        case "listChannels": {
          const r = await getJson(
            `${BASE}/conversations.list?types=public_channel,private_channel`,
            this.headers(),
            this.scope.timeoutMs,
          );
          return ret(r);
        }
      }
    } catch (err) {
      return { success: false, error: `Slack operation failed: ${(err as Error).message}` };
    }
  }
}

function ret(r: { ok: boolean; status: number; data: unknown; error?: string }): ChannelResult<SlackResult> {
  return r.ok
    ? { success: true, data: { status: r.status, data: r.data } }
    : { success: false, error: r.error ?? "request failed", data: { status: r.status, data: r.data } };
}
