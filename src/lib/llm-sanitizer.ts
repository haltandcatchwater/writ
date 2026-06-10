/**
 * Writ — Shared LLM-channel sanitizer
 *
 * Applies the prompt-injection guard to an array of provider-shaped
 * messages and returns the sanitized copy. Centralizing the policy here
 * means a guard tweak (e.g. new jailbreak pattern, new wrap delimiter)
 * lands in one place rather than once per provider channel.
 */

import {
  containsJailbreakPattern,
  wrapUntrusted,
  type InjectionDetection,
} from "./prompt-injection-guard";

export interface SanitizerOptions {
  /** When true, suspicious content is wrapped + accompanied by a directive instead of rejected. */
  allowsUntrustedContent?: boolean;
}

export interface SanitizedMessage<TRole = string, TContent = unknown> {
  role: TRole;
  content: TContent;
}

/**
 * Sanitize a message-shaped array. Each user-role message's text content is
 * scanned for jailbreak patterns. If allowsUntrustedContent is false (the
 * default) and a pattern matches, throws — the base ScopedChannel.send
 * catches and returns a structured error.
 *
 * Returns: { sanitized, prependedDirectives, detections }.
 *   - prependedDirectives: directives to merge into the system prompt
 *     (channels handle this differently per provider).
 *   - detections: per-message detection results (for audit logging).
 */
export function sanitizeMessages<TMsg extends SanitizedMessage<string, unknown>>(
  messages: TMsg[],
  opts: SanitizerOptions = {},
): {
  sanitized: TMsg[];
  prependedDirectives: string[];
  detections: InjectionDetection[];
} {
  const sanitized: TMsg[] = [];
  const prependedDirectives: string[] = [];
  const detections: InjectionDetection[] = [];

  for (const m of messages) {
    if (m.role !== "user") {
      sanitized.push(m);
      continue;
    }
    const text = extractText(m.content);
    if (text === null) {
      // Non-text content (e.g. multipart blocks) — pass through. A future
      // version can scan text segments inside content arrays.
      sanitized.push(m);
      continue;
    }
    const detection = containsJailbreakPattern(text);
    detections.push(detection);
    if (!detection.matched) {
      sanitized.push(m);
      continue;
    }
    if (!opts.allowsUntrustedContent) {
      throw new Error(
        `prompt-injection-suspected: matched ${detection.patterns.length} pattern(s) in user message — set allowsUntrustedContent: true on scope to wrap-instead-of-reject`,
      );
    }
    const { wrapped, directive } = wrapUntrusted(text);
    prependedDirectives.push(directive);
    sanitized.push({ ...m, content: wrapped } as TMsg);
  }

  return { sanitized, prependedDirectives, detections };
}

/**
 * Extract text from a message content field — handles strings and
 * arrays of {type:"text", text:"..."} blocks. Returns null for shapes
 * we don't yet scan (image blocks, tool_use blocks, etc.).
 */
function extractText(content: unknown): string | null {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    const texts: string[] = [];
    for (const block of content) {
      if (typeof block === "string") {
        texts.push(block);
        continue;
      }
      if (block && typeof block === "object" && (block as { type?: string }).type === "text") {
        const t = (block as { text?: unknown }).text;
        if (typeof t === "string") texts.push(t);
      }
    }
    return texts.length > 0 ? texts.join("\n") : null;
  }
  return null;
}
