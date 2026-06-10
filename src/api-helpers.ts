/**
 * Writ — Shared helpers for structured-intent API channels.
 *
 * Each provider channel reads its API key from process.env at
 * construction time. The agent NEVER sees the secret value — the
 * channel stores it privately and injects it into the request header
 * on `execute`. If the env var is unset at construction, the channel
 * throws — preferred to silently shipping `${API_KEY}` to upstream.
 */

/**
 * Resolve a single env-var name to its value at construction time. Throws
 * if unset / empty. Channels store the returned string privately.
 */
export function resolveSecretFromEnv(envVar: string): string {
  const v = process.env[envVar];
  if (v === undefined || v === "") {
    throw new Error(
      `Channel construction failed: env var "${envVar}" is not set. Define it before constructing the channel.`,
    );
  }
  return v;
}

/**
 * Sliding-window rate limiter. Records timestamps of each call and
 * rejects when the count in the trailing window exceeds the cap.
 *
 * Lives at the channel layer so a compromised caller can't escape the
 * cap by caching the channel reference — every send() goes through
 * validate, which calls this.
 *
 * Note: in-memory and per-process. In a horizontally-scaled deploy
 * (N replicas) the effective cap is N × capacity.
 */
export class RateLimiter {
  private readonly windowMs: number;
  private readonly capacity: number;
  private readonly events: number[] = [];

  constructor(capacityPerMinute: number, windowMs: number = 60_000) {
    this.windowMs = windowMs;
    this.capacity = capacityPerMinute;
  }

  /**
   * Returns null if the call is allowed; an error message if the cap
   * would be exceeded. Side effect: records the timestamp on success.
   */
  tryConsume(now: number = Date.now()): string | null {
    const cutoff = now - this.windowMs;
    while (this.events.length > 0 && this.events[0] < cutoff) {
      this.events.shift();
    }
    if (this.events.length >= this.capacity) {
      const retryAfter = this.events[0] + this.windowMs - now;
      return `Rate limit exceeded (${this.capacity} calls per ${this.windowMs}ms). Retry in ${retryAfter}ms.`;
    }
    this.events.push(now);
    return null;
  }

  /** For tests / introspection — current usage. */
  currentCount(): number {
    return this.events.length;
  }
}

interface JsonResponse {
  ok: boolean;
  status: number;
  data: unknown;
  error?: string;
}

/** POST JSON with timeout. */
export async function postJson(
  url: string,
  body: unknown,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<JsonResponse> {
  return jsonRequest("POST", url, body, headers, timeoutMs);
}

/** GET with timeout — same shape as postJson. */
export async function getJson(
  url: string,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<JsonResponse> {
  return jsonRequest("GET", url, undefined, headers, timeoutMs);
}

/** Generic JSON request supporting all methods. */
export async function jsonRequest(
  method: string,
  url: string,
  body: unknown,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<JsonResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method,
      headers:
        body !== undefined ? { "content-type": "application/json", ...headers } : headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    const text = await response.text();
    let parsed: unknown = text;
    try {
      parsed = JSON.parse(text);
    } catch {
      /* keep as text */
    }
    return {
      ok: response.ok,
      status: response.status,
      data: parsed,
      ...(!response.ok ? { error: `HTTP ${response.status}: ${response.statusText}` } : {}),
    };
  } catch (err) {
    if ((err as Error).name === "AbortError") {
      return { ok: false, status: 0, data: null, error: `Request timed out after ${timeoutMs}ms` };
    }
    return { ok: false, status: 0, data: null, error: `Request failed: ${(err as Error).message}` };
  } finally {
    clearTimeout(timer);
  }
}
