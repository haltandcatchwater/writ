/**
 * Writ — HTTP Channel. Scoped to allowed hosts and methods.
 *
 * An HTTP channel wired to "api.stripe.com" only talks to Stripe.
 * The agent can't widen the scope because it can't touch channel code.
 */

import { ScopedChannel } from "./base-channel";
import type { HttpScope, ChannelResult } from "./types";

export interface HttpIntent {
  url: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";
  headers?: Record<string, string>;
  body?: unknown;
}

export class HttpChannel extends ScopedChannel<HttpScope> {
  /** Pre-resolved headers to inject on every outbound request. */
  private readonly resolvedInjectHeaders: Record<string, string>;

  /** Lowercase set of injected header names — used to drop agent overrides. */
  private readonly injectedNames: Set<string>;

  constructor(name: string, scope: HttpScope) {
    super(name, scope);
    this.resolvedInjectHeaders = resolveInjectHeaders(scope.injectHeaders);
    this.injectedNames = new Set(
      Object.keys(this.resolvedInjectHeaders).map((k) => k.toLowerCase()),
    );
  }

  validateIntent(intent: unknown): string | null {
    const req = intent as HttpIntent;

    if (!req || typeof req !== "object") {
      return "Intent must be an HttpIntent object";
    }

    if (!req.url || typeof req.url !== "string") {
      return "Intent must include a url string";
    }

    if (!req.method) {
      return "Intent must include a method";
    }

    if (!this.scope.allowedMethods.includes(req.method)) {
      return `Method "${req.method}" is not allowed. Allowed: ${this.scope.allowedMethods.join(", ")}`;
    }

    let hostname: string;
    try {
      hostname = new URL(req.url).hostname;
    } catch {
      return `Invalid URL: "${req.url}"`;
    }

    const hostAllowed = this.scope.allowedHosts.some(
      (allowed) => hostname === allowed || hostname.endsWith(`.${allowed}`),
    );

    if (!hostAllowed) {
      return `Host "${hostname}" is not allowed. Allowed: ${this.scope.allowedHosts.join(", ")}`;
    }

    return null;
  }

  async execute(intent: unknown): Promise<ChannelResult> {
    const req = intent as HttpIntent;

    // Build the final header set: start with agent-supplied headers, drop any
    // whose name (case-insensitive) collides with an injected header, then
    // overlay the channel's injected headers. The agent cannot poison or
    // exfiltrate the channel's auth credentials this way.
    const headers: Record<string, string> = {};
    if (req.headers && typeof req.headers === "object") {
      for (const [k, v] of Object.entries(req.headers)) {
        if (!this.injectedNames.has(k.toLowerCase())) {
          headers[k] = v;
        }
      }
    }
    for (const [k, v] of Object.entries(this.resolvedInjectHeaders)) {
      headers[k] = v;
    }

    try {
      const response = await fetch(req.url, {
        method: req.method,
        headers,
        body: req.body ? JSON.stringify(req.body) : undefined,
      });

      const data = await response.text();

      return {
        success: response.ok,
        data: {
          status: response.status,
          statusText: response.statusText,
          body: data,
        },
        ...(!response.ok ? { error: `HTTP ${response.status}: ${response.statusText}` } : {}),
      };
    } catch (err) {
      return {
        success: false,
        error: `HTTP request failed: ${(err as Error).message}`,
      };
    }
  }
}

/**
 * Resolve `${ENV_VAR}` placeholders in injectHeaders against process.env.
 * Throws on unresolved placeholders — better to fail loudly at channel
 * construction than to ship a literal "${API_KEY}" upstream.
 */
function resolveInjectHeaders(
  raw: Record<string, string> | undefined,
): Record<string, string> {
  if (!raw) return {};
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    out[key] = value.replace(/\$\{([A-Z0-9_]+)\}/g, (_match, name: string) => {
      const v = process.env[name];
      if (v === undefined || v === "") {
        throw new Error(
          `HttpChannel injectHeaders: env var "${name}" referenced in header "${key}" is not set`,
        );
      }
      return v;
    });
  }
  return out;
}
