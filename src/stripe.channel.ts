/**
 * Writ — Stripe Channel. Structured-intent access to the Stripe API.
 *
 * Safety gate: livemodeAllowed defaults false in every example. Channel
 * construction throws if the API key starts with `sk_live_` and
 * livemodeAllowed is false. Test keys (sk_test_) always permitted.
 *
 * Optional maxRefundAmountCents caps refunds — protects against
 * agent-issued large refunds. Payouts are not an operation this channel
 * offers at all: the agent cannot move money out, only back to customers.
 */

import { ScopedChannel } from "./base-channel";
import { resolveSecretFromEnv, RateLimiter, jsonRequest } from "./api-helpers";
import type { StripeScope, StripeOperation, ChannelResult } from "./types";

export interface StripeIntent {
  operation: StripeOperation;
  // checkout
  successUrl?: string;
  cancelUrl?: string;
  lineItems?: Array<{ price: string; quantity: number }>;
  mode?: "payment" | "subscription" | "setup";
  customer?: string;
  // refund
  charge?: string;
  amountCents?: number;
  reason?: "duplicate" | "fraudulent" | "requested_by_customer";
  // get/list
  customerId?: string;
  invoiceId?: string;
  subscriptionId?: string;
  email?: string;
  limit?: number;
  // create customer
  name?: string;
  description?: string;
  metadata?: Record<string, string>;
}

export interface StripeResult {
  status: number;
  data: unknown;
}

const BASE = "https://api.stripe.com";

export class StripeChannel extends ScopedChannel<StripeScope> {
  private readonly apiKey: string;
  private readonly rateLimiter: RateLimiter;
  private opCounter = 0;
  private readonly baseUrl: string;

  constructor(name: string, scope: StripeScope) {
    super(name, scope, "payments");
    this.apiKey = resolveSecretFromEnv(scope.apiKeyEnvVar);
    if (this.apiKey.startsWith("sk_live_") && !scope.livemodeAllowed) {
      throw new Error(
        "StripeChannel: API key is a live key (sk_live_) but scope.livemodeAllowed is false. Use a test key or explicitly set livemodeAllowed: true.",
      );
    }
    this.rateLimiter = new RateLimiter(scope.maxOpsPerMinute);
    this.baseUrl = (scope.baseUrl ?? BASE).replace(/\/$/, "");
  }

  private headers(): Record<string, string> {
    return {
      authorization: `Bearer ${this.apiKey}`,
      "content-type": "application/x-www-form-urlencoded",
    };
  }

  validateIntent(intent: unknown): string | null {
    const req = intent as StripeIntent;
    if (!req || typeof req !== "object") return "Intent must be a StripeIntent object";
    if (!req.operation) return "Intent must include an operation";
    if (!this.scope.allowedOperations.includes(req.operation)) {
      return `Operation "${req.operation}" is not in allowedOperations`;
    }
    if (this.opCounter >= this.scope.maxOpsPerRun) {
      return `Op cap exceeded (maxOpsPerRun=${this.scope.maxOpsPerRun})`;
    }
    if (req.operation === "createCheckoutSession") {
      if (!req.successUrl || !req.cancelUrl) return "createCheckoutSession requires successUrl + cancelUrl";
      if (!Array.isArray(req.lineItems) || req.lineItems.length === 0) {
        return "createCheckoutSession requires non-empty lineItems";
      }
    }
    if (req.operation === "refundCharge") {
      if (!req.charge) return "refundCharge requires charge";
      if (req.amountCents !== undefined) {
        if (typeof req.amountCents !== "number" || req.amountCents <= 0) {
          return "refundCharge amountCents must be a positive number";
        }
        if (
          this.scope.maxRefundAmountCents !== undefined &&
          req.amountCents > this.scope.maxRefundAmountCents
        ) {
          return `refundCharge amountCents ${req.amountCents} exceeds scope.maxRefundAmountCents`;
        }
      }
    }
    if (req.operation === "getCustomer" && !req.customerId) return "getCustomer requires customerId";
    if (req.operation === "getInvoice" && !req.invoiceId) return "getInvoice requires invoiceId";
    if (req.operation === "createCustomer" && !req.email) return "createCustomer requires email";

    const rl = this.rateLimiter.tryConsume();
    if (rl) return rl;
    return null;
  }

  async execute(intent: unknown): Promise<ChannelResult<StripeResult>> {
    const req = intent as StripeIntent;
    this.opCounter += 1;
    try {
      switch (req.operation) {
        case "createCheckoutSession": {
          const params = new URLSearchParams();
          params.set("success_url", req.successUrl!);
          params.set("cancel_url", req.cancelUrl!);
          params.set("mode", req.mode ?? "payment");
          if (req.customer) params.set("customer", req.customer);
          req.lineItems!.forEach((li, i) => {
            params.set(`line_items[${i}][price]`, li.price);
            params.set(`line_items[${i}][quantity]`, String(li.quantity));
          });
          return await this.formPost("/v1/checkout/sessions", params);
        }
        case "refundCharge": {
          const params = new URLSearchParams();
          params.set("charge", req.charge!);
          if (req.amountCents !== undefined) params.set("amount", String(req.amountCents));
          if (req.reason) params.set("reason", req.reason);
          return await this.formPost("/v1/refunds", params);
        }
        case "listCustomers": {
          const qs = new URLSearchParams();
          if (req.email) qs.set("email", req.email);
          if (req.limit) qs.set("limit", String(req.limit));
          return await this.get(`/v1/customers${qs.toString() ? `?${qs}` : ""}`);
        }
        case "getCustomer":
          return await this.get(`/v1/customers/${req.customerId}`);
        case "getInvoice":
          return await this.get(`/v1/invoices/${req.invoiceId}`);
        case "listSubscriptions": {
          const qs = new URLSearchParams();
          if (req.customerId) qs.set("customer", req.customerId);
          if (req.limit) qs.set("limit", String(req.limit));
          return await this.get(`/v1/subscriptions${qs.toString() ? `?${qs}` : ""}`);
        }
        case "createCustomer": {
          const params = new URLSearchParams();
          params.set("email", req.email!);
          if (req.name) params.set("name", req.name);
          if (req.description) params.set("description", req.description);
          if (req.metadata) {
            for (const [k, v] of Object.entries(req.metadata)) params.set(`metadata[${k}]`, v);
          }
          return await this.formPost("/v1/customers", params);
        }
      }
    } catch (err) {
      return { success: false, error: `Stripe operation failed: ${(err as Error).message}` };
    }
  }

  private async formPost(path: string, params: URLSearchParams): Promise<ChannelResult<StripeResult>> {
    // Stripe uses application/x-www-form-urlencoded, not JSON.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.scope.timeoutMs);
    try {
      const resp = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: this.headers(),
        body: params,
        signal: controller.signal,
      });
      const text = await resp.text();
      let parsed: unknown = text;
      try {
        parsed = JSON.parse(text);
      } catch {
        /* keep as text */
      }
      return resp.ok
        ? { success: true, data: { status: resp.status, data: parsed } }
        : { success: false, error: `HTTP ${resp.status}`, data: { status: resp.status, data: parsed } };
    } finally {
      clearTimeout(timer);
    }
  }

  private async get(path: string): Promise<ChannelResult<StripeResult>> {
    const r = await jsonRequest("GET", `${this.baseUrl}${path}`, undefined, this.headers(), this.scope.timeoutMs);
    return r.ok
      ? { success: true, data: { status: r.status, data: r.data } }
      : { success: false, error: r.error ?? "request failed", data: { status: r.status, data: r.data } };
  }
}
