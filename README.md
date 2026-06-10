# Writ

**MCP gives your agent tools. Writ gives them permissions.**

Writ is a small TypeScript library for wrapping the tools you hand an AI agent in **typed, frozen permission grants**. A *writ* is a scope: a structured statement of exactly what a tool may do — which hosts, which operations, which files, how often, up to what amount — fixed at construction time and impossible to widen from the agent side.

```
npm install agent-writ
```

> Status: early (v0.x). The scope model and channel API are stable enough to build on; expect additive changes before 1.0.

## Why

Today an agent with an MCP server mounted gets whatever the underlying API key can do. Mount the Stripe server and the agent can refund *and* pay out. Mount a filesystem server and a prompt injection can read your `.env`. The tool surface is all-or-nothing, and the credential lives in the agent's reach.

Writ moves the boundary. Each tool becomes a **scoped channel**:

- The **scope is frozen** (`Object.freeze`) at construction. The agent cannot touch channel code, so it cannot widen its own grant.
- The **credential never enters agent context.** It is read from `process.env` at construction and injected into the outbound request. The agent literally cannot read or leak it.
- Out-of-scope calls return a **structured denial** the model can read and adapt to — not a crash.
- LLM channels run a **prompt-injection guard** on untrusted content before it leaves your process.

This is capability-based security, applied to agent tools.

## 30-second example

```ts
import { StripeChannel } from "agent-writ";

// A writ: refunds up to $50, read-only otherwise, test mode only.
const payments = new StripeChannel("payments", {
  description: "Refunds up to $50; customer lookups; no live mode",
  apiKeyEnvVar: "STRIPE_API_KEY",     // read here, never seen by the agent
  livemodeAllowed: false,             // throws on an sk_live_ key
  allowedOperations: ["refundCharge", "getCustomer"],  // no payouts. ever.
  maxRefundAmountCents: 5000,
  maxOpsPerRun: 20,
  maxOpsPerMinute: 10,
  timeoutMs: 10_000,
});

// The agent calls through send(). Everything is checked first.
await payments.send({ operation: "refundCharge", charge: "ch_123", amountCents: 2500 });
// → ok

await payments.send({ operation: "refundCharge", charge: "ch_123", amountCents: 999900 });
// → { success: false, error: "Scope violation: refundCharge amountCents 999900 exceeds scope.maxRefundAmountCents" }

await payments.send({ operation: "createCheckoutSession", /* ... */ });
// → { success: false, error: "Scope violation: Operation \"createCheckoutSession\" is not in allowedOperations" }
```

## The lethal trifecta, defused

Simon Willison's [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/): an agent with **private data access + untrusted content + external communication** is one injection away from exfiltration. Writ scopes each leg so the combination can't fire.

```
npm run demo
```

Runs the same prompt-injection attack twice — once against raw tools, once against Writ channels. Same compromised agent; only the permission layer differs. In the scoped run, both the private file read and the off-host POST are denied at the boundary, before any byte leaves the process.

## Channels included

| Channel | What the scope controls |
|---|---|
| `HttpChannel` | allowed hosts, allowed methods, injected auth headers the agent never sees |
| `FileChannel` | allowed dirs, allowed ops, protected paths/extensions (deny overrides allow), delete caps, max file size, symlink-canonicalized |
| `AnthropicChannel` | allowed models, max tokens/call, calls/min, response schema, prompt-injection guard on user content |
| `SlackChannel` | allowed channel IDs, allowed ops, message length + rate caps |
| `StripeChannel` | allowed ops (no payouts), refund caps, live-key gate, op caps |

All extend `ScopedChannel`. Writing your own is a class with `validateIntent()` and `execute()` — see [AGENTS.md](AGENTS.md).

## Using with MCP

`toMcpTools()` turns a set of channels into MCP tool definitions. The MCP layer never carries the credential or the scope — those stay frozen inside your process. A poisoned tool description or a confused model cannot widen the grant; out-of-scope calls come back as readable tool errors.

```ts
import { toMcpTools, StripeChannel, SlackChannel } from "agent-writ";

const tools = toMcpTools({
  payments: new StripeChannel("payments", { /* scope */ }),
  support: new SlackChannel("support", { /* scope */ }),
});

// Register each on your MCP server of choice (see AGENTS.md for an
// @modelcontextprotocol/sdk wiring example).
```

## Design notes

- **Scope is pinned at construction, per instance.** Build a fresh channel per task/session if you want counters (rate limits, op caps, delete caps) to reset.
- **Fail loud at construction.** A missing `injectHeaders` env var or an `sk_live_` key under `livemodeAllowed: false` throws immediately — not at the first call.
- **Defense in depth, not a silver bullet.** The prompt-injection guard raises the cost of basic injection and produces audit signal; it does not claim completeness. The load-bearing guarantee is the scope boundary, which holds regardless of what the model decides to do.
- **Composes with sandboxes.** Writ governs *what a tool may mean to do* (semantic scope). A container/microVM sandbox governs *where bytes may physically go*. Run both: Writ inside, sandbox outside.

## License

[Apache-2.0](LICENSE). Originally developed as part of the Fractal Code project and relicensed by its owner. See [NOTICE](NOTICE).
