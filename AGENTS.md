# Writ — guide for agents and integrators

This file is for an AI agent (or the engineer wiring one up) who is integrating Writ. It explains the model, the API, and how to add a channel.

## Mental model

A **channel** is one tool with a frozen **scope** (its *writ*). The agent never holds the credential and never sees channel internals. Every call goes through:

```
channel.send(intent)
  → validateIntent(intent)   // sync, in-scope check. Returns null or an error string.
  → preflight(intent)        // async checks (e.g. distributed rate limit). Default: pass.
  → sanitizeRequest(intent)  // async transform (e.g. wrap injected content). Default: identity.
  → execute(intent)          // the actual I/O
```

If any step rejects, `send` returns `{ success: false, error }`. It does not throw. Treat a denial as information: read the error, narrow the intent, try again within scope.

## The core API

```ts
import { ScopedChannel, type ChannelResult } from "agent-writ";

abstract class ScopedChannel<TScope> {
  readonly name: string;
  readonly scope: Readonly<TScope>;   // frozen at construction
  abstract validateIntent(intent: unknown): string | null;
  abstract execute(intent: unknown): Promise<ChannelResult>;
  protected preflight(intent: unknown): Promise<string | null>;     // override optional
  protected sanitizeRequest(intent: unknown): Promise<unknown>;     // override optional
  send(intent: unknown): Promise<ChannelResult>;
}
```

## Writing a new channel

```ts
import { ScopedChannel, resolveSecretFromEnv, RateLimiter, postJson, type ChannelResult } from "agent-writ";

interface NotionScope {
  description: string;
  apiKeyEnvVar: string;
  allowedTargetIds: string[];
  maxOpsPerMinute: number;
  timeoutMs: number;
}

type NotionIntent = { operation: "createPage" | "getPage"; targetId: string; /* ... */ };

export class NotionChannel extends ScopedChannel<NotionScope> {
  private readonly key: string;
  private readonly rl: RateLimiter;

  constructor(name: string, scope: NotionScope) {
    super(name, scope, "http");
    this.key = resolveSecretFromEnv(scope.apiKeyEnvVar);  // never exposed to the agent
    this.rl = new RateLimiter(scope.maxOpsPerMinute);
  }

  validateIntent(intent: unknown): string | null {
    const req = intent as NotionIntent;
    if (!req?.operation) return "Intent must include an operation";
    if (!this.scope.allowedTargetIds.includes(req.targetId)) {
      return `Target "${req.targetId}" is not in allowedTargetIds`;
    }
    return this.rl.tryConsume();  // null = ok
  }

  async execute(intent: unknown): Promise<ChannelResult> {
    const req = intent as NotionIntent;
    const r = await postJson("https://api.notion.com/v1/pages", { /* body */ },
      { authorization: `Bearer ${this.key}` }, this.scope.timeoutMs);
    return r.ok ? { success: true, data: r.data } : { success: false, error: r.error };
  }
}
```

Rules of thumb:
- **Resolve secrets in the constructor**, store privately, inject in `execute`. Never put a secret on the intent or the scope.
- **Put counters on the instance** (rate limit, op cap). Construct a fresh channel per task if you want them to reset.
- **Deny overrides allow.** If you support a deny-list (protected paths, protected refs), check it after the allow-list and let it win.
- **Validate both ends of a move.** For rename/copy-style ops, scope-check source *and* destination.
- **Fail closed.** When a check can't be evaluated, reject.

## Wiring into an MCP server

```ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { toMcpTools, StripeChannel } from "agent-writ";

const tools = toMcpTools({
  payments: new StripeChannel("payments", { /* scope */ }),
});
const byName = new Map(tools.map((t) => [t.name, t]));

const server = new Server({ name: "writ-tools", version: "0.1.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })),
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const tool = byName.get(req.params.name);
  if (!tool) throw new Error(`unknown tool ${req.params.name}`);
  return tool.handler(req.params.arguments ?? {});
});
```

`@modelcontextprotocol/sdk` is an **optional peer dependency** — Writ's core has zero runtime dependencies. You only need the SDK if you use the MCP server wiring.

## What Writ is not

- It is not a sandbox. It governs *what a tool may mean to do*, not *where bytes may physically travel*. Pair it with a container/microVM for kernel-level egress control.
- The prompt-injection guard is defense in depth, not a guarantee. The scope boundary is the guarantee.
