/**
 * Writ — MCP adapter
 *
 * Exposes scoped channels as Model Context Protocol tools. The adapter is
 * dependency-free: `toMcpTools` produces tool definitions in MCP wire
 * format (JSON Schema input), and you wire them into whichever MCP server
 * implementation you use. See README for an @modelcontextprotocol/sdk
 * example.
 *
 * The crucial property: the MCP layer never carries credentials or scope.
 * Scope lives inside the channel, frozen at construction in YOUR process.
 * A poisoned tool description, a confused model, or a malicious client
 * cannot widen it — out-of-scope calls return a structured denial that
 * the model can read and adapt to.
 */

import type { ScopedChannel } from "./base-channel";

/** An MCP tool definition + handler pair, ready to register on any MCP server. */
export interface WritMcpTool {
  name: string;
  description: string;
  /** JSON Schema for the tool input (MCP `inputSchema` wire format). */
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  };
  /** Invoke the underlying channel. Returns MCP content blocks. */
  handler: (args: Record<string, unknown>) => Promise<{
    content: Array<{ type: "text"; text: string }>;
    isError?: boolean;
  }>;
}

/**
 * Convert a set of scoped channels into MCP tool definitions.
 *
 * Each channel becomes one tool named `writ_<channelName>`. The tool's
 * input is the channel's intent object, passed through `channel.send()`,
 * which runs the full validate → preflight → sanitize → execute pipeline.
 * Scope denials surface as readable tool errors, not protocol failures —
 * the agent learns what its writ permits and self-corrects.
 */
export function toMcpTools(channels: Record<string, ScopedChannel>): WritMcpTool[] {
  return Object.entries(channels).map(([key, channel]) => {
    const ops = extractAllowedOperations(channel);
    const opsNote = ops ? ` Allowed operations: ${ops.join(", ")}.` : "";
    return {
      name: `writ_${key}`,
      description:
        `${channel.scope.description}${opsNote} ` +
        `Calls outside this scope are denied with a structured error.`,
      inputSchema: {
        type: "object" as const,
        properties: {
          intent: {
            type: "object",
            description:
              "The structured intent for this channel (operation + parameters). " +
              "See the channel's intent type for the exact shape.",
          },
        },
        required: ["intent"],
        additionalProperties: false,
      },
      handler: async (args: Record<string, unknown>) => {
        const result = await channel.send(args.intent);
        if (!result.success) {
          return {
            content: [{ type: "text" as const, text: `DENIED: ${result.error}` }],
            isError: true,
          };
        }
        return {
          content: [
            {
              type: "text" as const,
              text: typeof result.data === "string" ? result.data : JSON.stringify(result.data, null, 2),
            },
          ],
        };
      },
    };
  });
}

/** Best-effort extraction of an allowedOperations list from a channel scope. */
function extractAllowedOperations(channel: ScopedChannel): string[] | null {
  const scope = channel.scope as Record<string, unknown>;
  const ops = scope.allowedOperations;
  if (Array.isArray(ops) && ops.every((o) => typeof o === "string")) {
    return ops as string[];
  }
  return null;
}
