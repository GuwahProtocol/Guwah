import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { createGuwahDownstreamClient } from "../src/guwahGateway.js";

/**
 * Catalog entry served by the fake downstream MCP server.
 * Evaluation fixture only: not a production provider and not a Guwah bypass.
 */
export type GuwahFakeDownstreamTool = {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema: Tool["inputSchema"];
};

export type GuwahFakeDownstreamInvocation = {
  readonly name: string;
  readonly arguments: unknown;
};

/**
 * Injected tools/call failure. Messages must not embed production credentials.
 */
export type GuwahFakeDownstreamCallFailure =
  | { readonly kind: "throw"; readonly error: Error }
  | { readonly kind: "mcp-error"; readonly code: ErrorCode; readonly message: string }
  | { readonly kind: "is-error-result"; readonly text: string };

export type GuwahFakeDownstreamCallHandler = (request: {
  readonly name: string;
  readonly arguments: unknown;
}) => CallToolResult | GuwahFakeDownstreamCallFailure | Promise<CallToolResult | GuwahFakeDownstreamCallFailure>;

export type GuwahFakeDownstreamOptions = {
  readonly name?: string;
  readonly version?: string;
  readonly tools?: readonly GuwahFakeDownstreamTool[];
  readonly onCall?: GuwahFakeDownstreamCallHandler;
};

export type GuwahFakeDownstreamConnection = {
  readonly client: Client;
  readonly isHealthy: () => boolean;
  readonly assertHealthy: () => void;
};

/**
 * In-repo fake downstream MCP server for gateway tests.
 * Uses in-memory transport only. Does not open network sockets, store credentials,
 * or provide a path that skips Guwah validation.
 */
export class GuwahFakeDownstreamServer {
  private tools: GuwahFakeDownstreamTool[];
  private onCall: GuwahFakeDownstreamCallHandler | undefined;
  private readonly invocations: GuwahFakeDownstreamInvocation[] = [];
  private nextFailures: GuwahFakeDownstreamCallFailure[] = [];
  private server: Server | undefined;
  private client: Client | undefined;
  private healthy = false;
  private readonly serverName: string;
  private readonly serverVersion: string;

  constructor(options?: GuwahFakeDownstreamOptions) {
    this.tools = options?.tools !== undefined ? [...options.tools] : [];
    this.onCall = options?.onCall;
    this.serverName = options?.name ?? "guwah-fake-downstream";
    this.serverVersion = options?.version ?? "0.0.0";
  }

  getInvocationCount(): number {
    return this.invocations.length;
  }

  getInvocations(): readonly GuwahFakeDownstreamInvocation[] {
    return Object.freeze([...this.invocations]);
  }

  resetInvocations(): void {
    this.invocations.length = 0;
  }

  setTools(tools: readonly GuwahFakeDownstreamTool[]): void {
    this.tools = [...tools];
  }

  setCallHandler(handler: GuwahFakeDownstreamCallHandler | undefined): void {
    this.onCall = handler;
  }

  /**
   * Queues a one-shot failure for the next tools/call (FIFO).
   * Does not create a Guwah bypass; the gateway must still approve before this runs.
   */
  injectNextFailure(failure: GuwahFakeDownstreamCallFailure): void {
    this.nextFailures.push(failure);
  }

  markDead(): void {
    this.healthy = false;
  }

  markHealthy(): void {
    if (this.client !== undefined && this.server !== undefined) {
      this.healthy = true;
    }
  }

  getConnection(): GuwahFakeDownstreamConnection {
    const client = this.client;
    if (client === undefined) {
      throw new Error("Fake downstream server is not started.");
    }
    return {
      client,
      isHealthy: () => this.healthy,
      assertHealthy: () => {
        if (!this.healthy) {
          throw new Error("Fake downstream connection is dead.");
        }
      },
    };
  }

  async start(): Promise<GuwahFakeDownstreamConnection> {
    if (this.server !== undefined || this.client !== undefined) {
      throw new Error("Fake downstream server is already started.");
    }

    const server = new Server(
      { name: this.serverName, version: this.serverVersion },
      { capabilities: { tools: {} } },
    );

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.tools.map((tool) => {
        if (tool.description === undefined) {
          return {
            name: tool.name,
            inputSchema: tool.inputSchema,
          };
        }
        return {
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
        };
      }),
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const name = request.params.name;
      const args = request.params.arguments ?? {};
      this.invocations.push(
        Object.freeze({
          name,
          arguments: structuredClone(args),
        }),
      );

      const queued = this.nextFailures.shift();
      if (queued !== undefined) {
        return this.applyFailure(queued);
      }

      if (this.onCall !== undefined) {
        const handled = await this.onCall({ name, arguments: args });
        if (handled !== undefined && isCallFailure(handled)) {
          return this.applyFailure(handled);
        }
        if (handled !== undefined) {
          return handled;
        }
      }

      return {
        content: [{ type: "text", text: `fake-ok:${name}` }],
      };
    });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = createGuwahDownstreamClient({
      name: "guwah-fake-downstream-client",
      version: "0.0.0",
    });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    this.server = server;
    this.client = client;
    this.healthy = true;
    return this.getConnection();
  }

  async stop(): Promise<void> {
    const client = this.client;
    const server = this.server;
    this.healthy = false;
    this.client = undefined;
    this.server = undefined;
    this.nextFailures = [];
    if (client !== undefined) {
      await client.close().catch(() => undefined);
    }
    if (server !== undefined) {
      await server.close().catch(() => undefined);
    }
  }

  private applyFailure(failure: GuwahFakeDownstreamCallFailure): CallToolResult {
    if (failure.kind === "throw") {
      throw failure.error;
    }
    if (failure.kind === "mcp-error") {
      throw new McpError(failure.code, failure.message);
    }
    return {
      isError: true,
      content: [{ type: "text", text: failure.text }],
    };
  }
}

function isCallFailure(
  value: CallToolResult | GuwahFakeDownstreamCallFailure,
): value is GuwahFakeDownstreamCallFailure {
  return (
    typeof value === "object" &&
    value !== null &&
    "kind" in value &&
    (value.kind === "throw" || value.kind === "mcp-error" || value.kind === "is-error-result")
  );
}

/**
 * Starts a fake downstream server and returns it with an active connection.
 * Caller must stop the fixture.
 */
export async function startGuwahFakeDownstream(
  options?: GuwahFakeDownstreamOptions,
): Promise<{
  readonly fixture: GuwahFakeDownstreamServer;
  readonly connection: GuwahFakeDownstreamConnection;
}> {
  const fixture = new GuwahFakeDownstreamServer(options);
  const connection = await fixture.start();
  return { fixture, connection };
}
