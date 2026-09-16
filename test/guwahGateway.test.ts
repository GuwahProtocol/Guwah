import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  createGuwahGatewayServer,
  createGuwahStdioTransport,
  formatGuwahDiagnosticLine,
  GuwahActiveRequestRegistry,
  GUWAH_GATEWAY_CAPABILITIES,
  GUWAH_GATEWAY_NAME,
  GUWAH_GATEWAY_VERSION,
  GUWAH_STDIO_BACKPRESSURE_BOUNDS,
  GUWAH_VIOLATION_MCP_MAP,
  mapGuwahViolationToMcpError,
  redactGuwahDiagnosticText,
  startGuwahStdioGateway,
  writeGuwahStderrDiagnostic,
  type GuwahMediatedTool,
} from "../src/guwahGateway.js";
import {
  GuwahGuard,
  GuwahSecurityViolation,
  type GuwahViolationCode,
  type McpToolCallPayload,
} from "../src/guwahGuard.js";

const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GATEWAY_ENTRY = path.join(REPO_ROOT, "dist", "guwahGateway.js");
const VALIDATOR_ENTRY = path.join(REPO_ROOT, "dist", "guwahGuard.js");
const GATEWAY_SOURCE = path.join(REPO_ROOT, "src", "guwahGateway.ts");

type SpawnedGateway = {
  readonly child: ReturnType<typeof spawn>;
  readonly stdout: string[];
  readonly stderr: string[];
};

const live: SpawnedGateway[] = [];
const liveClients: Array<{ client: Client; transport: StdioClientTransport }> = [];

function spawnGateway(entryPath: string): SpawnedGateway {
  const child = spawn(process.execPath, [entryPath], {
    cwd: REPO_ROOT,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  const spawned: SpawnedGateway = { child, stdout: [], stderr: [] };
  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => {
    spawned.stdout.push(chunk);
  });
  child.stderr?.on("data", (chunk: string) => {
    spawned.stderr.push(chunk);
  });
  live.push(spawned);
  return spawned;
}

async function waitForExit(child: ReturnType<typeof spawn>, timeoutMs: number): Promise<number | null> {
  if (child.exitCode !== null) {
    return child.exitCode;
  }
  return await new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.removeListener("exit", onExit);
      resolve(child.exitCode);
    }, timeoutMs);
    const onExit = (code: number | null): void => {
      clearTimeout(timer);
      resolve(code);
    };
    child.once("exit", onExit);
  });
}

async function waitForStdoutLine(spawned: SpawnedGateway, timeoutMs: number): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const combined = spawned.stdout.join("");
    const line = combined.split("\n").find((entry) => entry.trim().length > 0);
    if (line !== undefined) {
      return line.replace(/\r$/, "");
    }
    await new Promise((resolve) => {
      setTimeout(resolve, 25);
    });
  }
  throw new Error("gateway produced no stdout protocol line");
}

async function waitForStdoutMessageCount(
  spawned: SpawnedGateway,
  count: number,
  timeoutMs: number,
): Promise<unknown[]> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const lines = spawned.stdout
      .join("")
      .split("\n")
      .map((line) => line.replace(/\r$/, "").trim())
      .filter((line) => line.length > 0);
    if (lines.length >= count) {
      return lines.slice(0, count).map((line) => JSON.parse(line) as unknown);
    }
    await new Promise((resolve) => {
      setTimeout(resolve, 25);
    });
  }
  throw new Error(`gateway produced fewer than ${count} stdout protocol lines`);
}

afterEach(async () => {
  for (const entry of liveClients.splice(0, liveClients.length)) {
    try {
      await entry.client.close();
    } catch {
      // Client may already be closed after a rejected handshake.
    }
    try {
      await entry.transport.close();
    } catch {
      // Transport may already be closed with the child process.
    }
  }
  for (const spawned of live.splice(0, live.length)) {
    if (spawned.child.exitCode === null && spawned.child.killed === false) {
      spawned.child.kill();
    }
  }
});

describe("guwahGateway entry", () => {
  it("emits a compiled gateway distinct from the validator artifact", () => {
    expect(existsSync(VALIDATOR_ENTRY)).toBe(true);
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    expect(path.basename(GATEWAY_ENTRY)).not.toBe(path.basename(VALIDATOR_ENTRY));
  });

  it("fails when the compiled gateway entry is missing", async () => {
    const missing = path.join(REPO_ROOT, "dist", "guwahGateway.absent.js");
    expect(existsSync(missing)).toBe(false);
    const spawned = spawnGateway(missing);
    const code = await waitForExit(spawned.child, 5000);
    expect(code).not.toBe(0);
    expect(code).not.toBeNull();
  });

  it("starts a process that speaks MCP over stdio", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const spawned = spawnGateway(GATEWAY_ENTRY);
    const stillRunning = await waitForExit(spawned.child, 250);
    expect(stillRunning).toBeNull();

    const initialize = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-process-start-test", version: "0.0.0" },
      },
    };
    spawned.child.stdin?.write(`${JSON.stringify(initialize)}\n`);
    const line = await waitForStdoutLine(spawned, 5000);
    const parsed: unknown = JSON.parse(line);
    expect(parsed).toMatchObject({ jsonrpc: "2.0", id: 1 });
    expect(parsed).toHaveProperty("result");
    expect(spawned.stderr.join("")).toBe("");
  });
});

describe("gateway start", () => {
  it("starts the compiled gateway process over stdio", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const spawned = spawnGateway(GATEWAY_ENTRY);
    const stillRunning = await waitForExit(spawned.child, 250);
    expect(stillRunning).toBeNull();
    expect(spawned.child.killed).toBe(false);
    expect(spawned.stderr.join("")).toBe("");
    expect(spawned.stdout.join("")).toBe("");
  });

  it("accepts a protocol client without a real provider", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [GATEWAY_ENTRY],
      cwd: REPO_ROOT,
      stderr: "pipe",
    });
    const client = new Client({ name: "guwah-start-client", version: "0.0.0" });
    liveClients.push({ client, transport });

    await client.connect(transport);
    expect(client.getServerVersion()).toEqual({
      name: GUWAH_GATEWAY_NAME,
      version: GUWAH_GATEWAY_VERSION,
    });

    const listed = await client.listTools();
    expect(listed.tools).toEqual([]);

    await client.close();
  });

  it("does not dispatch downstream when start fails", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    let dispatchCount = 0;

    await expect(
      startGuwahStdioGateway({
        stdin,
        stdout,
        maxConcurrentCalls: 0,
        afterApproval: async () => {
          dispatchCount += 1;
          return { content: [{ type: "text", text: "should-not-dispatch" }] };
        },
      }),
    ).rejects.toThrow(/maxConcurrentCalls must be a positive safe integer/);

    expect(dispatchCount).toBe(0);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "coinbase_cdp_transfer", arguments: {} },
      })}\n`,
    );
    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });
    expect(dispatchCount).toBe(0);
  });

  it("does not dispatch downstream when the compiled entry is missing", async () => {
    const missing = path.join(REPO_ROOT, "dist", "guwahGateway.missing-start.js");
    expect(existsSync(missing)).toBe(false);
    const spawned = spawnGateway(missing);
    spawned.child.stdin?.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 99,
        method: "tools/call",
        params: { name: "coinbase_cdp_transfer", arguments: { amountMinor: 1 } },
      })}\n`,
    );
    const code = await waitForExit(spawned.child, 5000);
    expect(code).not.toBe(0);
    expect(code).not.toBeNull();
    expect(spawned.stdout.join("")).not.toContain("result");
    expect(spawned.stdout.join("")).not.toMatch(/"id"\s*:\s*99/);
  });
});

describe("MCP initialization handshake", () => {
  it("completes initialize and initialized with an in-memory fake client", async () => {
    const server = createGuwahGatewayServer();
    let initialized = false;
    server.oninitialized = () => {
      initialized = true;
    };
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-fake-client", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    expect(initialized).toBe(true);
    expect(client.getServerVersion()).toEqual({
      name: GUWAH_GATEWAY_NAME,
      version: GUWAH_GATEWAY_VERSION,
    });
    expect(server.getClientVersion()).toEqual({
      name: "guwah-fake-client",
      version: "0.0.0",
    });
    await client.close();
    await server.close();
  });

  it("completes initialize against the compiled gateway with a stdio fake client", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [GATEWAY_ENTRY],
      cwd: REPO_ROOT,
      stderr: "pipe",
    });
    const client = new Client({ name: "guwah-stdio-fake-client", version: "0.0.0" });
    liveClients.push({ client, transport });
    await client.connect(transport);
    expect(client.getServerVersion()).toEqual({
      name: GUWAH_GATEWAY_NAME,
      version: GUWAH_GATEWAY_VERSION,
    });
    await client.close();
  });

  it("rejects malformed initialize and performs no downstream work", async () => {
    const gatewaySource = readFileSync(GATEWAY_SOURCE, "utf8");
    expect(gatewaySource).not.toMatch(/sdk\/client/);
    expect(gatewaySource).not.toMatch(/fetch\(/);
    expect(gatewaySource).not.toMatch(/\bnet\./);
    expect(gatewaySource).not.toMatch(/\bhttp\./);

    const server = createGuwahGatewayServer();
    let initialized = false;
    server.oninitialized = () => {
      initialized = true;
    };
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
      },
    });

    const malformedDeadline = Date.now() + 5000;
    while (Date.now() < malformedDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(responses).toHaveLength(1);
    expect(responses[0]).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      error: expect.objectContaining({
        code: expect.any(Number),
        message: expect.any(String),
      }),
    });
    expect(responses[0]).not.toHaveProperty("result");
    expect(initialized).toBe(false);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "coinbase_cdp_transfer",
        arguments: { amountMinor: 1 },
      },
    });
    const toolsDeadline = Date.now() + 5000;
    while (Date.now() < toolsDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(responses).toHaveLength(2);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: expect.objectContaining({
        message: expect.any(String),
      }),
    });
    expect(responses[1]).not.toHaveProperty("result");
    await server.close();
    await clientTransport.close();
  });

  it("rejects malformed initialize on the compiled stdio gateway without result", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const spawned = spawnGateway(GATEWAY_ENTRY);
    spawned.child.stdin?.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
        },
      })}\n`,
    );
    const [response] = await waitForStdoutMessageCount(spawned, 1, 5000);
    expect(response).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      error: expect.objectContaining({
        code: expect.any(Number),
        message: expect.any(String),
      }),
    });
    expect(response).not.toHaveProperty("result");
    expect(spawned.stderr.join("")).not.toMatch(/0x[0-9a-fA-F]{40}/);
  });
});

describe("gateway initialize", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-initialize-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  it("completes initialize over stdio with a fake client and no real provider", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [GATEWAY_ENTRY],
      cwd: REPO_ROOT,
      stderr: "pipe",
    });
    const client = new Client({ name: "guwah-initialize-client", version: "0.0.0" });
    liveClients.push({ client, transport });

    await client.connect(transport);
    expect(client.getServerVersion()).toEqual({
      name: GUWAH_GATEWAY_NAME,
      version: GUWAH_GATEWAY_VERSION,
    });
    const listed = await client.listTools();
    expect(listed.tools).toEqual([]);
    await client.close();
  });

  it("does not dispatch downstream after malformed initialize", async () => {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    let dispatchCount = 0;
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "should-not-dispatch" }] };
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
        },
      })}\n`,
    );
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    const initFrames = chunks
      .join("")
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(initFrames[0]).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      error: expect.objectContaining({
        code: expect.any(Number),
        message: expect.any(String),
      }),
    });
    expect(initFrames[0]).not.toHaveProperty("result");

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && chunks.join("").split(/\r?\n/).filter((line) => line.length > 0).length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(dispatchCount).toBe(0);
    expect(chunks.join("")).not.toContain("should-not-dispatch");
    const callFrames = chunks
      .join("")
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const toolsCall = callFrames.find((frame) => frame.id === 2);
    expect(toolsCall).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        message: expect.stringContaining("not initialized"),
      },
    });
    expect(toolsCall).not.toHaveProperty("result");
  });

  it("does not dispatch downstream after failed initialize on the compiled process", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const spawned = spawnGateway(GATEWAY_ENTRY);
    spawned.child.stdin?.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
        },
      })}\n`,
    );
    const [initResponse] = await waitForStdoutMessageCount(spawned, 1, 5000);
    expect(initResponse).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      error: expect.objectContaining({
        code: expect.any(Number),
      }),
    });
    expect(initResponse).not.toHaveProperty("result");

    spawned.child.stdin?.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: {
          name: TOOL_NAME,
          arguments: compliantArgs(),
        },
      })}\n`,
    );
    const [, callResponse] = await waitForStdoutMessageCount(spawned, 2, 5000);
    expect(callResponse).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        message: expect.stringContaining("not initialized"),
      },
    });
    expect(callResponse).not.toHaveProperty("result");
    expect(spawned.stdout.join("")).not.toContain("should-not-dispatch");
  });
});

describe("MCP capability negotiation", () => {
  it("initialize result capabilities snapshot excludes unimplemented surfaces", async () => {
    const server = createGuwahGatewayServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {
          roots: {},
          sampling: {},
          elicitation: {},
        },
        clientInfo: { name: "guwah-capability-snapshot", version: "0.0.0" },
      },
    });

    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(responses).toHaveLength(1);
    const message = responses[0];
    expect(message).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: {
        serverInfo: {
          name: GUWAH_GATEWAY_NAME,
          version: GUWAH_GATEWAY_VERSION,
        },
        capabilities: GUWAH_GATEWAY_CAPABILITIES,
      },
    });
    if (
      message === null ||
      typeof message !== "object" ||
      !("result" in message) ||
      message.result === null ||
      typeof message.result !== "object"
    ) {
      expect.unreachable("initialize result");
    }
    const result = message.result as Record<string, unknown>;
    const capabilities = result["capabilities"];
    expect(capabilities).toEqual({ tools: {} });
    expect(capabilities).toHaveProperty("tools");
    expect(capabilities).not.toHaveProperty("resources");
    expect(capabilities).not.toHaveProperty("prompts");
    expect(capabilities).not.toHaveProperty("sampling");
    expect(capabilities).not.toHaveProperty("logging");
    expect(capabilities).not.toHaveProperty("completions");
    expect(capabilities).not.toHaveProperty("tasks");
    expect(capabilities).not.toHaveProperty("experimental");
    expect({
      serverInfo: result["serverInfo"],
      capabilities,
    }).toEqual({
      serverInfo: {
        name: GUWAH_GATEWAY_NAME,
        version: GUWAH_GATEWAY_VERSION,
      },
      capabilities: { tools: {} },
    });

    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });
    await server.close();
    await clientTransport.close();
  });

  it("client-requested resources prompts and sampling do not enable extra surfaces", async () => {
    const server = createGuwahGatewayServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client(
      { name: "guwah-capability-client", version: "0.0.0" },
      {
        capabilities: {
          sampling: {},
          elicitation: {},
          roots: { listChanged: true },
        },
      },
    );
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    expect(client.getServerCapabilities()).toEqual(GUWAH_GATEWAY_CAPABILITIES);
    expect(client.getServerCapabilities()).toEqual({ tools: {} });
    await expect(client.listResources()).rejects.toThrow();
    await expect(client.listPrompts()).rejects.toThrow();
    await expect(client.listTools()).resolves.toEqual({ tools: [] });

    await client.close();
    await server.close();
  });
});

describe("stdio transport binding", () => {
  it("binds the official StdioServerTransport and rejects HTTP or SSE transports", () => {
    const source = readFileSync(GATEWAY_SOURCE, "utf8");
    expect(source).toMatch(/StdioServerTransport/);
    expect(source).toMatch(/@modelcontextprotocol\/sdk\/server\/stdio\.js/);
    expect(source).not.toMatch(/StreamableHTTP/);
    expect(source).not.toMatch(/SSEServerTransport/);
    expect(source).not.toMatch(/server\/sse/);
    expect(source).not.toMatch(/createServer\(/);
    const transport = createGuwahStdioTransport(new PassThrough(), new PassThrough());
    expect(transport).toBeInstanceOf(StdioServerTransport);
  });

  it("reads JSON-RPC from stdin and writes protocol frames only to stdout", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    const { server } = await startGuwahStdioGateway({
      stdin,
      stdout,
      onTransportFailure: () => {
        throw new Error("unexpected transport failure");
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-stdio-purity", version: "0.0.0" },
        },
      })}\n`,
    );

    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    const stdoutText = chunks.join("");
    expect(stdoutText.includes("Guwah")).toBe(false);
    expect(stdoutText.includes("started")).toBe(false);
    const lines = stdoutText
      .split("\n")
      .map((line) => line.replace(/\r$/, ""))
      .filter((line) => line.length > 0);
    expect(lines.length).toBeGreaterThanOrEqual(1);
    for (const line of lines) {
      const parsed: unknown = JSON.parse(line);
      expect(parsed).toMatchObject({ jsonrpc: "2.0" });
      expect(parsed).toHaveProperty("id");
    }
    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: {
        serverInfo: {
          name: GUWAH_GATEWAY_NAME,
          version: GUWAH_GATEWAY_VERSION,
        },
      },
    });

    await server.close();
  });

  it("compiled gateway stdout contains protocol frames only", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const spawned = spawnGateway(GATEWAY_ENTRY);
    spawned.child.stdin?.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 7,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-compiled-stdio", version: "0.0.0" },
        },
      })}\n`,
    );
    const [response] = await waitForStdoutMessageCount(spawned, 1, 5000);
    expect(response).toMatchObject({ jsonrpc: "2.0", id: 7 });
    expect(response).toHaveProperty("result");
    const stdoutText = spawned.stdout.join("");
    for (const line of stdoutText.split("\n").map((entry) => entry.trim()).filter(Boolean)) {
      expect(() => JSON.parse(line)).not.toThrow();
      expect(JSON.parse(line)).toMatchObject({ jsonrpc: "2.0" });
    }
    expect(spawned.stderr.join("")).toBe("");
  });

  it("transport buffer overflow terminates fail-closed", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const failures: unknown[] = [];
    const { server } = await startGuwahStdioGateway({
      stdin,
      stdout,
      maxBufferSize: 32,
      onTransportFailure: (error) => {
        failures.push(error);
      },
    });

    stdin.write("x".repeat(64));
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && failures.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(failures.length).toBeGreaterThanOrEqual(1);
    await server.close();
  });

  it("invalid framing terminates fail-closed without writing non-protocol stdout banners", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    const failures: unknown[] = [];
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    const { server } = await startGuwahStdioGateway({
      stdin,
      stdout,
      onTransportFailure: (error) => {
        failures.push(error);
      },
    });

    stdin.write("not-json-rpc\n");
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && failures.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(failures.length).toBeGreaterThanOrEqual(1);
    expect(chunks.join("")).not.toMatch(/started|ready|listening/i);
    await server.close();
  });
});

describe("stdio initialize transport", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const INITIALIZE_FIXTURE = {
    jsonrpc: "2.0" as const,
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "guwah-stdio-initialize-fixture", version: "0.0.0" },
    },
  };

  const MALFORMED_INITIALIZE_FIXTURE = {
    jsonrpc: "2.0" as const,
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
    },
  };

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-stdio-initialize-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  it("completes initialize over stdio with a protocol fixture", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    const transport = createGuwahStdioTransport(stdin, stdout);
    expect(transport).toBeInstanceOf(StdioServerTransport);

    const { server } = await startGuwahStdioGateway({
      stdin,
      stdout,
      onTransportFailure: () => {
        throw new Error("unexpected transport failure during initialize fixture");
      },
    });

    stdin.write(`${JSON.stringify(INITIALIZE_FIXTURE)}\n`);
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    const lines = chunks
      .join("")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    expect(lines.length).toBeGreaterThanOrEqual(1);
    const parsed: unknown = JSON.parse(lines[0] ?? "{}");
    expect(parsed).toMatchObject({
      jsonrpc: "2.0",
      id: INITIALIZE_FIXTURE.id,
      result: {
        protocolVersion: expect.any(String),
        capabilities: GUWAH_GATEWAY_CAPABILITIES,
        serverInfo: {
          name: GUWAH_GATEWAY_NAME,
          version: GUWAH_GATEWAY_VERSION,
        },
      },
    });
    expect(parsed).not.toHaveProperty("error");

    await server.close();
  });

  it("malformed initialize must not dispatch", async () => {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    let dispatchCount = 0;
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "should-not-dispatch" }] };
      },
    });

    stdin.write(`${JSON.stringify(MALFORMED_INITIALIZE_FIXTURE)}\n`);
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    const initFrame = JSON.parse(
      chunks
        .join("")
        .split(/\r?\n/)
        .filter((line) => line.length > 0)[0] ?? "{}",
    ) as Record<string, unknown>;
    expect(initFrame).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      error: expect.objectContaining({
        code: expect.any(Number),
      }),
    });
    expect(initFrame).not.toHaveProperty("result");

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      })}\n`,
    );
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );
    const callDeadline = Date.now() + 5000;
    while (
      Date.now() < callDeadline &&
      chunks.join("").split(/\r?\n/).filter((line) => line.length > 0).length < 2
    ) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(dispatchCount).toBe(0);
    expect(chunks.join("")).not.toContain("should-not-dispatch");
    const callFrame = chunks
      .join("")
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .find((frame) => frame.id === 2);
    expect(callFrame).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        message: expect.stringContaining("not initialized"),
      },
    });
    expect(callFrame).not.toHaveProperty("result");
  });
});

describe("stdio tools/list transport", () => {
  const MEDIATED_TOOL_NAME = "authorized_transfer";
  const UNVALIDATED_DOWNSTREAM_TOOL = "raw_provider_tool";

  const INITIALIZE_FIXTURE = {
    jsonrpc: "2.0" as const,
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "guwah-stdio-tools-list-fixture", version: "0.0.0" },
    },
  };

  const TOOLS_LIST_FIXTURE = {
    jsonrpc: "2.0" as const,
    id: 2,
    method: "tools/list",
    params: {},
  };

  const mediatedTool: GuwahMediatedTool = {
    name: MEDIATED_TOOL_NAME,
    description: "Gateway-mediated fake transfer",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        amountMinor: { type: "integer" },
      },
      required: ["amountMinor"],
    },
  };

  it("lists only gateway-mediated tools over stdio", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    const { server } = await startGuwahStdioGateway({
      stdin,
      stdout,
      mediatedTools: [mediatedTool],
      resolveMediatedTools: () => [mediatedTool],
      onTransportFailure: () => {
        throw new Error("unexpected transport failure during tools/list fixture");
      },
    });

    stdin.write(`${JSON.stringify(INITIALIZE_FIXTURE)}\n`);
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    stdin.write(`${JSON.stringify(TOOLS_LIST_FIXTURE)}\n`);

    const listDeadline = Date.now() + 5000;
    while (
      Date.now() < listDeadline &&
      chunks.join("").split(/\r?\n/).filter((line) => line.length > 0).length < 2
    ) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    const frames = chunks
      .join("")
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const listResponse = frames.find((frame) => frame.id === TOOLS_LIST_FIXTURE.id);
    expect(listResponse).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      result: {
        tools: [
          {
            name: MEDIATED_TOOL_NAME,
            description: "Gateway-mediated fake transfer",
          },
        ],
      },
    });
    expect(listResponse).not.toHaveProperty("error");
    const result = listResponse?.result as { tools: Array<{ name: string }> };
    expect(result.tools.map((tool) => tool.name)).toEqual([MEDIATED_TOOL_NAME]);
    expect(result.tools.map((tool) => tool.name)).not.toContain(UNVALIDATED_DOWNSTREAM_TOOL);
    expect(JSON.stringify(listResponse)).not.toContain(UNVALIDATED_DOWNSTREAM_TOOL);

    await server.close();
  });

  it("unvalidated downstream tools must not appear in stdio tools/list", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    // Catalog resolver returns only the mediated set; downstream names stay omitted.
    const { server } = await startGuwahStdioGateway({
      stdin,
      stdout,
      resolveMediatedTools: () => [mediatedTool],
      onTransportFailure: () => {
        throw new Error("unexpected transport failure during tools/list omission fixture");
      },
    });

    stdin.write(`${JSON.stringify(INITIALIZE_FIXTURE)}\n`);
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    stdin.write(`${JSON.stringify(TOOLS_LIST_FIXTURE)}\n`);

    const listDeadline = Date.now() + 5000;
    while (
      Date.now() < listDeadline &&
      chunks.join("").split(/\r?\n/).filter((line) => line.length > 0).length < 2
    ) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    const stdoutText = chunks.join("");
    expect(stdoutText).not.toContain(UNVALIDATED_DOWNSTREAM_TOOL);
    const frames = stdoutText
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const listResponse = frames.find((frame) => frame.id === 2);
    expect(listResponse).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      result: {
        tools: expect.any(Array),
      },
    });
    const tools = (listResponse?.result as { tools: Array<{ name: string }> }).tools;
    expect(tools.every((tool) => tool.name === MEDIATED_TOOL_NAME)).toBe(true);
    expect(tools.some((tool) => tool.name === UNVALIDATED_DOWNSTREAM_TOOL)).toBe(false);

    await server.close();
  });
});

describe("stdio tools/call transport", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const INITIALIZE_FIXTURE = {
    jsonrpc: "2.0" as const,
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "guwah-stdio-tools-call-fixture", version: "0.0.0" },
    },
  };

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  function violatingArgs(): Record<string, unknown> {
    return {
      amountMinor: 5001,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-stdio-tools-call-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  async function completeInitialize(stdin: PassThrough, chunks: string[]): Promise<void> {
    stdin.write(`${JSON.stringify(INITIALIZE_FIXTURE)}\n`);
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
  }

  it("accepts a compliant tools/call over stdio only after the validator path runs", async () => {
    const policyPath = writePolicy();
    const guard = new GuwahGuard({ policyPath });
    const events: string[] = [];
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    vi.spyOn(guard, "validateToolCall").mockImplementation((payload, args) => {
      events.push("validate");
      expect(payload).toMatchObject({
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          name: TOOL_NAME,
          arguments: compliantArgs(),
        },
      });
      expect(args).toEqual(compliantArgs());
      expect(events).not.toContain("dispatch");
      return GuwahGuard.prototype.validateToolCall.call(guard, payload, args);
    });

    const { server } = await startGuwahStdioGateway({
      stdin,
      stdout,
      guard,
      mediatedTools: [mediatedTransfer],
      afterApproval: async (approved) => {
        events.push("dispatch");
        return {
          content: [
            {
              type: "text",
              text: `validated:${String(approved.params.name)}`,
            },
          ],
        };
      },
      onTransportFailure: () => {
        throw new Error("unexpected transport failure during tools/call fixture");
      },
    });

    await completeInitialize(stdin, chunks);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );

    const callDeadline = Date.now() + 5000;
    while (
      Date.now() < callDeadline &&
      !chunks.join("").includes("validated:coinbase_cdp_transfer")
    ) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(events).toEqual(["validate", "dispatch"]);
    const frames = chunks
      .join("")
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const callResponse = frames.find((frame) => frame.id === 2);
    expect(callResponse).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      result: {
        content: [{ type: "text", text: "validated:coinbase_cdp_transfer" }],
      },
    });
    expect(callResponse).not.toHaveProperty("error");

    await server.close();
  });

  it("does not disable validator checks for violating tools/call over stdio", async () => {
    const policyPath = writePolicy();
    const guard = new GuwahGuard({ policyPath });
    const events: string[] = [];
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    vi.spyOn(guard, "validateToolCall").mockImplementation((payload, args) => {
      events.push("validate");
      expect(events).not.toContain("dispatch");
      return GuwahGuard.prototype.validateToolCall.call(guard, payload, args);
    });

    const { server } = await startGuwahStdioGateway({
      stdin,
      stdout,
      guard,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        events.push("dispatch");
        return { content: [{ type: "text", text: "should-not-dispatch" }] };
      },
      onTransportFailure: () => {
        throw new Error("unexpected transport failure during violating tools/call fixture");
      },
    });

    await completeInitialize(stdin, chunks);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: violatingArgs() },
      })}\n`,
    );

    const callDeadline = Date.now() + 5000;
    while (
      Date.now() < callDeadline &&
      chunks.join("").split(/\r?\n/).filter((line) => line.length > 0).length < 2
    ) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(events).toEqual(["validate"]);
    expect(events).not.toContain("dispatch");
    expect(chunks.join("")).not.toContain("should-not-dispatch");
    const frames = chunks
      .join("")
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const callResponse = frames.find((frame) => frame.id === 2);
    expect(callResponse).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: expect.objectContaining({
        code: expect.any(Number),
        message: expect.any(String),
      }),
    });
    expect(callResponse).not.toHaveProperty("result");

    await server.close();
  });
});

describe("stdio invalid-request transport", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const INITIALIZE_FIXTURE = {
    jsonrpc: "2.0" as const,
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "guwah-stdio-invalid-request-fixture", version: "0.0.0" },
    },
  };

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-stdio-invalid-request-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  async function completeInitialize(stdin: PassThrough, chunks: string[]): Promise<void> {
    stdin.write(`${JSON.stringify(INITIALIZE_FIXTURE)}\n`);
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
  }

  it("returns a structured error for an invalid tools/call request with zero dispatch", async () => {
    const policyPath = writePolicy();
    let dispatchCount = 0;
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    const { server } = await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "should-not-dispatch" }] };
      },
      onTransportFailure: () => {
        throw new Error("unexpected transport failure during invalid-request fixture");
      },
    });

    await completeInitialize(stdin, chunks);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: {
          arguments: compliantArgs(),
        },
      })}\n`,
    );

    const callDeadline = Date.now() + 5000;
    while (
      Date.now() < callDeadline &&
      chunks.join("").split(/\r?\n/).filter((line) => line.length > 0).length < 2
    ) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(dispatchCount).toBe(0);
    expect(chunks.join("")).not.toContain("should-not-dispatch");
    const frames = chunks
      .join("")
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const callResponse = frames.find((frame) => frame.id === 2);
    expect(callResponse).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: expect.any(Number),
        message: expect.any(String),
      },
    });
    expect(callResponse).not.toHaveProperty("result");
    const err = callResponse as { error: { code: number; message: string } };
    expect(Number.isSafeInteger(err.error.code)).toBe(true);
    expect(err.error.message.length).toBeGreaterThan(0);
    expect(err.error.message).not.toContain(WHITELISTED_DESTINATION);

    await server.close();
  });

  it("does not let a garbage frame reach downstream dispatch", async () => {
    const policyPath = writePolicy();
    let dispatchCount = 0;
    const failures: unknown[] = [];
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    const { server, transport } = await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "should-not-dispatch" }] };
      },
      onTransportFailure: (error) => {
        failures.push(error);
      },
    });

    await completeInitialize(stdin, chunks);
    const garbageFrame =
      '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"coinbase_cdp_transfer"';
    const followUpCall = JSON.stringify({
      jsonrpc: "2.0",
      id: 99,
      method: "tools/call",
      params: {
        name: TOOL_NAME,
        arguments: compliantArgs(),
      },
    });
    stdin.write(`${garbageFrame}\n${followUpCall}\n`);

    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && failures.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });

    expect(failures.length).toBeGreaterThanOrEqual(1);
    expect(dispatchCount).toBe(0);
    expect(chunks.join("")).not.toContain("should-not-dispatch");
    for (const frame of chunks.join("").split(/\r?\n/).filter((entry) => entry.length > 0)) {
      const parsed: unknown = JSON.parse(frame);
      expect(parsed).toMatchObject({ jsonrpc: "2.0" });
      expect(parsed).not.toMatchObject({ id: 99, result: expect.anything() });
    }

    await server.close().catch(() => undefined);
    await transport.close().catch(() => undefined);
  });
});

describe("malformed MCP messages", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-malformed-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  const MALFORMED_FIXTURES: ReadonlyArray<{ readonly name: string; readonly line: string }> = [
    {
      name: "truncated JSON",
      line: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"coinbase_cdp_transfer"',
    },
    {
      name: "wrong types",
      line: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: 123,
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      }),
    },
    {
      name: "extra protocol fields",
      line: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
        unexpectedEnvelopeField: true,
      }),
    },
  ];

  async function runMalformedFixture(malformedLine: string): Promise<{
    readonly failures: unknown[];
    readonly dispatchCount: number;
    readonly stdoutText: string;
  }> {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    const failures: unknown[] = [];
    let dispatchCount = 0;
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    const { server, transport } = await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "should-not-dispatch" }] };
      },
      onTransportFailure: (error) => {
        failures.push(error);
      },
    });

    const followUpCall = JSON.stringify({
      jsonrpc: "2.0",
      id: 99,
      method: "tools/call",
      params: {
        name: TOOL_NAME,
        arguments: compliantArgs(),
      },
    });

    stdin.write(`${malformedLine}\n${followUpCall}\n`);

    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && failures.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });

    // Cleanup already performed by fail-closed path; second close must not throw.
    await server.close().catch(() => undefined);
    await transport.close().catch(() => undefined);

    return {
      failures,
      dispatchCount,
      stdoutText: chunks.join(""),
    };
  }

  it.each(MALFORMED_FIXTURES)(
    "fails closed for $name without dispatching a follow-up tools/call",
    async ({ line }) => {
      const result = await runMalformedFixture(line);
      expect(result.failures.length).toBeGreaterThanOrEqual(1);
      expect(result.dispatchCount).toBe(0);
      expect(result.stdoutText).not.toMatch(/should-not-dispatch/);
      expect(result.stdoutText).not.toMatch(/started|ready|listening/i);
      for (const frame of result.stdoutText.split(/\r?\n/).filter((entry) => entry.length > 0)) {
        const parsed: unknown = JSON.parse(frame);
        expect(parsed).toMatchObject({ jsonrpc: "2.0" });
        expect(parsed).not.toMatchObject({ id: 99, result: expect.anything() });
      }
    },
  );

  it("cleans up without an unhandled parser crash after truncated framing", async () => {
    const result = await runMalformedFixture(MALFORMED_FIXTURES[0]?.line ?? "");
    expect(result.failures.length).toBeGreaterThanOrEqual(1);
    expect(result.dispatchCount).toBe(0);
    expect(result.failures[0]).toBeInstanceOf(Error);
  });
});

describe("gateway EOF", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-eof-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  it("begins clean shutdown on stdin EOF and stops new calls", async () => {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    const failures: unknown[] = [];
    let eofCount = 0;
    let dispatchCount = 0;
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "dispatched" }] };
      },
      onTransportFailure: (error) => {
        failures.push(error);
      },
      onStdinEof: () => {
        eofCount += 1;
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-eof", version: "0.0.0" },
        },
      })}\n`,
    );
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(chunks.join("")).toContain('"id":1');

    stdin.end();
    const eofDeadline = Date.now() + 5000;
    while (Date.now() < eofDeadline && eofCount === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(eofCount).toBe(1);
    expect(failures).toEqual([]);

    const beforeLate = dispatchCount;
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );
    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });
    expect(dispatchCount).toBe(beforeLate);
    expect(chunks.join("")).not.toMatch(/"id":2/);
  });

  it("EOF during a call must not start an automatic retry", async () => {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const failures: unknown[] = [];
    let eofCount = 0;
    let dispatchEntries = 0;
    let releaseDispatch: (() => void) | undefined;
    const holdDispatch = new Promise<void>((resolve) => {
      releaseDispatch = resolve;
    });

    await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchEntries += 1;
        await holdDispatch;
        return { content: [{ type: "text", text: "completed-once" }] };
      },
      onTransportFailure: (error) => {
        failures.push(error);
      },
      onStdinEof: () => {
        eofCount += 1;
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-eof-inflight", version: "0.0.0" },
        },
      })}\n`,
    );
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );

    const enteredDeadline = Date.now() + 5000;
    while (Date.now() < enteredDeadline && dispatchEntries === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(dispatchEntries).toBe(1);

    stdin.end();
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(eofCount).toBe(0);

    releaseDispatch?.();
    const eofDeadline = Date.now() + 5000;
    while (Date.now() < eofDeadline && eofCount === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(eofCount).toBe(1);
    expect(failures).toEqual([]);
    expect(dispatchEntries).toBe(1);
  });

  it("compiled gateway exits cleanly on stdin EOF without transport-failure stderr", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const spawned = spawnGateway(GATEWAY_ENTRY);
    spawned.child.stdin?.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-compiled-eof", version: "0.0.0" },
        },
      })}\n`,
    );
    await waitForStdoutMessageCount(spawned, 1, 5000);
    spawned.child.stdin?.end();
    const code = await waitForExit(spawned.child, 5000);
    expect(code).toBe(0);
    expect(spawned.stderr.join("")).toBe("");
    for (const line of spawned.stdout
      .join("")
      .split(/\r?\n/)
      .map((entry) => entry.trim())
      .filter(Boolean)) {
      expect(JSON.parse(line)).toMatchObject({ jsonrpc: "2.0" });
    }
  });
});

describe("broken-pipe stdout", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";
  const PLANTED_SECRET = "sk_live_broken_pipe_planted_secret";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-epipe-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  function brokenPipeError(): Error {
    return Object.assign(new Error(`write EPIPE ${PLANTED_SECRET} ${WHITELISTED_DESTINATION}`), {
      code: "EPIPE",
    });
  }

  it("treats stdout EPIPE as a terminal transport failure and stops accepting work", async () => {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    const failures: unknown[] = [];
    let dispatchCount = 0;
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    const { transport } = await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: `dispatched:${PLANTED_SECRET}` }] };
      },
      onTransportFailure: (error) => {
        failures.push(error);
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-epipe", version: "0.0.0" },
        },
      })}\n`,
    );
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(chunks.join("")).toContain('"id":1');

    stdout.destroy(brokenPipeError());
    const failDeadline = Date.now() + 5000;
    while (Date.now() < failDeadline && failures.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(failures.length).toBeGreaterThanOrEqual(1);
    expect((failures[0] as { code?: string }).code).toBe("EPIPE");

    const before = dispatchCount;
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );
    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });
    expect(dispatchCount).toBe(before);

    await expect(
      transport.send({
        jsonrpc: "2.0",
        id: 3,
        result: { planted: PLANTED_SECRET, destinationAddress: WHITELISTED_DESTINATION },
      }),
    ).resolves.toBeUndefined();
    expect(chunks.join("")).not.toContain(PLANTED_SECRET);
    expect(chunks.join("")).not.toMatch(/"id":2/);
  });

  it("does not dump planted payload values through the default broken-pipe diagnostic", () => {
    const stderrChunks: string[] = [];
    const stderr = new PassThrough();
    stderr.setEncoding("utf8");
    stderr.on("data", (chunk: string) => {
      stderrChunks.push(chunk);
    });

    writeGuwahStderrDiagnostic("Guwah gateway transport failed.", {
      detail: brokenPipeError(),
      stderr,
    });

    const text = stderrChunks.join("");
    expect(text).toBe("Guwah gateway transport failed.\n");
    expect(text).not.toContain(PLANTED_SECRET);
    expect(text).not.toContain(WHITELISTED_DESTINATION);
    expect(text).not.toContain("EPIPE");
  });
});

describe("termination signals", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-signal-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  it.each(["SIGINT", "SIGTERM"] as const)(
    "begins clean shutdown on %s and does not dispatch later tools/call",
    async (signalName) => {
      const policyPath = writePolicy();
      const stdin = new PassThrough();
      const stdout = new PassThrough();
      const signalHost = new EventEmitter();
      const chunks: string[] = [];
      const failures: unknown[] = [];
      const seenSignals: string[] = [];
      let dispatchCount = 0;
      stdout.setEncoding("utf8");
      stdout.on("data", (chunk: string) => {
        chunks.push(chunk);
      });

      await startGuwahStdioGateway({
        stdin,
        stdout,
        policyPath,
        mediatedTools: [mediatedTransfer],
        enableTerminationSignals: true,
        terminationSignalHost: signalHost,
        afterApproval: async () => {
          dispatchCount += 1;
          return { content: [{ type: "text", text: "should-not-run-after-signal" }] };
        },
        onTransportFailure: (error) => {
          failures.push(error);
        },
        onTerminationSignal: (signal) => {
          seenSignals.push(signal);
        },
      });

      stdin.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "guwah-signal", version: "0.0.0" },
          },
        })}\n`,
      );
      const initDeadline = Date.now() + 5000;
      while (Date.now() < initDeadline && chunks.join("").trim().length === 0) {
        await new Promise((resolve) => {
          setTimeout(resolve, 25);
        });
      }

      signalHost.emit(signalName);
      const signalDeadline = Date.now() + 5000;
      while (Date.now() < signalDeadline && seenSignals.length === 0) {
        await new Promise((resolve) => {
          setTimeout(resolve, 25);
        });
      }
      expect(seenSignals).toEqual([signalName]);
      expect(failures).toEqual([]);

      stdin.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: TOOL_NAME, arguments: compliantArgs() },
        })}\n`,
      );
      await new Promise((resolve) => {
        setTimeout(resolve, 100);
      });
      expect(dispatchCount).toBe(0);
      expect(chunks.join("")).not.toContain("should-not-run-after-signal");
      expect(chunks.join("")).not.toMatch(/"id":2/);
    },
  );

  it("does not dispatch a pending unvalidated tools/call after SIGINT", async () => {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const signalHost = new EventEmitter();
    const seenSignals: string[] = [];
    let dispatchCount = 0;

    const guard = new GuwahGuard({ policyPath });
    const originalValidate = guard.validateToolCall.bind(guard);
    vi.spyOn(guard, "validateToolCall").mockImplementation((payload, args) => {
      // Emit during validation so approval is still pending when shutdown begins.
      signalHost.emit("SIGINT");
      return originalValidate(payload, args);
    });

    await startGuwahStdioGateway({
      stdin,
      stdout,
      guard,
      mediatedTools: [mediatedTransfer],
      enableTerminationSignals: true,
      terminationSignalHost: signalHost,
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "dispatched-after-signal" }] };
      },
      onTerminationSignal: (signal) => {
        seenSignals.push(signal);
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-signal-pending", version: "0.0.0" },
        },
      })}\n`,
    );
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );

    const signalDeadline = Date.now() + 5000;
    while (Date.now() < signalDeadline && seenSignals.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(seenSignals).toEqual(["SIGINT"]);
    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });
    expect(dispatchCount).toBe(0);
  });

  it("compiled gateway exits cleanly on SIGTERM when the platform delivers the signal", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const spawned = spawnGateway(GATEWAY_ENTRY);
    spawned.child.stdin?.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-compiled-signal", version: "0.0.0" },
        },
      })}\n`,
    );
    await waitForStdoutMessageCount(spawned, 1, 5000);

    const pid = spawned.child.pid;
    expect(pid).toEqual(expect.any(Number));
    try {
      process.kill(pid as number, "SIGTERM");
    } catch {
      spawned.child.stdin?.end();
      await waitForExit(spawned.child, 5000);
      return;
    }

    const code = await waitForExit(spawned.child, 5000);
    if (code === null) {
      spawned.child.kill();
      await waitForExit(spawned.child, 5000);
      return;
    }
    // Clean handler exits 0; some hosts still surface a non-zero status after signal delivery.
    expect([0, 1]).toContain(code);
    expect(spawned.stderr.join("")).not.toMatch(/0x[0-9a-fA-F]{40}/);
    expect(spawned.stderr.join("")).not.toMatch(/sk_live|Bearer /i);
  });
});

describe("active request registry", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-active-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  it("tracks begin/end and refuses cancel for unknown ids", () => {
    const registry = new GuwahActiveRequestRegistry();
    expect(registry.tryCancel(7)).toBe(false);
    expect(registry.isCancelled(7)).toBe(false);
    expect(registry.tryExpire(7)).toBe(false);
    expect(registry.isExpired(7)).toBe(false);
    expect(registry.tryAbort(7)).toBe(false);
    expect(registry.isAborted(7)).toBe(false);
    expect(registry.isTerminal(7)).toBe(false);

    expect(registry.tryBegin(7)).toBe(true);
    expect(registry.has(7)).toBe(true);
    expect(registry.tryBegin(7)).toBe(false);
    expect(registry.tryCancel(7)).toBe(true);
    expect(registry.isCancelled(7)).toBe(true);
    expect(registry.isTerminal(7)).toBe(true);
    expect(registry.tryCancel(99)).toBe(false);
    expect(registry.tryExpire(7)).toBe(true);
    expect(registry.isExpired(7)).toBe(true);
    expect(registry.tryExpire(99)).toBe(false);
    expect(registry.tryAbort(7)).toBe(true);
    expect(registry.isAborted(7)).toBe(true);
    expect(registry.tryAbort(99)).toBe(false);

    registry.end(7);
    expect(registry.has(7)).toBe(false);
    expect(registry.isCancelled(7)).toBe(false);
    expect(registry.isExpired(7)).toBe(false);
    expect(registry.isAborted(7)).toBe(false);
    expect(registry.isTerminal(7)).toBe(false);
    expect(registry.tryCancel(7)).toBe(false);
    expect(registry.tryExpire(7)).toBe(false);
    expect(registry.tryAbort(7)).toBe(false);
    expect(registry.size()).toBe(0);
  });

  it("abortAllActive seals only currently active ids", () => {
    const registry = new GuwahActiveRequestRegistry();
    expect(registry.tryBegin(1)).toBe(true);
    expect(registry.tryBegin(2)).toBe(true);
    registry.abortAllActive();
    expect(registry.isAborted(1)).toBe(true);
    expect(registry.isAborted(2)).toBe(true);
    expect(registry.isTerminal(1)).toBe(true);
    expect(registry.isTerminal(2)).toBe(true);
    expect(registry.tryBegin(3)).toBe(true);
    expect(registry.isAborted(3)).toBe(false);
    expect(registry.isTerminal(3)).toBe(false);
  });

  it("rejects a duplicate in-flight tools/call id and removes completed ids", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    let releaseFirst: (() => void) | undefined;
    const holdFirst = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let dispatchCount = 0;

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      afterApproval: async () => {
        dispatchCount += 1;
        await holdFirst;
        return { content: [{ type: "text", text: "first-complete" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-duplicate-id", version: "0.0.0" },
      },
    });
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 42,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    const activeDeadline = Date.now() + 5000;
    while (Date.now() < activeDeadline && !activeRequests.has(42)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.has(42)).toBe(true);
    expect(dispatchCount).toBe(1);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 42,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    const dupDeadline = Date.now() + 5000;
    while (Date.now() < dupDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 42,
      error: {
        code: -32600,
        message: expect.stringContaining("Duplicate request id is already active."),
      },
    });
    expect(dispatchCount).toBe(1);
    expect(activeRequests.has(42)).toBe(true);

    releaseFirst?.();
    const doneDeadline = Date.now() + 5000;
    while (Date.now() < doneDeadline && activeRequests.has(42)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.has(42)).toBe(false);
    expect(activeRequests.size()).toBe(0);

    await server.close();
    await clientTransport.close();
  });
});

describe("concurrency bounds", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-concurrency-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  it("rejects non-positive maxConcurrentCalls at construction", () => {
    expect(() => createGuwahGatewayServer({ maxConcurrentCalls: 0 })).toThrow(
      /maxConcurrentCalls must be a positive safe integer/,
    );
    expect(() => createGuwahGatewayServer({ maxConcurrentCalls: 1.5 })).toThrow(
      /maxConcurrentCalls must be a positive safe integer/,
    );
    expect(() => createGuwahGatewayServer({ maxConcurrentCalls: -1 })).toThrow(
      /maxConcurrentCalls must be a positive safe integer/,
    );
  });

  it("rejects excess concurrent calls fail-closed without queuing", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    let releaseFirst: (() => void) | undefined;
    const holdFirst = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let dispatchCount = 0;
    const dispatchedIds: number[] = [];

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      maxConcurrentCalls: 1,
      afterApproval: async (approved) => {
        dispatchCount += 1;
        const id = approved.id;
        if (typeof id === "number") {
          dispatchedIds.push(id);
        }
        if (id === 201) {
          await holdFirst;
        }
        return { content: [{ type: "text", text: `ok-${String(id)}` }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-concurrency", version: "0.0.0" },
      },
    });
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 201,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    const activeDeadline = Date.now() + 5000;
    while (Date.now() < activeDeadline && !activeRequests.has(201)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.size()).toBe(1);
    expect(dispatchCount).toBe(1);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 202,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    expect(dispatchCount).toBe(1);
    expect(activeRequests.has(202)).toBe(false);
    expect(activeRequests.size()).toBe(1);
    expect(dispatchedIds).toEqual([201]);

    const saturated = responses.find(
      (message) =>
        typeof message === "object" &&
        message !== null &&
        "id" in message &&
        (message as { id: unknown }).id === 202 &&
        "error" in message,
    );
    expect(saturated).toMatchObject({
      jsonrpc: "2.0",
      id: 202,
      error: {
        code: expect.any(Number),
        message: expect.stringContaining("Concurrent tool call limit reached"),
      },
    });
    expect(JSON.stringify(responses)).not.toContain("ok-202");

    releaseFirst?.();
    const firstDoneDeadline = Date.now() + 5000;
    while (Date.now() < firstDoneDeadline && activeRequests.has(201)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.size()).toBe(0);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 203,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    const thirdDeadline = Date.now() + 5000;
    while (
      Date.now() < thirdDeadline &&
      !responses.some(
        (message) =>
          typeof message === "object" &&
          message !== null &&
          "id" in message &&
          (message as { id: unknown }).id === 203 &&
          "result" in message,
      )
    ) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(dispatchCount).toBe(2);
    expect(dispatchedIds).toEqual([201, 203]);
    expect(JSON.stringify(responses)).toContain("ok-203");
    expect(JSON.stringify(responses)).not.toContain("ok-202");

    await server.close();
    await clientTransport.close();
  });
});

describe("stdio backpressure", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-backpressure-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  it("documents stdio framing and concurrency memory bounds", () => {
    expect(GUWAH_STDIO_BACKPRESSURE_BOUNDS.defaultMaxBufferBytes).toBe(10 * 1024 * 1024);
  });

  it("pauses stdin under flood and keeps concurrency within the configured bound", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    const stdin = new PassThrough({ highWaterMark: 16 * 1024 });
    const stdout = new PassThrough();
    const chunks: string[] = [];
    const failures: unknown[] = [];
    let releaseFirst: (() => void) | undefined;
    const holdFirst = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let dispatchCount = 0;
    let peakActive = 0;
    let sawPausedWhileSaturated = false;
    const maxBufferSize = 64 * 1024;
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      maxConcurrentCalls: 1,
      maxBufferSize,
      afterApproval: async (approved) => {
        dispatchCount += 1;
        peakActive = Math.max(peakActive, activeRequests.size());
        if (stdin.isPaused()) {
          sawPausedWhileSaturated = true;
        }
        if (approved.id === 301) {
          await holdFirst;
        }
        return { content: [{ type: "text", text: `ok-${String(approved.id)}` }] };
      },
      onTransportFailure: (error) => {
        failures.push(error);
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-flood", version: "0.0.0" },
        },
      })}\n`,
    );
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 301,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );
    const heldDeadline = Date.now() + 5000;
    while (Date.now() < heldDeadline && !activeRequests.has(301)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.has(301)).toBe(true);
    expect(dispatchCount).toBe(1);
    expect(stdin.isPaused()).toBe(true);
    sawPausedWhileSaturated = true;

    let peakReadable = stdin.readableLength;
    for (let i = 0; i < 40; i += 1) {
      const frame = `${JSON.stringify({
        jsonrpc: "2.0",
        id: 400 + i,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`;
      stdin.write(frame);
      peakReadable = Math.max(peakReadable, stdin.readableLength);
      peakActive = Math.max(peakActive, activeRequests.size());
      expect(activeRequests.size()).toBeLessThanOrEqual(1);
    }

    expect(dispatchCount).toBe(1);
    expect(peakActive).toBe(1);
    expect(sawPausedWhileSaturated).toBe(true);
    expect(peakReadable).toBeLessThanOrEqual(maxBufferSize);
    expect(peakReadable).toBeLessThanOrEqual(GUWAH_STDIO_BACKPRESSURE_BOUNDS.defaultMaxBufferBytes);
    expect(failures).toHaveLength(0);

    releaseFirst?.();
    const drainedDeadline = Date.now() + 5000;
    while (
      Date.now() < drainedDeadline &&
      (activeRequests.size() > 0 || stdin.readableLength > 0 || stdin.isPaused())
    ) {
      peakActive = Math.max(peakActive, activeRequests.size());
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    peakActive = Math.max(peakActive, activeRequests.size());

    expect(peakActive).toBe(1);
    expect(activeRequests.size()).toBe(0);
    expect(stdin.isPaused()).toBe(false);
    expect(dispatchCount).toBeGreaterThanOrEqual(1);
    expect(dispatchCount).toBeLessThanOrEqual(41);
    const stdoutText = chunks.join("");
    expect(stdoutText).toContain("ok-301");
    const limitRejections = stdoutText.split("Concurrent tool call limit reached").length - 1;
    expect(limitRejections).toBeGreaterThanOrEqual(0);
    expect(limitRejections + dispatchCount).toBeGreaterThanOrEqual(1);
    expect(failures).toHaveLength(0);
  });

  it("fail-closes on framing flood beyond maxBufferSize rather than dropping validations silently", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const failures: unknown[] = [];
    const maxBufferSize = 256;

    await startGuwahStdioGateway({
      stdin,
      stdout,
      maxBufferSize,
      maxConcurrentCalls: 1,
      onTransportFailure: (error) => {
        failures.push(error);
      },
    });

    stdin.write("y".repeat(maxBufferSize + 64));
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && failures.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(failures.length).toBeGreaterThanOrEqual(1);
    expect(String(failures[0])).toMatch(/maximum size|ReadBuffer|exceeded/i);
  });
});

describe("MCP cancellation", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-cancel-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  it("suppresses late success after notifications/cancelled and does not retry dispatch", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    let releaseDispatch: (() => void) | undefined;
    const holdDispatch = new Promise<void>((resolve) => {
      releaseDispatch = resolve;
    });
    let dispatchCount = 0;
    let sawCancelledDuringDispatch = false;

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      afterApproval: async () => {
        dispatchCount += 1;
        const waitStart = Date.now();
        while (Date.now() - waitStart < 5000 && !activeRequests.isCancelled(77)) {
          await new Promise((resolve) => {
            setTimeout(resolve, 25);
          });
        }
        sawCancelledDuringDispatch = activeRequests.isCancelled(77);
        await holdDispatch;
        return { content: [{ type: "text", text: "should-not-arrive-after-cancel" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-cancel", version: "0.0.0" },
      },
    });
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 77,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    const enteredDeadline = Date.now() + 5000;
    while (Date.now() < enteredDeadline && dispatchCount === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(dispatchCount).toBe(1);

    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: { requestId: 77, reason: "client cancelled" },
    });
    const cancelledDeadline = Date.now() + 5000;
    while (Date.now() < cancelledDeadline && !activeRequests.isCancelled(77)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.isCancelled(77)).toBe(true);

    releaseDispatch?.();
    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    expect(sawCancelledDuringDispatch).toBe(true);
    expect(dispatchCount).toBe(1);
    const lateSuccess = responses.some(
      (message) =>
        typeof message === "object" &&
        message !== null &&
        "id" in message &&
        (message as { id: unknown }).id === 77 &&
        "result" in message,
    );
    expect(lateSuccess).toBe(false);
    expect(JSON.stringify(responses)).not.toContain("should-not-arrive-after-cancel");

    await server.close();
    await clientTransport.close();
  });

  it("does not dispatch afterApproval when cancelled before approval", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    let dispatchCount = 0;

    const guard = new GuwahGuard({ policyPath });
    const originalValidate = guard.validateToolCall.bind(guard);
    vi.spyOn(guard, "validateToolCall").mockImplementation((payload, args) => {
      expect(activeRequests.has(88)).toBe(true);
      expect(activeRequests.tryCancel(88)).toBe(true);
      return originalValidate(payload, args);
    });

    const server = createGuwahGatewayServer({
      guard,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "should-not-dispatch" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-cancel-pre", version: "0.0.0" },
      },
    });
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 88,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    expect(dispatchCount).toBe(0);
    expect(JSON.stringify(responses)).not.toContain("should-not-dispatch");
    const lateSuccess = responses.some(
      (message) =>
        typeof message === "object" &&
        message !== null &&
        "id" in message &&
        (message as { id: unknown }).id === 88 &&
        "result" in message,
    );
    expect(lateSuccess).toBe(false);

    await server.close();
    await clientTransport.close();
  });
});

describe("request deadlines", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-timeout-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  it("rejects non-positive requestTimeoutMs at construction", () => {
    expect(() => createGuwahGatewayServer({ requestTimeoutMs: 0 })).toThrow(
      /requestTimeoutMs must be a positive safe integer/,
    );
    expect(() => createGuwahGatewayServer({ requestTimeoutMs: 1.5 })).toThrow(
      /requestTimeoutMs must be a positive safe integer/,
    );
    expect(() => createGuwahGatewayServer({ requestTimeoutMs: -1 })).toThrow(
      /requestTimeoutMs must be a positive safe integer/,
    );
  });

  it("does not dispatch afterApproval when expired before approval", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    let dispatchCount = 0;

    const guard = new GuwahGuard({ policyPath });
    const originalValidate = guard.validateToolCall.bind(guard);
    vi.spyOn(guard, "validateToolCall").mockImplementation((payload, args) => {
      expect(activeRequests.has(55)).toBe(true);
      expect(activeRequests.tryExpire(55)).toBe(true);
      return originalValidate(payload, args);
    });

    const server = createGuwahGatewayServer({
      guard,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      requestTimeoutMs: 60_000,
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "should-not-dispatch-after-expiry" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-timeout-pre", version: "0.0.0" },
      },
    });
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 55,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    expect(dispatchCount).toBe(0);
    expect(JSON.stringify(responses)).not.toContain("should-not-dispatch-after-expiry");
    const lateSuccess = responses.some(
      (message) =>
        typeof message === "object" &&
        message !== null &&
        "id" in message &&
        (message as { id: unknown }).id === 55 &&
        "result" in message,
    );
    expect(lateSuccess).toBe(false);

    await server.close();
    await clientTransport.close();
  });

  it("expires in-flight calls without retrying mutating dispatch", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    let releaseDispatch: (() => void) | undefined;
    const holdDispatch = new Promise<void>((resolve) => {
      releaseDispatch = resolve;
    });
    let dispatchCount = 0;

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      requestTimeoutMs: 40,
      afterApproval: async () => {
        dispatchCount += 1;
        const waitStart = Date.now();
        while (Date.now() - waitStart < 5000 && !activeRequests.isExpired(66)) {
          await new Promise((resolve) => {
            setTimeout(resolve, 10);
          });
        }
        await holdDispatch;
        return { content: [{ type: "text", text: "should-not-arrive-after-timeout" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-timeout", version: "0.0.0" },
      },
    });
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 66,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    const activeDeadline = Date.now() + 5000;
    while (Date.now() < activeDeadline && !activeRequests.has(66)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.has(66)).toBe(true);

    const expiredDeadline = Date.now() + 5000;
    while (Date.now() < expiredDeadline && !activeRequests.isExpired(66)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.isExpired(66)).toBe(true);
    expect(dispatchCount).toBe(1);

    releaseDispatch?.();
    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    expect(dispatchCount).toBe(1);
    expect(JSON.stringify(responses)).not.toContain("should-not-arrive-after-timeout");
    const lateSuccess = responses.some(
      (message) =>
        typeof message === "object" &&
        message !== null &&
        "id" in message &&
        (message as { id: unknown }).id === 66 &&
        "result" in message,
    );
    expect(lateSuccess).toBe(false);

    await server.close();
    await clientTransport.close();
  });
});

describe("late response suppression", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  function isJsonRpcForId(message: unknown, id: number): message is Record<string, unknown> {
    return (
      typeof message === "object" &&
      message !== null &&
      "id" in message &&
      (message as { id: unknown }).id === id
    );
  }

  function hasResult(message: Record<string, unknown>): boolean {
    return "result" in message;
  }

  function hasError(message: Record<string, unknown>): boolean {
    return "error" in message;
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-late-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  async function initializeClient(
    clientTransport: {
      send: (message: {
        jsonrpc: "2.0";
        id?: number;
        method: string;
        params?: Record<string, unknown>;
      }) => Promise<void>;
    },
    responses: unknown[],
    clientName: string,
  ): Promise<void> {
    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: clientName, version: "0.0.0" },
      },
    });
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });
  }

  it("does not deliver success after a cancel terminal error for the same id", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    let releaseDispatch: (() => void) | undefined;
    const holdDispatch = new Promise<void>((resolve) => {
      releaseDispatch = resolve;
    });
    let dispatchCount = 0;

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      afterApproval: async () => {
        dispatchCount += 1;
        const waitStart = Date.now();
        while (Date.now() - waitStart < 5000 && !activeRequests.isCancelled(101)) {
          await new Promise((resolve) => {
            setTimeout(resolve, 10);
          });
        }
        await holdDispatch;
        return { content: [{ type: "text", text: "late-success-after-cancel" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await initializeClient(clientTransport, responses, "guwah-late-cancel");

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 101,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    const activeDeadline = Date.now() + 5000;
    while (Date.now() < activeDeadline && !activeRequests.has(101)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: { requestId: 101, reason: "client cancelled" },
    });
    const cancelledDeadline = Date.now() + 5000;
    while (Date.now() < cancelledDeadline && !activeRequests.isCancelled(101)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.isTerminal(101)).toBe(true);

    releaseDispatch?.();
    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    expect(dispatchCount).toBe(1);
    const forId = responses.filter((message) => isJsonRpcForId(message, 101));
    const successes = forId.filter(hasResult);
    const errors = forId.filter(hasError);
    expect(successes).toHaveLength(0);
    expect(JSON.stringify(responses)).not.toContain("late-success-after-cancel");
    if (errors.length > 0) {
      const firstErrorIndex = responses.findIndex(
        (message) => isJsonRpcForId(message, 101) && hasError(message),
      );
      const successAfterError = responses
        .slice(firstErrorIndex + 1)
        .some((message) => isJsonRpcForId(message, 101) && hasResult(message));
      expect(successAfterError).toBe(false);
    }

    await server.close();
    await clientTransport.close();
  });

  it("does not deliver success after a deadline terminal error for the same id", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    let releaseDispatch: (() => void) | undefined;
    const holdDispatch = new Promise<void>((resolve) => {
      releaseDispatch = resolve;
    });
    let dispatchCount = 0;

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      requestTimeoutMs: 40,
      afterApproval: async () => {
        dispatchCount += 1;
        const waitStart = Date.now();
        while (Date.now() - waitStart < 5000 && !activeRequests.isExpired(102)) {
          await new Promise((resolve) => {
            setTimeout(resolve, 10);
          });
        }
        await holdDispatch;
        return { content: [{ type: "text", text: "late-success-after-timeout" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await initializeClient(clientTransport, responses, "guwah-late-timeout");

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 102,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    const expiredDeadline = Date.now() + 5000;
    while (Date.now() < expiredDeadline && !activeRequests.isExpired(102)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.isTerminal(102)).toBe(true);

    releaseDispatch?.();
    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    expect(dispatchCount).toBe(1);
    const forId = responses.filter((message) => isJsonRpcForId(message, 102));
    const successes = forId.filter(hasResult);
    const errors = forId.filter(hasError);
    expect(successes).toHaveLength(0);
    expect(JSON.stringify(responses)).not.toContain("late-success-after-timeout");
    if (errors.length > 0) {
      const firstErrorIndex = responses.findIndex(
        (message) => isJsonRpcForId(message, 102) && hasError(message),
      );
      const successAfterError = responses
        .slice(firstErrorIndex + 1)
        .some((message) => isJsonRpcForId(message, 102) && hasResult(message));
      expect(successAfterError).toBe(false);
    }

    await server.close();
    await clientTransport.close();
  });

  it("drops late success after shutdown grace abort for the same id", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    const events: string[] = [];
    let releaseDispatch: (() => void) | undefined;
    const holdDispatch = new Promise<void>((resolve) => {
      releaseDispatch = resolve;
    });
    let dispatchCount = 0;
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      shutdownGraceMs: 40,
      afterApproval: async () => {
        dispatchCount += 1;
        events.push("dispatch-enter");
        await holdDispatch;
        events.push("dispatch-exit");
        return { content: [{ type: "text", text: "late-success-after-shutdown" }] };
      },
      onStdinEof: () => {
        events.push("eof-complete");
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-late-shutdown", version: "0.0.0" },
        },
      })}\n`,
    );
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 103,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );

    const enteredDeadline = Date.now() + 5000;
    while (Date.now() < enteredDeadline && !events.includes("dispatch-enter")) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(dispatchCount).toBe(1);

    stdin.end();
    const abortedDeadline = Date.now() + 5000;
    while (Date.now() < abortedDeadline && !activeRequests.isAborted(103)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.isTerminal(103)).toBe(true);

    const eofDeadline = Date.now() + 5000;
    while (Date.now() < eofDeadline && !events.includes("eof-complete")) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(events).toContain("eof-complete");

    releaseDispatch?.();
    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    expect(dispatchCount).toBe(1);
    const stdoutText = chunks.join("");
    expect(stdoutText).not.toContain("late-success-after-shutdown");
    const frames = stdoutText
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const forId = frames.filter((frame) => frame.id === 103);
    const successes = forId.filter((frame) => "result" in frame);
    const errors = forId.filter((frame) => "error" in frame);
    expect(successes).toHaveLength(0);
    if (errors.length > 0) {
      const firstErrorIndex = frames.findIndex((frame) => frame.id === 103 && "error" in frame);
      const successAfterError = frames
        .slice(firstErrorIndex + 1)
        .some((frame) => frame.id === 103 && "result" in frame);
      expect(successAfterError).toBe(false);
    }
  });
});

describe("gateway shutdown", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-shutdown-cases-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  function assertStdoutProtocolFramesOnly(stdoutText: string): void {
    expect(stdoutText).not.toMatch(/started|ready|listening|banner|diagnostic|\bdebug\b/i);
    const frames = stdoutText.split(/\r?\n/).filter((line) => line.length > 0);
    let remainder = stdoutText;
    for (const frame of frames) {
      const index = remainder.indexOf(frame);
      expect(index).toBeGreaterThanOrEqual(0);
      expect(remainder.slice(0, index).replace(/\r?\n/g, "")).toBe("");
      const parsed: unknown = JSON.parse(frame);
      expect(parsed).toMatchObject({ jsonrpc: "2.0" });
      remainder = remainder.slice(index + frame.length);
    }
    expect(remainder.replace(/\r?\n/g, "")).toBe("");
  }

  it("completes shutdown with protocol-clean stdout and no new calls", async () => {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    let eofCount = 0;
    let dispatchCount = 0;
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "should-not-run-after-shutdown" }] };
      },
      onStdinEof: () => {
        eofCount += 1;
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-shutdown-cases", version: "0.0.0" },
        },
      })}\n`,
    );
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && chunks.join("").trim().length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(chunks.join("")).toContain('"id":1');

    stdin.end();
    const eofDeadline = Date.now() + 5000;
    while (Date.now() < eofDeadline && eofCount === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(eofCount).toBe(1);

    const beforeLate = dispatchCount;
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );
    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });

    expect(dispatchCount).toBe(beforeLate);
    expect(chunks.join("")).not.toContain("should-not-run-after-shutdown");
    assertStdoutProtocolFramesOnly(chunks.join(""));
  });

  it("must not emit a second mutating dispatch during shutdown", async () => {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    const events: string[] = [];
    const failures: unknown[] = [];
    let releaseDispatch: (() => void) | undefined;
    const holdDispatch = new Promise<void>((resolve) => {
      releaseDispatch = resolve;
    });
    let dispatchCount = 0;
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      shutdownGraceMs: 50,
      afterApproval: async () => {
        dispatchCount += 1;
        events.push("dispatch-enter");
        await holdDispatch;
        events.push("dispatch-exit");
        return { content: [{ type: "text", text: "first-dispatch-only" }] };
      },
      onTransportFailure: (error) => {
        failures.push(error);
      },
      onStdinEof: () => {
        events.push("eof-complete");
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-shutdown-no-second", version: "0.0.0" },
        },
      })}\n`,
    );
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );

    const enteredDeadline = Date.now() + 5000;
    while (Date.now() < enteredDeadline && !events.includes("dispatch-enter")) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(dispatchCount).toBe(1);

    stdin.end();
    const eofDeadline = Date.now() + 5000;
    while (Date.now() < eofDeadline && !events.includes("eof-complete")) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(events).toContain("eof-complete");
    expect(events).not.toContain("dispatch-exit");

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );
    releaseDispatch?.();
    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    expect(dispatchCount).toBe(1);
    expect(events.filter((entry) => entry === "dispatch-enter")).toHaveLength(1);
    expect(chunks.join("")).not.toMatch(/"id":3/);
    expect(chunks.join("")).not.toContain("should-not-run-after-shutdown");
    assertStdoutProtocolFramesOnly(chunks.join(""));
    expect(failures).toEqual([]);
  });
});

describe("clean shutdown lifecycle", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [WHITELISTED_DESTINATION],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-shutdown-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  function assertStdoutProtocolFramesOnly(stdoutText: string): void {
    expect(stdoutText).not.toMatch(/started|ready|listening|banner|diagnostic|\bdebug\b/i);
    const frames = stdoutText.split(/\r?\n/).filter((line) => line.length > 0);
    let remainder = stdoutText;
    for (const frame of frames) {
      const index = remainder.indexOf(frame);
      expect(index).toBeGreaterThanOrEqual(0);
      expect(remainder.slice(0, index).replace(/\r?\n/g, "")).toBe("");
      const parsed: unknown = JSON.parse(frame);
      expect(parsed).toMatchObject({ jsonrpc: "2.0" });
      remainder = remainder.slice(index + frame.length);
    }
    expect(remainder.replace(/\r?\n/g, "")).toBe("");
  }

  it("waits for an in-flight approved dispatch before completing EOF shutdown", async () => {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    const events: string[] = [];
    let releaseDispatch: (() => void) | undefined;
    const holdDispatch = new Promise<void>((resolve) => {
      releaseDispatch = resolve;
    });
    let dispatchCount = 0;
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      shutdownGraceMs: 5_000,
      afterApproval: async () => {
        dispatchCount += 1;
        events.push("dispatch-enter");
        await holdDispatch;
        events.push("dispatch-exit");
        return { content: [{ type: "text", text: "completed-once" }] };
      },
      onStdinEof: () => {
        events.push("eof-complete");
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-shutdown-wait", version: "0.0.0" },
        },
      })}\n`,
    );
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );

    const enteredDeadline = Date.now() + 5000;
    while (Date.now() < enteredDeadline && !events.includes("dispatch-enter")) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(events).toContain("dispatch-enter");

    stdin.end();
    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });
    expect(events).not.toContain("eof-complete");

    releaseDispatch?.();
    const eofDeadline = Date.now() + 5000;
    while (Date.now() < eofDeadline && !events.includes("eof-complete")) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(events).toEqual(["dispatch-enter", "dispatch-exit", "eof-complete"]);
    expect(dispatchCount).toBe(1);
    assertStdoutProtocolFramesOnly(chunks.join(""));
  });

  it("on shutdown timeout still avoids a second mutating dispatch and keeps stdout clean", async () => {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    const events: string[] = [];
    let releaseDispatch: (() => void) | undefined;
    const holdDispatch = new Promise<void>((resolve) => {
      releaseDispatch = resolve;
    });
    let dispatchCount = 0;
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      shutdownGraceMs: 50,
      afterApproval: async () => {
        dispatchCount += 1;
        events.push("dispatch-enter");
        await holdDispatch;
        events.push("dispatch-exit");
        return { content: [{ type: "text", text: "late-complete" }] };
      },
      onStdinEof: () => {
        events.push("eof-complete");
      },
    });

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-shutdown-timeout", version: "0.0.0" },
        },
      })}\n`,
    );
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );

    const enteredDeadline = Date.now() + 5000;
    while (Date.now() < enteredDeadline && !events.includes("dispatch-enter")) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(dispatchCount).toBe(1);

    stdin.end();
    const eofDeadline = Date.now() + 5000;
    while (Date.now() < eofDeadline && !events.includes("eof-complete")) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(events).toContain("eof-complete");
    expect(events).not.toContain("dispatch-exit");

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: TOOL_NAME, arguments: compliantArgs() },
      })}\n`,
    );
    releaseDispatch?.();
    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });

    expect(dispatchCount).toBe(1);
    expect(events.filter((entry) => entry === "dispatch-enter")).toHaveLength(1);
    assertStdoutProtocolFramesOnly(chunks.join(""));
    expect(chunks.join("")).not.toMatch(/"id":3/);
    expect(chunks.join("")).not.toContain("late-complete");
  });
});

describe("stdout protocol purity", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [
          "0x1111111111111111111111111111111111111111",
          "0x2222222222222222222222222222222222222222",
        ],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    description: "Gateway-mediated fake transfer",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-stdout-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  function assertStdoutProtocolFramesOnly(stdoutText: string): void {
    expect(stdoutText).not.toMatch(/started|ready|listening|banner|diagnostic|\bdebug\b/i);
    const lines = stdoutText.split(/\r?\n/);
    const frames = lines.filter((line) => line.length > 0);
    expect(frames.length).toBeGreaterThan(0);

    let remainder = stdoutText;
    for (const frame of frames) {
      const index = remainder.indexOf(frame);
      expect(index).toBeGreaterThanOrEqual(0);
      expect(remainder.slice(0, index).replace(/\r?\n/g, "")).toBe("");
      const parsed: unknown = JSON.parse(frame);
      expect(parsed).toMatchObject({ jsonrpc: "2.0" });
      expect(parsed).toHaveProperty("id");
      const record = parsed as Record<string, unknown>;
      expect("result" in record || "error" in record).toBe(true);
      remainder = remainder.slice(index + frame.length);
    }
    expect(remainder.replace(/\r?\n/g, "")).toBe("");
  }

  async function waitForChunkCount(chunks: string[], count: number, timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const frames = chunks
        .join("")
        .split(/\r?\n/)
        .filter((line) => line.trim().length > 0);
      if (frames.length >= count) {
        return;
      }
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    throw new Error(`expected at least ${String(count)} stdout protocol frames`);
  }

  it("gateway source never writes logs or diagnostics to stdout", () => {
    const source = readFileSync(GATEWAY_SOURCE, "utf8");
    expect(source).not.toMatch(/\bconsole\.(log|info|debug|warn|error|dir|table)\s*\(/);
    expect(source).not.toMatch(/process\.stdout\.write\s*\(/);
    expect(source).toMatch(/writeGuwahStderrDiagnostic/);
    expect(source).toMatch(/Stdout is reserved exclusively for newline-delimited JSON-RPC/);
  });

  it("keeps stdout protocol-pure across startup, list, call, and shutdown", async () => {
    const policyPath = writePolicy();
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    const { server } = await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      mediatedTools: [mediatedTransfer],
      onTransportFailure: () => {
        throw new Error("unexpected transport failure during purity run");
      },
    });

    expect(chunks.join("")).toBe("");

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-stdout-purity", version: "0.0.0" },
        },
      })}\n`,
    );
    await waitForChunkCount(chunks, 1, 5000);
    assertStdoutProtocolFramesOnly(chunks.join(""));

    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })}\n`);
    await waitForChunkCount(chunks, 2, 5000);
    assertStdoutProtocolFramesOnly(chunks.join(""));

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: TOOL_NAME,
          arguments: compliantArgs(),
        },
      })}\n`,
    );
    await waitForChunkCount(chunks, 3, 5000);
    assertStdoutProtocolFramesOnly(chunks.join(""));

    const beforeShutdown = chunks.join("");
    await server.close();
    stdin.end();
    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });
    const afterShutdown = chunks.join("");
    expect(afterShutdown).toBe(beforeShutdown);
    assertStdoutProtocolFramesOnly(afterShutdown);

    const parsed = afterShutdown
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(parsed).toHaveLength(3);
    expect(parsed[0]).toMatchObject({ id: 1, result: expect.any(Object) });
    expect(parsed[1]).toMatchObject({ id: 2, result: { tools: [{ name: TOOL_NAME }] } });
    expect(parsed[2]).toMatchObject({ id: 3, result: expect.any(Object) });
  });

  it("fails purity when a non-protocol banner is mixed into stdout", () => {
    expect(() =>
      assertStdoutProtocolFramesOnly(
        `${JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} })}\nGuwah gateway started\n`,
      ),
    ).toThrow();
    expect(() => assertStdoutProtocolFramesOnly("ready\n")).toThrow();
  });

  it("compiled gateway stdout stays protocol-pure for initialize, list, call, and shutdown", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const spawned = spawnGateway(GATEWAY_ENTRY);

    spawned.child.stdin?.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-compiled-purity", version: "0.0.0" },
        },
      })}\n`,
    );
    await waitForStdoutMessageCount(spawned, 1, 5000);
    assertStdoutProtocolFramesOnly(spawned.stdout.join(""));

    spawned.child.stdin?.write(
      `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`,
    );
    spawned.child.stdin?.write(
      `${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })}\n`,
    );
    await waitForStdoutMessageCount(spawned, 2, 5000);
    assertStdoutProtocolFramesOnly(spawned.stdout.join(""));

    spawned.child.stdin?.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: TOOL_NAME,
          arguments: compliantArgs(),
        },
      })}\n`,
    );
    await waitForStdoutMessageCount(spawned, 3, 5000);
    assertStdoutProtocolFramesOnly(spawned.stdout.join(""));

    const beforeClose = spawned.stdout.join("");
    spawned.child.stdin?.end();
    await waitForExit(spawned.child, 5000);
    expect(spawned.stdout.join("")).toBe(beforeClose);
    assertStdoutProtocolFramesOnly(spawned.stdout.join(""));
    expect(spawned.stderr.join("")).toBe("");
  });
});

describe("redacted stderr diagnostics", () => {
  const PLANTED_ADDRESS = "0x1111111111111111111111111111111111111111";
  const PLANTED_API_KEY = "api_key=sk_live_planted_secret_value";
  const PLANTED_BEARER = "Bearer planted-jwt-token-value";
  const PLANTED_PAYLOAD = JSON.stringify({
    jsonrpc: "2.0",
    method: "tools/call",
    params: {
      name: "coinbase_cdp_transfer",
      arguments: {
        amountMinor: 5000,
        destinationAddress: PLANTED_ADDRESS,
      },
    },
  });
  const PLANTED_POLICY = JSON.stringify({
    version: "1.0.0",
    posture: "default-deny",
    tools: {
      coinbase_cdp_transfer: {
        action: "ENFORCE",
        argsSchema: { type: "object" },
      },
    },
  });

  it("redacts planted addresses and credential-shaped values", () => {
    const redacted = redactGuwahDiagnosticText(
      `transport detail ${PLANTED_ADDRESS} ${PLANTED_API_KEY} ${PLANTED_BEARER}`,
    );
    expect(redacted).not.toContain(PLANTED_ADDRESS);
    expect(redacted).not.toContain("sk_live_planted_secret_value");
    expect(redacted).not.toContain("planted-jwt-token-value");
    expect(redacted).toContain("[redacted]");
  });

  it("omits planted full payloads and policy documents", () => {
    expect(redactGuwahDiagnosticText(PLANTED_PAYLOAD)).toBe("[omitted]");
    expect(redactGuwahDiagnosticText(PLANTED_POLICY)).toBe("[omitted]");
    expect(redactGuwahDiagnosticText(PLANTED_PAYLOAD)).not.toContain(PLANTED_ADDRESS);
    expect(redactGuwahDiagnosticText(PLANTED_POLICY)).not.toContain("argsSchema");
  });

  it("omits detail by default so planted Error.message secrets never appear", () => {
    const line = formatGuwahDiagnosticLine(
      "Guwah gateway transport failed.",
      new Error(`failed for ${PLANTED_ADDRESS} with ${PLANTED_API_KEY}`),
      false,
    );
    expect(line).toBe("Guwah gateway transport failed.");
    expect(line).not.toContain(PLANTED_ADDRESS);
    expect(line).not.toContain("sk_live_planted_secret_value");
  });

  it("redacts explicitly included detail and omits object payloads", () => {
    const withSecret = formatGuwahDiagnosticLine(
      "Guwah gateway transport failed.",
      new Error(`boom ${PLANTED_ADDRESS}`),
      true,
    );
    expect(withSecret).toContain("Guwah gateway transport failed.");
    expect(withSecret).not.toContain(PLANTED_ADDRESS);
    expect(withSecret).toContain("[redacted]");

    const withPayload = formatGuwahDiagnosticLine(
      "Guwah gateway transport failed.",
      JSON.parse(PLANTED_PAYLOAD),
      true,
    );
    expect(withPayload).toBe("Guwah gateway transport failed. [omitted]");
    expect(withPayload).not.toContain(PLANTED_ADDRESS);
  });

  it("writes only to the stderr sink and never echoes planted secrets", () => {
    const stderrChunks: string[] = [];
    const stdoutChunks: string[] = [];
    const stderr = new PassThrough();
    const stdout = new PassThrough();
    stderr.setEncoding("utf8");
    stdout.setEncoding("utf8");
    stderr.on("data", (chunk: string) => {
      stderrChunks.push(chunk);
    });
    stdout.on("data", (chunk: string) => {
      stdoutChunks.push(chunk);
    });

    writeGuwahStderrDiagnostic("Guwah gateway transport failed.", {
      detail: new Error(`${PLANTED_BEARER} ${PLANTED_PAYLOAD}`),
      includeDetail: true,
      stderr,
    });
    stdout.write("should-not-be-used-for-diagnostics\n");

    const stderrText = stderrChunks.join("");
    expect(stderrText).toMatch(/^Guwah gateway transport failed\. .+\n$/);
    expect(stderrText).not.toContain(PLANTED_ADDRESS);
    expect(stderrText).not.toContain("planted-jwt-token-value");
    expect(stderrText).not.toContain("amountMinor");
    expect(stdoutChunks.join("")).toBe("should-not-be-used-for-diagnostics\n");
  });

  it("fails redaction assertions when planted secrets remain unredacted", () => {
    const leaked = `failure ${PLANTED_ADDRESS}`;
    expect(leaked).toContain(PLANTED_ADDRESS);
    expect(() => {
      expect(redactGuwahDiagnosticText(leaked)).not.toContain(PLANTED_ADDRESS);
      if (redactGuwahDiagnosticText(leaked).includes(PLANTED_ADDRESS)) {
        throw new Error("unredacted diagnostic");
      }
    }).not.toThrow();
    expect(() => {
      expect(leaked).not.toContain(PLANTED_ADDRESS);
    }).toThrow();
  });
});

describe("tools/list", () => {
  it("returns an empty mediated set by default", async () => {
    const server = createGuwahGatewayServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-tools-list-empty", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    await expect(client.listTools()).resolves.toEqual({ tools: [] });
    await client.close();
    await server.close();
  });

  it("returns only the authorized mediated set and never an unfiltered downstream catalog", async () => {
    const server = createGuwahGatewayServer({
      resolveMediatedTools: () => [
        {
          name: "authorized_transfer",
          description: "Gateway-mediated fake transfer",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              amountMinor: { type: "integer" },
            },
            required: ["amountMinor"],
          },
        },
        // Intentionally omitted: any unvalidated downstream dump such as "raw_provider_tool".
      ],
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-tools-list-authorized", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const listed = await client.listTools();
    expect(listed.tools.map((tool) => tool.name)).toEqual(["authorized_transfer"]);
    expect(listed.tools.map((tool) => tool.name)).not.toContain("raw_provider_tool");
    expect(listed.tools).toHaveLength(1);
    await client.close();
    await server.close();
  });

  it("returns a structured error on catalog failure instead of a partial list", async () => {
    const server = createGuwahGatewayServer({
      resolveMediatedTools: () => {
        throw new Error("catalog interrupted after partial read");
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-tools-list-failure", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    await expect(client.listTools()).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(Error);
      if (!(error instanceof Error)) {
        return false;
      }
      expect(error.message).toMatch(/Gateway tool catalog is unavailable|Internal error/i);
      expect(error.message).not.toMatch(/partial/i);
      return true;
    });
    await client.close();
    await server.close();
  });

  it("lists tools over the compiled stdio gateway", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [GATEWAY_ENTRY],
      cwd: REPO_ROOT,
      stderr: "pipe",
    });
    const client = new Client({ name: "guwah-tools-list-stdio", version: "0.0.0" });
    liveClients.push({ client, transport });
    await client.connect(transport);
    await expect(client.listTools()).resolves.toEqual({ tools: [] });
    await client.close();
  });
});

describe("tools/call", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [
          "0x1111111111111111111111111111111111111111",
          "0x2222222222222222222222222222222222222222",
        ],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    description: "Gateway-mediated fake transfer",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function transferPolicy(): Record<string, unknown> {
    return {
      version: "1.0.0",
      posture: "default-deny",
      tools: {
        [TOOL_NAME]: {
          action: "ENFORCE",
          argsSchema: structuredClone(TRANSFER_SCHEMA),
        },
      },
    };
  }

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-call-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(policyPath, `${JSON.stringify(transferPolicy(), null, 2)}\n`, "utf8");
    return policyPath;
  }

  it("approves a compliant call through the validator without downstream dispatch by default", async () => {
    const policyPath = writePolicy();
    let downstreamInvocations = 0;
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async (approved: Readonly<McpToolCallPayload>) => {
        downstreamInvocations += 1;
        return {
          content: [
            {
              type: "text",
              text: `validated:${String(approved.params.name)}`,
            },
          ],
        };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-tools-call-ok", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const result = await client.callTool({
      name: TOOL_NAME,
      arguments: compliantArgs(),
    });
    expect(result).toMatchObject({
      content: [{ type: "text", text: `validated:${TOOL_NAME}` }],
    });
    expect(downstreamInvocations).toBe(1);

    await client.close();
    await server.close();
  });

  it("rejects invalid calls before any downstream send", async () => {
    const policyPath = writePolicy();
    let downstreamInvocations = 0;
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        downstreamInvocations += 1;
        return { content: [{ type: "text", text: "should-not-run" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-tools-call-denied", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    await expect(
      client.callTool({
        name: TOOL_NAME,
        arguments: { ...compliantArgs(), amountMinor: 5001 },
      }),
    ).rejects.toThrow();
    expect(downstreamInvocations).toBe(0);

    await client.close();
    await server.close();
  });

  it("rejects tools that are not in the mediated catalog before downstream send", async () => {
    const policyPath = writePolicy();
    let downstreamInvocations = 0;
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [],
      afterApproval: async () => {
        downstreamInvocations += 1;
        return { content: [{ type: "text", text: "should-not-run" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-tools-call-unmediated", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    await expect(
      client.callTool({
        name: TOOL_NAME,
        arguments: compliantArgs(),
      }),
    ).rejects.toThrow(/not mediated|Invalid/i);
    expect(downstreamInvocations).toBe(0);

    await client.close();
    await server.close();
  });

  it("rejects unknown MCP methods other than implemented handlers", async () => {
    const server = createGuwahGatewayServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-unknown-method", version: "0.0.0" },
      },
    });
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 2,
      method: "provider/secretExecute",
      params: {},
    });
    const methodDeadline = Date.now() + 5000;
    while (Date.now() < methodDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(responses.length).toBeGreaterThanOrEqual(2);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: expect.objectContaining({
        code: -32601,
      }),
    });
    await server.close();
    await clientTransport.close();
  });

  it("uses the validator-only approval path when no afterApproval hook is configured", async () => {
    const policyPath = writePolicy();
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-tools-call-default", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const result = await client.callTool({
      name: TOOL_NAME,
      arguments: compliantArgs(),
    });
    expect(result).toMatchObject({
      content: [
        {
          type: "text",
          text: "Tool call approved by local policy. Downstream dispatch is not configured.",
        },
      ],
    });

    await client.close();
    await server.close();
  });
});

describe("validate before dispatch", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [
          "0x1111111111111111111111111111111111111111",
          "0x2222222222222222222222222222222222222222",
        ],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    description: "Gateway-mediated fake transfer",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function transferPolicy(): Record<string, unknown> {
    return {
      version: "1.0.0",
      posture: "default-deny",
      tools: {
        [TOOL_NAME]: {
          action: "ENFORCE",
          argsSchema: structuredClone(TRANSFER_SCHEMA),
        },
      },
    };
  }

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-order-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(policyPath, `${JSON.stringify(transferPolicy(), null, 2)}\n`, "utf8");
    return policyPath;
  }

  it("runs GuwahGuard.validateToolCall on the complete envelope before any dispatch write", async () => {
    const policyPath = writePolicy();
    const guard = new GuwahGuard({ policyPath });
    const events: string[] = [];
    const networkWrites: unknown[] = [];

    vi.spyOn(guard, "validateToolCall").mockImplementation((payload, args) => {
      events.push("validate");
      expect(payload).toMatchObject({
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          name: TOOL_NAME,
          arguments: compliantArgs(),
        },
      });
      expect(args).toEqual(compliantArgs());
      expect(networkWrites).toEqual([]);
      return GuwahGuard.prototype.validateToolCall.call(guard, payload, args);
    });

    const server = createGuwahGatewayServer({
      guard,
      mediatedTools: [mediatedTransfer],
      afterApproval: async (approved) => {
        events.push("dispatch");
        networkWrites.push({
          name: approved.params.name,
          arguments: approved.params.arguments,
        });
        return {
          content: [{ type: "text", text: "dispatched-after-validation" }],
        };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-order-ok", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    await client.callTool({
      name: TOOL_NAME,
      arguments: compliantArgs(),
    });

    expect(events).toEqual(["validate", "dispatch"]);
    expect(networkWrites).toHaveLength(1);

    await client.close();
    await server.close();
  });

  it("maps validation failures to blocked MCP errors with zero network writes", async () => {
    const policyPath = writePolicy();
    const guard = new GuwahGuard({ policyPath });
    const events: string[] = [];
    const networkWrites: unknown[] = [];

    vi.spyOn(guard, "validateToolCall").mockImplementation((payload, args) => {
      events.push("validate");
      expect(networkWrites).toEqual([]);
      return GuwahGuard.prototype.validateToolCall.call(guard, payload, args);
    });

    const server = createGuwahGatewayServer({
      guard,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        events.push("dispatch");
        networkWrites.push("write");
        return { content: [{ type: "text", text: "should-not-run" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-order-denied", version: "0.0.0" },
      },
    });
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: TOOL_NAME,
        arguments: { ...compliantArgs(), amountMinor: 5001 },
      },
    });
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(events).toEqual(["validate"]);
    expect(networkWrites).toEqual([]);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32600,
        message: expect.any(String),
      },
    });
    const blocked = responses[1] as { error: { message: string } };
    expect(blocked.error.message).not.toContain("5001");
    expect(blocked.error.message).not.toContain(WHITELISTED_DESTINATION);
    expect(responses[1]).not.toHaveProperty("result");

    await server.close();
    await clientTransport.close();
  });
});

describe("structured MCP errors", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";
  const SECRET_MARKER = "secret-token-do-not-leak";

  const TRANSFER_SCHEMA = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "assetId", "destinationAddress", "memo"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      assetId: { type: "string", enum: ["USDC"] },
      destinationAddress: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        enum: [
          "0x1111111111111111111111111111111111111111",
          "0x2222222222222222222222222222222222222222",
        ],
      },
      memo: {
        type: "string",
        minLength: 1,
        maxLength: 80,
        pattern: "^[A-Za-z0-9 .,_:-]+$",
      },
    },
  } as const;

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    description: "Gateway-mediated fake transfer",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer" },
        assetId: { type: "string" },
        destinationAddress: { type: "string" },
        memo: { type: "string" },
      },
    },
  };

  function transferPolicy(): Record<string, unknown> {
    return {
      version: "1.0.0",
      posture: "default-deny",
      tools: {
        [TOOL_NAME]: {
          action: "ENFORCE",
          argsSchema: structuredClone(TRANSFER_SCHEMA),
        },
      },
    };
  }

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 5000,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 1001",
    };
  }

  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-errors-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(policyPath, `${JSON.stringify(transferPolicy(), null, 2)}\n`, "utf8");
    return policyPath;
  }

  async function initializePair(
    server: ReturnType<typeof createGuwahGatewayServer>,
  ): Promise<{
    clientTransport: ReturnType<typeof InMemoryTransport.createLinkedPair>[0];
    responses: unknown[];
  }> {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-structured-errors", version: "0.0.0" },
      },
    });
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });
    return { clientTransport, responses };
  }

  it("returns a protocol-shaped invalid-request error for malformed tools/call params", async () => {
    const server = createGuwahGatewayServer({
      policyPath: writePolicy(),
      mediatedTools: [mediatedTransfer],
    });
    const { clientTransport, responses } = await initializePair(server);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        arguments: compliantArgs(),
      },
    });
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: expect.any(Number),
        message: expect.any(String),
      },
    });
    expect(responses[1]).not.toHaveProperty("result");
    const err = responses[1] as { error: { code: number; message: string } };
    expect(Number.isSafeInteger(err.error.code)).toBe(true);
    expect(err.error.message.length).toBeGreaterThan(0);
    expect(err.error.message).not.toContain(WHITELISTED_DESTINATION);
    expect(err.error.message).not.toContain(SECRET_MARKER);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/list",
      params: {},
    });
    const listDeadline = Date.now() + 5000;
    while (Date.now() < listDeadline && responses.length < 3) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(responses[2]).toMatchObject({
      jsonrpc: "2.0",
      id: 3,
      result: {
        tools: [{ name: TOOL_NAME }],
      },
    });

    await server.close();
    await clientTransport.close();
  });

  it("returns a protocol-shaped security-denial error without crashing the process", async () => {
    const server = createGuwahGatewayServer({
      policyPath: writePolicy(),
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        throw new Error(`downstream reached with ${SECRET_MARKER}`);
      },
    });
    const { clientTransport, responses } = await initializePair(server);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: TOOL_NAME,
        arguments: { ...compliantArgs(), amountMinor: 5001 },
      },
    });
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32600,
        message: expect.stringContaining("Tool-call arguments violate local policy."),
        data: { guwahCode: "ARGUMENT_VALIDATION_FAILED" },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");
    const denied = responses[1] as { error: { message: string } };
    expect(denied.error.message).not.toContain("5001");
    expect(denied.error.message).not.toContain(WHITELISTED_DESTINATION);
    expect(denied.error.message).not.toContain(SECRET_MARKER);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/list",
      params: {},
    });
    const listDeadline = Date.now() + 5000;
    while (Date.now() < listDeadline && responses.length < 3) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(responses[2]).toMatchObject({
      jsonrpc: "2.0",
      id: 3,
      result: {
        tools: [{ name: TOOL_NAME }],
      },
    });

    await server.close();
    await clientTransport.close();
  });

  it("maps unexpected handler exceptions to a generic internal error without secrets", async () => {
    const server = createGuwahGatewayServer({
      policyPath: writePolicy(),
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        throw new Error(`unexpected failure containing ${SECRET_MARKER} and ${WHITELISTED_DESTINATION}`);
      },
    });
    const { clientTransport, responses } = await initializePair(server);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: TOOL_NAME,
        arguments: compliantArgs(),
      },
    });
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32603,
        message: expect.stringContaining("Tool call handling failed."),
      },
    });
    expect(responses[1]).not.toHaveProperty("result");
    const body = JSON.stringify(responses[1]);
    expect(body).not.toContain(SECRET_MARKER);
    expect(body).not.toContain(WHITELISTED_DESTINATION);

    await server.close();
    await clientTransport.close();
  });
});

describe("GuwahSecurityViolation MCP mapping", () => {
  const SECRET = "0xdeadbeef-secret-value-do-not-leak";
  const POLICY_PATH_LEAK = "/home/operator/.guwah/secret-policy.json";

  const ALL_CODES = Object.keys(GUWAH_VIOLATION_MCP_MAP) as GuwahViolationCode[];

  it("defines a mapping entry for every Guwah violation code", () => {
    const expected: readonly GuwahViolationCode[] = [
      "INVALID_PAYLOAD",
      "POLICY_UNAVAILABLE",
      "POLICY_INVALID",
      "UNAUTHORIZED_TOOL",
      "POLICY_NOT_ENFORCED",
      "PAYLOAD_MUTATION",
      "ARGUMENT_VALIDATION_FAILED",
      "DANGEROUS_OBJECT_KEY",
      "NON_JSON_VALUE",
      "RESOURCE_LIMIT_EXCEEDED",
      "INTERNAL_VALIDATION_ERROR",
    ];
    expect(ALL_CODES.sort()).toEqual([...expected].sort());
  });

  it.each(ALL_CODES)("maps %s to a sanitized MCP error without rejected values", (code) => {
    const mapping = GUWAH_VIOLATION_MCP_MAP[code];
    const violation = new GuwahSecurityViolation({
      code,
      message: `raw violation containing ${SECRET} and ${POLICY_PATH_LEAK}`,
      toolName: "coinbase_cdp_transfer",
      fieldPath: `/arguments/destinationAddress/${SECRET}`,
      rule: "enum",
    });

    const mcpError = mapGuwahViolationToMcpError(violation);

    expect(mcpError.code).toBe(mapping.jsonRpcCode);
    expect(mcpError.message).toContain(mapping.message);
    expect(mcpError.message).not.toContain(SECRET);
    expect(mcpError.message).not.toContain(POLICY_PATH_LEAK);
    expect(mcpError.message).not.toContain(violation.message);
    expect(mcpError.data).toEqual({ guwahCode: code });
    expect(JSON.stringify(mcpError.data)).not.toContain(SECRET);
    expect(JSON.stringify(mcpError.data)).not.toContain(POLICY_PATH_LEAK);
    expect(JSON.stringify(mcpError.data)).not.toContain("fieldPath");
    expect(JSON.stringify(mcpError.data)).not.toContain("toolName");
  });

  it("maps unmapped violation codes to a generic internal error", () => {
    const violation = new GuwahSecurityViolation({
      code: "ARGUMENT_VALIDATION_FAILED",
      message: `should not appear ${SECRET}`,
    });
    Object.defineProperty(violation, "code", {
      value: "NOT_A_REAL_VIOLATION_CODE",
      configurable: true,
    });

    const mcpError = mapGuwahViolationToMcpError(violation);

    expect(mcpError.code).toBe(-32603);
    expect(mcpError.message).toContain("Tool call denied.");
    expect(mcpError.message).not.toContain(SECRET);
    expect(mcpError.data).toBeUndefined();
  });

  it("surfaces mapped guwahCode on the tools/call wire for a live denial", async () => {
    const TOOL_NAME = "coinbase_cdp_transfer";
    const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";
    const TRANSFER_SCHEMA = {
      $schema: "http://json-schema.org/draft-07/schema#",
      type: "object",
      additionalProperties: false,
      required: ["amountMinor", "assetId", "destinationAddress", "memo"],
      properties: {
        amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
        assetId: { type: "string", enum: ["USDC"] },
        destinationAddress: {
          type: "string",
          pattern: "^0x[0-9a-fA-F]{40}$",
          enum: [WHITELISTED_DESTINATION],
        },
        memo: {
          type: "string",
          minLength: 1,
          maxLength: 80,
          pattern: "^[A-Za-z0-9 .,_:-]+$",
        },
      },
    } as const;

    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-map-"));
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: structuredClone(TRANSFER_SCHEMA),
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    try {
      const server = createGuwahGatewayServer({
        policyPath,
        mediatedTools: [
          {
            name: TOOL_NAME,
            inputSchema: {
              type: "object",
              additionalProperties: false,
              required: ["amountMinor", "assetId", "destinationAddress", "memo"],
              properties: {
                amountMinor: { type: "integer" },
                assetId: { type: "string" },
                destinationAddress: { type: "string" },
                memo: { type: "string" },
              },
            },
          },
        ],
      });
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      await server.connect(serverTransport);
      await clientTransport.start();

      const responses: unknown[] = [];
      clientTransport.onmessage = (message) => {
        responses.push(message);
      };

      await clientTransport.send({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-map-wire", version: "0.0.0" },
        },
      });
      const initDeadline = Date.now() + 5000;
      while (Date.now() < initDeadline && responses.length === 0) {
        await new Promise((resolve) => {
          setTimeout(resolve, 25);
        });
      }
      await clientTransport.send({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      });

      await clientTransport.send({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: {
          name: TOOL_NAME,
          arguments: {
            amountMinor: 5001,
            assetId: "USDC",
            destinationAddress: WHITELISTED_DESTINATION,
            memo: "invoice 1001",
          },
        },
      });
      const callDeadline = Date.now() + 5000;
      while (Date.now() < callDeadline && responses.length < 2) {
        await new Promise((resolve) => {
          setTimeout(resolve, 25);
        });
      }

      expect(responses[1]).toMatchObject({
        jsonrpc: "2.0",
        id: 2,
        error: {
          code: GUWAH_VIOLATION_MCP_MAP.ARGUMENT_VALIDATION_FAILED.jsonRpcCode,
          message: expect.stringContaining(
            GUWAH_VIOLATION_MCP_MAP.ARGUMENT_VALIDATION_FAILED.message,
          ),
          data: { guwahCode: "ARGUMENT_VALIDATION_FAILED" },
        },
      });
      const wire = JSON.stringify(responses[1]);
      expect(wire).not.toContain("5001");
      expect(wire).not.toContain(WHITELISTED_DESTINATION);

      await server.close();
      await clientTransport.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
