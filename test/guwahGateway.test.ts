import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema, ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import {
  callGuwahDownstreamToolWithCancelPropagation,
  connectGuwahDownstream,
  createGuwahDownstreamClient,
  createGuwahDownstreamReconnectGate,
  createGuwahGatewayServer,
  createGuwahStdioTransport,
  classifyGuwahDownstreamDispatchState,
  classifyGuwahToolSideEffect,
  formatGuwahDiagnosticLine,
  GuwahActiveRequestRegistry,
  GUWAH_DOWNSTREAM_CLIENT_NAME,
  GUWAH_DOWNSTREAM_CLIENT_VERSION,
  GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR,
  GUWAH_DOWNSTREAM_CONNECTION_ERROR,
  GUWAH_DOWNSTREAM_FAILURE_CODE,
  GUWAH_DOWNSTREAM_FAILURE_ERROR,
  GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_CODE,
  GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_ERROR,
  GUWAH_DOWNSTREAM_RECONNECT_FAILED_ERROR,
  GUWAH_DOWNSTREAM_RECONNECTING_ERROR,
  GUWAH_DOWNSTREAM_TRANSPORT_CONFIG_ERROR,
  GUWAH_DOWNSTREAM_UNAVAILABLE_CODE,
  GUWAH_GATEWAY_CAPABILITIES,
  GUWAH_GATEWAY_NAME,
  GUWAH_GATEWAY_VERSION,
  GUWAH_IDEMPOTENCY_META_KEY,
  GUWAH_STDIO_BACKPRESSURE_BOUNDS,
  GUWAH_TOOL_COLLISION_ERROR,
  GUWAH_TOOL_NAMESPACE_ERROR,
  GUWAH_TOOL_NAMESPACE_PREFIX,
  GUWAH_VIOLATION_MCP_MAP,
  applyGuwahToolNamespacing,
  assertGuwahToolNamesUnique,
  detectGuwahDiscoveryListChange,
  discoverGuwahDownstreamTools,
  fingerprintGuwahDiscoveryList,
  guwahMayCoalesceMutatingCall,
  guwahToolAllowsAutomaticRetry,
  isGuwahEmittedMcpError,
  loadGuwahDownstreamTransportConfig,
  mapGuwahDownstreamDispatchStateToMcpError,
  mapGuwahDownstreamFailureToMcpError,
  mapGuwahViolationToMcpError,
  mirrorAuthorizedGuwahTools,
  namespaceGuwahToolName,
  parseGuwahGatewayToolName,
  pollGuwahDownstreamDiscovery,
  reconnectGuwahDownstreamFailClosed,
  refreshGuwahMirroredToolsFromDiscovery,
  remirrorGuwahToolsFromDiscovery,
  redactGuwahDiagnosticText,
  resolveGuwahDownstreamTransportConfig,
  resolveGuwahIdempotencyKey,
  sealGuwahRequestsForFailClosedReconnect,
  startGuwahStdioGateway,
  wrapGuwahAfterApprovalForDownstreamAmbiguity,
  writeGuwahStderrDiagnostic,
  type GuwahMediatedTool,
} from "../src/guwahGateway.js";
import {
  GuwahGuard,
  GuwahSecurityViolation,
  resolveGuwahActivePolicyPath,
  resolveGuwahPackagedSamplePolicyPath,
  type GuwahViolationCode,
  type McpToolCallPayload,
} from "../src/guwahGuard.js";
import {
  GuwahFakeDownstreamServer,
  startGuwahFakeDownstream,
} from "./guwahFakeDownstream.js";

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

describe("official MCP downstream client", () => {
  it("constructs the official SDK client for the gateway process", () => {
    const client = createGuwahDownstreamClient();
    expect(client).toBeInstanceOf(Client);
    expect(GUWAH_DOWNSTREAM_CLIENT_NAME).toBe("guwah-downstream");
    expect(GUWAH_DOWNSTREAM_CLIENT_VERSION).toBe(GUWAH_GATEWAY_VERSION);
  });

  it("fails closed on invalid construction inputs without an open-proxy substitute", () => {
    expect(() => createGuwahDownstreamClient({ name: "   " })).toThrow(
      "Downstream MCP client construction failed.",
    );
    expect(() => createGuwahDownstreamClient({ version: "" })).toThrow(
      "Downstream MCP client construction failed.",
    );
  });

  it("keeps client imports out of the validator and limited to the gateway module", () => {
    const validator = readFileSync(path.join(REPO_ROOT, "src", "guwahGuard.ts"), "utf8");
    const adapter = readFileSync(path.join(REPO_ROOT, "src", "guwahMcpAdapter.ts"), "utf8");
    const gateway = readFileSync(GATEWAY_SOURCE, "utf8");

    expect(validator).not.toMatch(/@modelcontextprotocol/);
    expect(validator).not.toMatch(/sdk\/client/);
    expect(adapter).not.toMatch(/sdk\/client/);
    expect(gateway).toMatch(/@modelcontextprotocol\/sdk\/client\/index\.js/);
    expect(gateway).toMatch(/export function createGuwahDownstreamClient/);
    expect(gateway).toMatch(/Fail closed: do not return a passthrough or unofficial substitute/);
  });
});

describe("downstream transport configuration", () => {
  const configDirs: string[] = [];

  afterEach(() => {
    for (const dir of configDirs.splice(0, configDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writeConfig(document: unknown): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-downstream-transport-"));
    configDirs.push(dir);
    const configPath = path.join(dir, "downstream-transport.json");
    writeFileSync(configPath, `${JSON.stringify(document, null, 2)}\n`, "utf8");
    return configPath;
  }

  it("loads a valid local stdio spawn configuration", () => {
    const configPath = writeConfig({
      transport: "stdio",
      command: process.execPath,
      args: ["-e", "process.exit(0)"],
      cwd: REPO_ROOT,
    });
    const loaded = loadGuwahDownstreamTransportConfig(configPath);
    expect(loaded).toEqual({
      transport: "stdio",
      command: process.execPath,
      args: ["-e", "process.exit(0)"],
      cwd: REPO_ROOT,
    });
    expect(Object.isFrozen(loaded)).toBe(true);
  });

  it("defaults to deny-all when no config path is provided", () => {
    expect(resolveGuwahDownstreamTransportConfig()).toBeUndefined();
    expect(resolveGuwahDownstreamTransportConfig({})).toBeUndefined();
    const gateway = readFileSync(GATEWAY_SOURCE, "utf8");
    expect(gateway).toMatch(/no implicit localhost/);
    expect(gateway).not.toMatch(/transport:\s*"stdio",\s*command:\s*"localhost"/);
  });

  it("rejects a missing configuration file", () => {
    const missing = path.join(tmpdir(), "guwah-downstream-missing", "absent.json");
    expect(() => loadGuwahDownstreamTransportConfig(missing)).toThrow(
      GUWAH_DOWNSTREAM_TRANSPORT_CONFIG_ERROR,
    );
  });

  it("rejects invalid configuration documents", () => {
    const cases: unknown[] = [
      { transport: "http", command: process.execPath },
      { transport: "sse", command: process.execPath },
      { transport: "stdio" },
      { transport: "stdio", command: "   " },
      { transport: "stdio", command: process.execPath, args: [1] },
      { transport: "stdio", command: process.execPath, unexpected: true },
      { transport: "stdio", command: process.execPath, cwd: "" },
      "stdio",
      null,
    ];
    for (const document of cases) {
      const configPath = writeConfig(document);
      expect(() => loadGuwahDownstreamTransportConfig(configPath)).toThrow(
        GUWAH_DOWNSTREAM_TRANSPORT_CONFIG_ERROR,
      );
    }
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-downstream-bad-json-"));
    configDirs.push(dir);
    const badJsonPath = path.join(dir, "broken.json");
    writeFileSync(badJsonPath, "{not-json\n", "utf8");
    expect(() => loadGuwahDownstreamTransportConfig(badJsonPath)).toThrow(
      GUWAH_DOWNSTREAM_TRANSPORT_CONFIG_ERROR,
    );
  });

  it("prevents gateway startup when a provided config path is invalid", async () => {
    const configPath = writeConfig({ transport: "stdio" });
    let dispatchCount = 0;
    await expect(
      startGuwahStdioGateway({
        stdin: new PassThrough(),
        stdout: new PassThrough(),
        downstreamTransportConfigPath: configPath,
        afterApproval: async () => {
          dispatchCount += 1;
          return { content: [{ type: "text", text: "should-not-run" }] };
        },
      }),
    ).rejects.toThrow(GUWAH_DOWNSTREAM_TRANSPORT_CONFIG_ERROR);
    expect(dispatchCount).toBe(0);
  });

  it("does not expose tools from an implicit localhost default", async () => {
    expect(resolveGuwahDownstreamTransportConfig()).toBeUndefined();
    const server = createGuwahGatewayServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-deny-all-default", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const listed = await client.listTools();
    expect(listed.tools).toEqual([]);
    await client.close();
    await server.close();
  });
});

describe("downstream connection", () => {
  const configDirs: string[] = [];
  const liveDownstream: Array<{ client: Client; transport: StdioClientTransport }> = [];

  afterEach(async () => {
    for (const entry of liveDownstream.splice(0, liveDownstream.length)) {
      try {
        await entry.client.close();
      } catch {
        // Test cleanup.
      }
      try {
        await entry.transport.close();
      } catch {
        // Test cleanup.
      }
    }
    for (const dir of configDirs.splice(0, configDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writeConfig(document: unknown): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-downstream-connect-"));
    configDirs.push(dir);
    const configPath = path.join(dir, "downstream-transport.json");
    writeFileSync(configPath, `${JSON.stringify(document, null, 2)}\n`, "utf8");
    return configPath;
  }

  it("connects to a configured stdio downstream MCP server", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const connection = await connectGuwahDownstream({
      transport: "stdio",
      command: process.execPath,
      args: [GATEWAY_ENTRY],
      cwd: REPO_ROOT,
    });
    liveDownstream.push({ client: connection.client, transport: connection.transport });
    expect(connection.client.getServerVersion()).toEqual({
      name: GUWAH_GATEWAY_NAME,
      version: GUWAH_GATEWAY_VERSION,
    });
  });

  it("fails closed for a missing command and exposes no tools", async () => {
    const missingCommand = path.join(
      tmpdir(),
      "guwah-missing-downstream-cmd",
      "no-such-guwah-downstream-binary",
    );
    expect(existsSync(missingCommand)).toBe(false);

    await expect(
      connectGuwahDownstream({
        transport: "stdio",
        command: missingCommand,
      }),
    ).rejects.toThrow(GUWAH_DOWNSTREAM_CONNECTION_ERROR);

    const configPath = writeConfig({
      transport: "stdio",
      command: missingCommand,
    });
    const mediatedLeak: GuwahMediatedTool = {
      name: "should-not-be-exposed",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {},
      },
    };
    let gatewayStarted = false;
    await expect(
      startGuwahStdioGateway({
        stdin: new PassThrough(),
        stdout: new PassThrough(),
        downstreamTransportConfigPath: configPath,
        mediatedTools: [mediatedLeak],
        afterApproval: async () => {
          gatewayStarted = true;
          return { content: [{ type: "text", text: "should-not-run" }] };
        },
      }),
    ).rejects.toThrow(GUWAH_DOWNSTREAM_CONNECTION_ERROR);
    expect(gatewayStarted).toBe(false);

    // A standalone deny-all gateway still lists no tools when connect never succeeds.
    const server = createGuwahGatewayServer({ mediatedTools: [] });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-connect-fail-tools", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    expect((await client.listTools()).tools).toEqual([]);
    await client.close();
    await server.close();
  });

  it("does not automatically retry a failed connection into a silent success", () => {
    const source = readFileSync(GATEWAY_SOURCE, "utf8");
    expect(source).toMatch(/Single attempt only/);
    expect(source).toMatch(/no automatic retry/);
    expect(source).not.toMatch(/for\s*\(.*retry/i);
  });
});

describe("downstream connection health", () => {
  const configDirs: string[] = [];
  const liveDownstream: Array<{ client: Client; transport: StdioClientTransport }> = [];

  afterEach(async () => {
    for (const entry of liveDownstream.splice(0, liveDownstream.length)) {
      try {
        await entry.client.close();
      } catch {
        // Test cleanup.
      }
      try {
        await entry.transport.close();
      } catch {
        // Test cleanup.
      }
    }
    for (const dir of configDirs.splice(0, configDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writeConfig(document: unknown): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-downstream-health-"));
    configDirs.push(dir);
    const configPath = path.join(dir, "downstream-transport.json");
    writeFileSync(configPath, `${JSON.stringify(document, null, 2)}\n`, "utf8");
    return configPath;
  }

  async function waitUntilUnhealthy(
    isHealthy: () => boolean,
    timeoutMs: number,
  ): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline && isHealthy()) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
  }

  it("marks a killed downstream as dead and fails closed for subsequent calls", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const connection = await connectGuwahDownstream({
      transport: "stdio",
      command: process.execPath,
      args: [GATEWAY_ENTRY],
      cwd: REPO_ROOT,
    });
    liveDownstream.push({ client: connection.client, transport: connection.transport });
    expect(connection.isHealthy()).toBe(true);
    connection.assertHealthy();

    const pid = connection.transport.pid;
    expect(pid).not.toBeNull();
    if (pid === null) {
      expect.unreachable("downstream pid");
    }
    process.kill(pid);

    await waitUntilUnhealthy(connection.isHealthy, 5000);
    expect(connection.isHealthy()).toBe(false);
    expect(() => connection.assertHealthy()).toThrow(GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR);
    // Stale connection must not be treated as healthy after death.
    expect(connection.isHealthy()).toBe(false);
  });

  it("fails closed for subsequent gateway calls after the downstream is killed", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const configPath = writeConfig({
      transport: "stdio",
      command: process.execPath,
      args: [GATEWAY_ENTRY],
      cwd: REPO_ROOT,
    });

    const policyDir = mkdtempSync(path.join(tmpdir(), "guwah-downstream-health-policy-"));
    configDirs.push(policyDir);
    const policyPath = path.join(policyDir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {},
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    let dispatchCount = 0;
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: string[] = [];
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => {
      chunks.push(chunk);
    });

    const { server, downstream } = await startGuwahStdioGateway({
      stdin,
      stdout,
      policyPath,
      downstreamTransportConfigPath: configPath,
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "should-not-dispatch-after-death" }] };
      },
    });
    expect(downstream).toBeDefined();
    if (downstream === undefined) {
      expect.unreachable("downstream");
    }
    liveDownstream.push({ client: downstream.client, transport: downstream.transport });
    expect(downstream.isHealthy()).toBe(true);

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-health-kill", version: "0.0.0" },
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

    const pid = downstream.transport.pid;
    expect(pid).not.toBeNull();
    if (pid === null) {
      expect.unreachable("downstream pid");
    }
    process.kill(pid);
    await waitUntilUnhealthy(downstream.isHealthy, 5000);
    expect(downstream.isHealthy()).toBe(false);
    expect(() => downstream.assertHealthy()).toThrow(GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR);
    expect(dispatchCount).toBe(0);
    expect(downstream.isHealthy()).toBe(false);

    await server.close().catch(() => undefined);
  });

  it("treats protocol death as an unhealthy connection", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const connection = await connectGuwahDownstream({
      transport: "stdio",
      command: process.execPath,
      args: [GATEWAY_ENTRY],
      cwd: REPO_ROOT,
    });
    liveDownstream.push({ client: connection.client, transport: connection.transport });
    expect(connection.isHealthy()).toBe(true);

    connection.transport.onerror?.(new Error("protocol death fixture"));
    expect(connection.isHealthy()).toBe(false);
    expect(() => connection.assertHealthy()).toThrow(GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR);
  });

  it("does not implement automatic provider failover", () => {
    const source = readFileSync(GATEWAY_SOURCE, "utf8");
    expect(source).toMatch(/no failover/);
    expect(source).toMatch(/reconnectGuwahDownstreamFailClosed/);
    expect(source).toMatch(/Automatic provider failover is not performed/);
    expect(source).not.toMatch(/automaticFailover|autoFailover|performAutomaticFailover/i);
  });
});

describe("fail-closed reconnection", () => {
  const policyDirs: string[] = [];
  const liveDownstream: Array<{ client: Client; transport: StdioClientTransport }> = [];
  const liveFixtures: GuwahFakeDownstreamServer[] = [];

  afterEach(async () => {
    while (liveFixtures.length > 0) {
      const fixture = liveFixtures.pop();
      if (fixture !== undefined) {
        await fixture.stop();
      }
    }
    for (const entry of liveDownstream.splice(0, liveDownstream.length)) {
      try {
        await entry.client.close();
      } catch {
        // Test cleanup.
      }
      try {
        await entry.transport.close();
      } catch {
        // Test cleanup.
      }
    }
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(tools: Record<string, unknown>): { policyPath: string; guard: GuwahGuard } {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-reconnect-policy-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return { policyPath, guard: new GuwahGuard({ policyPath }) };
  }

  it("keeps calls fail-closed while a reconnect gate is open", async () => {
    const gate = createGuwahDownstreamReconnectGate();
    const pending = gate.run(async () => {
      expect(gate.isReconnecting()).toBe(true);
      expect(() => gate.assertNotReconnecting()).toThrow(GUWAH_DOWNSTREAM_RECONNECTING_ERROR);
      await new Promise((resolve) => {
        setTimeout(resolve, 50);
      });
      return "done";
    });

    expect(gate.isReconnecting()).toBe(true);
    expect(() => gate.assertNotReconnecting()).toThrow(GUWAH_DOWNSTREAM_RECONNECTING_ERROR);
    await expect(gate.run(async () => "nested")).rejects.toThrow(GUWAH_DOWNSTREAM_RECONNECTING_ERROR);

    await expect(pending).resolves.toBe("done");
    expect(gate.isReconnecting()).toBe(false);
    gate.assertNotReconnecting();
  });

  it("does not restore tools until discovery and policy intersection succeed", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const { guard } = writePolicy({
      coinbase_cdp_transfer: {
        action: "ENFORCE",
        argsSchema: {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          additionalProperties: false,
          required: ["amountMinor"],
          properties: {
            amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
          },
        },
      },
    });

    const config = {
      transport: "stdio" as const,
      command: process.execPath,
      args: [GATEWAY_ENTRY],
      cwd: REPO_ROOT,
    };

    let mirrored: readonly GuwahMediatedTool[] = Object.freeze([
      {
        name: "guwah__stale_tool",
        downstreamName: "stale_tool",
        inputSchema: { type: "object", properties: {} },
      },
    ]);
    const gate = createGuwahDownstreamReconnectGate();
    const activeRequests = new GuwahActiveRequestRegistry();
    expect(activeRequests.tryBegin(1)).toBe(true);

    const reconnected = await gate.run(async () => {
      // Catalog cleared for the reconnect window; calls must see an empty set.
      mirrored = Object.freeze([]);
      sealGuwahRequestsForFailClosedReconnect(activeRequests);
      expect(activeRequests.isAborted(1)).toBe(true);
      expect(activeRequests.isTerminal(1)).toBe(true);
      // Ambiguous sealed work is outcome-unknown, not "unexecuted".
      expect(GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_ERROR).not.toMatch(/unexecuted/i);

      return reconnectGuwahDownstreamFailClosed({
        config,
        guard,
      });
    });

    liveDownstream.push({
      client: reconnected.connection.client,
      transport: reconnected.connection.transport,
    });
    mirrored = reconnected.mirrored;

    expect(reconnected.connection.isHealthy()).toBe(true);
    // Deny-all gateway entry exposes no tools; intersection stays empty until policy+discovery match.
    expect(mirrored).toEqual([]);
    expect(reconnected.discovered).toEqual([]);
  });

  it("restores only policy-intersected tools after a successful reconnect", async () => {
    const { guard } = writePolicy({
      fake_transfer: {
        action: "ENFORCE",
        argsSchema: {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          additionalProperties: false,
          properties: {
            amountMinor: { type: "integer" },
          },
        },
      },
    });

    const fakeServer = new Server(
      { name: "guwah-reconnect-downstream", version: "0.0.0" },
      { capabilities: { tools: {} } },
    );
    fakeServer.setRequestHandler(ListToolsRequestSchema, () => ({
      tools: [
        {
          name: "fake_transfer",
          description: "Authorized",
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
        {
          name: "extra_tool",
          description: "Not in policy",
          inputSchema: { type: "object", properties: {} },
        },
      ],
    }));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = createGuwahDownstreamClient({
      name: "guwah-reconnect-client",
      version: "0.0.0",
    });
    await fakeServer.connect(serverTransport);
    await client.connect(clientTransport);

    // Simulate reconnect completion path without spawning a second process:
    // discovery + remirror are what restore tools after the reconnect gate.
    const gate = createGuwahDownstreamReconnectGate();
    let mirrored: readonly GuwahMediatedTool[] = Object.freeze([]);
    let downstreamInvocations = 0;

    await gate.run(async () => {
      mirrored = Object.freeze([]);
      const discovered = await discoverGuwahDownstreamTools({
        client,
        isHealthy: () => true,
        assertHealthy: () => undefined,
      });
      mirrored = remirrorGuwahToolsFromDiscovery(discovered, guard);
    });

    expect(mirrored.map((tool) => tool.name)).toEqual(["guwah__fake_transfer"]);
    expect(mirrored.some((tool) => tool.name.includes("extra_tool"))).toBe(false);

    const gateway = createGuwahGatewayServer({
      guard,
      resolveMediatedTools: () => mirrored,
      beforeResolveMediatedTools: () => {
        gate.assertNotReconnecting();
      },
      afterApproval: async () => {
        downstreamInvocations += 1;
        return { content: [{ type: "text", text: "ok" }] };
      },
    });
    const [hostTransport, gatewayTransport] = InMemoryTransport.createLinkedPair();
    const host = new Client({ name: "guwah-reconnect-host", version: "0.0.0" });
    await gateway.connect(gatewayTransport);
    await host.connect(hostTransport);

    const listed = await host.listTools();
    expect(listed.tools.map((tool) => tool.name)).toEqual(["guwah__fake_transfer"]);

    await expect(
      host.callTool({
        name: "guwah__extra_tool",
        arguments: {},
      }),
    ).rejects.toThrow(/not authorized|Invalid/i);
    expect(downstreamInvocations).toBe(0);

    await host.close();
    await gateway.close();
    await client.close();
    await fakeServer.close();
  });

  it("leaves the catalog empty and fails closed when reconnect cannot complete", async () => {
    const { guard } = writePolicy({});
    let mirrored: readonly GuwahMediatedTool[] = Object.freeze([
      {
        name: "guwah__prior",
        downstreamName: "prior",
        inputSchema: { type: "object", properties: {} },
      },
    ]);
    const gate = createGuwahDownstreamReconnectGate();

    await expect(
      gate.run(async () => {
        mirrored = Object.freeze([]);
        return reconnectGuwahDownstreamFailClosed({
          config: {
            transport: "stdio",
            command: "no-such-guwah-reconnect-binary",
            args: [],
          },
          guard,
        });
      }),
    ).rejects.toThrow(GUWAH_DOWNSTREAM_RECONNECT_FAILED_ERROR);

    expect(mirrored).toEqual([]);
    expect(gate.isReconnecting()).toBe(false);
  });

  it("does not retry in-flight mutating dispatch across reconnect", async () => {
    const { policyPath, guard } = writePolicy({
      coinbase_cdp_transfer: {
        action: "ENFORCE",
        argsSchema: {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          additionalProperties: false,
          required: ["amountMinor"],
          properties: {
            amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
          },
        },
      },
    });

    const activeRequests = new GuwahActiveRequestRegistry();
    let downstreamInvocations = 0;
    let releaseDispatch: (() => void) | undefined;
    const gate = createGuwahDownstreamReconnectGate();
    let mirrored: readonly GuwahMediatedTool[] = remirrorGuwahToolsFromDiscovery(
      [
        {
          name: "coinbase_cdp_transfer",
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
      ],
      guard,
    );

    const gateway = createGuwahGatewayServer({
      policyPath,
      activeRequests,
      resolveMediatedTools: () => mirrored,
      beforeResolveMediatedTools: () => {
        gate.assertNotReconnecting();
      },
      afterApproval: async () => {
        downstreamInvocations += 1;
        await new Promise<void>((resolve) => {
          releaseDispatch = resolve;
        });
        return { content: [{ type: "text", text: "late" }] };
      },
    });
    const [hostTransport, gatewayTransport] = InMemoryTransport.createLinkedPair();
    const host = new Client({ name: "guwah-reconnect-inflight", version: "0.0.0" });
    await gateway.connect(gatewayTransport);
    await host.connect(hostTransport);

    const inFlight = host.callTool({
      name: "guwah__coinbase_cdp_transfer",
      arguments: { amountMinor: 100 },
    });

    const dispatchStarted = Date.now() + 2000;
    while (Date.now() < dispatchStarted && downstreamInvocations === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(downstreamInvocations).toBe(1);

    mirrored = Object.freeze([]);
    sealGuwahRequestsForFailClosedReconnect(activeRequests);
    expect(GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_ERROR).toMatch(/unknown/i);
    expect(GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_ERROR).not.toMatch(/unexecuted/i);

    releaseDispatch?.();
    await expect(inFlight).rejects.toThrow();
    expect(downstreamInvocations).toBe(1);

    await host.close().catch(() => undefined);
    await gateway.close().catch(() => undefined);
  });

  it("reconnect fixtures keep calls fail-closed until discovery and policy intersection succeed", async () => {
    const { policyPath, guard } = writePolicy({
      fake_transfer: {
        action: "ENFORCE",
        argsSchema: {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          additionalProperties: false,
          required: ["amountMinor"],
          properties: {
            amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
          },
        },
      },
    });

    const { fixture, connection } = await startGuwahFakeDownstream({
      tools: [
        {
          name: "fake_transfer",
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
        {
          name: "unvalidated_extra",
          inputSchema: { type: "object", properties: {} },
        },
      ],
    });
    liveFixtures.push(fixture);

    const gate = createGuwahDownstreamReconnectGate();
    let mirrored: readonly GuwahMediatedTool[] = remirrorGuwahToolsFromDiscovery(
      [
        {
          name: "fake_transfer",
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
      ],
      guard,
    );

    const gateway = createGuwahGatewayServer({
      policyPath,
      resolveMediatedTools: () => mirrored,
      beforeResolveMediatedTools: () => {
        gate.assertNotReconnecting();
      },
      afterApproval: async (approved, context) => {
        const args = approved.params.arguments;
        const callOptions: {
          client: typeof connection.client;
          name: string;
          signal: AbortSignal;
          arguments?: Record<string, unknown>;
        } = {
          client: connection.client,
          name: approved.params.name,
          signal: context.signal,
        };
        if (
          args !== undefined &&
          typeof args === "object" &&
          args !== null &&
          !Array.isArray(args)
        ) {
          callOptions.arguments = args as Record<string, unknown>;
        }
        return await callGuwahDownstreamToolWithCancelPropagation(callOptions);
      },
    });
    const [hostTransport, gatewayTransport] = InMemoryTransport.createLinkedPair();
    const host = new Client({ name: "guwah-reconnect-fixture", version: "0.0.0" });
    await gateway.connect(gatewayTransport);
    await host.connect(hostTransport);

    // During reconnect: catalog cleared; host calls fail closed; no unsafe send.
    const reconnectWork = gate.run(async () => {
      mirrored = Object.freeze([]);
      await new Promise((resolve) => {
        setTimeout(resolve, 40);
      });
      const discovered = await discoverGuwahDownstreamTools(connection);
      mirrored = remirrorGuwahToolsFromDiscovery(discovered, guard);
      return mirrored;
    });

    await expect(
      host.callTool({
        name: "guwah__fake_transfer",
        arguments: { amountMinor: 100 },
      }),
    ).rejects.toThrow();
    await expect(
      host.callTool({
        name: "guwah__unvalidated_extra",
        arguments: {},
      }),
    ).rejects.toThrow();
    expect(fixture.getInvocationCount()).toBe(0);

    const restored = await reconnectWork;
    expect(restored.map((tool) => tool.name)).toEqual(["guwah__fake_transfer"]);
    expect(restored.some((tool) => tool.name.includes("unvalidated_extra"))).toBe(false);

    // After intersection succeeds: authorized tool may dispatch once; unvalidated stays denied.
    await host.callTool({
      name: "guwah__fake_transfer",
      arguments: { amountMinor: 100 },
    });
    expect(fixture.getInvocationCount()).toBe(1);
    expect(fixture.getInvocations()[0]).toMatchObject({
      name: "fake_transfer",
      arguments: { amountMinor: 100 },
    });

    await expect(
      host.callTool({
        name: "guwah__unvalidated_extra",
        arguments: {},
      }),
    ).rejects.toThrow();
    expect(fixture.getInvocationCount()).toBe(1);

    await host.close();
    await gateway.close();
  });
});

describe("fail closed on ambiguous downstream state", () => {
  const policyDirs: string[] = [];
  const TOOL_NAME = "coinbase_cdp_transfer";

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-ambiguous-downstream-"));
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
              argsSchema: {
                $schema: "http://json-schema.org/draft-07/schema#",
                type: "object",
                additionalProperties: false,
                required: ["amountMinor"],
                properties: {
                  amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
                },
              },
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

  it("classifies pre-dispatch unavailability as blocked-locally and post-dispatch as outcome-unknown", () => {
    expect(
      classifyGuwahDownstreamDispatchState({
        isHealthy: () => false,
        dispatchStarted: false,
      }),
    ).toBe("blocked-locally");
    expect(
      classifyGuwahDownstreamDispatchState({
        isHealthy: () => true,
        isReconnecting: () => true,
        dispatchStarted: false,
      }),
    ).toBe("blocked-locally");
    expect(
      classifyGuwahDownstreamDispatchState({
        isHealthy: () => false,
        dispatchStarted: true,
      }),
    ).toBe("outcome-unknown");
    expect(
      classifyGuwahDownstreamDispatchState({
        isHealthy: () => true,
        dispatchStarted: false,
      }),
    ).toBe("available");

    const blocked = mapGuwahDownstreamDispatchStateToMcpError("blocked-locally");
    expect(blocked.message).toContain(GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR);
    expect(blocked.data).toMatchObject({ guwahCode: GUWAH_DOWNSTREAM_UNAVAILABLE_CODE });

    const unknown = mapGuwahDownstreamDispatchStateToMcpError("outcome-unknown");
    expect(unknown.message).toContain(GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_ERROR);
    expect(unknown.data).toMatchObject({ guwahCode: GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_CODE });
    expect(unknown.message).not.toMatch(/rollback|unexecuted/i);
    expect(blocked.message).not.toMatch(/rollback|unexecuted/i);
  });

  it("rejects speculative success when downstream disconnects during a call", async () => {
    const policyPath = writePolicy();
    let healthy = true;
    let downstreamInvocations = 0;

    const gateway = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [
        {
          name: `guwah__${TOOL_NAME}`,
          downstreamName: TOOL_NAME,
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
      ],
      afterApproval: wrapGuwahAfterApprovalForDownstreamAmbiguity({
        isHealthy: () => healthy,
        afterApproval: async () => {
          downstreamInvocations += 1;
          // Disconnect mid-dispatch after work has started.
          healthy = false;
          return { content: [{ type: "text", text: "speculative-success-must-not-surface" }] };
        },
      }),
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await gateway.connect(serverTransport);
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
        clientInfo: { name: "guwah-disconnect-during-call", version: "0.0.0" },
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
        name: `guwah__${TOOL_NAME}`,
        arguments: { amountMinor: 100 },
      },
    });
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(downstreamInvocations).toBe(1);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32603,
        message: expect.stringContaining(GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_ERROR),
        data: { guwahCode: GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_CODE },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");
    expect(JSON.stringify(responses[1])).not.toContain("speculative-success-must-not-surface");
    expect(JSON.stringify(responses[1])).not.toMatch(/rollback/i);

    await clientTransport.close();
    await gateway.close();
  });

  it("blocks locally before dispatch when downstream is already unavailable", async () => {
    const policyPath = writePolicy();
    let downstreamInvocations = 0;

    const gateway = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [
        {
          name: `guwah__${TOOL_NAME}`,
          downstreamName: TOOL_NAME,
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
      ],
      afterApproval: wrapGuwahAfterApprovalForDownstreamAmbiguity({
        isHealthy: () => false,
        afterApproval: async () => {
          downstreamInvocations += 1;
          return { content: [{ type: "text", text: "should-not-run" }] };
        },
      }),
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await gateway.connect(serverTransport);
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
        clientInfo: { name: "guwah-blocked-locally", version: "0.0.0" },
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
        name: `guwah__${TOOL_NAME}`,
        arguments: { amountMinor: 100 },
      },
    });
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(downstreamInvocations).toBe(0);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32603,
        message: expect.stringContaining(GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR),
        data: { guwahCode: GUWAH_DOWNSTREAM_UNAVAILABLE_CODE },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");

    await clientTransport.close();
    await gateway.close();
  });
});

describe("downstream tool discovery", () => {
  const livePairs: Array<{ client: Client; server: Server }> = [];

  afterEach(async () => {
    for (const entry of livePairs.splice(0, livePairs.length)) {
      try {
        await entry.client.close();
      } catch {
        // Test cleanup.
      }
      try {
        await entry.server.close();
      } catch {
        // Test cleanup.
      }
    }
  });

  async function startFakeDownstream(tools: unknown): Promise<{
    readonly client: Client;
    readonly server: Server;
    readonly connection: {
      readonly client: Client;
      readonly isHealthy: () => boolean;
      readonly assertHealthy: () => void;
    };
  }> {
    const server = new Server(
      { name: "guwah-fake-downstream", version: "0.0.0" },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, () => {
      if (tools instanceof Error) {
        throw tools;
      }
      return tools as { tools: unknown[] };
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = createGuwahDownstreamClient({ name: "guwah-discover-test", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    livePairs.push({ client, server });
    return {
      client,
      server,
      connection: {
        client,
        isHealthy: () => true,
        assertHealthy: () => undefined,
      },
    };
  }

  it("lists tools from a fake downstream fixture into a mediated set", async () => {
    const { connection } = await startFakeDownstream({
      tools: [
        {
          name: "fake_transfer",
          description: "Fake downstream transfer",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              amountMinor: { type: "integer" },
            },
          },
        },
      ],
    });

    const discovered = await discoverGuwahDownstreamTools(connection);
    expect(discovered).toEqual([
      {
        name: "fake_transfer",
        description: "Fake downstream transfer",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: {
            amountMinor: { type: "integer" },
          },
        },
      },
    ]);
    expect(Object.isFrozen(discovered)).toBe(true);
    expect(Object.isFrozen(discovered[0])).toBe(true);
  });

  it("yields an empty mediated set on discovery errors, not passthrough", async () => {
    const { connection } = await startFakeDownstream(new Error("downstream list failed"));
    const discovered = await discoverGuwahDownstreamTools(connection);
    expect(discovered).toEqual([]);
  });

  it("rejects malformed list payloads instead of passing them through", async () => {
    const malformedCases: unknown[] = [
      { tools: "not-an-array" },
      { tools: [{ name: "missing_schema" }] },
      { tools: [{ inputSchema: { type: "object" } }] },
      { tools: [{ name: "ok", inputSchema: { type: "object" } }, { name: 1, inputSchema: {} }] },
      { tools: [null] },
      {},
      null,
    ];

    for (const payload of malformedCases) {
      const client = createGuwahDownstreamClient({
        name: "guwah-discover-malformed",
        version: "0.0.0",
      });
      vi.spyOn(client, "listTools").mockResolvedValue(payload as never);
      const discovered = await discoverGuwahDownstreamTools({
        client,
        isHealthy: () => true,
        assertHealthy: () => undefined,
      });
      expect(discovered).toEqual([]);
      vi.restoreAllMocks();
    }
  });

  it("yields an empty mediated set when the downstream connection is dead", async () => {
    const { connection } = await startFakeDownstream({ tools: [] });
    const dead = {
      client: connection.client,
      isHealthy: () => false,
      assertHealthy: () => {
        throw new Error(GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR);
      },
    };
    const discovered = await discoverGuwahDownstreamTools(dead);
    expect(discovered).toEqual([]);
  });

  it("does not treat discovered inputSchema as policy authority", () => {
    const source = readFileSync(GATEWAY_SOURCE, "utf8");
    expect(source).toMatch(/never trusted as policy/);
    expect(source).toMatch(/export async function discoverGuwahDownstreamTools/);
  });
});

describe("monitor downstream tool discovery changes", () => {
  const livePairs: Array<{ client: Client; server: Server }> = [];

  afterEach(async () => {
    for (const entry of livePairs.splice(0, livePairs.length)) {
      try {
        await entry.client.close();
      } catch {
        // Test cleanup.
      }
      try {
        await entry.server.close();
      } catch {
        // Test cleanup.
      }
    }
  });

  const transferSchema = {
    type: "object",
    additionalProperties: false,
    properties: {
      amountMinor: { type: "integer" },
    },
  } as const;

  const balanceSchema = {
    type: "object",
    additionalProperties: false,
    properties: {
      asset: { type: "string" },
    },
  } as const;

  async function startMutableFakeDownstream(initialTools: {
    tools: Array<{
      name: string;
      description?: string;
      inputSchema: Record<string, unknown>;
    }>;
  }): Promise<{
    readonly connection: {
      readonly client: Client;
      readonly isHealthy: () => boolean;
      readonly assertHealthy: () => void;
    };
    setTools: (next: {
      tools: Array<{
        name: string;
        description?: string;
        inputSchema: Record<string, unknown>;
      }>;
    }) => void;
    markDead: () => void;
  }> {
    let currentTools = initialTools;
    let healthy = true;
    const server = new Server(
      { name: "guwah-fake-discovery-monitor", version: "0.0.0" },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, () => currentTools);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = createGuwahDownstreamClient({
      name: "guwah-discovery-monitor-test",
      version: "0.0.0",
    });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    livePairs.push({ client, server });
    return {
      connection: {
        client,
        isHealthy: () => healthy,
        assertHealthy: () => {
          if (!healthy) {
            throw new Error(GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR);
          }
        },
      },
      setTools: (next) => {
        currentTools = next;
      },
      markDead: () => {
        healthy = false;
      },
    };
  }

  it("reports unchanged when the downstream tools/list is stable", async () => {
    const { connection } = await startMutableFakeDownstream({
      tools: [
        {
          name: "coinbase_cdp_transfer",
          description: "Transfer",
          inputSchema: structuredClone(transferSchema),
        },
      ],
    });

    const previous = await discoverGuwahDownstreamTools(connection);
    const change = await pollGuwahDownstreamDiscovery(connection, previous);

    expect(change.changed).toBe(false);
    expect(change.addedNames).toEqual([]);
    expect(change.removedNames).toEqual([]);
    expect(change.changedSchemaNames).toEqual([]);
    expect(change.currentFingerprint).toBe(change.previousFingerprint);
    expect(change.currentFingerprint).toBe(fingerprintGuwahDiscoveryList(previous));
  });

  it("detects added and removed tools after a mutable list change", async () => {
    const { connection, setTools } = await startMutableFakeDownstream({
      tools: [
        {
          name: "coinbase_cdp_transfer",
          description: "Transfer",
          inputSchema: structuredClone(transferSchema),
        },
        {
          name: "read_balance",
          description: "Balance",
          inputSchema: structuredClone(balanceSchema),
        },
      ],
    });

    const previous = await discoverGuwahDownstreamTools(connection);
    setTools({
      tools: [
        {
          name: "coinbase_cdp_transfer",
          description: "Transfer",
          inputSchema: structuredClone(transferSchema),
        },
        {
          name: "newly_listed_tool",
          description: "Appeared later",
          inputSchema: { type: "object", properties: {} },
        },
      ],
    });

    const change = await pollGuwahDownstreamDiscovery(connection, previous);
    expect(change.changed).toBe(true);
    expect(change.addedNames).toEqual(["newly_listed_tool"]);
    expect(change.removedNames).toEqual(["read_balance"]);
    expect(change.changedSchemaNames).toEqual([]);
    expect(change.current.map((tool) => tool.name).sort()).toEqual([
      "coinbase_cdp_transfer",
      "newly_listed_tool",
    ]);
  });

  it("detects retained-name schema drift without remirroring under policy", async () => {
    const { connection, setTools } = await startMutableFakeDownstream({
      tools: [
        {
          name: "coinbase_cdp_transfer",
          description: "Transfer",
          inputSchema: structuredClone(transferSchema),
        },
      ],
    });

    const previous = await discoverGuwahDownstreamTools(connection);
    setTools({
      tools: [
        {
          name: "coinbase_cdp_transfer",
          description: "Transfer",
          inputSchema: {
            type: "object",
            additionalProperties: true,
            properties: {
              amountMinor: { type: "integer" },
              memo: { type: "string" },
            },
          },
        },
      ],
    });

    const change = await pollGuwahDownstreamDiscovery(connection, previous);
    expect(change.changed).toBe(true);
    expect(change.addedNames).toEqual([]);
    expect(change.removedNames).toEqual([]);
    expect(change.changedSchemaNames).toEqual(["coinbase_cdp_transfer"]);

    const source = readFileSync(GATEWAY_SOURCE, "utf8");
    const pollStart = source.indexOf("export async function pollGuwahDownstreamDiscovery");
    const pollEnd = source.indexOf(
      "export function mirrorAuthorizedGuwahTools",
      pollStart,
    );
    expect(pollStart).toBeGreaterThanOrEqual(0);
    expect(pollEnd).toBeGreaterThan(pollStart);
    const pollBody = source.slice(pollStart, pollEnd);
    expect(pollBody).toMatch(/does not remirror/i);
    expect(pollBody).not.toMatch(/mirrorAuthorizedGuwahTools/);
  });

  it("treats discovery failure after a non-empty snapshot as a detectable empty change", async () => {
    const { connection } = await startMutableFakeDownstream({
      tools: [
        {
          name: "coinbase_cdp_transfer",
          description: "Transfer",
          inputSchema: structuredClone(transferSchema),
        },
      ],
    });
    const previous = await discoverGuwahDownstreamTools(connection);
    vi.spyOn(connection.client, "listTools").mockRejectedValue(new Error("list failed"));

    const change = await pollGuwahDownstreamDiscovery(connection, previous);
    expect(change.changed).toBe(true);
    expect(change.current).toEqual([]);
    expect(change.removedNames).toEqual(["coinbase_cdp_transfer"]);
    expect(change.addedNames).toEqual([]);

    vi.restoreAllMocks();
  });

  it("treats a dead connection poll as an empty current set when previous was non-empty", async () => {
    const { connection, markDead } = await startMutableFakeDownstream({
      tools: [
        {
          name: "coinbase_cdp_transfer",
          description: "Transfer",
          inputSchema: structuredClone(transferSchema),
        },
      ],
    });
    const previous = await discoverGuwahDownstreamTools(connection);
    markDead();

    const change = await pollGuwahDownstreamDiscovery(connection, previous);
    expect(change.changed).toBe(true);
    expect(change.current).toEqual([]);
    expect(change.removedNames).toEqual(["coinbase_cdp_transfer"]);
  });

  it("compares discovery snapshots deterministically regardless of tool order", () => {
    const left: GuwahMediatedTool[] = [
      {
        name: "b_tool",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "a_tool",
        description: "A",
        inputSchema: { type: "object", properties: { x: { type: "integer" } } },
      },
    ];
    const right: GuwahMediatedTool[] = [
      {
        name: "a_tool",
        description: "A",
        inputSchema: { type: "object", properties: { x: { type: "integer" } } },
      },
      {
        name: "b_tool",
        inputSchema: { type: "object", properties: {} },
      },
    ];
    const change = detectGuwahDiscoveryListChange(left, right);
    expect(change.changed).toBe(false);
    expect(fingerprintGuwahDiscoveryList(left)).toBe(fingerprintGuwahDiscoveryList(right));
  });
});

describe("handle downstream tool-list mutation", () => {
  const policyDirs: string[] = [];
  const livePairs: Array<{ client: Client; server: Server }> = [];
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  afterEach(async () => {
    for (const entry of livePairs.splice(0, livePairs.length)) {
      try {
        await entry.client.close();
      } catch {
        // Test cleanup.
      }
      try {
        await entry.server.close();
      } catch {
        // Test cleanup.
      }
    }
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(tools: Record<string, unknown>): { policyPath: string; guard: GuwahGuard } {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-list-mutation-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return { policyPath, guard: new GuwahGuard({ policyPath }) };
  }

  const transferArgsSchema = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "destinationAddress", "asset", "network"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      destinationAddress: {
        type: "string",
        enum: [WHITELISTED_DESTINATION],
      },
      asset: { type: "string", enum: ["usdc"] },
      network: { type: "string", enum: ["base"] },
    },
  } as const;

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 100,
      destinationAddress: WHITELISTED_DESTINATION,
      asset: "usdc",
      network: "base",
    };
  }

  async function startMutableFakeDownstream(initialTools: {
    tools: Array<{
      name: string;
      description?: string;
      inputSchema: Record<string, unknown>;
    }>;
  }): Promise<{
    readonly connection: {
      readonly client: Client;
      readonly isHealthy: () => boolean;
      readonly assertHealthy: () => void;
    };
    setTools: (next: {
      tools: Array<{
        name: string;
        description?: string;
        inputSchema: Record<string, unknown>;
      }>;
    }) => void;
  }> {
    let currentTools = initialTools;
    const server = new Server(
      { name: "guwah-fake-list-mutation", version: "0.0.0" },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, () => currentTools);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = createGuwahDownstreamClient({
      name: "guwah-list-mutation-downstream",
      version: "0.0.0",
    });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    livePairs.push({ client, server });
    return {
      connection: {
        client,
        isHealthy: () => true,
        assertHealthy: () => undefined,
      },
      setTools: (next) => {
        currentTools = next;
      },
    };
  }

  it("removes tools from the mirrored catalog and keeps newly added tools denied", async () => {
    const { policyPath, guard } = writePolicy({
      [TOOL_NAME]: {
        action: "ENFORCE",
        argsSchema: structuredClone(transferArgsSchema),
      },
    });

    const { connection, setTools } = await startMutableFakeDownstream({
      tools: [
        {
          name: TOOL_NAME,
          description: "Authorized transfer",
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
        {
          name: "extra_downstream_tool",
          description: "Not in policy",
          inputSchema: { type: "object", properties: {} },
        },
      ],
    });

    let lastDiscovered = await discoverGuwahDownstreamTools(connection);
    let mirrored = remirrorGuwahToolsFromDiscovery(lastDiscovered, guard);
    expect(mirrored.map((tool) => tool.name)).toEqual([`guwah__${TOOL_NAME}`]);

    let downstreamInvocations = 0;
    const gateway = createGuwahGatewayServer({
      policyPath,
      resolveMediatedTools: () => mirrored,
      beforeResolveMediatedTools: async () => {
        const refreshed = await refreshGuwahMirroredToolsFromDiscovery(
          connection,
          lastDiscovered,
          guard,
        );
        lastDiscovered = refreshed.discovered;
        mirrored = refreshed.mirrored;
      },
      afterApproval: async () => {
        downstreamInvocations += 1;
        return { content: [{ type: "text", text: "dispatched" }] };
      },
    });
    const [hostTransport, gatewayTransport] = InMemoryTransport.createLinkedPair();
    const host = new Client({ name: "guwah-list-mutation-host", version: "0.0.0" });
    await gateway.connect(gatewayTransport);
    await host.connect(hostTransport);

    const listedBefore = await host.listTools();
    expect(listedBefore.tools.map((tool) => tool.name)).toEqual([`guwah__${TOOL_NAME}`]);
    expect(listedBefore.tools.some((tool) => tool.name.includes("extra_downstream"))).toBe(false);

    setTools({
      tools: [
        {
          name: "newly_listed_tool",
          description: "Appeared after mutation",
          inputSchema: { type: "object", properties: {} },
        },
      ],
    });

    const listedAfter = await host.listTools();
    expect(listedAfter.tools.map((tool) => tool.name)).toEqual([]);
    expect(listedAfter.tools.some((tool) => tool.name.includes(TOOL_NAME))).toBe(false);
    expect(listedAfter.tools.some((tool) => tool.name.includes("newly_listed"))).toBe(false);

    await expect(
      host.callTool({
        name: "guwah__newly_listed_tool",
        arguments: {},
      }),
    ).rejects.toThrow(/not authorized|Invalid/i);
    expect(downstreamInvocations).toBe(0);

    await expect(
      host.callTool({
        name: `guwah__${TOOL_NAME}`,
        arguments: compliantArgs(),
      }),
    ).rejects.toThrow(/not authorized|Invalid/i);
    expect(downstreamInvocations).toBe(0);

    await host.close();
    await gateway.close();
  });

  it("does not trust a widened downstream schema as policy after remirror", async () => {
    const { policyPath, guard } = writePolicy({
      [TOOL_NAME]: {
        action: "ENFORCE",
        argsSchema: structuredClone(transferArgsSchema),
      },
    });

    const { connection, setTools } = await startMutableFakeDownstream({
      tools: [
        {
          name: TOOL_NAME,
          description: "Authorized transfer",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: { amountMinor: { type: "integer" } },
          },
        },
      ],
    });

    let lastDiscovered = await discoverGuwahDownstreamTools(connection);
    let mirrored = remirrorGuwahToolsFromDiscovery(lastDiscovered, guard);
    let downstreamInvocations = 0;

    const gateway = createGuwahGatewayServer({
      policyPath,
      resolveMediatedTools: () => mirrored,
      beforeResolveMediatedTools: async () => {
        const refreshed = await refreshGuwahMirroredToolsFromDiscovery(
          connection,
          lastDiscovered,
          guard,
        );
        lastDiscovered = refreshed.discovered;
        mirrored = refreshed.mirrored;
      },
      afterApproval: async () => {
        downstreamInvocations += 1;
        return { content: [{ type: "text", text: "dispatched" }] };
      },
    });
    const [hostTransport, gatewayTransport] = InMemoryTransport.createLinkedPair();
    const host = new Client({ name: "guwah-list-mutation-schema", version: "0.0.0" });
    await gateway.connect(gatewayTransport);
    await host.connect(hostTransport);

    setTools({
      tools: [
        {
          name: TOOL_NAME,
          description: "Authorized transfer",
          inputSchema: {
            type: "object",
            additionalProperties: true,
            properties: {
              amountMinor: { type: "integer" },
              memo: { type: "string" },
            },
          },
        },
      ],
    });

    const listed = await host.listTools();
    expect(listed.tools.map((tool) => tool.name)).toEqual([`guwah__${TOOL_NAME}`]);
    expect(refreshedCatalogInputAllowsExtra(mirrored)).toBe(true);

    await expect(
      host.callTool({
        name: `guwah__${TOOL_NAME}`,
        arguments: {
          ...compliantArgs(),
          memo: "only-allowed-by-widened-downstream-schema",
        },
      }),
    ).rejects.toThrow(/Invalid|argument/i);
    expect(downstreamInvocations).toBe(0);

    await host.callTool({
      name: `guwah__${TOOL_NAME}`,
      arguments: compliantArgs(),
    });
    expect(downstreamInvocations).toBe(1);

    await host.close();
    await gateway.close();
  });

  function refreshedCatalogInputAllowsExtra(tools: readonly GuwahMediatedTool[]): boolean {
    const tool = tools.find((entry) => entry.name === `guwah__${TOOL_NAME}`);
    if (tool === undefined) {
      return false;
    }
    const schema = tool.inputSchema as { additionalProperties?: unknown };
    return schema.additionalProperties === true;
  }
});

describe("handle downstream schema changes", () => {
  const policyDirs: string[] = [];
  const livePairs: Array<{ client: Client; server: Server }> = [];
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  afterEach(async () => {
    for (const entry of livePairs.splice(0, livePairs.length)) {
      try {
        await entry.client.close();
      } catch {
        // Test cleanup.
      }
      try {
        await entry.server.close();
      } catch {
        // Test cleanup.
      }
    }
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(tools: Record<string, unknown>): { policyPath: string; guard: GuwahGuard } {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-schema-change-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return { policyPath, guard: new GuwahGuard({ policyPath }) };
  }

  const transferArgsSchema = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor", "destinationAddress", "asset", "network"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
      destinationAddress: {
        type: "string",
        enum: [WHITELISTED_DESTINATION],
      },
      asset: { type: "string", enum: ["usdc"] },
      network: { type: "string", enum: ["base"] },
    },
  } as const;

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 100,
      destinationAddress: WHITELISTED_DESTINATION,
      asset: "usdc",
      network: "base",
    };
  }

  async function startMutableFakeDownstream(initialTools: {
    tools: Array<{
      name: string;
      description?: string;
      inputSchema: Record<string, unknown>;
    }>;
  }): Promise<{
    readonly connection: {
      readonly client: Client;
      readonly isHealthy: () => boolean;
      readonly assertHealthy: () => void;
    };
    setTools: (next: {
      tools: Array<{
        name: string;
        description?: string;
        inputSchema: Record<string, unknown>;
      }>;
    }) => void;
  }> {
    let currentTools = initialTools;
    const server = new Server(
      { name: "guwah-fake-schema-change", version: "0.0.0" },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, () => currentTools);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = createGuwahDownstreamClient({
      name: "guwah-schema-change-downstream",
      version: "0.0.0",
    });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    livePairs.push({ client, server });
    return {
      connection: {
        client,
        isHealthy: () => true,
        assertHealthy: () => undefined,
      },
      setTools: (next) => {
        currentTools = next;
      },
    };
  }

  it("keeps acceptance bound to policy argsSchema after downstream schema widens", async () => {
    const { policyPath, guard } = writePolicy({
      [TOOL_NAME]: {
        action: "ENFORCE",
        argsSchema: structuredClone(transferArgsSchema),
      },
    });

    const { connection, setTools } = await startMutableFakeDownstream({
      tools: [
        {
          name: TOOL_NAME,
          description: "Authorized transfer",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {
              amountMinor: { type: "integer" },
              destinationAddress: { type: "string" },
              asset: { type: "string" },
              network: { type: "string" },
            },
          },
        },
      ],
    });

    let lastDiscovered = await discoverGuwahDownstreamTools(connection);
    let mirrored = remirrorGuwahToolsFromDiscovery(lastDiscovered, guard);
    let downstreamInvocations = 0;

    const gateway = createGuwahGatewayServer({
      policyPath,
      resolveMediatedTools: () => mirrored,
      beforeResolveMediatedTools: async () => {
        const refreshed = await refreshGuwahMirroredToolsFromDiscovery(
          connection,
          lastDiscovered,
          guard,
        );
        lastDiscovered = refreshed.discovered;
        mirrored = refreshed.mirrored;
      },
      afterApproval: async () => {
        downstreamInvocations += 1;
        return { content: [{ type: "text", text: "should-not-run-for-widened-args" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await gateway.connect(serverTransport);
    await clientTransport.start();
    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    setTools({
      tools: [
        {
          name: TOOL_NAME,
          description: "Authorized transfer",
          inputSchema: {
            type: "object",
            additionalProperties: true,
            properties: {
              amountMinor: { type: "integer" },
              destinationAddress: { type: "string" },
              asset: { type: "string" },
              network: { type: "string" },
              memo: { type: "string" },
              routingHint: { type: "string" },
            },
          },
        },
      ],
    });

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-schema-change", version: "0.0.0" },
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
      method: "tools/list",
      params: {},
    });
    const listDeadline = Date.now() + 5000;
    while (Date.now() < listDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    const listResult = responses[1] as {
      result?: { tools?: Array<{ name: string; inputSchema?: { additionalProperties?: unknown } }> };
    };
    expect(listResult.result?.tools?.map((tool) => tool.name)).toEqual([`guwah__${TOOL_NAME}`]);
    expect(listResult.result?.tools?.[0]?.inputSchema?.additionalProperties).toBe(true);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: `guwah__${TOOL_NAME}`,
        arguments: {
          ...compliantArgs(),
          routingHint: "only-valid-on-widened-downstream-schema",
        },
      },
    });
    const denyDeadline = Date.now() + 5000;
    while (Date.now() < denyDeadline && responses.length < 3) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(downstreamInvocations).toBe(0);
    expect(responses[2]).toMatchObject({
      jsonrpc: "2.0",
      id: 3,
      error: {
        code: -32600,
        data: { guwahCode: "ARGUMENT_VALIDATION_FAILED" },
      },
    });
    expect(responses[2]).not.toHaveProperty("result");

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: `guwah__${TOOL_NAME}`,
        arguments: compliantArgs(),
      },
    });
    const okDeadline = Date.now() + 5000;
    while (Date.now() < okDeadline && responses.length < 4) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(downstreamInvocations).toBe(1);
    expect(responses[3]).toMatchObject({
      jsonrpc: "2.0",
      id: 4,
      result: {
        content: [{ type: "text", text: "should-not-run-for-widened-args" }],
      },
    });
    expect(responses[3]).not.toHaveProperty("error");

    await clientTransport.close();
    await gateway.close();
  });
});

describe("mirror authorized tools", () => {
  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(tools: Record<string, unknown>): { policyPath: string; guard: GuwahGuard } {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-mirror-policy-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return { policyPath, guard: new GuwahGuard({ policyPath }) };
  }

  const authorizedSchema = {
    type: "object",
    additionalProperties: false,
    properties: {
      amountMinor: { type: "integer" },
    },
  } as const;

  it("lists only the intersection of policy ENFORCE tools and discovery", async () => {
    const { policyPath, guard } = writePolicy({
      coinbase_cdp_transfer: {
        action: "ENFORCE",
        argsSchema: {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          additionalProperties: false,
          required: ["amountMinor"],
          properties: {
            amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
          },
        },
      },
      denied_tool: {
        action: "DENY",
        argsSchema: {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          additionalProperties: false,
          properties: {},
        },
      },
    });

    expect(guard.listEnforcedToolNames()).toEqual(["coinbase_cdp_transfer"]);

    const discovered: GuwahMediatedTool[] = [
      {
        name: "coinbase_cdp_transfer",
        description: "Authorized transfer",
        inputSchema: authorizedSchema,
      },
      {
        name: "extra_downstream_tool",
        description: "Not in policy",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "denied_tool",
        description: "Policy DENY",
        inputSchema: { type: "object", properties: {} },
      },
    ];

    const mirrored = mirrorAuthorizedGuwahTools(discovered, guard);
    expect(mirrored.map((tool) => tool.name)).toEqual(["coinbase_cdp_transfer"]);
    expect(mirrored.some((tool) => tool.name === "extra_downstream_tool")).toBe(false);
    expect(mirrored.some((tool) => tool.name === "denied_tool")).toBe(false);

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: mirrored,
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-mirror-list", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const listed = await client.listTools();
    expect(listed.tools.map((tool) => tool.name)).toEqual(["coinbase_cdp_transfer"]);
    expect(listed.tools.map((tool) => tool.name)).not.toContain("extra_downstream_tool");
    expect(listed.tools.map((tool) => tool.name)).not.toContain("denied_tool");

    await client.close();
    await server.close();
  });

  it("omits fake downstream extras from the gateway list snapshot", async () => {
    const { guard } = writePolicy({
      coinbase_cdp_transfer: {
        action: "ENFORCE",
        argsSchema: {
          $schema: "http://json-schema.org/draft-07/schema#",
          type: "object",
          additionalProperties: false,
          properties: {
            amountMinor: { type: "integer" },
          },
        },
      },
    });

    const fakeDownstreamExtras: GuwahMediatedTool[] = [
      {
        name: "coinbase_cdp_transfer",
        inputSchema: authorizedSchema,
      },
      {
        name: "provider_secret_exfil",
        inputSchema: { type: "object", properties: { token: { type: "string" } } },
      },
      {
        name: "unlisted_payment_rail",
        inputSchema: { type: "object", properties: {} },
      },
    ];

    const snapshot = mirrorAuthorizedGuwahTools(fakeDownstreamExtras, guard);
    expect(snapshot).toEqual([
      {
        name: "coinbase_cdp_transfer",
        inputSchema: authorizedSchema,
      },
    ]);
    expect(snapshot).not.toEqual(fakeDownstreamExtras);
  });

  it("does not auto-authorize tools that appear only in discovery", () => {
    const { guard } = writePolicy({});
    const discovered: GuwahMediatedTool[] = [
      {
        name: "brand_new_downstream_tool",
        inputSchema: { type: "object", properties: {} },
      },
    ];
    expect(mirrorAuthorizedGuwahTools(discovered, guard)).toEqual([]);
    expect(guard.listEnforcedToolNames()).toEqual([]);
  });
});

describe("deterministic tool namespacing", () => {
  it("applies a stable documented gateway prefix", () => {
    expect(GUWAH_TOOL_NAMESPACE_PREFIX).toBe("guwah__");
    expect(namespaceGuwahToolName("coinbase_cdp_transfer")).toBe("guwah__coinbase_cdp_transfer");
    expect(namespaceGuwahToolName("a")).toBe("guwah__a");
    expect(namespaceGuwahToolName("tool.v2")).toBe("guwah__tool.v2");
    expect(parseGuwahGatewayToolName("guwah__coinbase_cdp_transfer")).toBe("coinbase_cdp_transfer");
    expect(parseGuwahGatewayToolName("coinbase_cdp_transfer")).toBeUndefined();
  });

  it("rejects ambiguous names rather than aliasing them silently", () => {
    expect(() => namespaceGuwahToolName("guwah__already")).toThrow(GUWAH_TOOL_NAMESPACE_ERROR);
    expect(() => namespaceGuwahToolName("")).toThrow(GUWAH_TOOL_NAMESPACE_ERROR);
    expect(() => namespaceGuwahToolName("   ")).toThrow(GUWAH_TOOL_NAMESPACE_ERROR);
    expect(() => namespaceGuwahToolName("bad name")).toThrow(GUWAH_TOOL_NAMESPACE_ERROR);
    expect(() => namespaceGuwahToolName("slash/name")).toThrow(GUWAH_TOOL_NAMESPACE_ERROR);
    expect(() =>
      applyGuwahToolNamespacing([
        {
          name: "guwah__preprefixed",
          inputSchema: { type: "object", properties: {} },
        },
      ]),
    ).toThrow(GUWAH_TOOL_NAMESPACE_ERROR);
  });

  it("snapshots namespaced mirrored tools for the host catalog", () => {
    const mirrored: GuwahMediatedTool[] = [
      {
        name: "coinbase_cdp_transfer",
        description: "Authorized transfer",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: { amountMinor: { type: "integer" } },
        },
      },
      {
        name: "read_balance",
        inputSchema: { type: "object", properties: {} },
      },
    ];
    const namespaced = applyGuwahToolNamespacing(mirrored);
    expect(namespaced).toMatchInlineSnapshot(`
      [
        {
          "description": "Authorized transfer",
          "downstreamName": "coinbase_cdp_transfer",
          "inputSchema": {
            "additionalProperties": false,
            "properties": {
              "amountMinor": {
                "type": "integer",
              },
            },
            "type": "object",
          },
          "name": "guwah__coinbase_cdp_transfer",
        },
        {
          "downstreamName": "read_balance",
          "inputSchema": {
            "properties": {},
            "type": "object",
          },
          "name": "guwah__read_balance",
        },
      ]
    `);
    expect(namespaced.every((tool) => tool.name !== tool.downstreamName)).toBe(true);
    expect(namespaced.every((tool) => tool.name.startsWith(GUWAH_TOOL_NAMESPACE_PREFIX))).toBe(true);
  });

  it("validates policy against the downstream name for a namespaced host call", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-namespace-policy-"));
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            coinbase_cdp_transfer: {
              action: "ENFORCE",
              argsSchema: {
                $schema: "http://json-schema.org/draft-07/schema#",
                type: "object",
                additionalProperties: false,
                required: ["amountMinor"],
                properties: {
                  amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
                },
              },
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    const namespaced = applyGuwahToolNamespacing([
      {
        name: "coinbase_cdp_transfer",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: { amountMinor: { type: "integer" } },
        },
      },
    ]);
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: namespaced,
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-namespace-call", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const listed = await client.listTools();
    expect(listed.tools.map((tool) => tool.name)).toEqual(["guwah__coinbase_cdp_transfer"]);
    expect(listed.tools.map((tool) => tool.name)).not.toContain("coinbase_cdp_transfer");

    const result = await client.callTool({
      name: "guwah__coinbase_cdp_transfer",
      arguments: { amountMinor: 100 },
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
    rmSync(dir, { recursive: true, force: true });
  });

  it("documents the naming algorithm in gateway source", () => {
    const source = readFileSync(GATEWAY_SOURCE, "utf8");
    expect(source).toMatch(/Deterministic gateway tool naming algorithm/);
    expect(source).toMatch(/guwah__/);
    expect(source).toMatch(/ambiguous; rejected, not re-aliased/);
  });
});

describe("tool-name collisions", () => {
  const schema: GuwahMediatedTool["inputSchema"] = {
    type: "object",
    additionalProperties: false,
    properties: {},
  };

  const liveFixtures: GuwahFakeDownstreamServer[] = [];

  afterEach(async () => {
    while (liveFixtures.length > 0) {
      const fixture = liveFixtures.pop();
      if (fixture !== undefined) {
        await fixture.stop();
      }
    }
  });

  it("rejects namespacing when two tools would share a gateway name", () => {
    expect(() =>
      applyGuwahToolNamespacing([
        { name: "shared_tool", description: "first", inputSchema: schema },
        { name: "shared_tool", description: "second", inputSchema: schema },
      ]),
    ).toThrow(GUWAH_TOOL_COLLISION_ERROR);
  });

  it("rejects catalogs that already contain duplicate gateway names", () => {
    expect(() =>
      assertGuwahToolNamesUnique([
        { name: "guwah__dup", downstreamName: "a", inputSchema: schema },
        { name: "guwah__dup", downstreamName: "b", inputSchema: schema },
      ]),
    ).toThrow(GUWAH_TOOL_COLLISION_ERROR);
  });

  it("fails closed so neither colliding tool is callable and schemas are not merged", async () => {
    const colliding: GuwahMediatedTool[] = [
      {
        name: "guwah__collide",
        downstreamName: "alpha",
        description: "alpha schema",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: { a: { type: "integer" } },
        },
      },
      {
        name: "guwah__collide",
        downstreamName: "beta",
        description: "beta schema",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          properties: { b: { type: "string" } },
        },
      },
    ];

    expect(() => createGuwahGatewayServer({ mediatedTools: colliding })).toThrow(
      GUWAH_TOOL_COLLISION_ERROR,
    );

    // A fail-closed catalog must not leave a callable merged tool.
    const emptyServer = createGuwahGatewayServer({ mediatedTools: [] });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-collision-call", version: "0.0.0" });
    await emptyServer.connect(serverTransport);
    await client.connect(clientTransport);

    expect((await client.listTools()).tools).toEqual([]);
    await expect(
      client.callTool({
        name: "guwah__collide",
        arguments: { a: 1 },
      }),
    ).rejects.toThrow();
    await expect(
      client.callTool({
        name: "guwah__collide",
        arguments: { b: "x" },
      }),
    ).rejects.toThrow();

    await client.close();
    await emptyServer.close();
  });

  it("collision fixtures produce zero unsafe downstream dispatch", async () => {
    const { fixture, connection } = await startGuwahFakeDownstream({
      tools: [
        { name: "alpha", inputSchema: schema },
        { name: "beta", inputSchema: schema },
      ],
    });
    liveFixtures.push(fixture);

    const colliding: GuwahMediatedTool[] = [
      {
        name: "guwah__shared",
        downstreamName: "alpha",
        inputSchema: schema,
      },
      {
        name: "guwah__shared",
        downstreamName: "beta",
        inputSchema: schema,
      },
    ];

    expect(() =>
      createGuwahGatewayServer({
        mediatedTools: colliding,
        afterApproval: async (approved, context) => {
          const args = approved.params.arguments;
          const callOptions: {
            client: typeof connection.client;
            name: string;
            signal: AbortSignal;
            arguments?: Record<string, unknown>;
          } = {
            client: connection.client,
            name: approved.params.name,
            signal: context.signal,
          };
          if (
            args !== undefined &&
            typeof args === "object" &&
            args !== null &&
            !Array.isArray(args)
          ) {
            callOptions.arguments = args as Record<string, unknown>;
          }
          return await callGuwahDownstreamToolWithCancelPropagation(callOptions);
        },
      }),
    ).toThrow(GUWAH_TOOL_COLLISION_ERROR);

    // No gateway was created; fake downstream must not have been invoked.
    expect(fixture.getInvocationCount()).toBe(0);
    expect(fixture.getInvocations()).toEqual([]);

    // Namespacing collision from raw downstream names also fails closed with no merge.
    expect(() =>
      applyGuwahToolNamespacing([
        { name: "shared", inputSchema: { type: "object", properties: { a: { type: "integer" } } } },
        { name: "shared", inputSchema: { type: "object", properties: { b: { type: "string" } } } },
      ]),
    ).toThrow(GUWAH_TOOL_COLLISION_ERROR);
    expect(fixture.getInvocationCount()).toBe(0);
  });

  it("does not silently repair collisions with automatic suffixes", () => {
    const source = readFileSync(GATEWAY_SOURCE, "utf8");
    expect(source).toMatch(/no automatic suffix repair/);
    expect(source).not.toMatch(/\$\{gatewayName\}_\d+/);
    expect(source).not.toMatch(/gatewayName \+ "_" \+ /);
  });
});

describe("policy binding for mirrored tools", () => {
  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(tools: Record<string, unknown>): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-policy-bind-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  const transferArgsSchema = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
    },
  } as const;

  it("denies a discovered but unbound tool on the call path", async () => {
    const policyPath = writePolicy({
      coinbase_cdp_transfer: {
        action: "ENFORCE",
        argsSchema: structuredClone(transferArgsSchema),
      },
    });

    // Catalog includes a discovered tool that was never bound in policy.
    const mediatedTools: GuwahMediatedTool[] = [
      {
        name: "guwah__coinbase_cdp_transfer",
        downstreamName: "coinbase_cdp_transfer",
        inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
      },
      {
        name: "guwah__discovered_unbound",
        downstreamName: "discovered_unbound",
        inputSchema: { type: "object", properties: {} },
      },
    ];

    let dispatchCount = 0;
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools,
      afterApproval: async () => {
        dispatchCount += 1;
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
        clientInfo: { name: "guwah-unbound-raw", version: "0.0.0" },
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
        name: "guwah__discovered_unbound",
        arguments: {},
      },
    });
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(dispatchCount).toBe(0);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32600,
        data: { guwahCode: "UNAUTHORIZED_TOOL" },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");

    await clientTransport.close();
    await server.close();
  });

  it("keeps DENY-action tools non-executable even if present in the mediated catalog", async () => {
    const policyPath = writePolicy({
      denied_tool: {
        action: "DENY",
        argsSchema: structuredClone(transferArgsSchema),
      },
    });

    let dispatchCount = 0;
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [
        {
          name: "guwah__denied_tool",
          downstreamName: "denied_tool",
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
      ],
      afterApproval: async () => {
        dispatchCount += 1;
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
        clientInfo: { name: "guwah-deny-bind", version: "0.0.0" },
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
        name: "guwah__denied_tool",
        arguments: { amountMinor: 100 },
      },
    });
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(dispatchCount).toBe(0);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32600,
        data: { guwahCode: "POLICY_NOT_ENFORCED" },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");

    await clientTransport.close();
    await server.close();
  });
});

describe("deny unknown tools", () => {
  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(tools: Record<string, unknown>): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-deny-unknown-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return policyPath;
  }

  const transferArgsSchema = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
    },
  } as const;

  it("denies a call to a name absent from policy with zero downstream invocation", async () => {
    const policyPath = writePolicy({
      coinbase_cdp_transfer: {
        action: "ENFORCE",
        argsSchema: structuredClone(transferArgsSchema),
      },
    });

    let downstreamInvocations = 0;
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [
        {
          name: "guwah__coinbase_cdp_transfer",
          downstreamName: "coinbase_cdp_transfer",
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
      ],
      afterApproval: async () => {
        downstreamInvocations += 1;
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
        clientInfo: { name: "guwah-unknown-tool", version: "0.0.0" },
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
        name: "totally_unknown_tool",
        arguments: { amountMinor: 100 },
      },
    });
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(downstreamInvocations).toBe(0);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32600,
        data: { guwahCode: "UNAUTHORIZED_TOOL" },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");

    await clientTransport.close();
    await server.close();
  });
});

describe("deny newly discovered tools", () => {
  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(tools: Record<string, unknown>): { policyPath: string; guard: GuwahGuard } {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-dynamic-deny-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return { policyPath, guard: new GuwahGuard({ policyPath }) };
  }

  const transferArgsSchema = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
    },
  } as const;

  it("keeps tools appearing after startup denied and unlisted across catalog refresh", async () => {
    const { policyPath, guard } = writePolicy({
      coinbase_cdp_transfer: {
        action: "ENFORCE",
        argsSchema: structuredClone(transferArgsSchema),
      },
    });

    let discovered: GuwahMediatedTool[] = [
      {
        name: "coinbase_cdp_transfer",
        description: "Authorized transfer",
        inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
      },
    ];

    let downstreamInvocations = 0;
    const server = createGuwahGatewayServer({
      policyPath,
      resolveMediatedTools: () =>
        applyGuwahToolNamespacing(mirrorAuthorizedGuwahTools(discovered, guard)),
      afterApproval: async () => {
        downstreamInvocations += 1;
        return { content: [{ type: "text", text: "should-not-run" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-dynamic-deny", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const listedBefore = await client.listTools();
    expect(listedBefore.tools.map((tool) => tool.name)).toEqual(["guwah__coinbase_cdp_transfer"]);

    // Discovery churn after startup: a new downstream tool appears.
    discovered = [
      ...discovered,
      {
        name: "newly_discovered_tool",
        description: "Appeared after startup",
        inputSchema: { type: "object", properties: {} },
      },
    ];

    const listedAfter = await client.listTools();
    expect(listedAfter.tools.map((tool) => tool.name)).toEqual(["guwah__coinbase_cdp_transfer"]);
    expect(listedAfter.tools.some((tool) => tool.name.includes("newly_discovered"))).toBe(false);

    await expect(
      client.callTool({
        name: "guwah__newly_discovered_tool",
        arguments: {},
      }),
    ).rejects.toThrow(/not authorized|Invalid/i);
    expect(downstreamInvocations).toBe(0);

    await expect(
      client.callTool({
        name: "newly_discovered_tool",
        arguments: {},
      }),
    ).rejects.toThrow(/not authorized|Invalid/i);
    expect(downstreamInvocations).toBe(0);

    await client.close();
    await server.close();
  });
});

describe("deny unmirrored tools", () => {
  const policyDirs: string[] = [];

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(tools: Record<string, unknown>): { policyPath: string; guard: GuwahGuard } {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-unmirrored-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return { policyPath, guard: new GuwahGuard({ policyPath }) };
  }

  const transferArgsSchema = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
    },
  } as const;

  it("rejects a guessed raw downstream name without aliasing or dispatch", async () => {
    const { policyPath, guard } = writePolicy({
      coinbase_cdp_transfer: {
        action: "ENFORCE",
        argsSchema: structuredClone(transferArgsSchema),
      },
    });

    const discovered: GuwahMediatedTool[] = [
      {
        name: "coinbase_cdp_transfer",
        description: "Authorized transfer",
        inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
      },
    ];
    const mediated = applyGuwahToolNamespacing(mirrorAuthorizedGuwahTools(discovered, guard));
    expect(mediated.map((tool) => tool.name)).toEqual(["guwah__coinbase_cdp_transfer"]);
    expect(mediated[0]?.downstreamName).toBe("coinbase_cdp_transfer");

    let downstreamInvocations = 0;
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: mediated,
      afterApproval: async () => {
        downstreamInvocations += 1;
        return { content: [{ type: "text", text: "dispatched" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-raw-name-bypass", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const listed = await client.listTools();
    expect(listed.tools.map((tool) => tool.name)).toEqual(["guwah__coinbase_cdp_transfer"]);
    expect(listed.tools.some((tool) => tool.name === "coinbase_cdp_transfer")).toBe(false);

    await client.callTool({
      name: "guwah__coinbase_cdp_transfer",
      arguments: { amountMinor: 100 },
    });
    expect(downstreamInvocations).toBe(1);

    await expect(
      client.callTool({
        name: "coinbase_cdp_transfer",
        arguments: { amountMinor: 100 },
      }),
    ).rejects.toThrow(/not authorized|Invalid/i);
    expect(downstreamInvocations).toBe(1);

    await client.close();
    await server.close();

    const rawServer = createGuwahGatewayServer({
      policyPath,
      mediatedTools: mediated,
      afterApproval: async () => {
        downstreamInvocations += 1;
        return { content: [{ type: "text", text: "should-not-run" }] };
      },
    });
    const [rawClientTransport, rawServerTransport] = InMemoryTransport.createLinkedPair();
    await rawServer.connect(rawServerTransport);
    await rawClientTransport.start();
    const responses: unknown[] = [];
    rawClientTransport.onmessage = (message) => {
      responses.push(message);
    };
    await rawClientTransport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-raw-name-raw", version: "0.0.0" },
      },
    });
    const initDeadline = Date.now() + 5000;
    while (Date.now() < initDeadline && responses.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    await rawClientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    });
    await rawClientTransport.send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "coinbase_cdp_transfer",
        arguments: { amountMinor: 100 },
      },
    });
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(downstreamInvocations).toBe(1);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32600,
        data: { guwahCode: "UNAUTHORIZED_TOOL" },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");

    await rawClientTransport.close();
    await rawServer.close();
  });
});

describe("candidate-argument parity at the gateway boundary", () => {
  const policyDirs: string[] = [];
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
    vi.restoreAllMocks();
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-parity-"));
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
              argsSchema: {
                $schema: "http://json-schema.org/draft-07/schema#",
                type: "object",
                additionalProperties: false,
                required: ["amountMinor", "destinationAddress", "asset", "network"],
                properties: {
                  amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
                  destinationAddress: {
                    type: "string",
                    enum: [WHITELISTED_DESTINATION],
                  },
                  asset: { type: "string", enum: ["usdc"] },
                  network: { type: "string", enum: ["base"] },
                },
              },
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

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 100,
      destinationAddress: WHITELISTED_DESTINATION,
      asset: "usdc",
      network: "base",
    };
  }

  it("yields PAYLOAD_MUTATION with zero downstream invocation when embedded and candidate args diverge", async () => {
    const policyPath = writePolicy();
    const guard = new GuwahGuard({ policyPath });
    let downstreamInvocations = 0;
    let suppliedBothChannels = false;

    vi.spyOn(guard, "validateToolCall").mockImplementation((payload, candidateArgs) => {
      expect(payload).toMatchObject({
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          name: TOOL_NAME,
          arguments: expect.any(Object),
        },
      });
      expect(candidateArgs).toEqual(compliantArgs());
      const envelope = payload as {
        params: { arguments: Record<string, unknown> };
      };
      // Embedded and candidate must be distinct snapshots (no shared-reference shortcut).
      expect(envelope.params.arguments).not.toBe(candidateArgs);
      expect(envelope.params.arguments).toEqual(candidateArgs);
      suppliedBothChannels = true;
      // Client-runtime mutation: embedded args diverge from the candidate channel.
      envelope.params.arguments = {
        ...compliantArgs(),
        amountMinor: 1,
      };
      return GuwahGuard.prototype.validateToolCall.call(guard, payload, candidateArgs);
    });

    const server = createGuwahGatewayServer({
      guard,
      mediatedTools: [
        {
          name: TOOL_NAME,
          inputSchema: {
            type: "object",
            properties: {
              amountMinor: { type: "integer" },
              destinationAddress: { type: "string" },
              asset: { type: "string" },
              network: { type: "string" },
            },
          },
        },
      ],
      afterApproval: async () => {
        downstreamInvocations += 1;
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
        clientInfo: { name: "guwah-parity-mutation", version: "0.0.0" },
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
        arguments: compliantArgs(),
      },
    });
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(suppliedBothChannels).toBe(true);
    expect(downstreamInvocations).toBe(0);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32600,
        data: { guwahCode: "PAYLOAD_MUTATION" },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");

    await clientTransport.close();
    await server.close();
  });
});

describe("forward only the exact approved copy", () => {
  const policyDirs: string[] = [];
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  afterEach(() => {
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-exact-forward-"));
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
              argsSchema: {
                $schema: "http://json-schema.org/draft-07/schema#",
                type: "object",
                additionalProperties: false,
                required: ["amountMinor", "destinationAddress", "asset", "network"],
                properties: {
                  amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
                  destinationAddress: {
                    type: "string",
                    enum: [WHITELISTED_DESTINATION],
                  },
                  asset: { type: "string", enum: ["usdc"] },
                  network: { type: "string", enum: ["base"] },
                },
              },
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

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 100,
      destinationAddress: WHITELISTED_DESTINATION,
      asset: "usdc",
      network: "base",
    };
  }

  it("keeps serialized downstream args equal to the frozen approved copy after caller mutation", async () => {
    const policyPath = writePolicy();
    const callerArgs = compliantArgs();
    const expectedDownstreamJson = JSON.stringify({
      amountMinor: 100,
      destinationAddress: WHITELISTED_DESTINATION,
      asset: "usdc",
      network: "base",
    });

    let approvedArgsJson: string | undefined;
    let downstreamArgsJson: string | undefined;

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [
        {
          name: TOOL_NAME,
          inputSchema: {
            type: "object",
            properties: {
              amountMinor: { type: "integer" },
              destinationAddress: { type: "string" },
              asset: { type: "string" },
              network: { type: "string" },
            },
          },
        },
      ],
      afterApproval: async (approved) => {
        expect(Object.isFrozen(approved)).toBe(true);
        expect(Object.isFrozen(approved.params)).toBe(true);
        expect(Object.isFrozen(approved.params.arguments as object)).toBe(true);
        expect(approved.params.arguments).not.toBe(callerArgs);

        approvedArgsJson = JSON.stringify(approved.params.arguments);

        // Later mutation of the original caller object must not change forwarded bytes.
        callerArgs.amountMinor = 9999;
        callerArgs["injected"] = "drift";

        // Simulated downstream tools/call uses only the frozen approved arguments.
        const downstreamToolsCall = {
          name: approved.params.name,
          arguments: approved.params.arguments,
        };
        downstreamArgsJson = JSON.stringify(downstreamToolsCall.arguments);

        expect(downstreamArgsJson).toBe(approvedArgsJson);
        expect(downstreamArgsJson).toBe(expectedDownstreamJson);
        expect(downstreamArgsJson).not.toContain("9999");
        expect(downstreamArgsJson).not.toContain("injected");

        return { content: [{ type: "text", text: "forwarded" }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-exact-forward", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    await client.callTool({
      name: TOOL_NAME,
      arguments: callerArgs,
    });

    expect(approvedArgsJson).toBe(expectedDownstreamJson);
    expect(downstreamArgsJson).toBe(expectedDownstreamJson);
    expect(callerArgs.amountMinor).toBe(9999);

    await client.close();
    await server.close();
  });
});

describe("approved forwarding", () => {
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
      amountMinor: 2500,
      assetId: "USDC",
      destinationAddress: WHITELISTED_DESTINATION,
      memo: "invoice 42",
    };
  }

  const policyDirs: string[] = [];
  const liveFixtures: GuwahFakeDownstreamServer[] = [];

  afterEach(async () => {
    while (liveFixtures.length > 0) {
      const fixture = liveFixtures.pop();
      if (fixture !== undefined) {
        await fixture.stop();
      }
    }
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-approved-forward-"));
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

  it("compliant call reaches fake downstream once with approved args", async () => {
    const policyPath = writePolicy();
    const callerArgs = compliantArgs();
    const expectedArgsJson = JSON.stringify(compliantArgs());

    const { fixture, connection } = await startGuwahFakeDownstream({
      tools: [
        {
          name: TOOL_NAME,
          description: "Fake transfer",
          inputSchema: mediatedTransfer.inputSchema,
        },
      ],
    });
    liveFixtures.push(fixture);

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async (approved, context) => {
        expect(Object.isFrozen(approved.params.arguments as object)).toBe(true);
        // Caller mutation after approval must not affect the forwarded snapshot.
        callerArgs.amountMinor = 9999;
        callerArgs["injected"] = "drift";

        const args = approved.params.arguments;
        const callOptions: {
          client: typeof connection.client;
          name: string;
          signal: AbortSignal;
          arguments?: Record<string, unknown>;
          tool: GuwahMediatedTool;
        } = {
          client: connection.client,
          name: approved.params.name,
          signal: context.signal,
          tool: mediatedTransfer,
        };
        if (
          args !== undefined &&
          typeof args === "object" &&
          args !== null &&
          !Array.isArray(args)
        ) {
          callOptions.arguments = args as Record<string, unknown>;
        }
        return await callGuwahDownstreamToolWithCancelPropagation(callOptions);
      },
    });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-approved-forward", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    expect(fixture.getInvocationCount()).toBe(0);
    const result = await client.callTool({
      name: TOOL_NAME,
      arguments: callerArgs,
    });

    expect(result).toMatchObject({
      content: [{ type: "text", text: `fake-ok:${TOOL_NAME}` }],
    });
    expect(fixture.getInvocationCount()).toBe(1);
    expect(fixture.getInvocations()).toHaveLength(1);
    const invocation = fixture.getInvocations()[0];
    expect(invocation?.name).toBe(TOOL_NAME);
    expect(JSON.stringify(invocation?.arguments)).toBe(expectedArgsJson);
    expect(JSON.stringify(invocation?.arguments)).not.toContain("9999");
    expect(JSON.stringify(invocation?.arguments)).not.toContain("injected");
    expect(callerArgs.amountMinor).toBe(9999);

    await client.close();
    await server.close();
  });
});

describe("blocked-forwarding invocation proof", () => {
  const policyDirs: string[] = [];
  const liveFixtures: GuwahFakeDownstreamServer[] = [];
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  afterEach(async () => {
    while (liveFixtures.length > 0) {
      const fixture = liveFixtures.pop();
      if (fixture !== undefined) {
        await fixture.stop();
      }
    }
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
    vi.restoreAllMocks();
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-zero-dispatch-"));
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
              argsSchema: {
                $schema: "http://json-schema.org/draft-07/schema#",
                type: "object",
                additionalProperties: false,
                required: ["amountMinor", "destinationAddress", "asset", "network"],
                properties: {
                  amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
                  destinationAddress: {
                    type: "string",
                    enum: [WHITELISTED_DESTINATION],
                  },
                  asset: { type: "string", enum: ["usdc"] },
                  network: { type: "string", enum: ["base"] },
                },
              },
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

  function compliantArgs(): Record<string, unknown> {
    return {
      amountMinor: 100,
      destinationAddress: WHITELISTED_DESTINATION,
      asset: "usdc",
      network: "base",
    };
  }

  const mediatedTransfer: GuwahMediatedTool = {
    name: TOOL_NAME,
    inputSchema: {
      type: "object",
      properties: {
        amountMinor: { type: "integer" },
        destinationAddress: { type: "string" },
        asset: { type: "string" },
        network: { type: "string" },
      },
    },
  };

  async function expectBlockedCall(options: {
    readonly policyPath?: string;
    readonly guard?: GuwahGuard;
    readonly mediatedTools?: readonly GuwahMediatedTool[];
    readonly prepareGuard?: (guard: GuwahGuard) => void;
    readonly callParams: { readonly name: string; readonly arguments: Record<string, unknown> };
    readonly expectedGuwahCode: string;
  }): Promise<void> {
    const policyPath = options.policyPath ?? writePolicy();
    const guard = options.guard ?? new GuwahGuard({ policyPath });
    options.prepareGuard?.(guard);

    const { fixture, connection } = await startGuwahFakeDownstream({
      tools: [
        {
          name: TOOL_NAME,
          inputSchema: mediatedTransfer.inputSchema,
        },
      ],
    });
    liveFixtures.push(fixture);

    const server = createGuwahGatewayServer({
      guard,
      mediatedTools: options.mediatedTools ?? [mediatedTransfer],
      afterApproval: async (approved, context) => {
        // Real fake-downstream send: must never run after validation failure.
        const args = approved.params.arguments;
        const callOptions: {
          client: typeof connection.client;
          name: string;
          signal: AbortSignal;
          arguments?: Record<string, unknown>;
          tool: GuwahMediatedTool;
        } = {
          client: connection.client,
          name: approved.params.name,
          signal: context.signal,
          tool: mediatedTransfer,
        };
        if (
          args !== undefined &&
          typeof args === "object" &&
          args !== null &&
          !Array.isArray(args)
        ) {
          callOptions.arguments = args as Record<string, unknown>;
        }
        return await callGuwahDownstreamToolWithCancelPropagation(callOptions);
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
        clientInfo: { name: "guwah-zero-dispatch", version: "0.0.0" },
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
    expect(fixture.getInvocationCount()).toBe(0);
    await clientTransport.send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: options.callParams,
    });
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    // Invocation-proof: blocked calls must not send to the fake downstream.
    expect(fixture.getInvocationCount()).toBe(0);
    expect(fixture.getInvocations()).toEqual([]);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32600,
        data: { guwahCode: options.expectedGuwahCode },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");

    await clientTransport.close();
    await server.close();
  }

  it("keeps fake downstream invocation at zero for schema failure", async () => {
    await expectBlockedCall({
      callParams: {
        name: TOOL_NAME,
        arguments: { ...compliantArgs(), amountMinor: 5001 },
      },
      expectedGuwahCode: "ARGUMENT_VALIDATION_FAILED",
    });
  });

  it("keeps fake downstream invocation at zero for allowlist failure", async () => {
    await expectBlockedCall({
      callParams: {
        name: TOOL_NAME,
        arguments: {
          ...compliantArgs(),
          destinationAddress: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        },
      },
      expectedGuwahCode: "ARGUMENT_VALIDATION_FAILED",
    });
  });

  it("keeps fake downstream invocation at zero for unknown-tool failure", async () => {
    await expectBlockedCall({
      callParams: {
        name: "totally_unknown_tool",
        arguments: compliantArgs(),
      },
      expectedGuwahCode: "UNAUTHORIZED_TOOL",
    });
  });

  it("keeps fake downstream invocation at zero for over-limit failure", async () => {
    const policyPath = writePolicy();
    const guard = new GuwahGuard({
      policyPath,
      resourceLimits: { maxInputBytes: 40 },
    });
    await expectBlockedCall({
      policyPath,
      guard,
      callParams: {
        name: TOOL_NAME,
        arguments: compliantArgs(),
      },
      expectedGuwahCode: "RESOURCE_LIMIT_EXCEEDED",
    });
  });

  it("keeps fake downstream invocation at zero for payload-mutation failure", async () => {
    const policyPath = writePolicy();
    const guard = new GuwahGuard({ policyPath });
    await expectBlockedCall({
      policyPath,
      guard,
      prepareGuard: (activeGuard) => {
        vi.spyOn(activeGuard, "validateToolCall").mockImplementation((payload, candidateArgs) => {
          const envelope = payload as {
            params: { arguments: Record<string, unknown> };
          };
          envelope.params.arguments = {
            ...compliantArgs(),
            amountMinor: 1,
          };
          return GuwahGuard.prototype.validateToolCall.call(activeGuard, payload, candidateArgs);
        });
      },
      callParams: {
        name: TOOL_NAME,
        arguments: compliantArgs(),
      },
      expectedGuwahCode: "PAYLOAD_MUTATION",
    });
  });
});

describe("prevent direct downstream bypass", () => {
  const PACKAGE_JSON = path.join(REPO_ROOT, "package.json");
  const README = path.join(REPO_ROOT, "README.md");

  it("packages only the gateway as the host-facing MCP server start entry", () => {
    const pkg = JSON.parse(readFileSync(PACKAGE_JSON, "utf8")) as {
      scripts?: Record<string, string>;
      bin?: unknown;
      exports?: unknown;
      main?: string;
      files?: string[];
    };

    expect(pkg.scripts?.["gateway"]).toBe("node dist/guwahGateway.js");

    const mcpServerStartScripts = Object.entries(pkg.scripts ?? {}).filter(([, command]) =>
      /guwahGateway\.js|StdioServerTransport|mcp-server/i.test(command),
    );
    expect(mcpServerStartScripts).toEqual([["gateway", "node dist/guwahGateway.js"]]);

    // No second host-visible server binary is published by this package.
    expect(pkg.bin).toBeUndefined();
    expect(pkg.main).toBe("./dist/guwahGuard.js");
    expect(pkg.exports).toEqual({
      ".": {
        types: "./dist/guwahGuard.d.ts",
        import: "./dist/guwahGuard.js",
      },
    });
    expect(pkg.files).toEqual(["dist", "guwah-policy.json"]);
  });

  it("gateway process registers a single host Server and uses Client for downstream only", () => {
    const source = readFileSync(GATEWAY_SOURCE, "utf8");
    const hostServers = source.match(/new Server\(/g) ?? [];
    expect(hostServers).toHaveLength(1);

    expect(source).toMatch(/StdioServerTransport/);
    expect(source).toMatch(/StdioClientTransport/);
    expect(source).toMatch(/gateway-owned client only/);
    expect(source).toMatch(/must not be bound as a second/);
    expect(source).toMatch(/host-visible MCP server on the gateway process stdio/);

    const entryBlock = source.slice(source.indexOf("if (isGatewayEntry())"));
    expect(entryBlock).toMatch(/startGuwahStdioGateway/);
    expect(entryBlock).toMatch(/Host-facing entry starts only the gateway server/);
    expect(entryBlock).not.toMatch(/new Server\(/);
    expect(entryBlock).not.toMatch(/StdioServerTransport/);
  });

  it("documents that the host must connect only to the gateway", () => {
    const readme = readFileSync(README, "utf8");
    expect(readme).toMatch(/Host deployment boundary/);
    expect(readme).toMatch(/exposes only the Guwah gateway process to the host MCP client/);
    expect(readme).toMatch(/not registered by this package as additional host-visible MCP servers/);
    expect(readme).toMatch(/only host-facing MCP server this package starts/);
    expect(readme).toMatch(/npm run gateway/);
  });

  it("compiled gateway entry starts without registering a second host-visible MCP server", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [GATEWAY_ENTRY],
      cwd: REPO_ROOT,
      stderr: "pipe",
    });
    const client = new Client({ name: "guwah-host-only", version: "0.0.0" });
    liveClients.push({ client, transport });

    await client.connect(transport);
    expect(client.getServerVersion()).toEqual({
      name: GUWAH_GATEWAY_NAME,
      version: GUWAH_GATEWAY_VERSION,
    });

    const listed = await client.listTools();
    expect(Array.isArray(listed.tools)).toBe(true);

    // One host session only: the gateway process is the sole MCP server endpoint.
    await client.close();
  });
});

describe("direct-bypass prevention", () => {
  const policyDirs: string[] = [];
  const liveFixtures: GuwahFakeDownstreamServer[] = [];
  const RAW_DOWNSTREAM_NAME = "coinbase_cdp_transfer";
  const UNMIRRORED_NAME = "unmirrored_provider_tool";

  const transferArgsSchema = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    additionalProperties: false,
    required: ["amountMinor"],
    properties: {
      amountMinor: { type: "integer", minimum: 1, maximum: 5000 },
    },
  } as const;

  afterEach(async () => {
    while (liveFixtures.length > 0) {
      const fixture = liveFixtures.pop();
      if (fixture !== undefined) {
        await fixture.stop();
      }
    }
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function writePolicy(tools: Record<string, unknown>): { policyPath: string; guard: GuwahGuard } {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-bypass-proof-"));
    policyDirs.push(dir);
    const policyPath = path.join(dir, "guwah-policy.json");
    writeFileSync(
      policyPath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return { policyPath, guard: new GuwahGuard({ policyPath }) };
  }

  async function expectZeroDownstreamDispatch(options: {
    readonly policyPath: string;
    readonly mediatedTools: readonly GuwahMediatedTool[];
    readonly callName: string;
    readonly callArguments: Record<string, unknown>;
  }): Promise<void> {
    const { fixture, connection } = await startGuwahFakeDownstream({
      tools: [
        {
          name: RAW_DOWNSTREAM_NAME,
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
        {
          name: UNMIRRORED_NAME,
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
      ],
    });
    liveFixtures.push(fixture);

    const server = createGuwahGatewayServer({
      policyPath: options.policyPath,
      mediatedTools: options.mediatedTools,
      afterApproval: async (approved, context) => {
        const args = approved.params.arguments;
        const callOptions: {
          client: typeof connection.client;
          name: string;
          signal: AbortSignal;
          arguments?: Record<string, unknown>;
        } = {
          client: connection.client,
          name: approved.params.name,
          signal: context.signal,
        };
        if (
          args !== undefined &&
          typeof args === "object" &&
          args !== null &&
          !Array.isArray(args)
        ) {
          callOptions.arguments = args as Record<string, unknown>;
        }
        return await callGuwahDownstreamToolWithCancelPropagation(callOptions);
      },
    });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-bypass-fixture", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    expect(fixture.getInvocationCount()).toBe(0);
    await expect(
      client.callTool({
        name: options.callName,
        arguments: options.callArguments,
      }),
    ).rejects.toThrow();
    expect(fixture.getInvocationCount()).toBe(0);
    expect(fixture.getInvocations()).toEqual([]);

    await client.close();
    await server.close();
  }

  it("raw downstream names cannot be invoked through the gateway and record zero invocations", async () => {
    const { policyPath, guard } = writePolicy({
      [RAW_DOWNSTREAM_NAME]: {
        action: "ENFORCE",
        argsSchema: structuredClone(transferArgsSchema),
      },
    });
    const discovered: GuwahMediatedTool[] = [
      {
        name: RAW_DOWNSTREAM_NAME,
        inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
      },
    ];
    const mediated = applyGuwahToolNamespacing(mirrorAuthorizedGuwahTools(discovered, guard));
    expect(mediated.map((tool) => tool.name)).toEqual([`guwah__${RAW_DOWNSTREAM_NAME}`]);

    await expectZeroDownstreamDispatch({
      policyPath,
      mediatedTools: mediated,
      callName: RAW_DOWNSTREAM_NAME,
      callArguments: { amountMinor: 100 },
    });
  });

  it("unmirrored tools cannot be invoked through the gateway and record zero invocations", async () => {
    const { policyPath, guard } = writePolicy({
      [RAW_DOWNSTREAM_NAME]: {
        action: "ENFORCE",
        argsSchema: structuredClone(transferArgsSchema),
      },
      [UNMIRRORED_NAME]: {
        action: "ENFORCE",
        argsSchema: structuredClone(transferArgsSchema),
      },
    });
    const discovered: GuwahMediatedTool[] = [
      {
        name: RAW_DOWNSTREAM_NAME,
        inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
      },
      // Policy lists UNMIRRORED_NAME, but discovery did not surface it for mirroring.
    ];
    const mediated = applyGuwahToolNamespacing(mirrorAuthorizedGuwahTools(discovered, guard));
    expect(mediated.some((tool) => tool.downstreamName === UNMIRRORED_NAME)).toBe(false);
    expect(mediated.some((tool) => tool.name.includes(UNMIRRORED_NAME))).toBe(false);

    await expectZeroDownstreamDispatch({
      policyPath,
      mediatedTools: mediated,
      callName: `guwah__${UNMIRRORED_NAME}`,
      callArguments: { amountMinor: 100 },
    });
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

describe("sample versus active policy at startup", () => {
  const configDirs: string[] = [];

  afterEach(() => {
    for (const dir of configDirs.splice(0, configDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("binds stdio startup to the provisioned active path, not the packaged sample", async () => {
    const configBaseDir = mkdtempSync(path.join(tmpdir(), "guwah-startup-active-"));
    configDirs.push(configBaseDir);
    const samplePolicyPath = resolveGuwahPackagedSamplePolicyPath();
    const expectedActive = resolveGuwahActivePolicyPath({ configBaseDir });

    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const { server, activePolicyPath } = await startGuwahStdioGateway({
      stdin,
      stdout,
      configBaseDir,
      samplePolicyPath,
      mediatedTools: [],
      onTransportFailure: () => {
        throw new Error("unexpected transport failure during active-policy startup");
      },
    });

    expect(activePolicyPath).toBe(expectedActive);
    expect(activePolicyPath).not.toBe(path.resolve(samplePolicyPath));
    expect(existsSync(expectedActive)).toBe(true);
    expect(existsSync(samplePolicyPath)).toBe(true);

    await server.close();
  });

  it("does not validate against the packaged sample when an active user policy exists", async () => {
    const configBaseDir = mkdtempSync(path.join(tmpdir(), "guwah-startup-prefer-active-"));
    configDirs.push(configBaseDir);
    const samplePolicyPath = resolveGuwahPackagedSamplePolicyPath();
    const activePath = resolveGuwahActivePolicyPath({ configBaseDir });
    mkdirSync(path.dirname(activePath), { recursive: true });
    writeFileSync(
      activePath,
      `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            coinbase_cdp_transfer: {
              action: "ENFORCE",
              argsSchema: {
                $schema: "http://json-schema.org/draft-07/schema#",
                type: "object",
                additionalProperties: false,
                required: ["amountMinor", "assetId", "destinationAddress", "memo"],
                properties: {
                  amountMinor: { type: "integer", minimum: 1, maximum: 100 },
                  assetId: { type: "string", enum: ["USDC"] },
                  destinationAddress: {
                    type: "string",
                    pattern: "^0x[0-9a-fA-F]{40}$",
                    enum: ["0x1111111111111111111111111111111111111111"],
                  },
                  memo: {
                    type: "string",
                    minLength: 1,
                    maxLength: 80,
                    pattern: "^[A-Za-z0-9 .,_:-]+$",
                  },
                },
              },
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const chunks: Buffer[] = [];
    stdout.on("data", (chunk: Buffer) => {
      chunks.push(Buffer.from(chunk));
    });

    const mediatedTransfer: GuwahMediatedTool = {
      name: "coinbase_cdp_transfer",
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

    let dispatched = 0;
    const { server, activePolicyPath } = await startGuwahStdioGateway({
      stdin,
      stdout,
      configBaseDir,
      samplePolicyPath,
      policyPath: samplePolicyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatched += 1;
        return { content: [{ type: "text", text: "ok" }] };
      },
      onTransportFailure: () => {
        throw new Error("unexpected transport failure during sample-vs-active startup");
      },
    });

    expect(activePolicyPath).toBe(activePath);
    expect(activePolicyPath).not.toBe(path.resolve(samplePolicyPath));

    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-sample-vs-active", version: "0.0.0" },
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
        id: 2,
        method: "tools/call",
        params: {
          name: "coinbase_cdp_transfer",
          arguments: {
            amountMinor: 5000,
            assetId: "USDC",
            destinationAddress: "0x1111111111111111111111111111111111111111",
            memo: "invoice 1001",
          },
        },
      })}\n`,
    );
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && !chunks.join("").includes('"id":2')) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(dispatched).toBe(0);
    expect(chunks.join("")).toMatch(/ARGUMENT_VALIDATION_FAILED|guwahCode/);

    await server.close();
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
    expect(gatewaySource).toMatch(/This factory does not open a downstream client by default/);
    expect(gatewaySource).not.toMatch(/fetch\(/);
    expect(gatewaySource).not.toMatch(/\bnet\./);
    expect(gatewaySource).not.toMatch(/\bhttp\./);
    const serverFactoryStart = gatewaySource.indexOf("export function createGuwahGatewayServer");
    const serverFactoryEnd = gatewaySource.indexOf("export const GUWAH_STDIO_BACKPRESSURE_BOUNDS");
    expect(serverFactoryStart).toBeGreaterThan(-1);
    expect(serverFactoryEnd).toBeGreaterThan(serverFactoryStart);
    const serverFactory = gatewaySource.slice(serverFactoryStart, serverFactoryEnd);
    expect(serverFactory).not.toMatch(/createGuwahDownstreamClient\(/);

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

describe("stdio unsupported-method transport", () => {
  const TOOL_NAME = "coinbase_cdp_transfer";
  const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";

  const INITIALIZE_FIXTURE = {
    jsonrpc: "2.0" as const,
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "guwah-stdio-unsupported-method-fixture", version: "0.0.0" },
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
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-stdio-unsupported-method-"));
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

  it("rejects an unknown method over stdio without dispatch", async () => {
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
        throw new Error("unexpected transport failure during unsupported-method fixture");
      },
    });

    await completeInitialize(stdin, chunks);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "provider/secretExecute",
        params: {
          name: TOOL_NAME,
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
    const methodResponse = frames.find((frame) => frame.id === 2);
    expect(methodResponse).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: expect.objectContaining({
        code: -32601,
      }),
    });
    expect(methodResponse).not.toHaveProperty("result");

    await server.close();
  });

  it("cannot smuggle a tools/call payload through an unsupported stdio method", async () => {
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
        return { content: [{ type: "text", text: "smuggled-dispatch" }] };
      },
      onTransportFailure: () => {
        throw new Error("unexpected transport failure during smuggle fixture");
      },
    });

    await completeInitialize(stdin, chunks);
    stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/execute",
        params: {
          jsonrpc: "2.0",
          method: "tools/call",
          name: TOOL_NAME,
          arguments: compliantArgs(),
          params: {
            name: TOOL_NAME,
            arguments: compliantArgs(),
          },
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
    expect(chunks.join("")).not.toContain("smuggled-dispatch");
    const frames = chunks
      .join("")
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const methodResponse = frames.find((frame) => frame.id === 2);
    expect(methodResponse).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: expect.objectContaining({
        code: -32601,
      }),
    });
    expect(methodResponse).not.toHaveProperty("result");

    await server.close();
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

  it("forwards cancel downstream when a request is active without a second tools/call", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();

    let releaseDownstream: (() => void) | undefined;
    const holdDownstream = new Promise<void>((resolve) => {
      releaseDownstream = resolve;
    });
    let downstreamToolCalls = 0;
    const downstreamCancelled: unknown[] = [];

    const downstreamServer = new Server(
      { name: "guwah-downstream-cancel", version: "0.0.0" },
      { capabilities: { tools: {} } },
    );
    downstreamServer.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: TOOL_NAME,
          inputSchema: mediatedTransfer.inputSchema,
        },
      ],
    }));
    downstreamServer.setRequestHandler(CallToolRequestSchema, async () => {
      downstreamToolCalls += 1;
      await holdDownstream;
      return { content: [{ type: "text", text: "late-downstream-success" }] };
    });

    const [downstreamClientTransport, downstreamServerTransport] = InMemoryTransport.createLinkedPair();
    await downstreamServer.connect(downstreamServerTransport);
    const serverMessageHandler = downstreamServerTransport.onmessage;
    downstreamServerTransport.onmessage = (message) => {
      if (
        typeof message === "object" &&
        message !== null &&
        "method" in message &&
        (message as { method: unknown }).method === "notifications/cancelled"
      ) {
        downstreamCancelled.push(message);
      }
      serverMessageHandler?.(message);
    };

    const downstreamClient = createGuwahDownstreamClient();
    await downstreamClient.connect(downstreamClientTransport);

    let dispatchCount = 0;
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      afterApproval: async (approved, context) => {
        dispatchCount += 1;
        const args = approved.params.arguments;
        const callOptions: {
          client: typeof downstreamClient;
          name: string;
          signal: AbortSignal;
          arguments?: Record<string, unknown>;
        } = {
          client: downstreamClient,
          name: approved.params.name,
          signal: context.signal,
        };
        if (
          args !== undefined &&
          typeof args === "object" &&
          args !== null &&
          !Array.isArray(args)
        ) {
          callOptions.arguments = args as Record<string, unknown>;
        }
        return await callGuwahDownstreamToolWithCancelPropagation(callOptions);
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
        clientInfo: { name: "guwah-cancel-propagate", version: "0.0.0" },
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
      id: 91,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });
    const enteredDeadline = Date.now() + 5000;
    while (Date.now() < enteredDeadline && downstreamToolCalls === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(downstreamToolCalls).toBe(1);
    expect(dispatchCount).toBe(1);

    await clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: { requestId: 91, reason: "host cancelled" },
    });

    const cancelDeadline = Date.now() + 5000;
    while (Date.now() < cancelDeadline && downstreamCancelled.length === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(downstreamCancelled.length).toBeGreaterThanOrEqual(1);
    expect(downstreamCancelled[0]).toMatchObject({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
    });
    expect(dispatchCount).toBe(1);
    expect(downstreamToolCalls).toBe(1);

    releaseDownstream?.();
    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    const lateSuccess = responses.some(
      (message) =>
        typeof message === "object" &&
        message !== null &&
        "id" in message &&
        (message as { id: unknown }).id === 91 &&
        "result" in message,
    );
    expect(lateSuccess).toBe(false);
    expect(JSON.stringify(responses)).not.toContain("late-downstream-success");
    expect(dispatchCount).toBe(1);
    expect(downstreamToolCalls).toBe(1);

    await server.close();
    await clientTransport.close();
    await downstreamClient.close();
    await downstreamServer.close();
  });

  it("suppresses late success without retry when downstream cancel is unsupported", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    let releaseDispatch: (() => void) | undefined;
    const holdDispatch = new Promise<void>((resolve) => {
      releaseDispatch = resolve;
    });
    let dispatchCount = 0;
    let observedSignalAborted = false;

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      afterApproval: async (_approved, context) => {
        dispatchCount += 1;
        // Downstream does not honor cancel; dispatch continues until local completion.
        const waitStart = Date.now();
        while (Date.now() - waitStart < 5000 && !context.signal.aborted) {
          await new Promise((resolve) => {
            setTimeout(resolve, 25);
          });
        }
        observedSignalAborted = context.signal.aborted;
        await holdDispatch;
        return { content: [{ type: "text", text: "unsupported-cancel-late-success" }] };
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
        clientInfo: { name: "guwah-cancel-unsupported", version: "0.0.0" },
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
      id: 92,
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
      params: { requestId: 92, reason: "host cancelled" },
    });
    const cancelledDeadline = Date.now() + 5000;
    while (Date.now() < cancelledDeadline && !activeRequests.isCancelled(92)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.isCancelled(92)).toBe(true);

    releaseDispatch?.();
    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    expect(observedSignalAborted).toBe(true);
    expect(dispatchCount).toBe(1);
    const lateSuccess = responses.some(
      (message) =>
        typeof message === "object" &&
        message !== null &&
        "id" in message &&
        (message as { id: unknown }).id === 92 &&
        "result" in message,
    );
    expect(lateSuccess).toBe(false);
    expect(JSON.stringify(responses)).not.toContain("unsupported-cancel-late-success");

    await server.close();
    await clientTransport.close();
  });

  it("does not retry callTool when cancel aborts an in-flight downstream request", async () => {
    let callCount = 0;
    const controller = new AbortController();
    const fakeClient = {
      callTool: async (
        _params: unknown,
        _schema?: unknown,
        options?: { signal?: AbortSignal },
      ) => {
        callCount += 1;
        expect(options?.signal).toBe(controller.signal);
        await new Promise<never>((_resolve, reject) => {
          const onAbort = (): void => {
            reject(new Error("aborted"));
          };
          if (options?.signal?.aborted) {
            onAbort();
            return;
          }
          options?.signal?.addEventListener("abort", onAbort, { once: true });
        });
      },
    };

    const pending = callGuwahDownstreamToolWithCancelPropagation({
      client: fakeClient as unknown as Pick<Client, "callTool">,
      name: TOOL_NAME,
      arguments: compliantArgs(),
      signal: controller.signal,
    });
    controller.abort();
    await expect(pending).rejects.toThrow();
    expect(callCount).toBe(1);
  });

  it("discards a late callTool success when the cancel signal is already aborted", async () => {
    const LATE_SECRET = "late-body-secret-must-not-return";
    const controller = new AbortController();
    controller.abort();
    const fakeClient = {
      callTool: async () => ({
        content: [{ type: "text", text: LATE_SECRET }],
      }),
    };

    await expect(
      callGuwahDownstreamToolWithCancelPropagation({
        client: fakeClient as unknown as Pick<Client, "callTool">,
        name: TOOL_NAME,
        arguments: compliantArgs(),
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({
      message: expect.stringContaining("no longer active"),
    });
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

describe("mutating call retry prohibition", () => {
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
    vi.restoreAllMocks();
  });

  function writePolicy(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-mutating-retry-"));
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

  it("treats unclassified tools and the sample transfer as mutating without automatic retry", () => {
    expect(classifyGuwahToolSideEffect(undefined)).toBe("mutating");
    expect(classifyGuwahToolSideEffect(mediatedTransfer)).toBe("mutating");
    expect(classifyGuwahToolSideEffect({ sideEffectClass: "mutating" })).toBe("mutating");
    expect(classifyGuwahToolSideEffect({ sideEffectClass: "read-only" })).toBe("read-only");
    expect(guwahToolAllowsAutomaticRetry(undefined)).toBe(false);
    expect(guwahToolAllowsAutomaticRetry(mediatedTransfer)).toBe(false);
    expect(guwahToolAllowsAutomaticRetry({ sideEffectClass: "read-only" })).toBe(false);
  });

  it("timeout shows a single downstream dispatch attempt for a mutating transfer", async () => {
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();
    let callToolCount = 0;
    const controllerSeen: AbortSignal[] = [];

    const fakeClient = {
      callTool: async (
        _params: unknown,
        _schema?: unknown,
        options?: { signal?: AbortSignal },
      ) => {
        callToolCount += 1;
        if (options?.signal !== undefined) {
          controllerSeen.push(options.signal);
        }
        await new Promise<never>((_resolve, reject) => {
          const onAbort = (): void => {
            reject(new Error("downstream timed out"));
          };
          if (options?.signal?.aborted) {
            onAbort();
            return;
          }
          options?.signal?.addEventListener("abort", onAbort, { once: true });
        });
      },
    };

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      requestTimeoutMs: 40,
      afterApproval: async (approved, context) =>
        callGuwahDownstreamToolWithCancelPropagation({
          client: fakeClient as unknown as Pick<Client, "callTool">,
          name: approved.params.name,
          arguments: compliantArgs(),
          signal: context.signal,
          tool: mediatedTransfer,
        }),
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
        clientInfo: { name: "guwah-mutating-timeout", version: "0.0.0" },
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
      id: 301,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });

    const startedDeadline = Date.now() + 5000;
    while (Date.now() < startedDeadline && callToolCount === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 10);
      });
    }
    expect(callToolCount).toBe(1);

    const finishedDeadline = Date.now() + 5000;
    while (Date.now() < finishedDeadline && activeRequests.has(301)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.has(301)).toBe(false);
    expect(callToolCount).toBe(1);
    expect(controllerSeen).toHaveLength(1);
    expect(controllerSeen[0]?.aborted).toBe(true);

    const successes = responses.filter(
      (message) =>
        typeof message === "object" &&
        message !== null &&
        "id" in message &&
        (message as { id: unknown }).id === 301 &&
        "result" in message,
    );
    expect(successes).toHaveLength(0);

    await server.close();
    await clientTransport.close();
  });

  it("disconnect shows a single downstream dispatch attempt for a mutating transfer", async () => {
    const policyPath = writePolicy();
    let callToolCount = 0;
    let releaseCall: (() => void) | undefined;
    const holdCall = new Promise<void>((resolve) => {
      releaseCall = resolve;
    });
    let healthy = true;

    const fakeClient = {
      callTool: async () => {
        callToolCount += 1;
        await holdCall;
        throw new Error("connection reset");
      },
    };

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: wrapGuwahAfterApprovalForDownstreamAmbiguity({
        isHealthy: () => healthy,
        afterApproval: async (approved, context) =>
          callGuwahDownstreamToolWithCancelPropagation({
            client: fakeClient as unknown as Pick<Client, "callTool">,
            name: approved.params.name,
            arguments: compliantArgs(),
            signal: context.signal,
            tool: mediatedTransfer,
          }),
      }),
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-mutating-disconnect", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const pending = client.callTool({
      name: TOOL_NAME,
      arguments: compliantArgs(),
    });

    const startedDeadline = Date.now() + 5000;
    while (Date.now() < startedDeadline && callToolCount === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(callToolCount).toBe(1);

    healthy = false;
    releaseCall?.();
    await expect(pending).rejects.toThrow();
    expect(callToolCount).toBe(1);

    await client.close();
    await server.close();
  });

  it("host retries use a new request id and must re-validate", async () => {
    const policyPath = writePolicy();
    const guard = new GuwahGuard({ policyPath });
    const validateSpy = vi.spyOn(guard, "validateToolCall");
    let dispatchCount = 0;

    const server = createGuwahGatewayServer({
      guard,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: `ok-${dispatchCount}` }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-host-retry", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    await client.callTool({ name: TOOL_NAME, arguments: compliantArgs() });
    await client.callTool({ name: TOOL_NAME, arguments: compliantArgs() });

    expect(dispatchCount).toBe(2);
    expect(validateSpy).toHaveBeenCalledTimes(2);
    const firstId = (validateSpy.mock.calls[0]?.[0] as { id?: unknown } | undefined)?.id;
    const secondId = (validateSpy.mock.calls[1]?.[0] as { id?: unknown } | undefined)?.id;
    expect(firstId).not.toBe(secondId);

    await client.close();
    await server.close();
  });
});

describe("idempotency controls", () => {
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
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-idempotency-"));
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

  it("requires an explicit key and enforcer before coalescing is allowed", () => {
    expect(resolveGuwahIdempotencyKey(undefined)).toBeUndefined();
    expect(resolveGuwahIdempotencyKey({})).toBeUndefined();
    expect(resolveGuwahIdempotencyKey({ [GUWAH_IDEMPOTENCY_META_KEY]: "  " })).toBeUndefined();
    expect(resolveGuwahIdempotencyKey({ [GUWAH_IDEMPOTENCY_META_KEY]: "xfer-1" })).toBe("xfer-1");
    expect(
      guwahMayCoalesceMutatingCall({ idempotencyKey: undefined, enforcerConfigured: true }),
    ).toBe(false);
    expect(
      guwahMayCoalesceMutatingCall({ idempotencyKey: "xfer-1", enforcerConfigured: false }),
    ).toBe(false);
    expect(
      guwahMayCoalesceMutatingCall({ idempotencyKey: "xfer-1", enforcerConfigured: true }),
    ).toBe(true);
  });

  it("duplicate-request: absent key plus duplicate payload does not auto-deduplicate a transfer", async () => {
    const policyPath = writePolicy();
    let dispatchCount = 0;
    const tryReuse = vi.fn((_key?: string) => ({
      content: [{ type: "text" as const, text: "should-not-reuse-without-key" }],
    }));

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      // Enforcer present but unused without an explicit key — silent payload coalescing is forbidden.
      idempotencyEnforcer: { tryReuse },
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: `dispatch-${dispatchCount}` }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-dup-payload", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const args = compliantArgs();
    const first = await client.callTool({ name: TOOL_NAME, arguments: args });
    const second = await client.callTool({ name: TOOL_NAME, arguments: structuredClone(args) });

    expect(dispatchCount).toBe(2);
    expect(tryReuse).not.toHaveBeenCalled();
    expect(first).toMatchObject({ content: [{ type: "text", text: "dispatch-1" }] });
    expect(second).toMatchObject({ content: [{ type: "text", text: "dispatch-2" }] });

    await client.close();
    await server.close();
  });

  it("duplicate-request: concurrent identical payloads without a key each dispatch once", async () => {
    const policyPath = writePolicy();
    let dispatchCount = 0;
    let releaseGate: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });
    let entered = 0;

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        entered += 1;
        if (entered === 2) {
          releaseGate?.();
        }
        await gate;
        dispatchCount += 1;
        return { content: [{ type: "text", text: `concurrent-${dispatchCount}` }] };
      },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "guwah-dup-concurrent", version: "0.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const args = compliantArgs();
    const [a, b] = await Promise.all([
      client.callTool({ name: TOOL_NAME, arguments: args }),
      client.callTool({ name: TOOL_NAME, arguments: structuredClone(args) }),
    ]);

    expect(dispatchCount).toBe(2);
    expect(entered).toBe(2);
    expect(a).toBeDefined();
    expect(b).toBeDefined();

    await client.close();
    await server.close();
  });

  it("duplicate-request: explicit key with enforcer may reuse; key alone does not", async () => {
    const policyPath = writePolicy();
    let dispatchCount = 0;
    const prior = {
      content: [{ type: "text" as const, text: "reused-under-key" }],
    };
    const tryReuse = vi.fn((key: string) => (key === "xfer-42" ? prior : undefined));

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      idempotencyEnforcer: { tryReuse },
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: `fresh-${dispatchCount}` }] };
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
        clientInfo: { name: "guwah-idem-key", version: "0.0.0" },
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
      id: 10,
      method: "tools/call",
      params: {
        name: TOOL_NAME,
        arguments: compliantArgs(),
        _meta: { [GUWAH_IDEMPOTENCY_META_KEY]: "xfer-42" },
      },
    });
    const reusedDeadline = Date.now() + 5000;
    while (
      Date.now() < reusedDeadline &&
      !responses.some(
        (message) =>
          typeof message === "object" &&
          message !== null &&
          "id" in message &&
          (message as { id: unknown }).id === 10 &&
          "result" in message,
      )
    ) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(tryReuse).toHaveBeenCalledWith("xfer-42");
    expect(dispatchCount).toBe(0);
    expect(JSON.stringify(responses)).toContain("reused-under-key");

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 11,
      method: "tools/call",
      params: {
        name: TOOL_NAME,
        arguments: compliantArgs(),
        _meta: { [GUWAH_IDEMPOTENCY_META_KEY]: "xfer-99" },
      },
    });
    const freshDeadline = Date.now() + 5000;
    while (
      Date.now() < freshDeadline &&
      !responses.some(
        (message) =>
          typeof message === "object" &&
          message !== null &&
          "id" in message &&
          (message as { id: unknown }).id === 11 &&
          "result" in message,
      )
    ) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(dispatchCount).toBe(1);
    expect(JSON.stringify(responses)).toContain("fresh-1");

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

  it("delayed-response: discards late downstream body after deadline without logging secrets", async () => {
    const LATE_SECRET = "late-downstream-secret-token-do-not-leak";
    const policyPath = writePolicy();
    const activeRequests = new GuwahActiveRequestRegistry();

    let releaseDownstream: (() => void) | undefined;
    const holdDownstream = new Promise<void>((resolve) => {
      releaseDownstream = resolve;
    });
    let downstreamToolCalls = 0;

    const downstreamServer = new Server(
      { name: "guwah-downstream-late", version: "0.0.0" },
      { capabilities: { tools: {} } },
    );
    downstreamServer.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: TOOL_NAME,
          inputSchema: mediatedTransfer.inputSchema,
        },
      ],
    }));
    downstreamServer.setRequestHandler(CallToolRequestSchema, async () => {
      downstreamToolCalls += 1;
      await holdDownstream;
      return {
        content: [{ type: "text", text: `approved:${LATE_SECRET}` }],
      };
    });

    const [downstreamClientTransport, downstreamServerTransport] = InMemoryTransport.createLinkedPair();
    await downstreamServer.connect(downstreamServerTransport);
    const downstreamClient = createGuwahDownstreamClient();
    await downstreamClient.connect(downstreamClientTransport);

    const diagnosticWrites: string[] = [];
    const originalStderrWrite = process.stderr.write.bind(process.stderr);
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(((
      chunk: string | Uint8Array,
      encodingOrCallback?: BufferEncoding | ((error?: Error | null) => void),
      callback?: (error?: Error | null) => void,
    ) => {
      const text =
        typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
      diagnosticWrites.push(text);
      if (typeof encodingOrCallback === "function") {
        return originalStderrWrite(chunk, encodingOrCallback);
      }
      if (callback !== undefined) {
        return originalStderrWrite(chunk, encodingOrCallback as BufferEncoding, callback);
      }
      if (encodingOrCallback !== undefined) {
        return originalStderrWrite(chunk, encodingOrCallback as BufferEncoding);
      }
      return originalStderrWrite(chunk);
    }) as typeof process.stderr.write);

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      activeRequests,
      requestTimeoutMs: 50,
      afterApproval: async (approved, context) => {
        const args = approved.params.arguments;
        const callOptions: {
          client: typeof downstreamClient;
          name: string;
          signal: AbortSignal;
          arguments?: Record<string, unknown>;
        } = {
          client: downstreamClient,
          name: approved.params.name,
          signal: context.signal,
        };
        if (
          args !== undefined &&
          typeof args === "object" &&
          args !== null &&
          !Array.isArray(args)
        ) {
          callOptions.arguments = args as Record<string, unknown>;
        }
        return await callGuwahDownstreamToolWithCancelPropagation(callOptions);
      },
    });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();

    const responses: unknown[] = [];
    clientTransport.onmessage = (message) => {
      responses.push(message);
    };

    await initializeClient(clientTransport, responses, "guwah-delayed-response");

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 201,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: compliantArgs() },
    });

    const enteredDeadline = Date.now() + 5000;
    while (Date.now() < enteredDeadline && downstreamToolCalls === 0) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(downstreamToolCalls).toBe(1);

    // Deadline seals the call; registry end() clears flags, so wait until the id is inactive.
    const finishedDeadline = Date.now() + 5000;
    while (Date.now() < finishedDeadline && activeRequests.has(201)) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }
    expect(activeRequests.has(201)).toBe(false);

    releaseDownstream?.();
    await new Promise((resolve) => {
      setTimeout(resolve, 200);
    });

    expect(downstreamToolCalls).toBe(1);
    const forId = responses.filter((message) => isJsonRpcForId(message, 201));
    const successes = forId.filter(hasResult);
    expect(successes).toHaveLength(0);
    const responseText = JSON.stringify(responses);
    expect(responseText).not.toContain(LATE_SECRET);
    expect(responseText).not.toContain("approved:");
    expect(diagnosticWrites.join("")).not.toContain(LATE_SECRET);

    stderrSpy.mockRestore();
    await server.close();
    await clientTransport.close();
    await downstreamClient.close();
    await downstreamServer.close();
  }, 15_000);
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
    ).rejects.toThrow(/not authorized|Invalid/i);
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

describe("complete call envelope", () => {
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
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-envelope-"));
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
        clientInfo: { name: "guwah-complete-envelope", version: "0.0.0" },
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

  it("keeps GuwahGuard as the enforcement engine for the complete envelope", async () => {
    const policyPath = writePolicy();
    const guard = new GuwahGuard({ policyPath });
    const events: string[] = [];
    const meta = { progressToken: "envelope-token", note: "operator context" };
    let approvedMeta: unknown;

    vi.spyOn(guard, "validateToolCall").mockImplementation((payload, args) => {
      events.push("validate");
      expect(payload).toMatchObject({
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          name: TOOL_NAME,
          arguments: compliantArgs(),
          _meta: meta,
        },
      });
      expect(args).toEqual(compliantArgs());
      expect(args).not.toHaveProperty("progressToken");
      expect(events).not.toContain("dispatch");
      return GuwahGuard.prototype.validateToolCall.call(guard, payload, args);
    });

    const server = createGuwahGatewayServer({
      guard,
      mediatedTools: [mediatedTransfer],
      afterApproval: async (approved) => {
        events.push("dispatch");
        approvedMeta = approved.params._meta;
        return {
          content: [{ type: "text", text: "envelope-approved" }],
        };
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
        _meta: meta,
      },
    });
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(events).toEqual(["validate", "dispatch"]);
    expect(approvedMeta).toEqual(meta);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      result: {
        content: [{ type: "text", text: "envelope-approved" }],
      },
    });

    await server.close();
    await clientTransport.close();
  });

  it("checks arguments through GuwahGuard and does not dispatch on denial", async () => {
    const policyPath = writePolicy();
    const guard = new GuwahGuard({ policyPath });
    let dispatchCount = 0;

    vi.spyOn(guard, "validateToolCall").mockImplementation((payload, args) => {
      return GuwahGuard.prototype.validateToolCall.call(guard, payload, args);
    });

    const server = createGuwahGatewayServer({
      guard,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "should-not-dispatch" }] };
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
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(dispatchCount).toBe(0);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32600,
        data: { guwahCode: "ARGUMENT_VALIDATION_FAILED" },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");

    await server.close();
    await clientTransport.close();
  });

  it("does not let _meta authorize a call when arguments violate policy", async () => {
    const policyPath = writePolicy();
    let dispatchCount = 0;
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "should-not-dispatch" }] };
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
        _meta: {
          authorize: true,
          amountMinor: 5000,
          destinationAddress: WHITELISTED_DESTINATION,
        },
      },
    });
    const callDeadline = Date.now() + 5000;
    while (Date.now() < callDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(dispatchCount).toBe(0);
    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: {
        code: -32600,
        data: { guwahCode: "ARGUMENT_VALIDATION_FAILED" },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");

    await server.close();
    await clientTransport.close();
  });
});

describe("alternate-envelope bypass", () => {
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
    const dir = mkdtempSync(path.join(tmpdir(), "guwah-gateway-alt-envelope-"));
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
        clientInfo: { name: "guwah-alt-envelope", version: "0.0.0" },
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

  const UNSUPPORTED_METHODS: ReadonlyArray<string> = [
    "provider/secretExecute",
    "tools/execute",
    "tools/invoke",
    "Tools/Call",
  ];

  it.each(UNSUPPORTED_METHODS)(
    "rejects unsupported method %s without dispatching tools",
    async (method) => {
      const policyPath = writePolicy();
      let dispatchCount = 0;
      const server = createGuwahGatewayServer({
        policyPath,
        mediatedTools: [mediatedTransfer],
        afterApproval: async () => {
          dispatchCount += 1;
          return { content: [{ type: "text", text: "should-not-dispatch" }] };
        },
      });
      const { clientTransport, responses } = await initializePair(server);

      await clientTransport.send({
        jsonrpc: "2.0",
        id: 2,
        method,
        params: {
          name: TOOL_NAME,
          arguments: compliantArgs(),
        },
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
      expect(responses[1]).not.toHaveProperty("result");
      expect(dispatchCount).toBe(0);

      await server.close();
      await clientTransport.close();
    },
  );

  it("cannot smuggle a tools/call payload through an unsupported method", async () => {
    const policyPath = writePolicy();
    let dispatchCount = 0;
    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async () => {
        dispatchCount += 1;
        return { content: [{ type: "text", text: "smuggled-dispatch" }] };
      },
    });
    const { clientTransport, responses } = await initializePair(server);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 2,
      method: "provider/secretExecute",
      params: {
        jsonrpc: "2.0",
        method: "tools/call",
        name: TOOL_NAME,
        arguments: compliantArgs(),
        params: {
          name: TOOL_NAME,
          arguments: compliantArgs(),
        },
      },
    });
    const methodDeadline = Date.now() + 5000;
    while (Date.now() < methodDeadline && responses.length < 2) {
      await new Promise((resolve) => {
        setTimeout(resolve, 25);
      });
    }

    expect(responses[1]).toMatchObject({
      jsonrpc: "2.0",
      id: 2,
      error: expect.objectContaining({
        code: -32601,
      }),
    });
    expect(dispatchCount).toBe(0);

    await server.close();
    await clientTransport.close();
  });

  it("wires tool execution only through the tools/call registration path", () => {
    const source = readFileSync(GATEWAY_SOURCE, "utf8");
    expect(source).toMatch(/Only tools\/call may execute tools/);
    expect(source).toMatch(/registerGatewayToolsCall\(server, callOptions\)/);
    expect(source).toMatch(/server\.setRequestHandler\(CallToolRequestSchema/);
    const afterApprovalInvocations =
      source.match(/await options\.afterApproval\(approved,\s*\{\s*signal:\s*downstreamCancel\.signal,\s*\}\)/g) ??
      [];
    expect(afterApprovalInvocations).toHaveLength(1);
    const callHandlerIndex = source.indexOf("server.setRequestHandler(CallToolRequestSchema");
    const afterApprovalIndex = source.indexOf("await options.afterApproval(approved,");
    expect(callHandlerIndex).toBeGreaterThan(-1);
    expect(afterApprovalIndex).toBeGreaterThan(callHandlerIndex);
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

  it("planted-secret downstream error is mapped to the generic downstream-failure code", async () => {
    const policyPath = writePolicy();
    const PLANTED = `sk_live_downstream_${SECRET_MARKER}_provider_dump`;

    expect(isGuwahEmittedMcpError(mapGuwahDownstreamFailureToMcpError(new Error(PLANTED)))).toBe(
      true,
    );
    const mapped = mapGuwahDownstreamFailureToMcpError(new Error(PLANTED));
    expect(mapped.message).toContain(GUWAH_DOWNSTREAM_FAILURE_ERROR);
    expect(mapped.message).not.toContain(PLANTED);
    expect(mapped.data).toMatchObject({ guwahCode: GUWAH_DOWNSTREAM_FAILURE_CODE });

    const server = createGuwahGatewayServer({
      policyPath,
      mediatedTools: [mediatedTransfer],
      afterApproval: async (_approved, context) =>
        callGuwahDownstreamToolWithCancelPropagation({
          client: {
            callTool: async () => {
              throw new McpError(
                ErrorCode.InternalError,
                `Provider rejected transfer api_key=${PLANTED} destination=${WHITELISTED_DESTINATION}`,
                { rawProviderBody: { secret: PLANTED } },
              );
            },
          } as unknown as Pick<Client, "callTool">,
          name: TOOL_NAME,
          arguments: compliantArgs(),
          signal: context.signal,
          tool: mediatedTransfer,
        }),
    });
    const { clientTransport, responses } = await initializePair(server);

    await clientTransport.send({
      jsonrpc: "2.0",
      id: 9,
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
      id: 9,
      error: {
        code: -32603,
        message: expect.stringContaining(GUWAH_DOWNSTREAM_FAILURE_ERROR),
        data: { guwahCode: GUWAH_DOWNSTREAM_FAILURE_CODE },
      },
    });
    expect(responses[1]).not.toHaveProperty("result");
    const body = JSON.stringify(responses[1]);
    expect(body).not.toContain(PLANTED);
    expect(body).not.toContain(SECRET_MARKER);
    expect(body).not.toContain(WHITELISTED_DESTINATION);
    expect(body).not.toContain("rawProviderBody");
    expect(body).not.toContain("api_key=");

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
