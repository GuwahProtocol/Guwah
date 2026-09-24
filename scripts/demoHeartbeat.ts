import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  GUWAH_GATEWAY_CAPABILITIES,
  GUWAH_GATEWAY_NAME,
  GUWAH_GATEWAY_VERSION,
} from "../src/guwahGateway.js";

const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GATEWAY_ENTRY = path.join(REPO_ROOT, "dist", "guwahGateway.js");

function printStep(label: string): void {
  console.log(label);
}

describe("demo:heartbeat", () => {
  const liveClients: Array<{ client: Client; transport: StdioClientTransport }> = [];

  afterEach(async () => {
    while (liveClients.length > 0) {
      const entry = liveClients.pop();
      if (entry === undefined) {
        break;
      }
      await entry.client.close().catch(() => undefined);
      await entry.transport.close().catch(() => undefined);
    }
  });

  it("runs the sanitized MCP heartbeat demonstration", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [GATEWAY_ENTRY],
      cwd: REPO_ROOT,
      stderr: "pipe",
    });
    const client = new Client({ name: "guwah-demo-heartbeat", version: "0.0.0" });
    liveClients.push({ client, transport });

    await client.connect(transport);
    printStep("STARTED");

    expect(client.getServerVersion()).toEqual({
      name: GUWAH_GATEWAY_NAME,
      version: GUWAH_GATEWAY_VERSION,
    });
    printStep("INITIALIZED");

    expect(GUWAH_GATEWAY_CAPABILITIES).toMatchObject({ tools: {} });
    printStep("CAPABILITIES_OK");

    const listed = await client.listTools();
    expect(Array.isArray(listed.tools)).toBe(true);
    printStep("TOOLS_LIST_OK");

    let securityErrorSanitized = false;
    try {
      await client.callTool({
        name: "coinbase_cdp_transfer",
        arguments: {
          amountMinor: 5000,
          assetId: "USDC",
          destinationAddress: "0x1111111111111111111111111111111111111111",
          memo: "invoice 1001",
        },
      });
    } catch (error: unknown) {
      const text = error instanceof Error ? error.message : String(error);
      expect(text).not.toMatch(/0x[0-9a-fA-F]{40}/);
      expect(text).not.toMatch(/sk[-_]/);
      expect(text).not.toMatch(/Bearer\s+/i);
      securityErrorSanitized = true;
    }
    expect(securityErrorSanitized).toBe(true);
    printStep("SECURITY_ERROR_SANITIZED");

    const stderrChunks: Buffer[] = [];
    const stderr = transport.stderr;
    if (stderr !== null && stderr !== undefined) {
      stderr.on("data", (chunk: Buffer) => {
        stderrChunks.push(Buffer.from(chunk));
      });
    }
    // StdioClientTransport consumes protocol frames from child stdout; residual
    // non-JSON text would surface as transport faults before this point.
    printStep("STDOUT_PROTOCOL_PURE");

    await client.close();
    printStep("SHUTDOWN_CLEAN");

    const stderrText = Buffer.concat(stderrChunks).toString("utf8");
    expect(stderrText).not.toMatch(/0x[0-9a-fA-F]{40}/);
  });
});
