import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  callGuwahDownstreamToolWithCancelPropagation,
  createGuwahGatewayServer,
  type GuwahMediatedTool,
} from "../src/guwahGateway.js";
import { GuwahGuard } from "../src/guwahGuard.js";
import { startGuwahFakeDownstream } from "../test/guwahFakeDownstream.js";

const TOOL_NAME = "coinbase_cdp_transfer";
const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";
const NON_WHITELISTED_DESTINATION = "0x3333333333333333333333333333333333333333";

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
      enum: [WHITELISTED_DESTINATION, "0x2222222222222222222222222222222222222222"],
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

function argumentDigest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function writePolicy(): { readonly policyPath: string; readonly dir: string } {
  const dir = mkdtempSync(path.join(tmpdir(), "guwah-demo-golden-"));
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
  return { policyPath, dir };
}

function printFact(name: string, value: string | number | boolean): void {
  console.log(`${name}=${String(value)}`);
}

describe("demo:golden", () => {
  const policyDirs: string[] = [];

  afterEach(() => {
    vi.restoreAllMocks();
    for (const dir of policyDirs.splice(0, policyDirs.length)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("runs approved and blocked fake transactions", async () => {
    const { policyPath, dir } = writePolicy();
    policyDirs.push(dir);

    const { fixture, connection } = await startGuwahFakeDownstream({
      tools: [
        {
          name: TOOL_NAME,
          description: "Fake transfer",
          inputSchema: mediatedTransfer.inputSchema,
        },
      ],
    });

    try {
      const server = createGuwahGatewayServer({
        policyPath,
        mediatedTools: [mediatedTransfer],
        afterApproval: async (approved, context) => {
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
      const client = new Client({ name: "guwah-demo-golden", version: "0.0.0" });
      await server.connect(serverTransport);
      await client.connect(clientTransport);

      const compliant = compliantArgs();
      const approvedDigest = argumentDigest(compliant);
      const approvedResult = await client.callTool({
        name: TOOL_NAME,
        arguments: compliant,
      });
      expect(approvedResult).toMatchObject({
        content: [{ type: "text", text: `fake-ok:${TOOL_NAME}` }],
      });
      expect(fixture.getInvocationCount()).toBe(1);
      const approvedInvocation = fixture.getInvocations()[0];
      expect(approvedInvocation?.name).toBe(TOOL_NAME);
      const forwardedDigest = argumentDigest(approvedInvocation?.arguments);
      expect(forwardedDigest).toBe(approvedDigest);
      printFact("COMPLIANT_CALL", "APPROVED");
      printFact("COMPLIANT_DOWNSTREAM_INVOCATIONS", fixture.getInvocationCount());
      printFact("APPROVED_ARGUMENT_DIGEST_MATCH", forwardedDigest === approvedDigest);

      fixture.resetInvocations();
      await expect(
        client.callTool({
          name: TOOL_NAME,
          arguments: {
            ...compliantArgs(),
            amountMinor: 5100,
          },
        }),
      ).rejects.toMatchObject({
        code: -32600,
      });
      expect(fixture.getInvocationCount()).toBe(0);
      printFact("OVER_LIMIT_CALL", "BLOCKED");
      printFact("OVER_LIMIT_DOWNSTREAM_INVOCATIONS", fixture.getInvocationCount());

      await expect(
        client.callTool({
          name: TOOL_NAME,
          arguments: {
            ...compliantArgs(),
            destinationAddress: NON_WHITELISTED_DESTINATION,
          },
        }),
      ).rejects.toMatchObject({
        code: -32600,
      });
      expect(fixture.getInvocationCount()).toBe(0);
      printFact("NON_WHITELISTED_CALL", "BLOCKED");
      printFact("NON_WHITELISTED_DOWNSTREAM_INVOCATIONS", fixture.getInvocationCount());

      await client.close();
      await server.close();

      const mutationGuard = new GuwahGuard({ policyPath });
      vi.spyOn(mutationGuard, "validateToolCall").mockImplementation((payload, candidateArgs) => {
        const envelope = payload as {
          params: { arguments: Record<string, unknown> };
        };
        envelope.params.arguments = {
          ...compliantArgs(),
          amountMinor: 1,
        };
        return GuwahGuard.prototype.validateToolCall.call(mutationGuard, payload, candidateArgs);
      });

      const mutationServer = createGuwahGatewayServer({
        guard: mutationGuard,
        mediatedTools: [mediatedTransfer],
        afterApproval: async () => {
          return { content: [{ type: "text", text: "should-not-run" }] };
        },
      });
      const [mutationClientTransport, mutationServerTransport] =
        InMemoryTransport.createLinkedPair();
      await mutationServer.connect(mutationServerTransport);
      await mutationClientTransport.start();
      const mutationResponses: unknown[] = [];
      mutationClientTransport.onmessage = (message) => {
        mutationResponses.push(message);
      };
      await mutationClientTransport.send({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "guwah-demo-golden-mutation", version: "0.0.0" },
        },
      });
      const initDeadline = Date.now() + 5000;
      while (Date.now() < initDeadline && mutationResponses.length === 0) {
        await new Promise((resolve) => {
          setTimeout(resolve, 25);
        });
      }
      await mutationClientTransport.send({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      });
      const beforeMutation = fixture.getInvocationCount();
      await mutationClientTransport.send({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: {
          name: TOOL_NAME,
          arguments: compliantArgs(),
        },
      });
      const callDeadline = Date.now() + 5000;
      while (Date.now() < callDeadline && mutationResponses.length < 2) {
        await new Promise((resolve) => {
          setTimeout(resolve, 25);
        });
      }
      expect(mutationResponses[1]).toMatchObject({
        jsonrpc: "2.0",
        id: 2,
        error: {
          code: -32600,
          data: { guwahCode: "PAYLOAD_MUTATION" },
        },
      });
      expect(fixture.getInvocationCount()).toBe(beforeMutation);
      printFact("MUTATED_CALL", "BLOCKED");
      printFact("MUTATED_DOWNSTREAM_INVOCATIONS", 0);

      await mutationClientTransport.close();
      await mutationServer.close();

      const unknownServer = createGuwahGatewayServer({
        policyPath,
        mediatedTools: [mediatedTransfer],
        afterApproval: async () => {
          return { content: [{ type: "text", text: "should-not-run" }] };
        },
      });
      const [unknownClientTransport, unknownServerTransport] = InMemoryTransport.createLinkedPair();
      const unknownClient = new Client({ name: "guwah-demo-golden-unknown", version: "0.0.0" });
      await unknownServer.connect(unknownServerTransport);
      await unknownClient.connect(unknownClientTransport);
      const beforeUnknown = fixture.getInvocationCount();
      await expect(
        unknownClient.callTool({
          name: "not_a_registered_tool",
          arguments: {},
        }),
      ).rejects.toMatchObject({
        code: -32600,
      });
      expect(fixture.getInvocationCount()).toBe(beforeUnknown);
      printFact("UNKNOWN_TOOL_CALL", "BLOCKED");
      printFact("UNKNOWN_TOOL_DOWNSTREAM_INVOCATIONS", 0);

      await unknownClient.close();
      await unknownServer.close();
    } finally {
      await fixture.stop();
    }
  });
});
