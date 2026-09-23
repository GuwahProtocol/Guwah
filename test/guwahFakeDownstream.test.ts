import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import {
  GuwahFakeDownstreamServer,
  startGuwahFakeDownstream,
} from "./guwahFakeDownstream.js";

const FIXTURE_SOURCE = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "guwahFakeDownstream.ts",
);

describe("Guwah fake downstream MCP server", () => {
  const live: GuwahFakeDownstreamServer[] = [];

  afterEach(async () => {
    while (live.length > 0) {
      const fixture = live.pop();
      if (fixture !== undefined) {
        await fixture.stop();
      }
    }
  });

  it("starts and stops without real network providers", async () => {
    const { fixture, connection } = await startGuwahFakeDownstream({
      tools: [
        {
          name: "fake_transfer",
          description: "Fake transfer",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties: { amountMinor: { type: "integer" } },
          },
        },
      ],
    });
    live.push(fixture);

    expect(connection.isHealthy()).toBe(true);
    connection.assertHealthy();
    const listed = await connection.client.listTools();
    expect(listed.tools).toHaveLength(1);
    expect(listed.tools[0]?.name).toBe("fake_transfer");

    await fixture.stop();
    expect(connection.isHealthy()).toBe(false);
    expect(() => connection.assertHealthy()).toThrow(/dead/i);
    await expect(connection.client.listTools()).rejects.toThrow();
  });

  it("counts tools/call invocations and records arguments", async () => {
    const { fixture, connection } = await startGuwahFakeDownstream({
      tools: [
        {
          name: "fake_transfer",
          inputSchema: { type: "object", properties: { amountMinor: { type: "integer" } } },
        },
      ],
    });
    live.push(fixture);

    expect(fixture.getInvocationCount()).toBe(0);
    const result = await connection.client.callTool({
      name: "fake_transfer",
      arguments: { amountMinor: 100 },
    });
    expect(result).toMatchObject({
      content: [{ type: "text", text: "fake-ok:fake_transfer" }],
    });
    expect(fixture.getInvocationCount()).toBe(1);
    expect(fixture.getInvocations()).toEqual([
      { name: "fake_transfer", arguments: { amountMinor: 100 } },
    ]);

    await connection.client.callTool({
      name: "fake_transfer",
      arguments: { amountMinor: 200 },
    });
    expect(fixture.getInvocationCount()).toBe(2);
    fixture.resetInvocations();
    expect(fixture.getInvocationCount()).toBe(0);
  });

  it("supports configurable tool catalogs at runtime", async () => {
    const { fixture, connection } = await startGuwahFakeDownstream({ tools: [] });
    live.push(fixture);

    expect((await connection.client.listTools()).tools).toEqual([]);
    fixture.setTools([
      {
        name: "alpha",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "beta",
        description: "Beta tool",
        inputSchema: { type: "object", properties: { x: { type: "string" } } },
      },
    ]);
    const listed = await connection.client.listTools();
    expect(listed.tools.map((tool) => tool.name)).toEqual(["alpha", "beta"]);
    expect(listed.tools[1]).toMatchObject({ description: "Beta tool" });
  });

  it("supports injectable failures on tools/call", async () => {
    const { fixture, connection } = await startGuwahFakeDownstream({
      tools: [
        {
          name: "fake_transfer",
          inputSchema: { type: "object", properties: {} },
        },
      ],
    });
    live.push(fixture);

    fixture.injectNextFailure({
      kind: "mcp-error",
      code: ErrorCode.InternalError,
      message: "injected fake failure",
    });
    await expect(
      connection.client.callTool({ name: "fake_transfer", arguments: {} }),
    ).rejects.toThrow(/injected fake failure/);
    expect(fixture.getInvocationCount()).toBe(1);

    fixture.injectNextFailure({
      kind: "is-error-result",
      text: "soft-fail",
    });
    const soft = await connection.client.callTool({
      name: "fake_transfer",
      arguments: {},
    });
    expect(soft).toMatchObject({
      isError: true,
      content: [{ type: "text", text: "soft-fail" }],
    });
    expect(fixture.getInvocationCount()).toBe(2);

    fixture.setCallHandler(() => ({
      kind: "throw",
      error: new Error("handler-injected"),
    }));
    await expect(
      connection.client.callTool({ name: "fake_transfer", arguments: {} }),
    ).rejects.toThrow(/handler-injected/);
    expect(fixture.getInvocationCount()).toBe(3);
  });

  it("does not implement a Guwah bypass path", () => {
    const source = readFileSync(FIXTURE_SOURCE, "utf8");
    expect(source).toMatch(/not a Guwah bypass|Does not.*bypass|not provide a path that skips Guwah/i);
    expect(source).not.toMatch(/\bbypassGuwah\b/);
    expect(source).not.toMatch(/\bskipValidation\b/);
    expect(source).not.toMatch(/\bunguardedDispatch\b/);
    expect(source).not.toMatch(/sk_live_/);
    expect(source).not.toMatch(/api[_-]?key\s*[:=]/i);
    expect(source).not.toMatch(/Bearer\s+[A-Za-z0-9._-]+/);
  });
});
