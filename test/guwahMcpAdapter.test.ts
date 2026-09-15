import { readFileSync } from "node:fs";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GuwahMcpAdapter } from "../src/guwahMcpAdapter.js";
import {
  GuwahGuard,
  GuwahSecurityViolation,
  type GuwahViolationCode,
} from "../src/guwahGuard.js";

const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";
const TOOL_NAME = "coinbase_cdp_transfer";
const SRC_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src");

const TRANSFER_SCHEMA = {
  $schema: "http://json-schema.org/draft-07/schema#",
  type: "object",
  additionalProperties: false,
  required: ["amountMinor", "assetId", "destinationAddress", "memo"],
  properties: {
    amountMinor: {
      type: "integer",
      minimum: 1,
      maximum: 5000,
    },
    assetId: {
      type: "string",
      enum: ["USDC"],
    },
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

function toolCallRequest(args: Record<string, unknown>): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id: "req-1",
    method: "tools/call",
    params: {
      name: TOOL_NAME,
      arguments: args,
    },
  };
}

function expectViolation(run: () => unknown, code: GuwahViolationCode): GuwahSecurityViolation {
  try {
    run();
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(GuwahSecurityViolation);
    if (error instanceof GuwahSecurityViolation) {
      expect(error.code).toBe(code);
      return error;
    }
  }
  expect.unreachable(`expected ${code}`);
}

describe("GuwahMcpAdapter", () => {
  let policyDir: string;
  let policyPath: string;

  beforeEach(() => {
    policyDir = mkdtempSync(path.join(tmpdir(), "guwah-adapter-policy-"));
    policyPath = path.join(policyDir, "guwah-policy.json");
    writeFileSync(policyPath, `${JSON.stringify(transferPolicy(), null, 2)}\n`, "utf8");
  });

  afterEach(() => {
    rmSync(policyDir, { recursive: true, force: true });
  });

  function createAdapter(): { adapter: GuwahMcpAdapter; guard: GuwahGuard } {
    const guard = new GuwahGuard({ policyPath });
    return { adapter: new GuwahMcpAdapter(guard), guard };
  }

  it("approves only after GuwahGuard validation", () => {
    const { adapter, guard } = createAdapter();
    const spy = vi.spyOn(guard, "validateToolCall");
    const request = toolCallRequest(compliantArgs());
    const params = request["params"];
    if (params === null || typeof params !== "object" || Array.isArray(params)) {
      expect.unreachable("params");
    }
    const approved = adapter.approveToolCall(request);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(request, Reflect.get(params, "arguments"));
    expect(approved.params.arguments).toEqual(compliantArgs());
    expect(Object.isFrozen(approved)).toBe(true);
  });

  it("does not return arguments when GuwahGuard denies the call", () => {
    const { adapter, guard } = createAdapter();
    const spy = vi.spyOn(guard, "validateToolCall");
    const args = { ...compliantArgs(), amountMinor: 5001 };
    const denied = expectViolation(
      () => adapter.approveToolCall(toolCallRequest(args)),
      "ARGUMENT_VALIDATION_FAILED",
    );
    expect(spy).toHaveBeenCalledTimes(1);
    expect(denied.message).not.toContain("5001");
    expect(denied).not.toHaveProperty("arguments");
  });

  it("does not substitute a weaker local allowlist for GuwahGuard", () => {
    const { adapter, guard } = createAdapter();
    vi.spyOn(guard, "validateToolCall").mockImplementation(() => {
      throw new GuwahSecurityViolation({
        code: "UNAUTHORIZED_TOOL",
        message: "Requested tool is not authorized by local policy.",
        toolName: TOOL_NAME,
        rule: "tool-allowlist",
      });
    });
    expectViolation(() => adapter.approveToolCall(toolCallRequest(compliantArgs())), "UNAUTHORIZED_TOOL");
  });

  it("fails closed when argument extraction throws", () => {
    const { adapter } = createAdapter();
    const request = {
      jsonrpc: "2.0",
      id: "req-1",
      method: "tools/call",
      get params(): Record<string, unknown> {
        throw new Error("accessor");
      },
    };
    expectViolation(() => adapter.approveToolCall(request), "INTERNAL_VALIDATION_ERROR");
  });
});

describe("module isolation", () => {
  it("keeps SDK and transport imports out of the validator module", () => {
    const validator = readFileSync(path.join(SRC_ROOT, "guwahGuard.ts"), "utf8");
    expect(validator).not.toMatch(/@modelcontextprotocol/);
    expect(validator).not.toMatch(/StdioServerTransport/);
    expect(validator).not.toMatch(/StreamableHTTP/);
  });

  it("does not import a downstream client or transport into the adapter", () => {
    const adapter = readFileSync(path.join(SRC_ROOT, "guwahMcpAdapter.ts"), "utf8");
    expect(adapter).toMatch(/@modelcontextprotocol\/sdk\/types\.js/);
    expect(adapter).not.toMatch(/sdk\/client/);
    expect(adapter).not.toMatch(/stdio/i);
    expect(adapter).not.toMatch(/StreamableHTTP/);
    expect(adapter).not.toMatch(/SSEServerTransport/);
  });
});
