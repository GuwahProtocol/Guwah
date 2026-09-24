import * as nodeFs from "node:fs";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  GUWAH_ACTIVE_POLICY_FILENAME,
  GUWAH_ACTIVE_POLICY_PROVISION_ERROR,
  GUWAH_ACTIVE_POLICY_SUBDIR,
  GUWAH_SAMPLE_POLICY_UNAVAILABLE,
  GUWAH_USER_CONFIG_DIR_UNAVAILABLE,
  GuwahGuard,
  GuwahSecurityViolation,
  isGuwahPathInsideRoot,
  provisionGuwahActivePolicy,
  resolveGuwahActivePolicyPath,
  resolveGuwahPackagedSamplePolicyPath,
  resolveGuwahUserConfigBaseDir,
  resolveGuwahLivePolicyPath,
  type GuwahGuardOptions,
  type GuwahViolationCode,
} from "../src/guwahGuard.js";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    readSync: vi.fn(actual.readSync),
    fstatSync: vi.fn(actual.fstatSync),
    closeSync: vi.fn(actual.closeSync),
  };
});

const WHITELISTED_DESTINATION = "0x1111111111111111111111111111111111111111";
const NON_WHITELISTED_DESTINATION = "0x3333333333333333333333333333333333333333";
const TOOL_NAME = "coinbase_cdp_transfer";
const MALICIOUS_MEMO = "invoice; DROP TABLE approvals; --";

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

function transferPolicy(action: "ENFORCE" | "DENY" = "ENFORCE"): Record<string, unknown> {
  return {
    version: "1.0.0",
    posture: "default-deny",
    tools: {
      [TOOL_NAME]: {
        action,
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

function toolCallPayload(
  args: Record<string, unknown>,
  meta?: Record<string, unknown>,
): Record<string, unknown> {
  const params: Record<string, unknown> = {
    name: TOOL_NAME,
    arguments: args,
  };
  if (meta !== undefined) {
    params["_meta"] = meta;
  }
  return {
    jsonrpc: "2.0",
    id: "req-1",
    method: "tools/call",
    params,
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

function patchToolSchema(mutator: (schema: Record<string, unknown>) => void): Record<string, unknown> {
  const policy = transferPolicy();
  const tools = policy["tools"] as Record<string, Record<string, unknown>>;
  const tool = tools[TOOL_NAME];
  if (tool === undefined) {
    expect.unreachable("missing tool");
  }
  const schema = structuredClone(TRANSFER_SCHEMA) as Record<string, unknown>;
  mutator(schema);
  tool["argsSchema"] = schema;
  return policy;
}

function minimalPolicy(): Record<string, unknown> {
  return {
    version: "1.0.0",
    posture: "default-deny",
    tools: {
      t: {
        action: "ENFORCE",
        argsSchema: {
          type: "object",
          additionalProperties: false,
          properties: {},
        },
      },
    },
  };
}

function enumerableSnapshot(error: GuwahSecurityViolation): string {
  const parts: string[] = [error.name, error.message, error.code];
  if (error.toolName !== undefined) {
    parts.push(error.toolName);
  }
  if (error.fieldPath !== undefined) {
    parts.push(error.fieldPath);
  }
  if (error.rule !== undefined) {
    parts.push(error.rule);
  }
  parts.push(JSON.stringify(error));
  for (const key of Reflect.ownKeys(error)) {
    if (typeof key !== "string") {
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, key);
    if (descriptor?.enumerable === true) {
      parts.push(String(descriptor.value));
    }
  }
  return parts.join("\n");
}

describe("GuwahGuard", () => {
  let policyDir: string;
  let policyPath: string;

  beforeEach(() => {
    policyDir = mkdtempSync(path.join(tmpdir(), "guwah-policy-"));
    policyPath = path.join(policyDir, "guwah-policy.json");
    writeFileSync(policyPath, `${JSON.stringify(transferPolicy(), null, 2)}\n`, "utf8");
  });

  afterEach(() => {
    rmSync(policyDir, { recursive: true, force: true });
  });

  function createGuard(options?: GuwahGuardOptions): GuwahGuard {
    return new GuwahGuard({
      ...options,
      policyPath,
    });
  }

  describe("existing behavior", () => {
    it("approves a compliant $50.00 transfer", () => {
      const instance = createGuard();
      const args = compliantArgs();
      const payload = toolCallPayload(args);
      const approved = instance.validateToolCall(payload, args);
      expect(approved.params.arguments).toEqual({
        amountMinor: 5000,
        assetId: "USDC",
        destinationAddress: WHITELISTED_DESTINATION,
        memo: "invoice 1001",
      });
    });

    it("rejects a $51.00 transfer", () => {
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        amountMinor: 5100,
      };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(args), args), "ARGUMENT_VALIDATION_FAILED");
    });

    it("rejects a structurally valid non-whitelisted destination", () => {
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        destinationAddress: NON_WHITELISTED_DESTINATION,
      };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(args), args), "ARGUMENT_VALIDATION_FAILED");
    });

    it("rejects a malicious memo", () => {
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        memo: MALICIOUS_MEMO,
      };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(args), args), "ARGUMENT_VALIDATION_FAILED");
    });

    it("rejects embedded and candidate argument mismatch as PAYLOAD_MUTATION", () => {
      const candidate = compliantArgs();
      const embedded: Record<string, unknown> = {
        ...compliantArgs(),
        amountMinor: 1,
      };
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(embedded), candidate),
        "PAYLOAD_MUTATION",
      );
    });

    it("rejects an additional argument", () => {
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        routingHint: "internal",
      };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(args), args), "ARGUMENT_VALIDATION_FAILED");
    });

    it("rejects a dangerous object key", () => {
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        metadata: {
          constructor: { name: "Attack" },
        },
      };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(args), args), "DANGEROUS_OBJECT_KEY");
    });
  });

  describe("MCP metadata", () => {
    it("accepts valid _meta", () => {
      const args = compliantArgs();
      const meta = { progressToken: "tok-1" };
      const approved = createGuard().validateToolCall(toolCallPayload(args, meta), args);
      expect(approved.params._meta).toEqual(meta);
    });

    it("preserves _meta values exactly", () => {
      const args = compliantArgs();
      const meta = { progressToken: "tok-2", nested: { n: 7 } };
      const approved = createGuard().validateToolCall(toolCallPayload(args, meta), args);
      expect(approved.params._meta).toEqual({
        progressToken: "tok-2",
        nested: { n: 7 },
      });
    });

    it("defensively copies returned _meta", () => {
      const args = compliantArgs();
      const meta = { progressToken: "tok-3", nested: { n: 1 } };
      const payload = toolCallPayload(args, meta);
      const approved = createGuard().validateToolCall(payload, args);
      expect(approved.params._meta).not.toBe(meta);
      expect(approved.params._meta).not.toBe((payload["params"] as Record<string, unknown>)["_meta"]);
      expect(approved.params._meta?.["nested"]).not.toBe(meta["nested"]);
    });

    it("deep-freezes returned _meta", () => {
      const args = compliantArgs();
      const meta = { progressToken: "tok-4", nested: { n: 1 } };
      const approved = createGuard().validateToolCall(toolCallPayload(args, meta), args);
      expect(Object.isFrozen(approved.params._meta)).toBe(true);
      expect(Object.isFrozen(approved.params._meta?.["nested"])).toBe(true);
    });

    it("does not compare _meta with candidate arguments", () => {
      const args = compliantArgs();
      const meta = { progressToken: "unrelated" };
      expect(() => createGuard().validateToolCall(toolCallPayload(args, meta), args)).not.toThrow();
    });

    it("rejects _meta that is not a JSON object", () => {
      const args = compliantArgs();
      const payload = toolCallPayload(args);
      (payload["params"] as Record<string, unknown>)["_meta"] = ["not-object"];
      expectViolation(() => createGuard().validateToolCall(payload, args), "INVALID_PAYLOAD");
    });

    it("rejects dangerous keys inside _meta", () => {
      const args = compliantArgs();
      const meta = { prototype: { polluted: true } };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(args, meta), args), "DANGEROUS_OBJECT_KEY");
    });
  });

  describe("JSON compatibility", () => {
    it("rejects NaN", () => {
      const args: Record<string, unknown> = { ...compliantArgs(), amountMinor: Number.NaN };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects Infinity", () => {
      const args: Record<string, unknown> = { ...compliantArgs(), amountMinor: Number.POSITIVE_INFINITY };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects -Infinity", () => {
      const args: Record<string, unknown> = { ...compliantArgs(), amountMinor: Number.NEGATIVE_INFINITY };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects undefined", () => {
      const args: Record<string, unknown> = { ...compliantArgs(), amountMinor: undefined };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects bigint", () => {
      const args: Record<string, unknown> = { ...compliantArgs(), amountMinor: 5000n };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects a function value", () => {
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        amountMinor: () => 5000,
      };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects a symbol value", () => {
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        amountMinor: Symbol("amount"),
      };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects a symbol-keyed property", () => {
      const args: Record<string, unknown> = compliantArgs();
      Object.defineProperty(args, Symbol("hidden"), {
        enumerable: true,
        value: 1,
      });
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects a getter without invoking it", () => {
      let getterCount = 0;
      const args: Record<string, unknown> = compliantArgs();
      Object.defineProperty(args, "trap", {
        configurable: true,
        enumerable: true,
        get() {
          getterCount += 1;
          return true;
        },
      });
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
      expect(getterCount).toBe(0);
    });

    it("rejects a setter property", () => {
      const args: Record<string, unknown> = compliantArgs();
      Object.defineProperty(args, "trap", {
        configurable: true,
        enumerable: true,
        set() {
          return;
        },
      });
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects a non-enumerable property", () => {
      const args: Record<string, unknown> = compliantArgs();
      Object.defineProperty(args, "hidden", {
        enumerable: false,
        value: 1,
      });
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects a sparse array", () => {
      const sparse: unknown[] = [];
      sparse[2] = 1;
      const args = compliantArgs();
      const payload = toolCallPayload(args, { items: sparse });
      expectViolation(() => createGuard().validateToolCall(payload, args), "NON_JSON_VALUE");
    });

    it("rejects an array with an extra named property", () => {
      const extra = [1, 2];
      Object.defineProperty(extra, "note", {
        enumerable: true,
        value: "x",
      });
      const args = compliantArgs();
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(args, { items: extra }), args),
        "NON_JSON_VALUE",
      );
    });

    it("rejects a cyclic object", () => {
      const args: Record<string, unknown> = compliantArgs();
      args["loop"] = args;
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects Date", () => {
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        amountMinor: new Date(0),
      };
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });

    it("rejects Map", () => {
      const args = compliantArgs();
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(args, { bag: new Map() }), args),
        "NON_JSON_VALUE",
      );
    });

    it("rejects Set", () => {
      const args = compliantArgs();
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(args, { bag: new Set() }), args),
        "NON_JSON_VALUE",
      );
    });

    it("rejects RegExp", () => {
      const args = compliantArgs();
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(args, { bag: /x/ }), args),
        "NON_JSON_VALUE",
      );
    });

    it("rejects a class instance", () => {
      class Sample {
        public readonly amountMinor = 5000;
      }
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), new Sample() as unknown),
        "NON_JSON_VALUE",
      );
    });

    it("rejects an object with an unsupported prototype", () => {
      const args = Object.assign(Object.create(null), compliantArgs()) as Record<string, unknown>;
      Object.setPrototypeOf(args, Object.create({ marker: true }));
      expectViolation(() => createGuard().validateToolCall(toolCallPayload(compliantArgs()), args), "NON_JSON_VALUE");
    });
  });

  describe("policy handling", () => {
    it("returns POLICY_UNAVAILABLE for a missing policy file", () => {
      const instance = new GuwahGuard({
        policyPath: path.join(policyDir, "missing.json"),
      });
      expectViolation(
        () => instance.validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_UNAVAILABLE",
      );
    });

    it("returns RESOURCE_LIMIT_EXCEEDED for an oversized policy", () => {
      const instance = new GuwahGuard({
        policyPath,
        resourceLimits: { maxPolicyBytes: 32 },
      });
      expectViolation(
        () => instance.validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "RESOURCE_LIMIT_EXCEEDED",
      );
    });

    it("fails closed on invalid UTF-8 policy bytes", () => {
      writeFileSync(policyPath, Buffer.from([0xff, 0xfe, 0x80]));
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
    });

    it("returns POLICY_INVALID for invalid JSON", () => {
      writeFileSync(policyPath, "{", "utf8");
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
    });

    it("returns POLICY_INVALID for an unsupported policy version", () => {
      const policy = transferPolicy();
      policy["version"] = "9.9.9";
      writeFileSync(policyPath, JSON.stringify(policy), "utf8");
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
    });

    it("returns POLICY_INVALID for an invalid posture", () => {
      const policy = transferPolicy();
      policy["posture"] = "allow-all";
      writeFileSync(policyPath, JSON.stringify(policy), "utf8");
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
    });

    it("returns POLICY_INVALID for an unknown action", () => {
      const policy = transferPolicy();
      const tools = policy["tools"] as Record<string, Record<string, unknown>>;
      const tool = tools[TOOL_NAME];
      if (tool === undefined) {
        expect.unreachable();
      }
      tool["action"] = "ALLOW";
      writeFileSync(policyPath, JSON.stringify(policy), "utf8");
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
    });

    it("returns UNAUTHORIZED_TOOL for an unknown tool", () => {
      const payload = toolCallPayload(compliantArgs());
      (payload["params"] as Record<string, unknown>)["name"] = "unknown_tool";
      expectViolation(
        () => createGuard().validateToolCall(payload, compliantArgs()),
        "UNAUTHORIZED_TOOL",
      );
    });

    it("returns POLICY_NOT_ENFORCED when the tool action is DENY", () => {
      writeFileSync(policyPath, JSON.stringify(transferPolicy("DENY")), "utf8");
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_NOT_ENFORCED",
      );
    });

    it("returns POLICY_INVALID when additionalProperties is not false", () => {
      const policy = transferPolicy();
      const tools = policy["tools"] as Record<string, Record<string, unknown>>;
      const tool = tools[TOOL_NAME];
      if (tool === undefined) {
        expect.unreachable();
      }
      const schema = structuredClone(TRANSFER_SCHEMA) as Record<string, unknown>;
      delete schema["additionalProperties"];
      tool["argsSchema"] = schema;
      writeFileSync(policyPath, JSON.stringify(policy), "utf8");
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
    });

    it("returns POLICY_INVALID for an unsupported schema keyword", () => {
      const policy = transferPolicy();
      const tools = policy["tools"] as Record<string, Record<string, unknown>>;
      const tool = tools[TOOL_NAME];
      if (tool === undefined) {
        expect.unreachable();
      }
      const schema = structuredClone(TRANSFER_SCHEMA) as Record<string, unknown>;
      schema["oneOf"] = [{ type: "object" }];
      tool["argsSchema"] = schema;
      writeFileSync(policyPath, JSON.stringify(policy), "utf8");
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
    });

    it("returns POLICY_INVALID for a remote $ref", () => {
      const policy = transferPolicy();
      const tools = policy["tools"] as Record<string, Record<string, unknown>>;
      const tool = tools[TOOL_NAME];
      if (tool === undefined) {
        expect.unreachable();
      }
      const schema = structuredClone(TRANSFER_SCHEMA) as Record<string, unknown>;
      schema["$ref"] = "https://example.invalid/schema.json";
      tool["argsSchema"] = schema;
      writeFileSync(policyPath, JSON.stringify(policy), "utf8");
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
    });

    it("returns POLICY_INVALID for an invalid regex", () => {
      const policy = transferPolicy();
      const tools = policy["tools"] as Record<string, Record<string, unknown>>;
      const tool = tools[TOOL_NAME];
      if (tool === undefined) {
        expect.unreachable();
      }
      const schema = structuredClone(TRANSFER_SCHEMA) as {
        properties: { memo: Record<string, unknown> };
      };
      schema.properties.memo["pattern"] = "[";
      tool["argsSchema"] = schema;
      writeFileSync(policyPath, JSON.stringify(policy), "utf8");
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
    });

    it("returns POLICY_INVALID for inconsistent numeric bounds", () => {
      const policy = transferPolicy();
      const tools = policy["tools"] as Record<string, Record<string, unknown>>;
      const tool = tools[TOOL_NAME];
      if (tool === undefined) {
        expect.unreachable();
      }
      const schema = structuredClone(TRANSFER_SCHEMA) as {
        properties: { amountMinor: Record<string, unknown> };
      };
      schema.properties.amountMinor["minimum"] = 5000;
      schema.properties.amountMinor["maximum"] = 1;
      tool["argsSchema"] = schema;
      writeFileSync(policyPath, JSON.stringify(policy), "utf8");
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
    });

    it("recompiles validators when policy content changes", () => {
      const instance = createGuard();
      const args = compliantArgs();
      expect(instance.validateToolCall(toolCallPayload(args), args).params.arguments).toEqual(args);

      const policy = transferPolicy();
      const tools = policy["tools"] as Record<string, Record<string, unknown>>;
      const tool = tools[TOOL_NAME];
      if (tool === undefined) {
        expect.unreachable();
      }
      const schema = structuredClone(TRANSFER_SCHEMA) as {
        properties: { amountMinor: Record<string, unknown> };
      };
      schema.properties.amountMinor["maximum"] = 100;
      tool["argsSchema"] = schema;
      writeFileSync(policyPath, JSON.stringify(policy), "utf8");

      expectViolation(
        () => instance.validateToolCall(toolCallPayload(args), args),
        "ARGUMENT_VALIDATION_FAILED",
      );
    });

    it("never falls back to a cached validator after the policy becomes unreadable", () => {
      const instance = createGuard();
      const args = compliantArgs();
      instance.validateToolCall(toolCallPayload(args), args);
      rmSync(policyPath);
      expectViolation(
        () => instance.validateToolCall(toolCallPayload(args), args),
        "POLICY_UNAVAILABLE",
      );
    });
  });

  describe("resource limits", () => {
    it("enforces maxPolicyBytes", () => {
      expectViolation(
        () =>
          createGuard({ resourceLimits: { maxPolicyBytes: 64 } }).validateToolCall(
            toolCallPayload(compliantArgs()),
            compliantArgs(),
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
    });

    it("enforces maxInputDepth", () => {
      const args = compliantArgs();
      const meta = { a: { b: { c: 1 } } };
      expectViolation(
        () =>
          createGuard({ resourceLimits: { maxInputDepth: 4 } }).validateToolCall(
            toolCallPayload(args, meta),
            args,
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
    });

    it("enforces maxInputNodes", () => {
      expectViolation(
        () =>
          createGuard({ resourceLimits: { maxInputNodes: 8 } }).validateToolCall(
            toolCallPayload(compliantArgs()),
            compliantArgs(),
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
    });

    it("enforces maxInputBytes", () => {
      const args = compliantArgs();
      const meta = { blob: "x".repeat(200) };
      expectViolation(
        () =>
          createGuard({ resourceLimits: { maxInputBytes: 40 } }).validateToolCall(
            toolCallPayload(args, meta),
            args,
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
    });

    it("counts UTF-8 string-value bytes toward maxInputBytes", () => {
      const args = compliantArgs();
      const error = expectViolation(
        () =>
          createGuard({ resourceLimits: { maxInputBytes: 50 } }).validateToolCall(
            toolCallPayload(args, { blob: "é".repeat(40) }),
            args,
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
      expect(error.rule).toBe("maxInputBytes");
    });

    it("counts object-key bytes toward maxInputBytes", () => {
      const args = compliantArgs();
      const meta: Record<string, unknown> = {};
      meta["é".repeat(40)] = 1;
      const error = expectViolation(
        () =>
          createGuard({ resourceLimits: { maxInputBytes: 50 } }).validateToolCall(
            toolCallPayload(args, meta),
            args,
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
      expect(error.rule).toBe("maxInputBytes");
    });

    it("does not charge numbers or booleans toward maxInputBytes", () => {
      const args = compliantArgs();
      expect(() =>
        createGuard({ resourceLimits: { maxInputBytes: 10_000 } }).validateToolCall(
          toolCallPayload(args, { n: 1234567890, flag: true, none: null }),
          args,
        ),
      ).not.toThrow();
    });

    it("accepts maxInputBytes at the exact passing boundary and rejects one extra string byte", () => {
      const args = compliantArgs();
      const payload = toolCallPayload(args, { blob: "x" });
      let limit = 1;
      let passed = false;
      while (limit < 10_000) {
        try {
          createGuard({ resourceLimits: { maxInputBytes: limit } }).validateToolCall(payload, args);
          passed = true;
          break;
        } catch {
          limit += 1;
        }
      }
      expect(passed).toBe(true);
      expect(() =>
        createGuard({ resourceLimits: { maxInputBytes: limit } }).validateToolCall(payload, args),
      ).not.toThrow();
      expectViolation(
        () =>
          createGuard({ resourceLimits: { maxInputBytes: limit } }).validateToolCall(
            toolCallPayload(args, { blob: "xy" }),
            args,
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
    });

    it("enforces maxArrayLength", () => {
      const args = compliantArgs();
      const meta = { items: [1, 2, 3] };
      expectViolation(
        () =>
          createGuard({ resourceLimits: { maxArrayLength: 2 } }).validateToolCall(
            toolCallPayload(args, meta),
            args,
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
    });

    it("enforces maxObjectProperties", () => {
      const args = compliantArgs();
      const meta = { a: 1, b: 2, c: 3, d: 4, e: 5 };
      expectViolation(
        () =>
          createGuard({ resourceLimits: { maxObjectProperties: 4 } }).validateToolCall(
            toolCallPayload(args, meta),
            args,
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
    });

    it("rejects invalid constructor limit overrides", () => {
      expectViolation(
        () =>
          new GuwahGuard({
            policyPath,
            resourceLimits: { maxInputDepth: 0 },
          }),
        "INVALID_PAYLOAD",
      );
    });
  });

  describe("immutability and errors", () => {
    it("leaves the original payload unchanged", () => {
      const args = compliantArgs();
      const payload = toolCallPayload(args, { progressToken: "tok" });
      const snapshot = structuredClone(payload);
      createGuard().validateToolCall(payload, args);
      expect(payload).toEqual(snapshot);
    });

    it("leaves the original arguments unchanged", () => {
      const args = compliantArgs();
      const snapshot = structuredClone(args);
      createGuard().validateToolCall(toolCallPayload(args), args);
      expect(args).toEqual(snapshot);
    });

    it("returns a different approved payload object", () => {
      const args = compliantArgs();
      const payload = toolCallPayload(args);
      const approved = createGuard().validateToolCall(payload, args);
      expect(approved).not.toBe(payload);
    });

    it("does not share approved arguments with either input", () => {
      const args = compliantArgs();
      const payload = toolCallPayload(args);
      const approved = createGuard().validateToolCall(payload, args);
      expect(approved.params.arguments).not.toBe(args);
      expect(approved.params.arguments).not.toBe(
        (payload["params"] as Record<string, unknown>)["arguments"],
      );
    });

    it("deep-freezes the approved payload graph", () => {
      const args = compliantArgs();
      const payload = toolCallPayload(args, { progressToken: "tok", nested: { n: 1 } });
      const approved = createGuard().validateToolCall(payload, args);
      expect(Object.isFrozen(approved)).toBe(true);
      expect(Object.isFrozen(approved.params)).toBe(true);
      expect(Object.isFrozen(approved.params.arguments)).toBe(true);
      expect(Object.isFrozen(approved.params._meta)).toBe(true);
      expect(Object.isFrozen(approved.params._meta?.["nested"])).toBe(true);
    });

    it("rejects mutation of the approved value", () => {
      const approved = createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs());
      expect(() => {
        (approved as { id: string }).id = "mutated";
      }).toThrow(TypeError);
    });

    it("omits rejected values from public error serialization", () => {
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        destinationAddress: NON_WHITELISTED_DESTINATION,
        memo: MALICIOUS_MEMO,
      };
      const error = expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(args), args),
        "ARGUMENT_VALIDATION_FAILED",
      );
      const publicSurface = enumerableSnapshot(error);
      expect(publicSurface).not.toContain(NON_WHITELISTED_DESTINATION);
      expect(publicSurface).not.toContain(MALICIOUS_MEMO);
      expect(publicSurface).not.toContain("DROP TABLE");
    });

    it("normalizes unexpected internal failures", () => {
      const instance = createGuard();
      (instance as unknown as { loadCompiledPolicy: () => never }).loadCompiledPolicy = () => {
        throw new Error("C:\\\\secret\\\\wallet.json");
      };
      const error = expectViolation(
        () => instance.validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "INTERNAL_VALIDATION_ERROR",
      );
      expect(error.message).not.toContain("wallet.json");
      expect(enumerableSnapshot(error)).not.toContain("wallet.json");
    });
  });

  describe("policy graph limits", () => {
    it("rejects a deeply nested policy schema", () => {
      let nested: Record<string, unknown> = { type: "string" };
      for (let index = 0; index < 20; index += 1) {
        nested = { type: "array", items: nested };
      }
      writeFileSync(
        policyPath,
        JSON.stringify({
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            t: {
              action: "ENFORCE",
              argsSchema: {
                type: "object",
                additionalProperties: false,
                properties: { nest: nested },
              },
            },
          },
        }),
        "utf8",
      );
      const error = expectViolation(
        () =>
          createGuard({ resourceLimits: { maxPolicyDepth: 8 } }).validateToolCall(
            toolCallPayload(compliantArgs()),
            compliantArgs(),
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
      expect(error.rule).toBe("maxPolicyDepth");
      expect(error.message).toBe("Local policy exceeds configured resource limits.");
    });

    it("rejects excessive policy node count", () => {
      const error = expectViolation(
        () =>
          createGuard({ resourceLimits: { maxPolicyNodes: 9 } }).validateToolCall(
            toolCallPayload(compliantArgs()),
            compliantArgs(),
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
      expect(error.rule).toBe("maxPolicyNodes");
    });

    it("rejects excessive properties in a policy object", () => {
      const properties: Record<string, unknown> = {};
      for (let index = 0; index < 6; index += 1) {
        properties[`f${index}`] = { type: "string" };
      }
      writeFileSync(
        policyPath,
        JSON.stringify({
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            t: {
              action: "ENFORCE",
              argsSchema: {
                type: "object",
                additionalProperties: false,
                properties,
              },
            },
          },
        }),
        "utf8",
      );
      const error = expectViolation(
        () =>
          createGuard({ resourceLimits: { maxPolicyObjectProperties: 5 } }).validateToolCall(
            toolCallPayload(compliantArgs()),
            compliantArgs(),
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
      expect(error.rule).toBe("maxPolicyObjectProperties");
    });

    it("rejects excessive policy array length", () => {
      writeFileSync(
        policyPath,
        JSON.stringify({
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            t: {
              action: "ENFORCE",
              argsSchema: {
                type: "object",
                additionalProperties: false,
                required: ["a", "b", "c", "d"],
                properties: {
                  a: { type: "string" },
                  b: { type: "string" },
                  c: { type: "string" },
                  d: { type: "string" },
                },
              },
            },
          },
        }),
        "utf8",
      );
      const error = expectViolation(
        () =>
          createGuard({ resourceLimits: { maxPolicyArrayLength: 3 } }).validateToolCall(
            toolCallPayload(compliantArgs()),
            compliantArgs(),
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
      expect(error.rule).toBe("maxPolicyArrayLength");
    });

    it("accepts a policy at exact structural maxima", () => {
      writeFileSync(policyPath, JSON.stringify(minimalPolicy()), "utf8");
      const instance = new GuwahGuard({
        policyPath,
        resourceLimits: {
          maxPolicyDepth: 5,
          maxPolicyNodes: 10,
          maxPolicyObjectProperties: 3,
        },
      });
      const payload = {
        jsonrpc: "2.0",
        id: "req-1",
        method: "tools/call",
        params: { name: "t", arguments: {} },
      };
      expect(instance.validateToolCall(payload, {})).toMatchObject({ method: "tools/call" });
    });

    it("invalidates cache after a valid policy is replaced by a structurally excessive policy", () => {
      writeFileSync(policyPath, JSON.stringify(minimalPolicy()), "utf8");
      const instance = new GuwahGuard({
        policyPath,
        resourceLimits: { maxPolicyNodes: 10 },
      });
      instance.validateToolCall(
        {
          jsonrpc: "2.0",
          id: "req-1",
          method: "tools/call",
          params: { name: "t", arguments: {} },
        },
        {},
      );
      writeFileSync(policyPath, JSON.stringify(transferPolicy()), "utf8");
      const error = expectViolation(
        () => instance.validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "RESOURCE_LIMIT_EXCEEDED",
      );
      expect(error.rule).toBe("maxPolicyNodes");
    });
  });

  describe("schema patterns", () => {
    function expectPattern(pattern: string, code: GuwahViolationCode): void {
      writeFileSync(
        policyPath,
        JSON.stringify(
          patchToolSchema((schema) => {
            const properties = schema["properties"] as { memo: Record<string, unknown> };
            properties.memo["pattern"] = pattern;
          }),
        ),
        "utf8",
      );
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        code,
      );
    }

    function expectAcceptedMemoPattern(pattern: string, memo: string): void {
      writeFileSync(
        policyPath,
        JSON.stringify(
          patchToolSchema((schema) => {
            const properties = schema["properties"] as { memo: Record<string, unknown> };
            properties.memo["pattern"] = pattern;
          }),
        ),
        "utf8",
      );
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        memo,
      };
      expect(createGuard().validateToolCall(toolCallPayload(args), args).params.arguments).toEqual(args);
    }

    it("accepts both shipped sample patterns", () => {
      expect(() =>
        createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
      ).not.toThrow();
    });

    it("accepts multiple exact fixed-width quantifiers", () => {
      expectAcceptedMemoPattern("^a{2}b{3}$", "aabbb");
    });

    it("accepts a single variable-width quantifier between literals", () => {
      expectAcceptedMemoPattern("^prefix[a-z]+suffix$", "prefixabcsuffix");
    });

    it("accepts exact fixed-width boundary quantifiers", () => {
      expectAcceptedMemoPattern("^x{0}y$", "y");
      expectPattern(`^a{${String(Number.MAX_SAFE_INTEGER)}}$`, "ARGUMENT_VALIDATION_FAILED");
    });

    it("rejects nested quantifiers", () => {
      expectPattern("^a++$", "POLICY_INVALID");
    });

    it("rejects sequential variable-width quantifiers", () => {
      expectPattern("^a*a*$", "POLICY_INVALID");
      expectPattern("^[a-z]*[a-z]*$", "POLICY_INVALID");
      expectPattern("^a?a?a?a?a?$", "POLICY_INVALID");
      expectPattern("^a{1,8}a{1,8}$", "POLICY_INVALID");
    });

    it("rejects inverted braced quantifier bounds", () => {
      expectPattern("^a{8,1}$", "POLICY_INVALID");
    });

    it("rejects a malformed braced quantifier comma", () => {
      expectPattern("^a{1,,8}$", "POLICY_INVALID");
    });

    it("rejects a braced quantifier exceeding a safe integer", () => {
      expectPattern(`^a{${String(Number.MAX_SAFE_INTEGER + 1)}}$`, "POLICY_INVALID");
    });

    it("rejects grouped nested quantifiers", () => {
      expectPattern("^(a+)+$", "POLICY_INVALID");
    });

    it("rejects alternation", () => {
      expectPattern("^ab|cd$", "POLICY_INVALID");
    });

    it("rejects lookaround", () => {
      expectPattern("^(?=a).*$", "POLICY_INVALID");
    });

    it("rejects backreferences", () => {
      expectPattern("^a\\1$", "POLICY_INVALID");
    });

    it("rejects unanchored patterns", () => {
      expectPattern("abc", "POLICY_INVALID");
    });

    it("rejects wildcard use", () => {
      expectPattern("^a.*$", "POLICY_INVALID");
    });

    it("rejects malformed character classes", () => {
      expectPattern("^[a-$", "POLICY_INVALID");
    });

    it("rejects excessive pattern length", () => {
      writeFileSync(
        policyPath,
        JSON.stringify(
          patchToolSchema((schema) => {
            const properties = schema["properties"] as { memo: Record<string, unknown> };
            properties.memo["pattern"] = `^${"a".repeat(20)}$`;
          }),
        ),
        "utf8",
      );
      const error = expectViolation(
        () =>
          createGuard({ resourceLimits: { maxPatternLength: 8 } }).validateToolCall(
            toolCallPayload(compliantArgs()),
            compliantArgs(),
          ),
        "POLICY_INVALID",
      );
      expect(error.rule).toBe("maxPatternLength");
    });

    it("accepts an escaped literal metacharacter", () => {
      writeFileSync(
        policyPath,
        JSON.stringify(
          patchToolSchema((schema) => {
            const properties = schema["properties"] as { memo: Record<string, unknown> };
            properties.memo["pattern"] = "^invoice\\.1001$";
          }),
        ),
        "utf8",
      );
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        memo: "invoice.1001",
      };
      expect(createGuard().validateToolCall(toolCallPayload(args), args).params.arguments).toEqual(args);
    });

    it("accepts a memo at the configured maximum string length", () => {
      const args: Record<string, unknown> = {
        ...compliantArgs(),
        memo: "a".repeat(80),
      };
      expect(createGuard().validateToolCall(toolCallPayload(args), args).params.arguments).toEqual(args);
    });
  });

  describe("numeric bound combinations", () => {
    const invalid: Array<{ name: string; bounds: Record<string, number>; type?: "integer" | "number" }> = [
      { name: "minimum greater than maximum", bounds: { minimum: 10, maximum: 1 } },
      { name: "minimum equals exclusiveMaximum", bounds: { minimum: 10, exclusiveMaximum: 10 } },
      { name: "minimum above exclusiveMaximum", bounds: { minimum: 10, exclusiveMaximum: 5 } },
      { name: "exclusiveMinimum equals maximum", bounds: { exclusiveMinimum: 10, maximum: 10 } },
      { name: "exclusiveMinimum above maximum", bounds: { exclusiveMinimum: 20, maximum: 10 } },
      {
        name: "integer interval with no integer",
        bounds: { exclusiveMinimum: 0, exclusiveMaximum: 1 },
        type: "integer",
      },
      {
        name: "integer ceil/floor empty interval",
        bounds: { minimum: 1.5, maximum: 1.5 },
        type: "integer",
      },
    ];

    for (const row of invalid) {
      it(`rejects ${row.name}`, () => {
        writeFileSync(
          policyPath,
          JSON.stringify(
            patchToolSchema((schema) => {
              const properties = schema["properties"] as { amountMinor: Record<string, unknown> };
              delete properties.amountMinor["minimum"];
              delete properties.amountMinor["maximum"];
              if (row.type !== undefined) {
                properties.amountMinor["type"] = row.type;
              }
              Object.assign(properties.amountMinor, row.bounds);
            }),
          ),
          "utf8",
        );
        expectViolation(
          () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
          "POLICY_INVALID",
        );
      });
    }

    const valid: Array<{ name: string; bounds: Record<string, number> }> = [
      { name: "inclusive equality", bounds: { minimum: 5000, maximum: 5000 } },
      { name: "exclusive interior", bounds: { exclusiveMinimum: 1, exclusiveMaximum: 5001 } },
      { name: "mixed inclusive bounds", bounds: { minimum: 1, exclusiveMaximum: 5001 } },
    ];

    for (const row of valid) {
      it(`accepts ${row.name}`, () => {
        writeFileSync(
          policyPath,
          JSON.stringify(
            patchToolSchema((schema) => {
              const properties = schema["properties"] as { amountMinor: Record<string, unknown> };
              delete properties.amountMinor["minimum"];
              delete properties.amountMinor["maximum"];
              Object.assign(properties.amountMinor, row.bounds);
            }),
          ),
          "utf8",
        );
        const args = compliantArgs();
        expect(createGuard().validateToolCall(toolCallPayload(args), args).params.arguments).toEqual(args);
      });
    }
  });

  describe("policy file reads", () => {
    beforeEach(async () => {
      const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
      vi.mocked(nodeFs.readSync).mockReset();
      vi.mocked(nodeFs.fstatSync).mockReset();
      vi.mocked(nodeFs.closeSync).mockReset();
      vi.mocked(nodeFs.readSync).mockImplementation(actual.readSync);
      vi.mocked(nodeFs.fstatSync).mockImplementation(actual.fstatSync);
      vi.mocked(nodeFs.closeSync).mockImplementation(actual.closeSync);
    });

    it("fails closed on an empty policy file", () => {
      writeFileSync(policyPath, Buffer.alloc(0));
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
    });

    it("assembles a file from multiple short reads", async () => {
      const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
      vi.mocked(nodeFs.readSync).mockImplementation(((
        fd: number,
        buffer: NodeJS.ArrayBufferView,
        offset?: number,
        length?: number,
        position?: number | bigint | null,
      ) => {
        if (typeof offset !== "number" || typeof length !== "number") {
          return actual.readSync(fd, buffer);
        }
        return actual.readSync(fd, buffer, offset, Math.min(3, length), position ?? null);
      }) as typeof nodeFs.readSync);
      const args = compliantArgs();
      expect(createGuard().validateToolCall(toolCallPayload(args), args).params.arguments).toEqual(args);
      expect(nodeFs.closeSync).toHaveBeenCalledTimes(1);
    });

    it("handles zero-byte EOF", () => {
      vi.mocked(nodeFs.readSync).mockReturnValue(0);
      expectViolation(
        () => createGuard().validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_INVALID",
      );
      expect(nodeFs.closeSync).toHaveBeenCalledTimes(1);
    });

    it("accepts a snapshot that is exactly maxPolicyBytes", async () => {
      const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
      vi.mocked(nodeFs.readSync).mockImplementation(((
        fd: number,
        buffer: NodeJS.ArrayBufferView,
        offset?: number,
        length?: number,
        position?: number | bigint | null,
      ) => {
        if (typeof offset !== "number" || typeof length !== "number") {
          return actual.readSync(fd, buffer);
        }
        return actual.readSync(fd, buffer, offset, Math.min(2, length), position ?? null);
      }) as typeof nodeFs.readSync);
      const policyBytes = nodeFs.readFileSync(policyPath);
      const args = compliantArgs();
      expect(
        createGuard({ resourceLimits: { maxPolicyBytes: policyBytes.length } }).validateToolCall(
          toolCallPayload(args),
          args,
        ).params.arguments,
      ).toEqual(args);
    });

    it("rejects observed content beyond maxPolicyBytes even when stat size is low", async () => {
      const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
      vi.mocked(nodeFs.fstatSync).mockImplementation(((fd: number) => {
        const stats = actual.fstatSync(fd);
        Object.defineProperty(stats, "size", { configurable: true, value: 8 });
        return stats;
      }) as typeof nodeFs.fstatSync);
      const error = expectViolation(
        () =>
          createGuard({ resourceLimits: { maxPolicyBytes: 8 } }).validateToolCall(
            toolCallPayload(compliantArgs()),
            compliantArgs(),
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
      expect(error.rule).toBe("maxPolicyBytes");
      expect(nodeFs.closeSync).toHaveBeenCalledTimes(1);
    });

    it("closes the descriptor after a validation failure", async () => {
      const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
      vi.mocked(nodeFs.fstatSync).mockImplementation(((fd: number) => {
        const stats = actual.fstatSync(fd);
        Object.defineProperty(stats, "size", { configurable: true, value: 100 });
        return stats;
      }) as typeof nodeFs.fstatSync);
      expectViolation(
        () =>
          createGuard({ resourceLimits: { maxPolicyBytes: 2 } }).validateToolCall(
            toolCallPayload(compliantArgs()),
            compliantArgs(),
          ),
        "RESOURCE_LIMIT_EXCEEDED",
      );
      expect(nodeFs.closeSync).toHaveBeenCalledTimes(1);
    });
  });

  describe("active policy location", () => {
    const locationDirs: string[] = [];

    afterEach(() => {
      for (const dir of locationDirs.splice(0, locationDirs.length)) {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("resolves active policy under an injected config base directory", () => {
      const configBaseDir = mkdtempSync(path.join(tmpdir(), "guwah-config-base-"));
      locationDirs.push(configBaseDir);
      const resolved = resolveGuwahActivePolicyPath({ configBaseDir });
      expect(path.isAbsolute(resolved)).toBe(true);
      expect(resolved).toBe(
        path.resolve(configBaseDir, GUWAH_ACTIVE_POLICY_SUBDIR, GUWAH_ACTIVE_POLICY_FILENAME),
      );
      expect(isGuwahPathInsideRoot(resolved, configBaseDir)).toBe(true);
    });

    it("rejects an empty injected config base directory", () => {
      expect(() => resolveGuwahActivePolicyPath({ configBaseDir: "" })).toThrow(
        /config base directory is required/i,
      );
      expect(() => resolveGuwahActivePolicyPath({ configBaseDir: "   " })).toThrow(
        /config base directory is required/i,
      );
    });

    it("keeps the active policy outside a replaced bundle tree", () => {
      const root = mkdtempSync(path.join(tmpdir(), "guwah-bundle-upgrade-"));
      locationDirs.push(root);
      const bundleRoot = path.join(root, "mcpb-unpack");
      const configBaseDir = path.join(root, "user-config");
      mkdirSync(bundleRoot, { recursive: true });
      mkdirSync(configBaseDir, { recursive: true });

      const bundleSamplePath = path.join(bundleRoot, GUWAH_ACTIVE_POLICY_FILENAME);
      writeFileSync(bundleSamplePath, `${JSON.stringify(transferPolicy(), null, 2)}\n`, "utf8");

      const activePath = resolveGuwahActivePolicyPath({ configBaseDir });
      mkdirSync(path.dirname(activePath), { recursive: true });
      const activeDocument = `${JSON.stringify(
        {
          ...transferPolicy(),
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: {
                ...TRANSFER_SCHEMA,
                properties: {
                  ...TRANSFER_SCHEMA.properties,
                  amountMinor: { type: "integer", minimum: 1, maximum: 2500 },
                },
              },
            },
          },
        },
        null,
        2,
      )}\n`;
      writeFileSync(activePath, activeDocument, "utf8");

      expect(isGuwahPathInsideRoot(activePath, bundleRoot)).toBe(false);
      expect(isGuwahPathInsideRoot(activePath, configBaseDir)).toBe(true);

      // Simulate a bundle upgrade that replaces unpack contents, including the sample.
      rmSync(bundleRoot, { recursive: true, force: true });
      mkdirSync(bundleRoot, { recursive: true });
      writeFileSync(
        path.join(bundleRoot, GUWAH_ACTIVE_POLICY_FILENAME),
        `${JSON.stringify({ version: "1.0.0", posture: "default-deny", tools: {} }, null, 2)}\n`,
        "utf8",
      );

      expect(readFileSync(activePath, "utf8")).toBe(activeDocument);
      expect(isGuwahPathInsideRoot(activePath, bundleRoot)).toBe(false);

      const guard = new GuwahGuard({ configBaseDir });
      expect(guard.getActivePolicyPath()).toBe(activePath);
      const args = {
        amountMinor: 2500,
        assetId: "USDC",
        destinationAddress: WHITELISTED_DESTINATION,
        memo: "invoice 1001",
      };
      expect(guard.validateToolCall(toolCallPayload(args), args).params.arguments).toEqual(args);
    });

    it("fails closed when the active policy file is missing under the config base", () => {
      const configBaseDir = mkdtempSync(path.join(tmpdir(), "guwah-missing-active-"));
      locationDirs.push(configBaseDir);
      const instance = new GuwahGuard({ configBaseDir });
      expect(isGuwahPathInsideRoot(instance.getActivePolicyPath(), configBaseDir)).toBe(true);
      expectViolation(
        () => instance.validateToolCall(toolCallPayload(compliantArgs()), compliantArgs()),
        "POLICY_UNAVAILABLE",
      );
    });

    it("does not default the active policy path into process.cwd()", () => {
      if (process.platform !== "win32" && process.platform !== "darwin") {
        expect(() => new GuwahGuard()).toThrow(GUWAH_USER_CONFIG_DIR_UNAVAILABLE);
        return;
      }
      const instance = new GuwahGuard();
      const activePath = instance.getActivePolicyPath();
      const configBase = resolveGuwahUserConfigBaseDir();
      expect(path.isAbsolute(activePath)).toBe(true);
      expect(isGuwahPathInsideRoot(activePath, process.cwd())).toBe(false);
      expect(activePath).toBe(resolveGuwahActivePolicyPath({ configBaseDir: configBase }));
      expect(activePath).not.toBe(path.resolve(process.cwd(), GUWAH_ACTIVE_POLICY_FILENAME));
    });
  });

  describe("platform user configuration directories", () => {
    it("resolves Windows APPDATA as an absolute non-bundle config base", () => {
      const injectedAppData = path.resolve(
        path.join(tmpdir(), "guwah-win-appdata-", String(process.pid)),
        "Roaming",
      );
      const resolved = resolveGuwahUserConfigBaseDir({
        platform: "win32",
        env: { APPDATA: injectedAppData },
        tmpdir: path.join(tmpdir(), "guwah-win-tmp-elsewhere"),
      });
      expect(path.isAbsolute(resolved)).toBe(true);
      expect(resolved).toBe(path.resolve(injectedAppData));
      expect(isGuwahPathInsideRoot(resolved, process.cwd())).toBe(false);
      const activePath = resolveGuwahActivePolicyPath({ configBaseDir: resolved });
      expect(isGuwahPathInsideRoot(activePath, process.cwd())).toBe(false);
    });

    it("resolves macOS Application Support under the injected home directory", () => {
      const injectedHome = path.resolve(
        path.join(tmpdir(), "guwah-mac-home-", String(process.pid)),
      );
      const resolved = resolveGuwahUserConfigBaseDir({
        platform: "darwin",
        homedir: injectedHome,
        tmpdir: path.join(tmpdir(), "guwah-mac-tmp-elsewhere"),
      });
      expect(path.isAbsolute(resolved)).toBe(true);
      expect(resolved).toBe(path.resolve(injectedHome, "Library", "Application Support"));
      expect(isGuwahPathInsideRoot(resolved, process.cwd())).toBe(false);
      const activePath = resolveGuwahActivePolicyPath({ configBaseDir: resolved });
      expect(activePath).toBe(
        path.resolve(
          injectedHome,
          "Library",
          "Application Support",
          GUWAH_ACTIVE_POLICY_SUBDIR,
          GUWAH_ACTIVE_POLICY_FILENAME,
        ),
      );
    });

    it("fails closed on unknown platforms instead of using tmp policy roots", () => {
      const ephemeral = path.resolve(tmpdir(), "guwah-unknown-tmp");
      expect(() =>
        resolveGuwahUserConfigBaseDir({
          platform: "linux",
          tmpdir: ephemeral,
          env: { TMPDIR: ephemeral, XDG_CONFIG_HOME: ephemeral },
          homedir: path.join(ephemeral, "home"),
        }),
      ).toThrow(GUWAH_USER_CONFIG_DIR_UNAVAILABLE);
      expect(() =>
        resolveGuwahUserConfigBaseDir({
          platform: "freebsd",
          tmpdir: ephemeral,
        }),
      ).toThrow(GUWAH_USER_CONFIG_DIR_UNAVAILABLE);
    });

    it("fails closed when Windows APPDATA is missing or ephemeral", () => {
      expect(() =>
        resolveGuwahUserConfigBaseDir({
          platform: "win32",
          env: {},
        }),
      ).toThrow(GUWAH_USER_CONFIG_DIR_UNAVAILABLE);
      expect(() =>
        resolveGuwahUserConfigBaseDir({
          platform: "win32",
          env: { APPDATA: "   " },
        }),
      ).toThrow(GUWAH_USER_CONFIG_DIR_UNAVAILABLE);

      const ephemeralRoot = path.resolve(tmpdir(), "guwah-appdata-in-tmp");
      expect(() =>
        resolveGuwahUserConfigBaseDir({
          platform: "win32",
          env: { APPDATA: path.join(ephemeralRoot, "Roaming") },
          tmpdir: ephemeralRoot,
        }),
      ).toThrow(GUWAH_USER_CONFIG_DIR_UNAVAILABLE);
    });

    it("fails closed when macOS home is missing or resolves under tmp", () => {
      expect(() =>
        resolveGuwahUserConfigBaseDir({
          platform: "darwin",
          homedir: "",
        }),
      ).toThrow(GUWAH_USER_CONFIG_DIR_UNAVAILABLE);

      const ephemeralRoot = path.resolve(tmpdir(), "guwah-mac-home-in-tmp");
      expect(() =>
        resolveGuwahUserConfigBaseDir({
          platform: "darwin",
          homedir: path.join(ephemeralRoot, "Users", "demo"),
          tmpdir: ephemeralRoot,
        }),
      ).toThrow(GUWAH_USER_CONFIG_DIR_UNAVAILABLE);
    });

    it("uses the live Windows config base when running on win32", () => {
      if (process.platform !== "win32") {
        return;
      }
      const resolved = resolveGuwahUserConfigBaseDir();
      expect(path.isAbsolute(resolved)).toBe(true);
      expect(resolved).toBe(path.resolve(String(process.env["APPDATA"])));
      expect(isGuwahPathInsideRoot(resolved, process.cwd())).toBe(false);
      expect(isGuwahPathInsideRoot(resolved, tmpdir())).toBe(false);
    });

    it("uses the live macOS Application Support base when running on darwin", () => {
      if (process.platform !== "darwin") {
        return;
      }
      const resolved = resolveGuwahUserConfigBaseDir();
      expect(path.isAbsolute(resolved)).toBe(true);
      expect(resolved).toBe(path.resolve(homedir(), "Library", "Application Support"));
      expect(isGuwahPathInsideRoot(resolved, process.cwd())).toBe(false);
      expect(isGuwahPathInsideRoot(resolved, tmpdir())).toBe(false);
    });
  });

  describe("first-run policy provisioning", () => {
    const provisionDirs: string[] = [];

    afterEach(() => {
      vi.restoreAllMocks();
      for (const dir of provisionDirs.splice(0, provisionDirs.length)) {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("creates a valid active policy from the sample on first run", () => {
      const configBaseDir = mkdtempSync(path.join(tmpdir(), "guwah-provision-first-"));
      provisionDirs.push(configBaseDir);
      const samplePolicyPath = resolveGuwahPackagedSamplePolicyPath();
      expect(nodeFs.existsSync(samplePolicyPath)).toBe(true);

      const result = provisionGuwahActivePolicy({ configBaseDir, samplePolicyPath });
      expect(result.created).toBe(true);
      expect(result.policyPath).toBe(resolveGuwahActivePolicyPath({ configBaseDir }));
      expect(nodeFs.existsSync(result.policyPath)).toBe(true);

      const guard = new GuwahGuard({ policyPath: result.policyPath });
      const args = compliantArgs();
      expect(guard.validateToolCall(toolCallPayload(args), args).params.arguments).toEqual(args);
    });

    it("does not overwrite an existing active policy on second run", () => {
      const configBaseDir = mkdtempSync(path.join(tmpdir(), "guwah-provision-second-"));
      provisionDirs.push(configBaseDir);
      const samplePolicyPath = resolveGuwahPackagedSamplePolicyPath();
      const first = provisionGuwahActivePolicy({ configBaseDir, samplePolicyPath });
      expect(first.created).toBe(true);

      const customized = `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: {
                ...TRANSFER_SCHEMA,
                properties: {
                  ...TRANSFER_SCHEMA.properties,
                  amountMinor: { type: "integer", minimum: 1, maximum: 100 },
                },
              },
            },
          },
        },
        null,
        2,
      )}\n`;
      writeFileSync(first.policyPath, customized, "utf8");

      const second = provisionGuwahActivePolicy({ configBaseDir, samplePolicyPath });
      expect(second.created).toBe(false);
      expect(second.policyPath).toBe(first.policyPath);
      expect(readFileSync(first.policyPath, "utf8")).toBe(customized);
    });

    it("leaves no active file when the sample cannot be read", () => {
      const configBaseDir = mkdtempSync(path.join(tmpdir(), "guwah-provision-missing-sample-"));
      provisionDirs.push(configBaseDir);
      const activePath = resolveGuwahActivePolicyPath({ configBaseDir });
      const missingSample = path.join(configBaseDir, "missing-sample.json");

      expect(() =>
        provisionGuwahActivePolicy({
          configBaseDir,
          samplePolicyPath: missingSample,
        }),
      ).toThrow(GUWAH_SAMPLE_POLICY_UNAVAILABLE);
      expect(nodeFs.existsSync(activePath)).toBe(false);
    });

    it("removes a half-written destination when exclusive copy fails", () => {
      const configBaseDir = mkdtempSync(path.join(tmpdir(), "guwah-provision-copy-fail-"));
      provisionDirs.push(configBaseDir);
      const samplePolicyPath = resolveGuwahPackagedSamplePolicyPath();
      const activePath = resolveGuwahActivePolicyPath({ configBaseDir });

      const copySpy = vi.spyOn(nodeFs, "copyFileSync").mockImplementation(((
        _src: nodeFs.PathLike,
        dest: nodeFs.PathLike,
      ) => {
        nodeFs.writeFileSync(dest, "{", "utf8");
        const error = new Error("simulated copy failure") as NodeJS.ErrnoException;
        error.code = "EIO";
        throw error;
      }) as typeof nodeFs.copyFileSync);

      expect(() =>
        provisionGuwahActivePolicy({ configBaseDir, samplePolicyPath }),
      ).toThrow(GUWAH_ACTIVE_POLICY_PROVISION_ERROR);
      expect(copySpy).toHaveBeenCalled();
      expect(nodeFs.existsSync(activePath)).toBe(false);

      const leftoverTemps = nodeFs
        .readdirSync(path.join(configBaseDir, GUWAH_ACTIVE_POLICY_SUBDIR), { withFileTypes: true })
        .filter((entry) => entry.isFile() && entry.name.endsWith(".tmp"));
      expect(leftoverTemps).toEqual([]);
    });
  });

  describe("active policy preservation", () => {
    const preserveDirs: string[] = [];

    afterEach(() => {
      for (const dir of preserveDirs.splice(0, preserveDirs.length)) {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("preserves operator edits across restart and sample upgrade without silent tool merge", () => {
      const root = mkdtempSync(path.join(tmpdir(), "guwah-upgrade-preserve-"));
      preserveDirs.push(root);
      const configBaseDir = path.join(root, "user-config");
      const bundleRoot = path.join(root, "package-v1");
      mkdirSync(configBaseDir, { recursive: true });
      mkdirSync(bundleRoot, { recursive: true });

      const sampleV1Path = path.join(bundleRoot, GUWAH_ACTIVE_POLICY_FILENAME);
      const sampleV1 = {
        version: "1.0.0",
        posture: "default-deny",
        tools: {
          [TOOL_NAME]: {
            action: "ENFORCE",
            argsSchema: structuredClone(TRANSFER_SCHEMA),
          },
        },
      };
      writeFileSync(sampleV1Path, `${JSON.stringify(sampleV1, null, 2)}\n`, "utf8");

      const first = provisionGuwahActivePolicy({
        configBaseDir,
        samplePolicyPath: sampleV1Path,
      });
      expect(first.created).toBe(true);

      // Operator edit: tighten the limit and keep only the original tool.
      const operatorEdit = {
        version: "1.0.0",
        posture: "default-deny",
        tools: {
          [TOOL_NAME]: {
            action: "ENFORCE",
            argsSchema: {
              ...TRANSFER_SCHEMA,
              properties: {
                ...TRANSFER_SCHEMA.properties,
                amountMinor: { type: "integer", minimum: 1, maximum: 100 },
              },
            },
          },
        },
      };
      const operatorEditJson = `${JSON.stringify(operatorEdit, null, 2)}\n`;
      writeFileSync(first.policyPath, operatorEditJson, "utf8");

      // Restart: live resolution must reuse the active file without rewriting it.
      const restartedPath = resolveGuwahLivePolicyPath({
        configBaseDir,
        samplePolicyPath: sampleV1Path,
      });
      expect(restartedPath).toBe(first.policyPath);
      expect(readFileSync(first.policyPath, "utf8")).toBe(operatorEditJson);

      // Upgrade: replace the packaged sample with a richer document that adds a tool.
      const upgradedBundle = path.join(root, "package-v2");
      mkdirSync(upgradedBundle, { recursive: true });
      const sampleV2Path = path.join(upgradedBundle, GUWAH_ACTIVE_POLICY_FILENAME);
      const extraToolName = "extra_upgrade_tool";
      const sampleV2 = {
        version: "1.0.0",
        posture: "default-deny",
        tools: {
          [TOOL_NAME]: {
            action: "ENFORCE",
            argsSchema: structuredClone(TRANSFER_SCHEMA),
          },
          [extraToolName]: {
            action: "ENFORCE",
            argsSchema: {
              $schema: "http://json-schema.org/draft-07/schema#",
              type: "object",
              additionalProperties: false,
              properties: {},
            },
          },
        },
      };
      writeFileSync(sampleV2Path, `${JSON.stringify(sampleV2, null, 2)}\n`, "utf8");
      rmSync(bundleRoot, { recursive: true, force: true });

      const afterUpgrade = provisionGuwahActivePolicy({
        configBaseDir,
        samplePolicyPath: sampleV2Path,
      });
      expect(afterUpgrade.created).toBe(false);
      expect(afterUpgrade.policyPath).toBe(first.policyPath);
      expect(readFileSync(first.policyPath, "utf8")).toBe(operatorEditJson);

      const liveAfterUpgrade = resolveGuwahLivePolicyPath({
        configBaseDir,
        samplePolicyPath: sampleV2Path,
      });
      expect(liveAfterUpgrade).toBe(first.policyPath);
      expect(readFileSync(first.policyPath, "utf8")).toBe(operatorEditJson);

      const guard = new GuwahGuard({ policyPath: first.policyPath });
      expect(guard.listEnforcedToolNames()).toEqual([TOOL_NAME]);
      expect(guard.listEnforcedToolNames()).not.toContain(extraToolName);

      const overLimit = { ...compliantArgs(), amountMinor: 5000 };
      expectViolation(
        () => guard.validateToolCall(toolCallPayload(overLimit), overLimit),
        "ARGUMENT_VALIDATION_FAILED",
      );
      expectViolation(
        () =>
          guard.validateToolCall(
            {
              jsonrpc: "2.0",
              id: "req-extra",
              method: "tools/call",
              params: {
                name: extraToolName,
                arguments: {},
              },
            },
            {},
          ),
        "UNAUTHORIZED_TOOL",
      );

      const allowed = { ...compliantArgs(), amountMinor: 100 };
      expect(guard.validateToolCall(toolCallPayload(allowed), allowed).params.arguments).toEqual(
        allowed,
      );
    });
  });

  describe("sample versus active policy", () => {
    const separationDirs: string[] = [];

    afterEach(() => {
      for (const dir of separationDirs.splice(0, separationDirs.length)) {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("resolves live startup to the active path after provisioning, not the packaged sample", () => {
      const configBaseDir = mkdtempSync(path.join(tmpdir(), "guwah-live-active-"));
      separationDirs.push(configBaseDir);
      const samplePolicyPath = resolveGuwahPackagedSamplePolicyPath();
      const livePath = resolveGuwahLivePolicyPath({ configBaseDir, samplePolicyPath });
      const activePath = resolveGuwahActivePolicyPath({ configBaseDir });

      expect(livePath).toBe(activePath);
      expect(livePath).not.toBe(path.resolve(samplePolicyPath));
      expect(nodeFs.existsSync(livePath)).toBe(true);
      expect(isGuwahPathInsideRoot(livePath, configBaseDir)).toBe(true);

      const guard = new GuwahGuard({ policyPath: livePath });
      expect(guard.getActivePolicyPath()).toBe(activePath);
      const args = compliantArgs();
      expect(guard.validateToolCall(toolCallPayload(args), args).params.arguments).toEqual(args);
    });

    it("prefers an existing active file over the packaged sample when both are present", () => {
      const root = mkdtempSync(path.join(tmpdir(), "guwah-sample-vs-active-"));
      separationDirs.push(root);
      const configBaseDir = path.join(root, "user-config");
      const bundleRoot = path.join(root, "package");
      mkdirSync(configBaseDir, { recursive: true });
      mkdirSync(bundleRoot, { recursive: true });

      const samplePolicyPath = path.join(bundleRoot, GUWAH_ACTIVE_POLICY_FILENAME);
      writeFileSync(samplePolicyPath, `${JSON.stringify(transferPolicy(), null, 2)}\n`, "utf8");

      const activePath = resolveGuwahActivePolicyPath({ configBaseDir });
      mkdirSync(path.dirname(activePath), { recursive: true });
      const activeOnly = `${JSON.stringify(
        {
          version: "1.0.0",
          posture: "default-deny",
          tools: {
            [TOOL_NAME]: {
              action: "ENFORCE",
              argsSchema: {
                ...TRANSFER_SCHEMA,
                properties: {
                  ...TRANSFER_SCHEMA.properties,
                  amountMinor: { type: "integer", minimum: 1, maximum: 100 },
                },
              },
            },
          },
        },
        null,
        2,
      )}\n`;
      writeFileSync(activePath, activeOnly, "utf8");

      const livePath = resolveGuwahLivePolicyPath({
        configBaseDir,
        samplePolicyPath,
        policyPath: samplePolicyPath,
      });
      expect(livePath).toBe(activePath);
      expect(livePath).not.toBe(path.resolve(samplePolicyPath));

      const guard = new GuwahGuard({ policyPath: livePath });
      expectViolation(
        () =>
          guard.validateToolCall(
            toolCallPayload({ ...compliantArgs(), amountMinor: 5000 }),
            { ...compliantArgs(), amountMinor: 5000 },
          ),
        "ARGUMENT_VALIDATION_FAILED",
      );
      const args = { ...compliantArgs(), amountMinor: 100 };
      expect(guard.validateToolCall(toolCallPayload(args), args).params.arguments).toEqual(args);
    });
  });
});
