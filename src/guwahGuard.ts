import { createHash } from "node:crypto";
import * as nodeFs from "node:fs";
import path from "node:path";
import AjvImport from "ajv";
import type {
  AnySchemaObject,
  ErrorObject,
  Options,
  ValidateFunction,
} from "ajv";

/**
 * Ajv is published as CommonJS. Under Node16 ESM typings the default import is a
 * namespace, not a construct signature. Narrow it to the methods this guard uses.
 */
interface GuwahAjv {
  compile(schema: AnySchemaObject): ValidateFunction;
}

interface GuwahAjvConstructor {
  new (options?: Options): GuwahAjv;
}

const Ajv = AjvImport as unknown as GuwahAjvConstructor;

/**
 * MCP-compatible JSON-RPC tool-call envelope.
 * Defined locally so this guard stays SDK- and transport-agnostic.
 */
export interface McpToolCallParams {
  readonly name: string;
  readonly arguments?: unknown;
  readonly _meta?: Readonly<Record<string, unknown>>;
}

export interface McpToolCallPayload {
  readonly jsonrpc: "2.0";
  readonly id: string | number;
  readonly method: "tools/call";
  readonly params: McpToolCallParams;
}

/**
 * Constructor-configurable resource limits. Every field is a positive safe integer.
 *
 * `maxInputBytes` counts cumulative UTF-8 bytes of string values and object keys
 * in the candidate payload and argument graphs. It does not count JSON punctuation,
 * numeric representations, booleans, null, or container overhead.
 */
export interface GuwahResourceLimits {
  readonly maxPolicyBytes: number;
  readonly maxPolicyDepth: number;
  readonly maxPolicyNodes: number;
  readonly maxPolicyArrayLength: number;
  readonly maxPolicyObjectProperties: number;
  readonly maxPatternLength: number;
  readonly maxInputDepth: number;
  readonly maxInputNodes: number;
  readonly maxInputBytes: number;
  readonly maxArrayLength: number;
  readonly maxObjectProperties: number;
}

export interface GuwahGuardOptions {
  readonly policyPath?: string;
  readonly resourceLimits?: Partial<GuwahResourceLimits>;
}

export type GuwahViolationCode =
  | "INVALID_PAYLOAD"
  | "POLICY_UNAVAILABLE"
  | "POLICY_INVALID"
  | "UNAUTHORIZED_TOOL"
  | "POLICY_NOT_ENFORCED"
  | "PAYLOAD_MUTATION"
  | "ARGUMENT_VALIDATION_FAILED"
  | "DANGEROUS_OBJECT_KEY"
  | "NON_JSON_VALUE"
  | "RESOURCE_LIMIT_EXCEEDED"
  | "INTERNAL_VALIDATION_ERROR";

export interface GuwahSecurityViolationOptions {
  readonly code: GuwahViolationCode;
  readonly message: string;
  readonly toolName?: string;
  readonly fieldPath?: string;
  readonly rule?: string;
  readonly cause?: unknown;
}

/**
 * Fail-closed security error. Messages must never include secrets, wallet
 * contents, complete payloads, policy contents, or rejected values.
 */
export class GuwahSecurityViolation extends Error {
  public override readonly name = "GuwahSecurityViolation";
  public readonly code: GuwahViolationCode;
  public readonly toolName?: string;
  public readonly fieldPath?: string;
  public readonly rule?: string;

  public constructor(options: GuwahSecurityViolationOptions) {
    super(options.message);
    this.code = options.code;
    if (options.toolName !== undefined) {
      this.toolName = options.toolName;
    }
    if (options.fieldPath !== undefined) {
      this.fieldPath = options.fieldPath;
    }
    if (options.rule !== undefined) {
      this.rule = options.rule;
    }
    if (options.cause !== undefined) {
      Object.defineProperty(this, "cause", {
        value: options.cause,
        enumerable: false,
        configurable: true,
        writable: false,
      });
    }
    Object.setPrototypeOf(this, new.target.prototype);
    if (typeof Error.captureStackTrace === "function") {
      Error.captureStackTrace(this, GuwahSecurityViolation);
    }
  }
}

export const DEFAULT_GUWAH_RESOURCE_LIMITS: GuwahResourceLimits = Object.freeze({
  maxPolicyBytes: 1_048_576,
  maxPolicyDepth: 32,
  maxPolicyNodes: 10_000,
  maxPolicyArrayLength: 1_000,
  maxPolicyObjectProperties: 1_000,
  maxPatternLength: 128,
  maxInputDepth: 32,
  maxInputNodes: 10_000,
  maxInputBytes: 1_048_576,
  maxArrayLength: 10_000,
  maxObjectProperties: 1_000,
});

const SUPPORTED_POLICY_VERSION = "1.0.0";
const REQUIRED_POLICY_POSTURE = "default-deny";
const ENFORCE_ACTION = "ENFORCE";
const DENY_ACTION = "DENY";
const KNOWN_TOOL_ACTIONS = new Set<string>([ENFORCE_ACTION, DENY_ACTION]);
const DEFAULT_POLICY_FILENAME = "guwah-policy.json";
const LOCAL_DRAFT07_SCHEMA_IDS = new Set<string>([
  "http://json-schema.org/draft-07/schema#",
  "http://json-schema.org/draft-07/schema",
]);
const DANGEROUS_OBJECT_KEYS = new Set<string>(["__proto__", "prototype", "constructor"]);
const ALLOWED_PAYLOAD_KEYS = new Set<string>(["jsonrpc", "id", "method", "params"]);
const ALLOWED_PARAMS_KEYS = new Set<string>(["name", "arguments", "_meta"]);
const ALLOWED_SCHEMA_KEYWORDS = new Set<string>([
  "$schema",
  "title",
  "description",
  "type",
  "properties",
  "required",
  "additionalProperties",
  "items",
  "enum",
  "const",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "multipleOf",
  "minLength",
  "maxLength",
  "pattern",
  "minItems",
  "maxItems",
  "uniqueItems",
]);
const OBJECT_TYPE_KEYWORDS = new Set<string>(["properties", "required", "additionalProperties"]);
const ARRAY_TYPE_KEYWORDS = new Set<string>(["items", "minItems", "maxItems", "uniqueItems"]);
const STRING_TYPE_KEYWORDS = new Set<string>(["minLength", "maxLength", "pattern"]);
const NUMBER_TYPE_KEYWORDS = new Set<string>([
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "multipleOf",
]);
const JSON_SCHEMA_TYPES = new Set<string>([
  "object",
  "array",
  "string",
  "integer",
  "number",
  "boolean",
  "null",
]);

interface GuwahToolPolicy {
  readonly action: string;
  readonly argsSchema: Record<string, unknown>;
}

interface GuwahPolicyDocument {
  readonly version: string;
  readonly posture: string;
  readonly tools: Readonly<Record<string, GuwahToolPolicy>>;
}

interface CompiledToolValidator {
  readonly action: string;
  readonly validateArgs: ValidateFunction;
}

interface CompiledPolicyCache {
  readonly digest: string;
  readonly tools: ReadonlyMap<string, CompiledToolValidator>;
}

type JsonWalkFrame =
  | { readonly kind: "enter"; readonly value: unknown; readonly path: string; readonly depth: number }
  | { readonly kind: "leave"; readonly object: object };

const POLICY_DOCUMENT_SCHEMA: AnySchemaObject = {
  $schema: "http://json-schema.org/draft-07/schema#",
  type: "object",
  additionalProperties: false,
  required: ["version", "posture", "tools"],
  properties: {
    version: { type: "string", const: SUPPORTED_POLICY_VERSION },
    posture: { type: "string", const: REQUIRED_POLICY_POSTURE },
    tools: {
      type: "object",
      additionalProperties: {
        type: "object",
        additionalProperties: false,
        required: ["action", "argsSchema"],
        properties: {
          action: { type: "string", enum: [ENFORCE_ACTION, DENY_ACTION] },
          argsSchema: { type: "object" },
        },
      },
    },
  },
};

function createStrictAjv(): GuwahAjv {
  return new Ajv({
    strict: true,
    allErrors: false,
    coerceTypes: false,
    removeAdditional: false,
    useDefaults: false,
    validateSchema: true,
  });
}

function fail(options: GuwahSecurityViolationOptions): never {
  throw new GuwahSecurityViolation(options);
}

function isPlainJsonObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function toJsonPointer(parentPath: string, key: string | number): string {
  const token = String(key).replace(/~/g, "~0").replace(/\//g, "~1");
  return parentPath === "" ? `/${token}` : `${parentPath}/${token}`;
}

function isCanonicalArrayIndex(key: string, length: number): boolean {
  if (!/^(0|[1-9][0-9]*)$/.test(key)) {
    return false;
  }
  const index = Number(key);
  return index < length && String(index) === key;
}

function isEnumerableDataDescriptor(
  descriptor: PropertyDescriptor | undefined,
): descriptor is PropertyDescriptor {
  if (descriptor === undefined) {
    return false;
  }
  if (descriptor.enumerable !== true) {
    return false;
  }
  if (descriptor.get !== undefined || descriptor.set !== undefined) {
    return false;
  }
  return Object.prototype.hasOwnProperty.call(descriptor, "value");
}

function descriptorDataValue(descriptor: PropertyDescriptor): unknown {
  return descriptor.value as unknown;
}

function readEnumerableDataValue(target: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  if (!isEnumerableDataDescriptor(descriptor)) {
    fail({
      code: "NON_JSON_VALUE",
      message: "Input contains a non-JSON runtime value.",
      fieldPath: toJsonPointer("", key),
      rule: "data-descriptor",
    });
  }
  return descriptorDataValue(descriptor);
}

/**
 * Bounded iterative JSON-value gate. Descriptors are inspected before any
 * property value is read so accessors are not invoked.
 */
function assertJsonCompatibleGraph(
  root: unknown,
  rootPath: string,
  limits: GuwahResourceLimits,
): void {
  const stack: JsonWalkFrame[] = [{ kind: "enter", value: root, path: rootPath, depth: 1 }];
  const inPath = new Set<object>();
  let nodes = 0;
  let bytes = 0;

  while (stack.length > 0) {
    const frame = stack.pop();
    if (frame === undefined) {
      break;
    }
    if (frame.kind === "leave") {
      inPath.delete(frame.object);
      continue;
    }

    if (frame.depth > limits.maxInputDepth) {
      fail({
        code: "RESOURCE_LIMIT_EXCEEDED",
        message: "Input exceeds configured resource limits.",
        fieldPath: frame.path === "" ? "/" : frame.path,
        rule: "maxInputDepth",
      });
    }

    const value = frame.value;
    if (value === null || typeof value === "boolean") {
      nodes += 1;
      if (nodes > limits.maxInputNodes) {
        fail({
          code: "RESOURCE_LIMIT_EXCEEDED",
          message: "Input exceeds configured resource limits.",
          fieldPath: frame.path === "" ? "/" : frame.path,
          rule: "maxInputNodes",
        });
      }
      continue;
    }

    if (typeof value === "string") {
      nodes += 1;
      // UTF-8 string-value bytes only; punctuation and numeric forms are not counted.
      bytes += Buffer.byteLength(value, "utf8");
      if (nodes > limits.maxInputNodes || bytes > limits.maxInputBytes) {
        fail({
          code: "RESOURCE_LIMIT_EXCEEDED",
          message: "Input exceeds configured resource limits.",
          fieldPath: frame.path === "" ? "/" : frame.path,
          rule: bytes > limits.maxInputBytes ? "maxInputBytes" : "maxInputNodes",
        });
      }
      continue;
    }

    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        fail({
          code: "NON_JSON_VALUE",
          message: "Input contains a non-JSON runtime value.",
          fieldPath: frame.path === "" ? "/" : frame.path,
          rule: "finite-number",
        });
      }
      nodes += 1;
      if (nodes > limits.maxInputNodes) {
        fail({
          code: "RESOURCE_LIMIT_EXCEEDED",
          message: "Input exceeds configured resource limits.",
          fieldPath: frame.path === "" ? "/" : frame.path,
          rule: "maxInputNodes",
        });
      }
      continue;
    }

    if (
      value === undefined ||
      typeof value === "bigint" ||
      typeof value === "function" ||
      typeof value === "symbol"
    ) {
      fail({
        code: "NON_JSON_VALUE",
        message: "Input contains a non-JSON runtime value.",
        fieldPath: frame.path === "" ? "/" : frame.path,
        rule: "json-type",
      });
    }

    if (typeof value !== "object") {
      fail({
        code: "NON_JSON_VALUE",
        message: "Input contains a non-JSON runtime value.",
        fieldPath: frame.path === "" ? "/" : frame.path,
        rule: "json-type",
      });
    }

    if (inPath.has(value)) {
      fail({
        code: "NON_JSON_VALUE",
        message: "Input contains a non-JSON runtime value.",
        fieldPath: frame.path === "" ? "/" : frame.path,
        rule: "cycle",
      });
    }

    nodes += 1;
    if (nodes > limits.maxInputNodes) {
      fail({
        code: "RESOURCE_LIMIT_EXCEEDED",
        message: "Input exceeds configured resource limits.",
        fieldPath: frame.path === "" ? "/" : frame.path,
        rule: "maxInputNodes",
      });
    }

    const ownKeys = Reflect.ownKeys(value);
    for (const key of ownKeys) {
      if (typeof key === "symbol") {
        fail({
          code: "NON_JSON_VALUE",
          message: "Input contains a non-JSON runtime value.",
          fieldPath: frame.path === "" ? "/" : frame.path,
          rule: "symbol-key",
        });
      }
    }

    inPath.add(value);
    stack.push({ kind: "leave", object: value });

    if (Array.isArray(value)) {
      if (value.length > limits.maxArrayLength) {
        fail({
          code: "RESOURCE_LIMIT_EXCEEDED",
          message: "Input exceeds configured resource limits.",
          fieldPath: frame.path === "" ? "/" : frame.path,
          rule: "maxArrayLength",
        });
      }
      for (const key of ownKeys) {
        if (typeof key !== "string") {
          fail({
            code: "NON_JSON_VALUE",
            message: "Input contains a non-JSON runtime value.",
            fieldPath: frame.path === "" ? "/" : frame.path,
            rule: "symbol-key",
          });
        }
        if (key === "length") {
          continue;
        }
        if (!isCanonicalArrayIndex(key, value.length)) {
          fail({
            code: "NON_JSON_VALUE",
            message: "Input contains a non-JSON runtime value.",
            fieldPath: toJsonPointer(frame.path, key),
            rule: "array-property",
          });
        }
      }
      for (let index = value.length - 1; index >= 0; index -= 1) {
        const indexKey = String(index);
        const descriptor = Object.getOwnPropertyDescriptor(value, indexKey);
        if (!isEnumerableDataDescriptor(descriptor)) {
          fail({
            code: "NON_JSON_VALUE",
            message: "Input contains a non-JSON runtime value.",
            fieldPath: toJsonPointer(frame.path, index),
            rule: "sparse-array",
          });
        }
        stack.push({
          kind: "enter",
          value: descriptorDataValue(descriptor),
          path: toJsonPointer(frame.path, index),
          depth: frame.depth + 1,
        });
      }
      continue;
    }

    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail({
        code: "NON_JSON_VALUE",
        message: "Input contains a non-JSON runtime value.",
        fieldPath: frame.path === "" ? "/" : frame.path,
        rule: "prototype",
      });
    }

    const stringKeys = ownKeys.filter((key): key is string => typeof key === "string");
    if (stringKeys.length > limits.maxObjectProperties) {
      fail({
        code: "RESOURCE_LIMIT_EXCEEDED",
        message: "Input exceeds configured resource limits.",
        fieldPath: frame.path === "" ? "/" : frame.path,
        rule: "maxObjectProperties",
      });
    }

    for (let offset = stringKeys.length - 1; offset >= 0; offset -= 1) {
      const key = stringKeys[offset];
      if (key === undefined) {
        continue;
      }
      bytes += Buffer.byteLength(key, "utf8");
      if (bytes > limits.maxInputBytes) {
        fail({
          code: "RESOURCE_LIMIT_EXCEEDED",
          message: "Input exceeds configured resource limits.",
          fieldPath: toJsonPointer(frame.path, key),
          rule: "maxInputBytes",
        });
      }
      if (DANGEROUS_OBJECT_KEYS.has(key)) {
        fail({
          code: "DANGEROUS_OBJECT_KEY",
          message: "Object graph contains a disallowed key.",
          fieldPath: toJsonPointer(frame.path, key),
          rule: "dangerous-object-key",
        });
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!isEnumerableDataDescriptor(descriptor)) {
        fail({
          code: "NON_JSON_VALUE",
          message: "Input contains a non-JSON runtime value.",
          fieldPath: toJsonPointer(frame.path, key),
          rule: "data-descriptor",
        });
      }
      stack.push({
        kind: "enter",
        value: descriptorDataValue(descriptor),
        path: toJsonPointer(frame.path, key),
        depth: frame.depth + 1,
      });
    }
  }
}

function deepEqualJson(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) {
    return true;
  }
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") {
    return false;
  }
  const leftIsArray = Array.isArray(left);
  const rightIsArray = Array.isArray(right);
  if (leftIsArray !== rightIsArray) {
    return false;
  }
  if (leftIsArray && rightIsArray) {
    if (left.length !== right.length) {
      return false;
    }
    for (let index = 0; index < left.length; index += 1) {
      if (!deepEqualJson(left[index], right[index])) {
        return false;
      }
    }
    return true;
  }
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  if (leftKeys.length !== rightKeys.length) {
    return false;
  }
  for (const key of leftKeys) {
    if (!Object.prototype.hasOwnProperty.call(right, key)) {
      return false;
    }
    if (!deepEqualJson(readEnumerableDataValue(left, key), readEnumerableDataValue(right, key))) {
      return false;
    }
  }
  return true;
}

function deepFreeze<T>(value: T, seen: WeakSet<object>): T {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (seen.has(value)) {
    return value;
  }
  seen.add(value);
  if (!Object.isFrozen(value)) {
    Object.freeze(value);
  }
  if (Array.isArray(value)) {
    for (const entry of value) {
      deepFreeze(entry, seen);
    }
    return value;
  }
  for (const key of Object.keys(value)) {
    deepFreeze(readEnumerableDataValue(value, key), seen);
  }
  return value;
}

function assertAllowedKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  fieldPath: string,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      fail({
        code: "INVALID_PAYLOAD",
        message: "Tool-call envelope contains an unexpected field.",
        fieldPath,
        rule: "envelope-allowlist",
      });
    }
  }
}

function assertMcpToolCallPayload(value: unknown): asserts value is McpToolCallPayload {
  if (!isPlainJsonObject(value)) {
    fail({
      code: "INVALID_PAYLOAD",
      message: "Tool-call payload must be a plain object.",
      rule: "payload-object",
    });
  }
  assertAllowedKeys(value, ALLOWED_PAYLOAD_KEYS, "/");

  if (value["jsonrpc"] !== "2.0") {
    fail({
      code: "INVALID_PAYLOAD",
      message: "Tool-call payload is not a valid MCP tools/call envelope.",
      fieldPath: "/jsonrpc",
      rule: "jsonrpc",
    });
  }

  const id = value["id"];
  const idIsNumber = typeof id === "number";
  const idIsString = typeof id === "string" && id.length > 0;
  if (!idIsNumber && !idIsString) {
    fail({
      code: "INVALID_PAYLOAD",
      message: "Tool-call payload is not a valid MCP tools/call envelope.",
      fieldPath: "/id",
      rule: "id",
    });
  }

  if (value["method"] !== "tools/call") {
    fail({
      code: "INVALID_PAYLOAD",
      message: "Tool-call payload is not a valid MCP tools/call envelope.",
      fieldPath: "/method",
      rule: "method",
    });
  }

  const params: unknown = value["params"];
  if (!isPlainJsonObject(params)) {
    fail({
      code: "INVALID_PAYLOAD",
      message: "Tool-call payload is not a valid MCP tools/call envelope.",
      fieldPath: "/params",
      rule: "params-object",
    });
  }
  assertAllowedKeys(params, ALLOWED_PARAMS_KEYS, "/params");

  const name: unknown = params["name"];
  if (typeof name !== "string" || name.length === 0) {
    fail({
      code: "INVALID_PAYLOAD",
      message: "Tool-call payload is not a valid MCP tools/call envelope.",
      fieldPath: "/params/name",
      rule: "tool-name",
    });
  }

  if (Object.prototype.hasOwnProperty.call(params, "_meta")) {
    const meta: unknown = params["_meta"];
    if (!isPlainJsonObject(meta)) {
      fail({
        code: "INVALID_PAYLOAD",
        message: "Tool-call metadata must be a JSON object.",
        fieldPath: "/params/_meta",
        rule: "params-meta",
      });
    }
  }
}

function asToolPolicy(value: unknown): GuwahToolPolicy | undefined {
  if (!isPlainJsonObject(value)) {
    return undefined;
  }
  const action: unknown = value["action"];
  const argsSchema: unknown = value["argsSchema"];
  if (typeof action !== "string" || !isPlainJsonObject(argsSchema)) {
    return undefined;
  }
  return { action, argsSchema };
}

function firstAjvError(errors: ErrorObject[] | null | undefined): ErrorObject | undefined {
  if (errors === undefined || errors === null) {
    return undefined;
  }
  return errors[0];
}

function throwPolicyInvalid(rule: string, fieldPath?: string): never {
  const message =
    fieldPath === "/version"
      ? "Local policy version is unsupported."
      : "Local policy structure is invalid.";
  if (fieldPath !== undefined) {
    fail({ code: "POLICY_INVALID", message, rule, fieldPath });
  }
  fail({ code: "POLICY_INVALID", message, rule });
}

function assertNonNegativeSafeInteger(value: unknown, fieldPath: string, rule: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throwPolicyInvalid(rule, fieldPath);
  }
  return value;
}

function assertFiniteNumericBound(value: unknown, fieldPath: string, rule: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throwPolicyInvalid(rule, fieldPath);
  }
  return value;
}

function assertJsonLiteral(value: unknown, fieldPath: string): void {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      assertJsonLiteral(value[index], toJsonPointer(fieldPath, index));
    }
    return;
  }
  if (!isPlainJsonObject(value)) {
    throwPolicyInvalid("enum-const", fieldPath);
  }
  for (const key of Object.keys(value)) {
    if (DANGEROUS_OBJECT_KEYS.has(key)) {
      throwPolicyInvalid("dangerous-object-key", toJsonPointer(fieldPath, key));
    }
    assertJsonLiteral(value[key], toJsonPointer(fieldPath, key));
  }
}

function assertKeywordMatchesType(
  keywords: ReadonlySet<string>,
  schemaType: string,
  fieldPath: string,
): void {
  for (const keyword of keywords) {
    if (OBJECT_TYPE_KEYWORDS.has(keyword) && schemaType !== "object") {
      throwPolicyInvalid(keyword, `${fieldPath}/${keyword}`);
    }
    if (ARRAY_TYPE_KEYWORDS.has(keyword) && schemaType !== "array") {
      throwPolicyInvalid(keyword, `${fieldPath}/${keyword}`);
    }
    if (STRING_TYPE_KEYWORDS.has(keyword) && schemaType !== "string") {
      throwPolicyInvalid(keyword, `${fieldPath}/${keyword}`);
    }
    if (
      NUMBER_TYPE_KEYWORDS.has(keyword) &&
      schemaType !== "integer" &&
      schemaType !== "number"
    ) {
      throwPolicyInvalid(keyword, `${fieldPath}/${keyword}`);
    }
  }
}

function numericIntervalIsEmpty(
  schemaType: "integer" | "number",
  minimum: number | undefined,
  maximum: number | undefined,
  exclusiveMinimum: number | undefined,
  exclusiveMaximum: number | undefined,
): boolean {
  if (schemaType === "integer") {
    let lower = Number.NEGATIVE_INFINITY;
    let upper = Number.POSITIVE_INFINITY;
    if (minimum !== undefined) {
      lower = Math.max(lower, Math.ceil(minimum));
    }
    if (exclusiveMinimum !== undefined) {
      lower = Math.max(lower, Math.floor(exclusiveMinimum) + 1);
    }
    if (maximum !== undefined) {
      upper = Math.min(upper, Math.floor(maximum));
    }
    if (exclusiveMaximum !== undefined) {
      upper = Math.min(upper, Math.ceil(exclusiveMaximum) - 1);
    }
    return lower > upper;
  }

  let lower = Number.NEGATIVE_INFINITY;
  let lowerExclusive = false;
  let upper = Number.POSITIVE_INFINITY;
  let upperExclusive = false;
  if (minimum !== undefined) {
    lower = minimum;
    lowerExclusive = false;
  }
  if (exclusiveMinimum !== undefined) {
    if (exclusiveMinimum > lower || (exclusiveMinimum === lower && !lowerExclusive)) {
      lower = exclusiveMinimum;
      lowerExclusive = true;
    } else if (exclusiveMinimum === lower) {
      lowerExclusive = true;
    }
  }
  if (maximum !== undefined) {
    upper = maximum;
    upperExclusive = false;
  }
  if (exclusiveMaximum !== undefined) {
    if (exclusiveMaximum < upper || (exclusiveMaximum === upper && !upperExclusive)) {
      upper = exclusiveMaximum;
      upperExclusive = true;
    } else if (exclusiveMaximum === upper) {
      upperExclusive = true;
    }
  }
  if (lower > upper) {
    return true;
  }
  return lower === upper && (lowerExclusive || upperExclusive);
}

const LINEAR_PATTERN_ESCAPES = new Set<string>([
  "\\",
  "[",
  "]",
  "^",
  "$",
  ".",
  "{",
  "}",
  "(",
  ")",
  "|",
  "+",
  "*",
  "?",
  "-",
]);

function throwUnsafePattern(fieldPath: string): never {
  throwPolicyInvalid("pattern", fieldPath);
}

function consumeSafeDecimal(
  pattern: string,
  start: number,
  end: number,
  fieldPath: string,
): { readonly value: number; readonly nextIndex: number } {
  if (start >= end) {
    throwUnsafePattern(fieldPath);
  }
  const first = pattern[start];
  if (first === undefined || first < "0" || first > "9") {
    throwUnsafePattern(fieldPath);
  }
  let index = start;
  let value = 0;
  while (index < end) {
    const character = pattern[index];
    if (character === undefined || character < "0" || character > "9") {
      break;
    }
    const digit = character.charCodeAt(0) - 48;
    if (value > Math.floor((Number.MAX_SAFE_INTEGER - digit) / 10)) {
      throwUnsafePattern(fieldPath);
    }
    value = value * 10 + digit;
    index += 1;
  }
  return { value, nextIndex: index };
}

function rejectAdjacentQuantifier(next: string | undefined, fieldPath: string): void {
  if (next === "+" || next === "*" || next === "?" || next === "{") {
    throwUnsafePattern(fieldPath);
  }
}

function consumeLinearQuantifier(
  pattern: string,
  start: number,
  end: number,
  fieldPath: string,
): { readonly nextIndex: number; readonly variableWidth: boolean } {
  const marker = pattern[start];
  if (marker === "+" || marker === "*" || marker === "?") {
    rejectAdjacentQuantifier(pattern[start + 1], fieldPath);
    return { nextIndex: start + 1, variableWidth: true };
  }
  if (marker !== "{") {
    throwUnsafePattern(fieldPath);
  }
  let index = start + 1;
  const lower = consumeSafeDecimal(pattern, index, end, fieldPath);
  index = lower.nextIndex;
  if (index >= end) {
    throwUnsafePattern(fieldPath);
  }
  if (pattern[index] === "}") {
    rejectAdjacentQuantifier(pattern[index + 1], fieldPath);
    return { nextIndex: index + 1, variableWidth: false };
  }
  if (pattern[index] !== ",") {
    throwUnsafePattern(fieldPath);
  }
  index += 1;
  if (index >= end) {
    throwUnsafePattern(fieldPath);
  }
  if (pattern[index] === ",") {
    throwUnsafePattern(fieldPath);
  }
  if (pattern[index] === "}") {
    rejectAdjacentQuantifier(pattern[index + 1], fieldPath);
    return { nextIndex: index + 1, variableWidth: true };
  }
  const upper = consumeSafeDecimal(pattern, index, end, fieldPath);
  index = upper.nextIndex;
  if (lower.value > upper.value) {
    throwUnsafePattern(fieldPath);
  }
  if (index >= end || pattern[index] !== "}") {
    throwUnsafePattern(fieldPath);
  }
  rejectAdjacentQuantifier(pattern[index + 1], fieldPath);
  return {
    nextIndex: index + 1,
    variableWidth: upper.value > lower.value,
  };
}

function isAsciiDigit(character: string | undefined): boolean {
  return character !== undefined && character >= "0" && character <= "9";
}

function isAsciiLetter(character: string | undefined): boolean {
  return (
    character !== undefined &&
    ((character >= "a" && character <= "z") || (character >= "A" && character <= "Z"))
  );
}

function rangeIsLinear(start: string, end: string): boolean {
  if (start.length !== 1 || end.length !== 1) {
    return false;
  }
  if (start > end) {
    return false;
  }
  const digitRange = isAsciiDigit(start) && isAsciiDigit(end);
  const lowerRange = start >= "a" && start <= "z" && end >= "a" && end <= "z";
  const upperRange = start >= "A" && start <= "Z" && end >= "A" && end <= "Z";
  return digitRange || lowerRange || upperRange;
}

function consumeLinearCharacterClass(
  pattern: string,
  start: number,
  end: number,
  fieldPath: string,
): number {
  let index = start + 1;
  if (index >= end || pattern[index] === "]" || pattern[index] === "^") {
    throwUnsafePattern(fieldPath);
  }
  while (index < end) {
    const character = pattern[index];
    if (character === undefined) {
      throwUnsafePattern(fieldPath);
    }
    if (character === "]") {
      if (index === start + 1) {
        throwUnsafePattern(fieldPath);
      }
      return index + 1;
    }
    if (character === "[" || character === "\\" || character === "^") {
      throwUnsafePattern(fieldPath);
    }
    const next = pattern[index + 1];
    const after = pattern[index + 2];
    if (next === "-" && after !== undefined && after !== "]") {
      if (!rangeIsLinear(character, after)) {
        throwUnsafePattern(fieldPath);
      }
      index += 3;
      continue;
    }
    index += 1;
  }
  throwUnsafePattern(fieldPath);
}

function consumeLinearEscape(pattern: string, start: number, end: number, fieldPath: string): number {
  if (start + 1 >= end) {
    throwUnsafePattern(fieldPath);
  }
  const escaped = pattern[start + 1];
  if (escaped === undefined || !LINEAR_PATTERN_ESCAPES.has(escaped)) {
    throwUnsafePattern(fieldPath);
  }
  return start + 2;
}

/**
 * Fully anchored concatenation of literals and character classes. At most one
 * variable-width quantifier is admitted; multiple exact `{n}` quantifiers are
 * allowed. Groups, alternation, lookaround, backreferences, wildcards, and
 * adjacent quantifiers are rejected.
 */
function assertLinearSchemaPattern(
  pattern: string,
  maxPatternLength: number,
  fieldPath: string,
): void {
  if (pattern.length > maxPatternLength) {
    throwPolicyInvalid("maxPatternLength", fieldPath);
  }
  if (pattern.length < 2 || pattern[0] !== "^" || pattern[pattern.length - 1] !== "$") {
    throwUnsafePattern(fieldPath);
  }
  let index = 1;
  const end = pattern.length - 1;
  let variableWidthCount = 0;
  while (index < end) {
    const character = pattern[index];
    if (
      character === undefined ||
      character === "(" ||
      character === ")" ||
      character === "|" ||
      character === "." ||
      character === "*" ||
      character === "+" ||
      character === "?" ||
      character === "{" ||
      character === "}" ||
      character === "^" ||
      character === "$"
    ) {
      throwUnsafePattern(fieldPath);
    }
    if (character === "[") {
      index = consumeLinearCharacterClass(pattern, index, end, fieldPath);
    } else if (character === "\\") {
      index = consumeLinearEscape(pattern, index, end, fieldPath);
    } else {
      index += 1;
    }
    const maybeQuantifier = pattern[index];
    if (
      maybeQuantifier === "+" ||
      maybeQuantifier === "*" ||
      maybeQuantifier === "?" ||
      maybeQuantifier === "{"
    ) {
      const quantifier = consumeLinearQuantifier(pattern, index, end, fieldPath);
      if (quantifier.variableWidth) {
        variableWidthCount += 1;
        if (variableWidthCount > 1) {
          throwUnsafePattern(fieldPath);
        }
      }
      index = quantifier.nextIndex;
    }
  }
}

/**
 * Iterative structural bound on the parsed policy graph. JSON.parse already
 * produced JSON-compatible data; this pass only counts and rejects dangerous keys.
 */
function assertPolicyGraphLimits(root: unknown, limits: GuwahResourceLimits): void {
  const stack: Array<{ readonly value: unknown; readonly depth: number; readonly path: string }> = [
    { value: root, depth: 1, path: "" },
  ];
  let nodes = 0;
  while (stack.length > 0) {
    const frame = stack.pop();
    if (frame === undefined) {
      break;
    }
    if (frame.depth > limits.maxPolicyDepth) {
      fail({
        code: "RESOURCE_LIMIT_EXCEEDED",
        message: "Local policy exceeds configured resource limits.",
        fieldPath: frame.path === "" ? "/" : frame.path,
        rule: "maxPolicyDepth",
      });
    }
    nodes += 1;
    if (nodes > limits.maxPolicyNodes) {
      fail({
        code: "RESOURCE_LIMIT_EXCEEDED",
        message: "Local policy exceeds configured resource limits.",
        fieldPath: frame.path === "" ? "/" : frame.path,
        rule: "maxPolicyNodes",
      });
    }
    const value = frame.value;
    if (value === null || typeof value !== "object") {
      continue;
    }
    if (Array.isArray(value)) {
      if (value.length > limits.maxPolicyArrayLength) {
        fail({
          code: "RESOURCE_LIMIT_EXCEEDED",
          message: "Local policy exceeds configured resource limits.",
          fieldPath: frame.path === "" ? "/" : frame.path,
          rule: "maxPolicyArrayLength",
        });
      }
      for (let index = value.length - 1; index >= 0; index -= 1) {
        stack.push({
          value: value[index],
          depth: frame.depth + 1,
          path: toJsonPointer(frame.path, index),
        });
      }
      continue;
    }
    const keys = Object.keys(value);
    if (keys.length > limits.maxPolicyObjectProperties) {
      fail({
        code: "RESOURCE_LIMIT_EXCEEDED",
        message: "Local policy exceeds configured resource limits.",
        fieldPath: frame.path === "" ? "/" : frame.path,
        rule: "maxPolicyObjectProperties",
      });
    }
    const record = value as Record<string, unknown>;
    for (let offset = keys.length - 1; offset >= 0; offset -= 1) {
      const key = keys[offset];
      if (key === undefined) {
        continue;
      }
      if (DANGEROUS_OBJECT_KEYS.has(key)) {
        fail({
          code: "DANGEROUS_OBJECT_KEY",
          message: "Object graph contains a disallowed key.",
          fieldPath: toJsonPointer(frame.path, key),
          rule: "dangerous-object-key",
        });
      }
      stack.push({
        value: record[key],
        depth: frame.depth + 1,
        path: toJsonPointer(frame.path, key),
      });
    }
  }
}

/**
 * Bounded policy-file assembly. Short reads are retried until EOF or
 * `maxPolicyBytes + 1` bytes are observed. The returned buffer is the snapshot
 * for this attempt.
 */
function assemblePolicyBytes(policyPath: string, maxPolicyBytes: number): Buffer {
  let fd: number | undefined;
  try {
    fd = nodeFs.openSync(policyPath, "r");
    const stats = nodeFs.fstatSync(fd);
    if (!stats.isFile()) {
      fail({
        code: "POLICY_UNAVAILABLE",
        message: "Local policy file is unavailable.",
      });
    }
    if (stats.size > maxPolicyBytes) {
      fail({
        code: "RESOURCE_LIMIT_EXCEEDED",
        message: "Local policy exceeds configured resource limits.",
        rule: "maxPolicyBytes",
      });
    }
    const capacity = maxPolicyBytes + 1;
    const buffer = Buffer.alloc(capacity);
    let offset = 0;
    let position = 0;
    while (offset < capacity) {
      const bytesRead = nodeFs.readSync(fd, buffer, offset, capacity - offset, position);
      if (bytesRead === 0) {
        break;
      }
      offset += bytesRead;
      position += bytesRead;
    }
    if (offset > maxPolicyBytes) {
      fail({
        code: "RESOURCE_LIMIT_EXCEEDED",
        message: "Local policy exceeds configured resource limits.",
        rule: "maxPolicyBytes",
      });
    }
    return Buffer.from(buffer.subarray(0, offset));
  } finally {
    if (fd !== undefined) {
      nodeFs.closeSync(fd);
    }
  }
}

/**
 * Restricts operator schemas to a locally evaluable subset so Ajv compile cannot
 * follow remote references or execute custom keywords. Recursion is bounded by
 * `maxPolicyDepth` enforced on the parsed policy graph before this function runs.
 */
function assertSupportedArgsSchema(
  schema: unknown,
  fieldPath: string,
  isRoot: boolean,
  maxPatternLength: number,
): void {
  if (!isPlainJsonObject(schema)) {
    throwPolicyInvalid("argsSchema", fieldPath);
  }

  const keywords = Object.keys(schema);
  for (const keyword of keywords) {
    if (!ALLOWED_SCHEMA_KEYWORDS.has(keyword)) {
      throwPolicyInvalid("unsupported-keyword", `${fieldPath}/${keyword}`);
    }
  }

  const schemaId = schema["$schema"];
  if (schemaId !== undefined) {
    if (typeof schemaId !== "string" || !LOCAL_DRAFT07_SCHEMA_IDS.has(schemaId)) {
      throwPolicyInvalid("$schema", `${fieldPath}/$schema`);
    }
  }

  const title = schema["title"];
  if (title !== undefined && typeof title !== "string") {
    throwPolicyInvalid("title", `${fieldPath}/title`);
  }
  const description = schema["description"];
  if (description !== undefined && typeof description !== "string") {
    throwPolicyInvalid("description", `${fieldPath}/description`);
  }

  const schemaType = schema["type"];
  if (typeof schemaType !== "string" || !JSON_SCHEMA_TYPES.has(schemaType)) {
    throwPolicyInvalid("type", `${fieldPath}/type`);
  }
  if (isRoot && schemaType !== "object") {
    throwPolicyInvalid("type", `${fieldPath}/type`);
  }
  assertKeywordMatchesType(new Set(keywords), schemaType, fieldPath);

  if (schemaType === "object") {
    if (schema["additionalProperties"] !== false) {
      throwPolicyInvalid("additionalProperties", `${fieldPath}/additionalProperties`);
    }
    const properties: unknown = schema["properties"];
    if (!isPlainJsonObject(properties)) {
      throwPolicyInvalid("properties", `${fieldPath}/properties`);
    }
    const required: unknown = schema["required"];
    if (required !== undefined) {
      if (!Array.isArray(required)) {
        throwPolicyInvalid("required", `${fieldPath}/required`);
      }
      const seen = new Set<string>();
      for (let index = 0; index < required.length; index += 1) {
        const name = required[index];
        if (typeof name !== "string" || name.length === 0 || seen.has(name)) {
          throwPolicyInvalid("required", toJsonPointer(`${fieldPath}/required`, index));
        }
        if (!Object.prototype.hasOwnProperty.call(properties, name)) {
          throwPolicyInvalid("required", toJsonPointer(`${fieldPath}/required`, index));
        }
        seen.add(name);
      }
    }
    for (const propertyName of Object.keys(properties)) {
      if (DANGEROUS_OBJECT_KEYS.has(propertyName)) {
        throwPolicyInvalid("dangerous-object-key", `${fieldPath}/properties/${propertyName}`);
      }
      assertSupportedArgsSchema(
        properties[propertyName],
        `${fieldPath}/properties/${propertyName}`,
        false,
        maxPatternLength,
      );
    }
  }

  if (schemaType === "array") {
    if (!Object.prototype.hasOwnProperty.call(schema, "items")) {
      throwPolicyInvalid("items", `${fieldPath}/items`);
    }
    assertSupportedArgsSchema(schema["items"], `${fieldPath}/items`, false, maxPatternLength);
    const minItems = schema["minItems"];
    const maxItems = schema["maxItems"];
    const minItemsValue =
      minItems === undefined ? undefined : assertNonNegativeSafeInteger(minItems, `${fieldPath}/minItems`, "minItems");
    const maxItemsValue =
      maxItems === undefined ? undefined : assertNonNegativeSafeInteger(maxItems, `${fieldPath}/maxItems`, "maxItems");
    if (minItemsValue !== undefined && maxItemsValue !== undefined && minItemsValue > maxItemsValue) {
      throwPolicyInvalid("bounds", `${fieldPath}/maxItems`);
    }
    const uniqueItems = schema["uniqueItems"];
    if (uniqueItems !== undefined && typeof uniqueItems !== "boolean") {
      throwPolicyInvalid("uniqueItems", `${fieldPath}/uniqueItems`);
    }
  }

  if (schemaType === "string") {
    const minLength = schema["minLength"];
    const maxLength = schema["maxLength"];
    const minLengthValue =
      minLength === undefined
        ? undefined
        : assertNonNegativeSafeInteger(minLength, `${fieldPath}/minLength`, "minLength");
    const maxLengthValue =
      maxLength === undefined
        ? undefined
        : assertNonNegativeSafeInteger(maxLength, `${fieldPath}/maxLength`, "maxLength");
    if (minLengthValue !== undefined && maxLengthValue !== undefined && minLengthValue > maxLengthValue) {
      throwPolicyInvalid("bounds", `${fieldPath}/maxLength`);
    }
    const pattern = schema["pattern"];
    if (pattern !== undefined) {
      if (typeof pattern !== "string") {
        throwPolicyInvalid("pattern", `${fieldPath}/pattern`);
      }
      assertLinearSchemaPattern(pattern, maxPatternLength, `${fieldPath}/pattern`);
    }
  }

  if (schemaType === "integer" || schemaType === "number") {
    const minimum =
      schema["minimum"] === undefined
        ? undefined
        : assertFiniteNumericBound(schema["minimum"], `${fieldPath}/minimum`, "minimum");
    const maximum =
      schema["maximum"] === undefined
        ? undefined
        : assertFiniteNumericBound(schema["maximum"], `${fieldPath}/maximum`, "maximum");
    if (minimum !== undefined && maximum !== undefined && minimum > maximum) {
      throwPolicyInvalid("bounds", `${fieldPath}/maximum`);
    }
    const exclusiveMinimum =
      schema["exclusiveMinimum"] === undefined
        ? undefined
        : assertFiniteNumericBound(
            schema["exclusiveMinimum"],
            `${fieldPath}/exclusiveMinimum`,
            "exclusiveMinimum",
          );
    const exclusiveMaximum =
      schema["exclusiveMaximum"] === undefined
        ? undefined
        : assertFiniteNumericBound(
            schema["exclusiveMaximum"],
            `${fieldPath}/exclusiveMaximum`,
            "exclusiveMaximum",
          );
    if (
      exclusiveMinimum !== undefined &&
      exclusiveMaximum !== undefined &&
      exclusiveMinimum >= exclusiveMaximum
    ) {
      throwPolicyInvalid("bounds", `${fieldPath}/exclusiveMaximum`);
    }
    if (
      numericIntervalIsEmpty(
        schemaType === "integer" ? "integer" : "number",
        minimum,
        maximum,
        exclusiveMinimum,
        exclusiveMaximum,
      )
    ) {
      throwPolicyInvalid("bounds", `${fieldPath}`);
    }
    const multipleOf = schema["multipleOf"];
    if (multipleOf !== undefined) {
      const multipleOfValue = assertFiniteNumericBound(
        multipleOf,
        `${fieldPath}/multipleOf`,
        "multipleOf",
      );
      if (multipleOfValue <= 0) {
        throwPolicyInvalid("multipleOf", `${fieldPath}/multipleOf`);
      }
    }
  }

  const enumValues = schema["enum"];
  if (enumValues !== undefined) {
    if (!Array.isArray(enumValues) || enumValues.length === 0) {
      throwPolicyInvalid("enum", `${fieldPath}/enum`);
    }
    for (let index = 0; index < enumValues.length; index += 1) {
      assertJsonLiteral(enumValues[index], toJsonPointer(`${fieldPath}/enum`, index));
    }
  }
  if (Object.prototype.hasOwnProperty.call(schema, "const")) {
    assertJsonLiteral(schema["const"], `${fieldPath}/const`);
  }
}

function assertPolicyDocument(
  value: unknown,
  maxPatternLength: number,
): asserts value is GuwahPolicyDocument {
  if (!isPlainJsonObject(value)) {
    throwPolicyInvalid("policy-object");
  }
  if (value["version"] !== SUPPORTED_POLICY_VERSION) {
    throwPolicyInvalid("policy-version", "/version");
  }
  if (value["posture"] !== REQUIRED_POLICY_POSTURE) {
    throwPolicyInvalid("policy-posture", "/posture");
  }
  const tools: unknown = value["tools"];
  if (!isPlainJsonObject(tools)) {
    throwPolicyInvalid("policy-tools", "/tools");
  }
  for (const toolName of Object.keys(tools)) {
    const tool = asToolPolicy(tools[toolName]);
    if (tool === undefined) {
      throwPolicyInvalid("policy-tool", `/tools/${toolName}`);
    }
    if (!KNOWN_TOOL_ACTIONS.has(tool.action)) {
      throwPolicyInvalid("action", `/tools/${toolName}/action`);
    }
    assertSupportedArgsSchema(tool.argsSchema, `/tools/${toolName}/argsSchema`, true, maxPatternLength);
  }
}

function resolveResourceLimits(
  overrides: Partial<GuwahResourceLimits> | undefined,
): GuwahResourceLimits {
  const resolved: GuwahResourceLimits = {
    maxPolicyBytes: overrides?.maxPolicyBytes ?? DEFAULT_GUWAH_RESOURCE_LIMITS.maxPolicyBytes,
    maxPolicyDepth: overrides?.maxPolicyDepth ?? DEFAULT_GUWAH_RESOURCE_LIMITS.maxPolicyDepth,
    maxPolicyNodes: overrides?.maxPolicyNodes ?? DEFAULT_GUWAH_RESOURCE_LIMITS.maxPolicyNodes,
    maxPolicyArrayLength:
      overrides?.maxPolicyArrayLength ?? DEFAULT_GUWAH_RESOURCE_LIMITS.maxPolicyArrayLength,
    maxPolicyObjectProperties:
      overrides?.maxPolicyObjectProperties ?? DEFAULT_GUWAH_RESOURCE_LIMITS.maxPolicyObjectProperties,
    maxPatternLength: overrides?.maxPatternLength ?? DEFAULT_GUWAH_RESOURCE_LIMITS.maxPatternLength,
    maxInputDepth: overrides?.maxInputDepth ?? DEFAULT_GUWAH_RESOURCE_LIMITS.maxInputDepth,
    maxInputNodes: overrides?.maxInputNodes ?? DEFAULT_GUWAH_RESOURCE_LIMITS.maxInputNodes,
    maxInputBytes: overrides?.maxInputBytes ?? DEFAULT_GUWAH_RESOURCE_LIMITS.maxInputBytes,
    maxArrayLength: overrides?.maxArrayLength ?? DEFAULT_GUWAH_RESOURCE_LIMITS.maxArrayLength,
    maxObjectProperties:
      overrides?.maxObjectProperties ?? DEFAULT_GUWAH_RESOURCE_LIMITS.maxObjectProperties,
  };
  for (const value of Object.values(resolved)) {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
      fail({
        code: "INVALID_PAYLOAD",
        message: "Resource limit configuration is invalid.",
        rule: "resource-limits",
      });
    }
  }
  return Object.freeze(resolved);
}

function sha256Bytes(contents: Uint8Array): string {
  // Digest is a local cache identity only. It is not a signature.
  return createHash("sha256").update(contents).digest("hex");
}

/**
 * Local, fail-closed interceptor for MCP tool-call payloads.
 * This layer does not transmit, sign, or settle transactions.
 */
export class GuwahGuard {
  private readonly policyPath: string;
  private readonly limits: GuwahResourceLimits;
  private readonly policyDocumentValidator: ValidateFunction;
  private toolAjv: GuwahAjv;
  private cache: CompiledPolicyCache | undefined;

  public constructor(options?: GuwahGuardOptions) {
    this.policyPath =
      options?.policyPath === undefined
        ? path.resolve(process.cwd(), DEFAULT_POLICY_FILENAME)
        : path.resolve(options.policyPath);
    this.limits = resolveResourceLimits(options?.resourceLimits);
    const policyAjv = createStrictAjv();
    this.policyDocumentValidator = policyAjv.compile(POLICY_DOCUMENT_SCHEMA);
    this.toolAjv = createStrictAjv();
  }

  /**
   * Candidate `args` are the enforcement input. Embedded `payload.params.arguments`
   * are compared only when present, to detect Client-Runtime Payload Mutation.
   * `_meta` is protocol metadata and is not compared or schema-validated as arguments.
   */
  public validateToolCall(payload: unknown, args: unknown): Readonly<McpToolCallPayload> {
    try {
      return this.executeValidation(payload, args);
    } catch (error: unknown) {
      if (error instanceof GuwahSecurityViolation) {
        throw error;
      }
      throw new GuwahSecurityViolation({
        code: "INTERNAL_VALIDATION_ERROR",
        message: "Validation terminated due to an internal error.",
        cause: error instanceof Error ? error : undefined,
      });
    }
  }

  /**
   * Returns tool names with policy action ENFORCE.
   * DENY and unknown tools are omitted. Used to mirror discovery without auto-authorizing.
   */
  public listEnforcedToolNames(): readonly string[] {
    const compiled = this.loadCompiledPolicy();
    const names: string[] = [];
    for (const [toolName, toolPolicy] of compiled.tools) {
      if (toolPolicy.action === ENFORCE_ACTION) {
        names.push(toolName);
      }
    }
    names.sort();
    return Object.freeze(names);
  }

  /**
   * Requires an explicit policy tools-map entry with action ENFORCE.
   * Unknown tools and DENY entries fail closed before argument validation.
   */
  public assertToolEnforced(toolName: string): void {
    if (typeof toolName !== "string" || toolName.trim().length === 0) {
      fail({
        code: "UNAUTHORIZED_TOOL",
        message: "Requested tool is not authorized by local policy.",
        rule: "tool-allowlist",
      });
    }
    const compiled = this.loadCompiledPolicy();
    const toolPolicy = compiled.tools.get(toolName);
    if (toolPolicy === undefined) {
      fail({
        code: "UNAUTHORIZED_TOOL",
        message: "Requested tool is not authorized by local policy.",
        toolName,
        rule: "tool-allowlist",
      });
    }
    if (toolPolicy.action !== ENFORCE_ACTION) {
      fail({
        code: "POLICY_NOT_ENFORCED",
        message: "Requested tool is not configured for local enforcement.",
        toolName,
        rule: "action",
      });
    }
  }

  private executeValidation(payload: unknown, args: unknown): Readonly<McpToolCallPayload> {
    assertJsonCompatibleGraph(payload, "", this.limits);
    assertJsonCompatibleGraph(args, "", this.limits);
    assertMcpToolCallPayload(payload);

    if (!isPlainJsonObject(args)) {
      fail({
        code: "INVALID_PAYLOAD",
        message: "Candidate arguments must be a plain object.",
        rule: "args-object",
      });
    }

    const toolName = payload.params.name;
    const compiled = this.loadCompiledPolicy();
    const toolPolicy = compiled.tools.get(toolName);
    if (toolPolicy === undefined) {
      fail({
        code: "UNAUTHORIZED_TOOL",
        message: "Requested tool is not authorized by local policy.",
        toolName,
        rule: "tool-allowlist",
      });
    }
    if (toolPolicy.action !== ENFORCE_ACTION) {
      fail({
        code: "POLICY_NOT_ENFORCED",
        message: "Requested tool is not configured for local enforcement.",
        toolName,
        rule: "action",
      });
    }

    if (Object.prototype.hasOwnProperty.call(payload.params, "arguments")) {
      if (!deepEqualJson(payload.params.arguments, args)) {
        fail({
          code: "PAYLOAD_MUTATION",
          message: "Embedded tool-call arguments do not match the candidate arguments.",
          toolName,
          fieldPath: "/params/arguments",
          rule: "payload-argument-parity",
        });
      }
    }

    const candidate = structuredClone(args);
    if (!toolPolicy.validateArgs(candidate)) {
      const ajvError = firstAjvError(toolPolicy.validateArgs.errors);
      const instancePath = ajvError?.instancePath;
      const rule = ajvError?.keyword ?? "argsSchema";
      if (instancePath !== undefined && instancePath.length > 0) {
        fail({
          code: "ARGUMENT_VALIDATION_FAILED",
          message: "Tool arguments failed local policy validation.",
          toolName,
          fieldPath: instancePath,
          rule,
        });
      }
      fail({
        code: "ARGUMENT_VALIDATION_FAILED",
        message: "Tool arguments failed local policy validation.",
        toolName,
        rule,
      });
    }

    const approvedParams: {
      name: string;
      arguments: unknown;
      _meta?: Readonly<Record<string, unknown>>;
    } = {
      name: toolName,
      arguments: structuredClone(args),
    };
    if (Object.prototype.hasOwnProperty.call(payload.params, "_meta")) {
      approvedParams._meta = structuredClone(payload.params._meta) as Readonly<
        Record<string, unknown>
      >;
    }

    const approved: McpToolCallPayload = {
      jsonrpc: "2.0",
      id: payload.id,
      method: "tools/call",
      params: approvedParams,
    };
    return deepFreeze(approved, new WeakSet<object>());
  }

  /**
   * Size is checked before and after the read. The resulting byte buffer is the
   * authoritative snapshot for this validation attempt.
   */
  private loadCompiledPolicy(): CompiledPolicyCache {
    let policyBytes: Buffer;
    try {
      policyBytes = this.readPolicyBytes();
    } catch (error: unknown) {
      this.invalidateCache();
      if (error instanceof GuwahSecurityViolation) {
        throw error;
      }
      fail({
        code: "POLICY_UNAVAILABLE",
        message: "Local policy file is unavailable.",
      });
    }

    const digest = sha256Bytes(policyBytes);
    if (this.cache !== undefined && this.cache.digest === digest) {
      return this.cache;
    }

    this.invalidateCache();

    let decoded: string;
    try {
      decoded = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(policyBytes);
    } catch {
      fail({
        code: "POLICY_INVALID",
        message: "Local policy is not valid JSON.",
        rule: "utf-8",
      });
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(decoded) as unknown;
    } catch {
      fail({
        code: "POLICY_INVALID",
        message: "Local policy is not valid JSON.",
        rule: "json",
      });
    }

    assertPolicyGraphLimits(parsed, this.limits);

    const schemaAccepted = this.policyDocumentValidator(parsed);
    if (!schemaAccepted) {
      const ajvError = firstAjvError(this.policyDocumentValidator.errors);
      const fieldPath =
        ajvError?.instancePath !== undefined && ajvError.instancePath.length > 0
          ? ajvError.instancePath
          : undefined;
      throwPolicyInvalid(ajvError?.keyword ?? "policy-schema", fieldPath);
    }

    try {
      assertPolicyDocument(parsed, this.limits.maxPatternLength);
    } catch (error: unknown) {
      this.invalidateCache();
      throw error;
    }

    this.toolAjv = createStrictAjv();
    const tools = new Map<string, CompiledToolValidator>();
    for (const toolName of Object.keys(parsed.tools)) {
      const tool = asToolPolicy(parsed.tools[toolName]);
      if (tool === undefined) {
        throwPolicyInvalid("policy-tool", `/tools/${toolName}`);
      }
      let validateArgs: ValidateFunction;
      try {
        validateArgs = this.toolAjv.compile(tool.argsSchema as AnySchemaObject);
      } catch {
        fail({
          code: "POLICY_INVALID",
          message: "Local policy schema could not be compiled.",
          toolName,
        });
      }
      tools.set(toolName, { action: tool.action, validateArgs });
    }

    this.cache = { digest, tools };
    return this.cache;
  }

  private readPolicyBytes(): Buffer {
    return assemblePolicyBytes(this.policyPath, this.limits.maxPolicyBytes);
  }

  private invalidateCache(): void {
    this.cache = undefined;
  }
}
