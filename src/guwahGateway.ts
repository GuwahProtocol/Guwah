import path from "node:path";
import type { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  type CallToolResult,
  type ServerCapabilities,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { GuwahGuard, GuwahSecurityViolation, type GuwahViolationCode, type McpToolCallPayload } from "./guwahGuard.js";

export const GUWAH_GATEWAY_NAME = "guwah";
export const GUWAH_GATEWAY_VERSION = "0.1.0";

/**
 * Stable Guwah violation → MCP JSON-RPC error mapping.
 * Messages are fixed operator text and must never include rejected values,
 * policy file contents, or violation.message.
 */
export type GuwahMcpViolationMapping = {
  readonly jsonRpcCode: ErrorCode;
  readonly message: string;
};

export const GUWAH_VIOLATION_MCP_MAP: Readonly<
  Record<GuwahViolationCode, GuwahMcpViolationMapping>
> = Object.freeze({
  INVALID_PAYLOAD: Object.freeze({
    jsonRpcCode: ErrorCode.InvalidRequest,
    message: "Tool-call payload is invalid.",
  }),
  POLICY_UNAVAILABLE: Object.freeze({
    jsonRpcCode: ErrorCode.InternalError,
    message: "Local policy is unavailable.",
  }),
  POLICY_INVALID: Object.freeze({
    jsonRpcCode: ErrorCode.InternalError,
    message: "Local policy is invalid.",
  }),
  UNAUTHORIZED_TOOL: Object.freeze({
    jsonRpcCode: ErrorCode.InvalidRequest,
    message: "Requested tool is not authorized by local policy.",
  }),
  POLICY_NOT_ENFORCED: Object.freeze({
    jsonRpcCode: ErrorCode.InvalidRequest,
    message: "Requested tool is not enforced by local policy.",
  }),
  PAYLOAD_MUTATION: Object.freeze({
    jsonRpcCode: ErrorCode.InvalidRequest,
    message: "Tool-call arguments do not match the embedded payload.",
  }),
  ARGUMENT_VALIDATION_FAILED: Object.freeze({
    jsonRpcCode: ErrorCode.InvalidRequest,
    message: "Tool-call arguments violate local policy.",
  }),
  DANGEROUS_OBJECT_KEY: Object.freeze({
    jsonRpcCode: ErrorCode.InvalidRequest,
    message: "Tool-call input contains a disallowed object key.",
  }),
  NON_JSON_VALUE: Object.freeze({
    jsonRpcCode: ErrorCode.InvalidRequest,
    message: "Tool-call input is not JSON-compatible.",
  }),
  RESOURCE_LIMIT_EXCEEDED: Object.freeze({
    jsonRpcCode: ErrorCode.InvalidRequest,
    message: "Tool-call input exceeds configured resource limits.",
  }),
  INTERNAL_VALIDATION_ERROR: Object.freeze({
    jsonRpcCode: ErrorCode.InternalError,
    message: "Tool-call validation failed internally.",
  }),
});

/**
 * Maps a Guwah security violation to a sanitized MCP error.
 * Unmapped codes fail closed as a generic internal error.
 */
export function mapGuwahViolationToMcpError(error: GuwahSecurityViolation): McpError {
  const mapping = (
    GUWAH_VIOLATION_MCP_MAP as Readonly<Record<string, GuwahMcpViolationMapping | undefined>>
  )[error.code];
  if (mapping === undefined) {
    return new McpError(ErrorCode.InternalError, "Tool call denied.");
  }
  return new McpError(mapping.jsonRpcCode, mapping.message, {
    guwahCode: error.code,
  });
}

/**
 * Advertised MCP server capabilities.
 * Only surfaces with registered handlers may appear here.
 * tools/list and tools/call are registered, so tools is advertised.
 * resources, prompts, sampling, logging, completions, and tasks stay absent until implemented.
 * Client-declared capabilities must never expand this set.
 */
export const GUWAH_GATEWAY_CAPABILITIES: Readonly<ServerCapabilities> = Object.freeze({
  tools: Object.freeze({}),
});

/**
 * A tool the gateway is authorized to mediate.
 * Downstream discovery must never bypass this catalog.
 */
export type GuwahMediatedTool = {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema: Tool["inputSchema"];
};

export type GuwahGatewayServerOptions = {
  /**
   * Authorized mediated tools. Defaults to an empty set until downstream mirroring exists.
   */
  readonly mediatedTools?: readonly GuwahMediatedTool[];
  /**
   * Optional resolver for the mediated catalog.
   * Failures must throw; the list handler must not return a partial catalog.
   */
  readonly resolveMediatedTools?: () => readonly GuwahMediatedTool[];
  readonly policyPath?: string;
  readonly guard?: GuwahGuard;
  /**
   * Invoked only after local validation approval.
   * Must never run for rejected calls. Defaults to a validator-only success with no downstream send.
   */
  readonly afterApproval?: (
    approved: Readonly<McpToolCallPayload>,
  ) => CallToolResult | Promise<CallToolResult>;
  /**
   * In-flight tools/call request-id registry. Defaults to a fresh registry per server.
   */
  readonly activeRequests?: GuwahActiveRequestRegistry;
  /**
   * Per-request tools/call deadline in milliseconds.
   * When set, must be a positive safe integer. Omitted disables the deadline.
   * Expiry is fail-closed: no dispatch after expiry and no automatic retry.
   */
  readonly requestTimeoutMs?: number;
  /**
   * Maximum concurrent in-flight tools/call requests.
   * When set, must be a positive safe integer. Omitted leaves concurrency unbounded.
   * Excess calls are rejected fail-closed and are not queued.
   */
  readonly maxConcurrentCalls?: number;
  /**
   * Invoked after the active tools/call count changes (begin or end).
   * Used by the stdio gateway to pause or resume input under concurrency bounds.
   */
  readonly onActiveCountChange?: (activeCount: number) => void;
};

export type GuwahRequestId = string | number;

/**
 * Explicit registry of in-flight MCP request ids for tools/call.
 * Duplicate begins are rejected. Completed ids are removed.
 * Unknown ids cannot be cancelled, expired, or aborted as if they were active.
 * Cancel, deadline expiry, and shutdown abort are terminal: late success must not return.
 */
export class GuwahActiveRequestRegistry {
  private readonly active = new Set<string>();
  private readonly cancelled = new Set<string>();
  private readonly expired = new Set<string>();
  private readonly aborted = new Set<string>();

  private key(id: GuwahRequestId): string {
    return `${typeof id}:${String(id)}`;
  }

  has(id: GuwahRequestId): boolean {
    return this.active.has(this.key(id));
  }

  size(): number {
    return this.active.size;
  }

  /**
   * Begins tracking a request id.
   * @returns false when the id is already active.
   */
  tryBegin(id: GuwahRequestId): boolean {
    const key = this.key(id);
    if (this.active.has(key)) {
      return false;
    }
    this.active.add(key);
    return true;
  }

  /**
   * Removes a completed or abandoned request id.
   */
  end(id: GuwahRequestId): void {
    const key = this.key(id);
    this.active.delete(key);
    this.cancelled.delete(key);
    this.expired.delete(key);
    this.aborted.delete(key);
  }

  /**
   * Records cancellation intent for an active request.
   * @returns false when the id is not active.
   */
  tryCancel(id: GuwahRequestId): boolean {
    const key = this.key(id);
    if (!this.active.has(key)) {
      return false;
    }
    this.cancelled.add(key);
    return true;
  }

  isCancelled(id: GuwahRequestId): boolean {
    return this.cancelled.has(this.key(id));
  }

  /**
   * Records deadline expiry for an active request.
   * @returns false when the id is not active.
   */
  tryExpire(id: GuwahRequestId): boolean {
    const key = this.key(id);
    if (!this.active.has(key)) {
      return false;
    }
    this.expired.add(key);
    return true;
  }

  isExpired(id: GuwahRequestId): boolean {
    return this.expired.has(this.key(id));
  }

  /**
   * Records shutdown abort for an active request.
   * @returns false when the id is not active.
   */
  tryAbort(id: GuwahRequestId): boolean {
    const key = this.key(id);
    if (!this.active.has(key)) {
      return false;
    }
    this.aborted.add(key);
    return true;
  }

  /**
   * Marks every active request aborted after shutdown grace expires.
   * Late success for those ids must be dropped.
   */
  abortAllActive(): void {
    for (const key of this.active) {
      this.aborted.add(key);
    }
  }

  isAborted(id: GuwahRequestId): boolean {
    return this.aborted.has(this.key(id));
  }

  /**
   * True when cancel, deadline expiry, or shutdown abort has sealed the id.
   */
  isTerminal(id: GuwahRequestId): boolean {
    const key = this.key(id);
    return this.cancelled.has(key) || this.expired.has(key) || this.aborted.has(key);
  }
}

export type GuwahStdioGatewayOptions = {
  readonly stdin?: Readable;
  readonly stdout?: Writable;
  readonly maxBufferSize?: number;
  readonly mediatedTools?: readonly GuwahMediatedTool[];
  readonly resolveMediatedTools?: () => readonly GuwahMediatedTool[];
  readonly policyPath?: string;
  readonly guard?: GuwahGuard;
  readonly afterApproval?: (
    approved: Readonly<McpToolCallPayload>,
  ) => CallToolResult | Promise<CallToolResult>;
  /**
   * Invoked when the stdio transport fails.
   * When omitted, the process writes a sanitized stderr line and exits non-zero.
   */
  readonly onTransportFailure?: (error: unknown) => void;
  /**
   * Invoked after stdin EOF triggers clean shutdown.
   * Does not retry in-flight work. When omitted, no process exit is performed.
   */
  readonly onStdinEof?: () => void;
  /**
   * When true, listen for SIGINT/SIGTERM on terminationSignalHost (default process).
   * Unsupported signals on the host platform are skipped.
   */
  readonly enableTerminationSignals?: boolean;
  /**
   * Event host for termination signals. Defaults to process when signal handling is enabled.
   */
  readonly terminationSignalHost?: {
    on(event: string, listener: () => void): unknown;
    off(event: string, listener: () => void): unknown;
  };
  /**
   * Invoked after a termination signal begins clean shutdown.
   */
  readonly onTerminationSignal?: (signal: NodeJS.Signals) => void;
  /**
   * Max time to wait for in-flight approved dispatches during clean shutdown.
   * Non-negative safe integer milliseconds. Defaults to 5000. `0` skips waiting.
   */
  readonly shutdownGraceMs?: number;
  readonly activeRequests?: GuwahActiveRequestRegistry;
  /**
   * Per-request tools/call deadline in milliseconds.
   * When set, must be a positive safe integer. Omitted disables the deadline.
   */
  readonly requestTimeoutMs?: number;
  /**
   * Maximum concurrent in-flight tools/call requests.
   * When set, must be a positive safe integer. Omitted leaves concurrency unbounded.
   * Excess calls are rejected fail-closed and are not queued.
   */
  readonly maxConcurrentCalls?: number;
};

function toProtocolTools(mediated: readonly GuwahMediatedTool[]): Tool[] {
  return mediated.map((tool) => {
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
  });
}

function defaultAfterApproval(): CallToolResult {
  return {
    content: [
      {
        type: "text",
        text: "Tool call approved by local policy. Downstream dispatch is not configured.",
      },
    ],
  };
}

/**
 * Registers tools/list.
 * Returns only gateway-mediated tools. Never returns an unfiltered downstream catalog.
 * Catalog resolution failure becomes a structured MCP error with no tool list.
 */
export function registerGatewayToolsList(
  server: Server,
  resolveMediatedTools: () => readonly GuwahMediatedTool[],
): void {
  server.setRequestHandler(ListToolsRequestSchema, () => {
    try {
      const mediated = resolveMediatedTools();
      return {
        tools: toProtocolTools(mediated),
      };
    } catch {
      throw new McpError(ErrorCode.InternalError, "Gateway tool catalog is unavailable.");
    }
  });
}

/**
 * Registers tools/call.
 * `GuwahGuard.validateToolCall` runs on the complete envelope and candidate
 * arguments before any afterApproval serialization or downstream send.
 * Rejected calls must never invoke afterApproval.
 * Expected denials and unexpected failures return JSON-RPC errors; they must
 * not crash the process or expose rejected payload values.
 * In-flight request ids are registered; duplicates are rejected fail-closed.
 * MCP cancellation aborts in-flight work; late success is not returned after cancel.
 * Per-request deadlines expire fail-closed; expired calls do not dispatch and are not retried.
 * Results arriving after cancel, deadline expiry, or shutdown abort are dropped.
 * Optional concurrency bounds reject excess calls fail-closed without queuing.
 */
export function registerGatewayToolsCall(
  server: Server,
  options: {
    readonly resolveMediatedTools: () => readonly GuwahMediatedTool[];
    readonly guard: GuwahGuard;
    readonly afterApproval: (
      approved: Readonly<McpToolCallPayload>,
    ) => CallToolResult | Promise<CallToolResult>;
    readonly activeRequests: GuwahActiveRequestRegistry;
    readonly requestTimeoutMs?: number;
    readonly maxConcurrentCalls?: number;
    readonly onActiveCountChange?: (activeCount: number) => void;
    readonly isHandshakeComplete: () => boolean;
  },
): void {
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const requestId = extra.requestId;
    if (typeof requestId !== "string" && typeof requestId !== "number") {
      throw new McpError(ErrorCode.InvalidRequest, "Tool call is missing a request id.");
    }
    // Stdio may deliver initialize, initialized, and tools/call in one read.
    // Initialize populates client info one microtask after the initialized notification.
    if (!options.isHandshakeComplete()) {
      await Promise.resolve();
    }
    if (!options.isHandshakeComplete()) {
      await Promise.resolve();
    }
    if (!options.isHandshakeComplete()) {
      // Failed or incomplete initialize must never reach downstream dispatch.
      throw new McpError(ErrorCode.InvalidRequest, "Gateway is not initialized.");
    }
    if (
      options.maxConcurrentCalls !== undefined &&
      options.activeRequests.size() >= options.maxConcurrentCalls
    ) {
      // Reject immediately; do not queue unbounded work.
      throw new McpError(ErrorCode.InvalidRequest, "Concurrent tool call limit reached.");
    }
    if (!options.activeRequests.tryBegin(requestId)) {
      throw new McpError(ErrorCode.InvalidRequest, "Duplicate request id is already active.");
    }
    options.onActiveCountChange?.(options.activeRequests.size());

    const markCancelled = (): void => {
      options.activeRequests.tryCancel(requestId);
    };
    if (extra.signal.aborted) {
      markCancelled();
    } else {
      extra.signal.addEventListener("abort", markCancelled, { once: true });
    }

    const markExpired = (): void => {
      options.activeRequests.tryExpire(requestId);
    };
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
    if (options.requestTimeoutMs !== undefined) {
      deadlineTimer = setTimeout(markExpired, options.requestTimeoutMs);
      deadlineTimer.unref?.();
    }

    const assertNotTerminal = (): void => {
      if (extra.signal.aborted || options.activeRequests.isCancelled(requestId)) {
        markCancelled();
        throw new McpError(ErrorCode.InvalidRequest, "Tool call was cancelled.");
      }
      if (options.activeRequests.isExpired(requestId)) {
        markExpired();
        throw new McpError(ErrorCode.InvalidRequest, "Tool call deadline expired.");
      }
      if (options.activeRequests.isAborted(requestId)) {
        options.activeRequests.tryAbort(requestId);
        throw new McpError(ErrorCode.InvalidRequest, "Tool call aborted during shutdown.");
      }
    };

    try {
      assertNotTerminal();

      let mediated: readonly GuwahMediatedTool[];
      try {
        mediated = options.resolveMediatedTools();
      } catch {
        throw new McpError(ErrorCode.InternalError, "Gateway tool catalog is unavailable.");
      }

      const toolName = request.params.name;
      if (!mediated.some((tool) => tool.name === toolName)) {
        throw new McpError(ErrorCode.InvalidParams, "Requested tool is not mediated by the gateway.");
      }

      const candidateArgs = request.params.arguments ?? {};
      const params: Record<string, unknown> = {
        name: toolName,
        arguments: candidateArgs,
      };
      if (request.params._meta !== undefined) {
        params["_meta"] = request.params._meta;
      }
      const envelope: Record<string, unknown> = {
        jsonrpc: "2.0",
        id: requestId,
        method: "tools/call",
        params,
      };

      assertNotTerminal();
      // Validation must complete before any dispatch serialization.
      const approved = options.guard.validateToolCall(envelope, candidateArgs);
      assertNotTerminal();
      // Terminal ids must not dispatch after cancel, expiry, or shutdown abort.
      const result = await options.afterApproval(approved);
      // Drop late success after a terminal outcome; never forward it upstream.
      assertNotTerminal();
      return result;
    } catch (error: unknown) {
      if (error instanceof McpError) {
        throw error;
      }
      if (error instanceof GuwahSecurityViolation) {
        throw mapGuwahViolationToMcpError(error);
      }
      // Do not forward Error.message: unexpected throws may contain rejected values.
      throw new McpError(ErrorCode.InternalError, "Tool call handling failed.");
    } finally {
      if (deadlineTimer !== undefined) {
        clearTimeout(deadlineTimer);
      }
      extra.signal.removeEventListener("abort", markCancelled);
      options.activeRequests.end(requestId);
      options.onActiveCountChange?.(options.activeRequests.size());
    }
  });
}

/**
 * Validates an optional per-request deadline.
 * Omitted disables the deadline. Invalid values fail closed at construction.
 */
function resolveRequestTimeoutMs(value: number | undefined): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 1) {
    return value;
  }
  throw new Error("requestTimeoutMs must be a positive safe integer.");
}

/**
 * Validates an optional concurrent tools/call bound.
 * Omitted leaves concurrency unbounded. Invalid values fail closed at construction.
 */
function resolveMaxConcurrentCalls(value: number | undefined): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 1) {
    return value;
  }
  throw new Error("maxConcurrentCalls must be a positive safe integer.");
}

function resolveCatalog(
  options?: Pick<GuwahGatewayServerOptions, "mediatedTools" | "resolveMediatedTools">,
): () => readonly GuwahMediatedTool[] {
  if (options?.resolveMediatedTools !== undefined) {
    return options.resolveMediatedTools;
  }
  const mediatedTools = options?.mediatedTools ?? [];
  return () => mediatedTools;
}

function resolveGuard(options?: GuwahGatewayServerOptions): GuwahGuard {
  if (options?.guard !== undefined) {
    return options.guard;
  }
  if (options?.policyPath !== undefined) {
    return new GuwahGuard({ policyPath: options.policyPath });
  }
  return new GuwahGuard();
}

/**
 * Builds the MCP gateway server.
 * `initialize` and `initialized` are handled by the official SDK Server.
 * Advertised capabilities are limited to surfaces the gateway actually mediates.
 * tools/list returns only the authorized mediated set.
 * tools/call runs GuwahGuard.validateToolCall before any downstream send.
 * MCP cancellation suppresses late success for cancelled in-flight calls.
 * Optional per-request deadlines expire fail-closed without automatic retry.
 * Late results after cancel, deadline expiry, or shutdown abort are dropped.
 * Optional concurrency bounds reject excess calls fail-closed without queuing.
 * tools/call is refused until initialize completes successfully.
 * This factory does not open a downstream client by default.
 */
export function createGuwahGatewayServer(options?: GuwahGatewayServerOptions): Server {
  const server = new Server(
    { name: GUWAH_GATEWAY_NAME, version: GUWAH_GATEWAY_VERSION },
    { capabilities: { ...GUWAH_GATEWAY_CAPABILITIES } },
  );
  let handshakeComplete = false;
  let initializedNotificationSeen = false;
  server.oninitialized = () => {
    initializedNotificationSeen = true;
    if (server.getClientVersion() !== undefined) {
      handshakeComplete = true;
    }
  };
  const resolveMediatedTools = resolveCatalog(options);
  const activeRequests = options?.activeRequests ?? new GuwahActiveRequestRegistry();
  const requestTimeoutMs = resolveRequestTimeoutMs(options?.requestTimeoutMs);
  const maxConcurrentCalls = resolveMaxConcurrentCalls(options?.maxConcurrentCalls);
  const isHandshakeComplete = (): boolean => {
    if (handshakeComplete) {
      return true;
    }
    // Initialize may finish one microtask after notifications/initialized in a burst.
    if (initializedNotificationSeen && server.getClientVersion() !== undefined) {
      handshakeComplete = true;
      return true;
    }
    return false;
  };
  const callOptions: {
    resolveMediatedTools: () => readonly GuwahMediatedTool[];
    guard: GuwahGuard;
    afterApproval: (
      approved: Readonly<McpToolCallPayload>,
    ) => CallToolResult | Promise<CallToolResult>;
    activeRequests: GuwahActiveRequestRegistry;
    requestTimeoutMs?: number;
    maxConcurrentCalls?: number;
    onActiveCountChange?: (activeCount: number) => void;
    isHandshakeComplete: () => boolean;
  } = {
    resolveMediatedTools,
    guard: resolveGuard(options),
    afterApproval: options?.afterApproval ?? defaultAfterApproval,
    activeRequests,
    isHandshakeComplete,
  };
  if (requestTimeoutMs !== undefined) {
    callOptions.requestTimeoutMs = requestTimeoutMs;
  }
  if (maxConcurrentCalls !== undefined) {
    callOptions.maxConcurrentCalls = maxConcurrentCalls;
  }
  if (options?.onActiveCountChange !== undefined) {
    callOptions.onActiveCountChange = options.onActiveCountChange;
  }
  registerGatewayToolsList(server, resolveMediatedTools);
  registerGatewayToolsCall(server, callOptions);
  return server;
}

/**
 * Documented stdio intake ceilings used for backpressure.
 * Framing bytes are capped by `maxBufferSize` (SDK default 10 MiB when omitted).
 * Concurrent tools/call work is capped by `maxConcurrentCalls` when configured.
 */
export const GUWAH_STDIO_BACKPRESSURE_BOUNDS = Object.freeze({
  defaultMaxBufferBytes: 10 * 1024 * 1024,
});

/**
 * Creates the official consumer stdio transport.
 * HTTP and SSE transports are not used.
 * Stdout is reserved exclusively for newline-delimited JSON-RPC protocol frames.
 * Logs, banners, and diagnostics must never be written to stdout.
 */
export function createGuwahStdioTransport(
  stdin: Readable = process.stdin,
  stdout: Writable = process.stdout,
  options?: { readonly maxBufferSize?: number },
): StdioServerTransport {
  if (options?.maxBufferSize === undefined) {
    return new StdioServerTransport(stdin, stdout);
  }
  return new StdioServerTransport(stdin, stdout, {
    maxBufferSize: options.maxBufferSize,
  });
}

const GUWAH_DIAGNOSTIC_REDACTED = "[redacted]";
const GUWAH_DIAGNOSTIC_OMITTED = "[omitted]";

const GUWAH_DIAGNOSTIC_SECRET_PATTERNS: readonly RegExp[] = [
  /\bBearer\s+\S+/gi,
  /\b(?:api[_-]?key|secret|password|token|credential|authorization)\b\s*[:=]\s*["']?[^\s"',}\\]+/gi,
  /0x[0-9a-fA-F]{40}/g,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g,
];

function looksLikePayloadOrPolicyText(text: string): boolean {
  const trimmed = text.trim();
  if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) {
    return false;
  }
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (parsed === null || typeof parsed !== "object") {
      return false;
    }
  } catch {
    return false;
  }
  // Any JSON object or array in a diagnostic is treated as payload or policy text.
  return true;
}

/**
 * Redacts credential-shaped values from diagnostic text.
 * Full JSON payloads and policy documents are omitted entirely.
 */
export function redactGuwahDiagnosticText(raw: string): string {
  if (looksLikePayloadOrPolicyText(raw)) {
    return GUWAH_DIAGNOSTIC_OMITTED;
  }
  let out = raw.replace(/\{[\s\S]*\}|\[[\s\S]*\]/g, (candidate) => {
    return looksLikePayloadOrPolicyText(candidate) ? GUWAH_DIAGNOSTIC_OMITTED : candidate;
  });
  for (const pattern of GUWAH_DIAGNOSTIC_SECRET_PATTERNS) {
    out = out.replace(pattern, GUWAH_DIAGNOSTIC_REDACTED);
  }
  return out;
}

/**
 * Formats one diagnostic line for stderr.
 * Detail is omitted by default so Error.message and unknown values cannot leak.
 */
export function formatGuwahDiagnosticLine(
  message: string,
  detail?: unknown,
  includeDetail = false,
): string {
  const safeMessage = redactGuwahDiagnosticText(message).replace(/\r?\n/g, " ").trim();
  const base = safeMessage.length === 0 ? "Guwah gateway diagnostic omitted." : safeMessage;
  if (!includeDetail || detail === undefined) {
    return base;
  }
  if (detail !== null && typeof detail === "object" && !(detail instanceof Error)) {
    return `${base} ${GUWAH_DIAGNOSTIC_OMITTED}`;
  }
  let detailText: string;
  if (detail instanceof Error) {
    detailText = detail.message;
  } else if (typeof detail === "string" || typeof detail === "number" || typeof detail === "boolean") {
    detailText = String(detail);
  } else {
    return `${base} ${GUWAH_DIAGNOSTIC_OMITTED}`;
  }
  const redactedDetail = redactGuwahDiagnosticText(detailText).replace(/\r?\n/g, " ").trim();
  if (redactedDetail.length === 0) {
    return base;
  }
  return `${base} ${redactedDetail}`;
}

/**
 * Writes a redacted diagnostic line to stderr only.
 * Never writes to stdout. Detail values are omitted unless explicitly requested,
 * and requested details are redacted before write.
 */
export function writeGuwahStderrDiagnostic(
  message: string,
  options?: {
    readonly detail?: unknown;
    readonly includeDetail?: boolean;
    readonly stderr?: Writable;
  },
): void {
  const line = formatGuwahDiagnosticLine(message, options?.detail, options?.includeDetail === true);
  const sink = options?.stderr ?? process.stderr;
  sink.write(`${line}\n`);
}

function failTransportClosed(error: unknown): void {
  writeGuwahStderrDiagnostic("Guwah gateway transport failed.", {
    detail: error,
  });
  process.exit(1);
}

function buildServerOptionsFromStdio(
  options?: GuwahStdioGatewayOptions,
): GuwahGatewayServerOptions | undefined {
  if (options === undefined) {
    return undefined;
  }
  const serverOptions: {
    mediatedTools?: readonly GuwahMediatedTool[];
    resolveMediatedTools?: () => readonly GuwahMediatedTool[];
    policyPath?: string;
    guard?: GuwahGuard;
    afterApproval?: (
      approved: Readonly<McpToolCallPayload>,
    ) => CallToolResult | Promise<CallToolResult>;
    activeRequests?: GuwahActiveRequestRegistry;
    requestTimeoutMs?: number;
    maxConcurrentCalls?: number;
  } = {};
  if (options.mediatedTools !== undefined) {
    serverOptions.mediatedTools = options.mediatedTools;
  }
  if (options.resolveMediatedTools !== undefined) {
    serverOptions.resolveMediatedTools = options.resolveMediatedTools;
  }
  if (options.policyPath !== undefined) {
    serverOptions.policyPath = options.policyPath;
  }
  if (options.guard !== undefined) {
    serverOptions.guard = options.guard;
  }
  if (options.afterApproval !== undefined) {
    serverOptions.afterApproval = options.afterApproval;
  }
  if (options.activeRequests !== undefined) {
    serverOptions.activeRequests = options.activeRequests;
  }
  if (options.requestTimeoutMs !== undefined) {
    serverOptions.requestTimeoutMs = options.requestTimeoutMs;
  }
  if (options.maxConcurrentCalls !== undefined) {
    serverOptions.maxConcurrentCalls = options.maxConcurrentCalls;
  }
  return serverOptions;
}

function resolveShutdownGraceMs(value: number | undefined): number {
  if (value === undefined) {
    return 5_000;
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  return 5_000;
}

/**
 * Starts the local MCP gateway on process stdio.
 * JSON-RPC is read from stdin and written to stdout only.
 * Startup, list, call, and shutdown must leave stdout free of logs and banners.
 * Malformed framing fails closed: refuse further messages, close transports, then diagnose.
 * Clean shutdown order: stop accepting, wait or time out active dispatches, then close transports.
 * Stdin EOF and SIGINT/SIGTERM begin that ordered shutdown when enabled.
 * Broken stdout (EPIPE) is a terminal transport failure; further writes are suppressed.
 * When maxConcurrentCalls is set, stdin reading pauses at the bound and resumes when a slot frees.
 * Framing intake is capped by maxBufferSize; overflow and backpressure faults fail closed.
 * Transport errors terminate fail-closed via stderr.
 */
export async function startGuwahStdioGateway(
  options?: GuwahStdioGatewayOptions,
): Promise<{ readonly server: Server; readonly transport: StdioServerTransport }> {
  const stdinStream = options?.stdin ?? process.stdin;
  const stdoutStream = options?.stdout ?? process.stdout;
  const shutdownGraceMs = resolveShutdownGraceMs(options?.shutdownGraceMs);
  const maxConcurrentCalls = resolveMaxConcurrentCalls(options?.maxConcurrentCalls);
  let acceptingNewMessages = true;
  let outboundClosed = false;
  let activeDispatches = 0;
  let stdinPausedForBackpressure = false;
  const idleWaiters: Array<() => void> = [];
  const activeRequests = options?.activeRequests ?? new GuwahActiveRequestRegistry();

  const notifyIdle = (): void => {
    if (activeDispatches !== 0) {
      return;
    }
    const waiters = idleWaiters.splice(0, idleWaiters.length);
    for (const waiter of waiters) {
      waiter();
    }
  };

  const waitForIdleDispatches = async (): Promise<"idle" | "timeout"> => {
    if (activeDispatches === 0) {
      return "idle";
    }
    if (shutdownGraceMs === 0) {
      return "timeout";
    }
    return await Promise.race([
      new Promise<"idle">((resolve) => {
        idleWaiters.push(() => {
          resolve("idle");
        });
      }),
      new Promise<"timeout">((resolve) => {
        setTimeout(() => {
          resolve("timeout");
        }, shutdownGraceMs);
      }),
    ]);
  };

  const syncStdinBackpressure = (activeCount: number): void => {
    if (maxConcurrentCalls === undefined) {
      return;
    }
    const shouldPause = activeCount >= maxConcurrentCalls;
    try {
      if (shouldPause) {
        if (!stdinPausedForBackpressure) {
          stdinStream.pause();
          stdinPausedForBackpressure = true;
        }
        return;
      }
      if (stdinPausedForBackpressure) {
        stdinStream.resume();
        stdinPausedForBackpressure = false;
      }
    } catch (error: unknown) {
      // Pause/resume failure must not silently drop work; close fail-closed.
      failClosed(error instanceof Error ? error : new Error("stdin backpressure failed"));
    }
  };

  const userAfterApproval = options?.afterApproval ?? defaultAfterApproval;
  const serverOptions = buildServerOptionsFromStdio({
    ...options,
    activeRequests,
    afterApproval: async (approved) => {
      if (!acceptingNewMessages) {
        throw new McpError(ErrorCode.InternalError, "Gateway is shutting down.");
      }
      activeDispatches += 1;
      try {
        // Re-check after booking the slot so shutdown cannot sneak a second dispatch.
        if (!acceptingNewMessages) {
          throw new McpError(ErrorCode.InternalError, "Gateway is shutting down.");
        }
        return await userAfterApproval(approved);
      } finally {
        activeDispatches = Math.max(0, activeDispatches - 1);
        notifyIdle();
      }
    },
  });
  const server = createGuwahGatewayServer({
    ...serverOptions,
    onActiveCountChange: syncStdinBackpressure,
  });
  const transport = createGuwahStdioTransport(
    stdinStream,
    stdoutStream,
    options?.maxBufferSize === undefined
      ? undefined
      : { maxBufferSize: options.maxBufferSize },
  );

  const onTransportFailure = options?.onTransportFailure ?? failTransportClosed;
  const onStdinEof = options?.onStdinEof;
  const onTerminationSignal = options?.onTerminationSignal;
  const signalHost = options?.terminationSignalHost ?? process;
  const watchedSignals = ["SIGINT", "SIGTERM"] as const satisfies readonly NodeJS.Signals[];
  const signalListeners = new Map<NodeJS.Signals, () => void>();

  const detachStdinEof = (): void => {
    stdinStream.off("end", onStdinEnd);
  };

  const detachStdoutError = (): void => {
    stdoutStream.off("error", onStdoutError);
  };

  const detachTerminationSignals = (): void => {
    for (const [signal, listener] of signalListeners) {
      try {
        signalHost.off(signal, listener);
      } catch {
        // Unsupported or already removed.
      }
    }
    signalListeners.clear();
  };

  const cleanupGateway = async (): Promise<void> => {
    detachStdinEof();
    detachStdoutError();
    detachTerminationSignals();
    try {
      await server.close();
    } catch {
      // Cleanup must not throw into the transport loop.
    }
    try {
      await transport.close();
    } catch {
      // Cleanup must not throw into the transport loop.
    }
  };

  const failClosed = (error: unknown): void => {
    if (!acceptingNewMessages && outboundClosed) {
      return;
    }
    acceptingNewMessages = false;
    outboundClosed = true;
    void (async () => {
      await cleanupGateway();
      onTransportFailure(error);
    })();
  };

  const beginCleanShutdown = (after: () => void): void => {
    if (!acceptingNewMessages) {
      return;
    }
    // 1) Stop accepting new work.
    acceptingNewMessages = false;
    void (async () => {
      // 2) Wait for in-flight approved dispatches, or time out.
      const waitOutcome = await waitForIdleDispatches();
      // Grace timeout seals remaining ids terminal so late success is dropped.
      if (waitOutcome === "timeout") {
        activeRequests.abortAllActive();
      }
      // 3) Suppress further outbound frames, then close transports.
      outboundClosed = true;
      await cleanupGateway();
      after();
    })();
  };

  const beginEofShutdown = (): void => {
    beginCleanShutdown(() => {
      onStdinEof?.();
    });
  };

  const beginSignalShutdown = (signal: NodeJS.Signals): void => {
    beginCleanShutdown(() => {
      onTerminationSignal?.(signal);
    });
  };

  function onStdinEnd(): void {
    beginEofShutdown();
  }

  function onStdoutError(error: Error): void {
    // Broken pipe and other stdout faults are terminal; do not dump payloads.
    failClosed(error);
  }

  transport.onerror = (error: Error) => {
    failClosed(error);
  };
  server.onerror = (error: Error) => {
    failClosed(error);
  };
  stdinStream.on("end", onStdinEnd);
  stdoutStream.on("error", onStdoutError);

  if (options?.enableTerminationSignals === true) {
    for (const signal of watchedSignals) {
      const listener = (): void => {
        beginSignalShutdown(signal);
      };
      try {
        signalHost.on(signal, listener);
        signalListeners.set(signal, listener);
      } catch {
        // Platform may not allow registering this signal.
      }
    }
  }

  await server.connect(transport);

  // Official stdio parse errors call onerror but keep reading the buffer.
  // Block subsequent onmessage dispatch after the first failure, EOF, or signal.
  type TransportMessageHandler = (message: unknown, extra?: unknown) => void;
  const priorOnMessage = transport.onmessage as TransportMessageHandler | undefined;
  const guardedOnMessage: TransportMessageHandler = (message, extra) => {
    if (!acceptingNewMessages) {
      return;
    }
    priorOnMessage?.(message, extra);
  };
  transport.onmessage = guardedOnMessage as NonNullable<typeof transport.onmessage>;

  const priorSend = transport.send.bind(transport);
  transport.send = (async (message) => {
    if (outboundClosed) {
      return;
    }
    try {
      await priorSend(message);
    } catch (error: unknown) {
      failClosed(error instanceof Error ? error : new Error("stdout write failed"));
    }
  }) as typeof transport.send;

  return { server, transport };
}

function isGatewayEntry(): boolean {
  const invoked = process.argv[1];
  if (invoked === undefined) {
    return false;
  }
  return path.resolve(fileURLToPath(import.meta.url)) === path.resolve(invoked);
}

function failStartup(): void {
  writeGuwahStderrDiagnostic("Guwah gateway failed to start.");
  process.exit(1);
}

if (isGatewayEntry()) {
  startGuwahStdioGateway({
    enableTerminationSignals: true,
    onStdinEof: () => {
      process.exit(0);
    },
    onTerminationSignal: () => {
      process.exit(0);
    },
  }).catch(() => {
    failStartup();
  });
}
