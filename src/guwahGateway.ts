import path from "node:path";
import { readFileSync } from "node:fs";
import type { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
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
import {
  GuwahGuard,
  GuwahSecurityViolation,
  resolveGuwahLivePolicyPath,
  type GuwahViolationCode,
  type McpToolCallPayload,
} from "./guwahGuard.js";

export const GUWAH_GATEWAY_NAME = "guwah";
export const GUWAH_GATEWAY_VERSION = "0.1.0";
export const GUWAH_DOWNSTREAM_CLIENT_NAME = "guwah-downstream";
export const GUWAH_DOWNSTREAM_CLIENT_VERSION = GUWAH_GATEWAY_VERSION;
export const GUWAH_DOWNSTREAM_TRANSPORT_CONFIG_ERROR =
  "Downstream transport configuration is missing or invalid.";
export const GUWAH_DOWNSTREAM_CONNECTION_ERROR = "Downstream MCP connection failed.";
export const GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR = "Downstream MCP connection is dead.";
export const GUWAH_DOWNSTREAM_RECONNECTING_ERROR = "Downstream MCP reconnection is in progress.";
export const GUWAH_DOWNSTREAM_RECONNECT_FAILED_ERROR =
  "Downstream MCP reconnection failed before discovery and policy intersection.";
export const GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_ERROR =
  "Downstream call outcome is unknown after connection loss or reconnect.";
export const GUWAH_DOWNSTREAM_UNAVAILABLE_CODE = "DOWNSTREAM_UNAVAILABLE";
export const GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_CODE = "DOWNSTREAM_OUTCOME_UNKNOWN";
export const GUWAH_DOWNSTREAM_FAILURE_ERROR = "Downstream tool call failed.";
export const GUWAH_DOWNSTREAM_FAILURE_CODE = "DOWNSTREAM_FAILURE";
export const GUWAH_TOOL_NAMESPACE_PREFIX = "guwah__";
export const GUWAH_TOOL_NAMESPACE_ERROR = "Gateway tool name is ambiguous or invalid.";
export const GUWAH_TOOL_COLLISION_ERROR = "Gateway tool name collision.";

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
 * Maps a downstream tool failure to a secret-free gateway MCP error.
 * Downstream messages are never copied; they may contain credentials or arguments.
 */
export function mapGuwahDownstreamFailureToMcpError(_error: unknown): McpError {
  return new McpError(ErrorCode.InternalError, GUWAH_DOWNSTREAM_FAILURE_ERROR, {
    guwahCode: GUWAH_DOWNSTREAM_FAILURE_CODE,
  });
}

/**
 * True when an MCP error was emitted by Guwah with a stable operator message.
 * Downstream SDK/provider errors must not match and must be remapped.
 */
export function isGuwahEmittedMcpError(error: McpError): boolean {
  const data = error.data as { guwahCode?: unknown } | undefined;
  if (typeof data?.guwahCode === "string" && data.guwahCode.length > 0) {
    return true;
  }
  const trustedMessages = new Set<string>([
    "Tool call was cancelled.",
    "Tool call deadline expired.",
    "Tool call aborted during shutdown.",
    "Tool call is no longer active.",
    "Gateway is not initialized.",
    "Tool call is missing a request id.",
    "Duplicate request id is already active.",
    "Concurrent tool call limit reached.",
    "Gateway tool catalog is unavailable.",
    "Gateway is shutting down.",
    "Tool call handling failed.",
    GUWAH_DOWNSTREAM_FAILURE_ERROR,
    GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR,
    GUWAH_DOWNSTREAM_RECONNECTING_ERROR,
    GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_ERROR,
  ]);
  // McpError prefixes messages as "MCP error <code>: <operator text>".
  const operatorText = error.message.replace(/^MCP error -?\d+:\s*/u, "");
  return trustedMessages.has(error.message) || trustedMessages.has(operatorText);
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
 * `name` is the host-facing gateway name. `downstreamName` is the raw downstream
 * tool name used for local policy and forwarding when namespacing is applied.
 */
/**
 * Authorized mediated catalog entry surfaced on tools/list and tools/call.
 * Tools are treated as mutating unless explicitly classified otherwise.
 * Automatic retry is never performed for mutating tools; read-only retry is out of scope.
 */
export type GuwahToolSideEffectClass = "mutating" | "read-only";

export type GuwahMediatedTool = {
  readonly name: string;
  readonly downstreamName?: string;
  readonly description?: string;
  readonly inputSchema: Tool["inputSchema"];
  /**
   * Explicit side-effect class. When omitted, the tool is mutating.
   */
  readonly sideEffectClass?: GuwahToolSideEffectClass;
};

/**
 * Resolves the side-effect class for a mediated tool.
 * Unclassified tools are mutating (fail-closed against automatic retry).
 */
export function classifyGuwahToolSideEffect(
  tool: Pick<GuwahMediatedTool, "sideEffectClass"> | GuwahToolSideEffectClass | undefined,
): GuwahToolSideEffectClass {
  if (tool === undefined) {
    return "mutating";
  }
  if (tool === "mutating" || tool === "read-only") {
    return tool;
  }
  return tool.sideEffectClass === "read-only" ? "read-only" : "mutating";
}

/**
 * Whether the gateway may automatically retry a downstream tools/call.
 * Always false today: mutating tools never auto-retry, and read-only retry is not defined.
 */
export function guwahToolAllowsAutomaticRetry(
  tool: Pick<GuwahMediatedTool, "sideEffectClass"> | GuwahToolSideEffectClass | undefined,
): boolean {
  // Classification is recorded for operators; automatic retry remains prohibited.
  void classifyGuwahToolSideEffect(tool);
  return false;
}

/**
 * MCP params._meta key for an explicit Guwah idempotency key.
 * Provider-native idempotency APIs are out of scope.
 */
export const GUWAH_IDEMPOTENCY_META_KEY = "guwah/idempotencyKey";

/**
 * Optional enforcer for reusing a prior outcome under an explicit idempotency key.
 * Must never match or coalesce on tool arguments alone.
 */
export type GuwahIdempotencyEnforcer = {
  readonly tryReuse: (key: string) => CallToolResult | undefined;
};

/**
 * Reads an explicit idempotency key from approved tool-call metadata.
 * Empty or non-string values are treated as absent.
 */
export function resolveGuwahIdempotencyKey(
  meta: Readonly<Record<string, unknown>> | undefined,
): string | undefined {
  if (meta === undefined) {
    return undefined;
  }
  const value = meta[GUWAH_IDEMPOTENCY_META_KEY];
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}

/**
 * Whether a mutating tools/call may reuse a prior outcome.
 * Requires both an explicit key and a configured enforcer.
 * Absent key (even with a duplicate payload) must never auto-deduplicate.
 */
export function guwahMayCoalesceMutatingCall(options: {
  readonly idempotencyKey: string | undefined;
  readonly enforcerConfigured: boolean;
}): boolean {
  return options.idempotencyKey !== undefined && options.enforcerConfigured === true;
}

export type GuwahAfterApprovalContext = {
  /**
   * Aborted when the host cancels the gateway tools/call.
   * Downstream dispatch must use this signal so cancel propagates as
   * notifications/cancelled — never as a second mutating tools/call.
   */
  readonly signal: AbortSignal;
};

export type GuwahAfterApprovalHandler = (
  approved: Readonly<McpToolCallPayload>,
  context: GuwahAfterApprovalContext,
) => CallToolResult | Promise<CallToolResult>;

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
  /**
   * Optional hook run before resolving the mediated catalog on tools/list and tools/call.
   * Used to refresh discovery and remirror under policy when the downstream list mutates.
   */
  readonly beforeResolveMediatedTools?: () => void | Promise<void>;
  readonly policyPath?: string;
  readonly guard?: GuwahGuard;
  /**
   * Invoked only after local validation approval.
   * Must never run for rejected calls. Defaults to a validator-only success with no downstream send.
   * Receives a cancel signal for propagating host cancellation downstream.
   */
  readonly afterApproval?: GuwahAfterApprovalHandler;
  /**
   * Optional idempotency enforcer. When omitted, every approved call is a new
   * dispatch even if the host repeats identical arguments.
   * Coalescing requires both this enforcer and an explicit idempotency key in _meta.
   */
  readonly idempotencyEnforcer?: GuwahIdempotencyEnforcer;
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
  readonly beforeResolveMediatedTools?: () => void | Promise<void>;
  readonly policyPath?: string;
  /**
   * Per-user configuration directory root for active-policy resolution and first-run
   * provisioning. Ignored when `guard` is set. When omitted with no `policyPath`, the
   * platform user-config base is used.
   */
  readonly configBaseDir?: string;
  /**
   * Optional packaged sample path for first-run provisioning. Defaults to the package
   * sample. The sample is never the live file when a distinct active policy exists.
   */
  readonly samplePolicyPath?: string;
  readonly guard?: GuwahGuard;
  readonly afterApproval?: GuwahAfterApprovalHandler;
  /**
   * Optional idempotency enforcer. When omitted, duplicate payloads are never coalesced.
   */
  readonly idempotencyEnforcer?: GuwahIdempotencyEnforcer;
  /**
   * Local path to downstream MCP transport configuration.
   * When set, the file must load and validate or startup fails closed.
   * When omitted, no downstream transport is configured (deny-all; no implicit localhost).
   */
  readonly downstreamTransportConfigPath?: string;
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

function defaultAfterApproval(
  _approved: Readonly<McpToolCallPayload>,
  _context: GuwahAfterApprovalContext,
): CallToolResult {
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
  options?: {
    readonly beforeResolveMediatedTools?: () => void | Promise<void>;
  },
): void {
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    try {
      if (options?.beforeResolveMediatedTools !== undefined) {
        await options.beforeResolveMediatedTools();
      }
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
    readonly beforeResolveMediatedTools?: () => void | Promise<void>;
    readonly guard: GuwahGuard;
    readonly afterApproval: GuwahAfterApprovalHandler;
    readonly activeRequests: GuwahActiveRequestRegistry;
    readonly requestTimeoutMs?: number;
    readonly maxConcurrentCalls?: number;
    readonly onActiveCountChange?: (activeCount: number) => void;
    readonly isHandshakeComplete: () => boolean;
    readonly idempotencyEnforcer?: GuwahIdempotencyEnforcer;
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

    // Linked to in-flight downstream tools/call; abort forwards notifications/cancelled.
    const downstreamCancel = new AbortController();
    const abortDownstream = (): void => {
      if (!downstreamCancel.signal.aborted) {
        // Terminal outcomes must stop the downstream wait so late bodies cannot become success.
        downstreamCancel.abort();
      }
    };
    const markCancelled = (): void => {
      options.activeRequests.tryCancel(requestId);
      abortDownstream();
    };
    if (extra.signal.aborted) {
      markCancelled();
    } else {
      extra.signal.addEventListener("abort", markCancelled, { once: true });
    }

    const markExpired = (): void => {
      options.activeRequests.tryExpire(requestId);
      abortDownstream();
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
        abortDownstream();
        throw new McpError(ErrorCode.InvalidRequest, "Tool call aborted during shutdown.");
      }
    };

    try {
      assertNotTerminal();

      if (options.beforeResolveMediatedTools !== undefined) {
        await options.beforeResolveMediatedTools();
      }

      let mediated: readonly GuwahMediatedTool[];
      try {
        mediated = options.resolveMediatedTools();
      } catch {
        throw new McpError(ErrorCode.InternalError, "Gateway tool catalog is unavailable.");
      }

      const toolName = request.params.name;
      // Match the gateway-facing name only; never alias a guessed raw downstream name.
      const mediatedTool = mediated.find((tool) => tool.name === toolName);
      if (mediatedTool === undefined) {
        // Unknown names are unauthorized by default; never reach afterApproval.
        throw new GuwahSecurityViolation({
          code: "UNAUTHORIZED_TOOL",
          message: "Requested tool is not authorized by local policy.",
          toolName,
          rule: "tool-allowlist",
        });
      }

      const policyToolName = mediatedTool.downstreamName ?? mediatedTool.name;
      const rawArguments = request.params.arguments ?? {};
      // Separate snapshots: parity compares embedded envelope args to candidate args.
      // Do not pass one shared reference as a trust-the-host shortcut.
      const candidateArgs = structuredClone(rawArguments);
      const params: Record<string, unknown> = {
        name: policyToolName,
        arguments: structuredClone(rawArguments),
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
      // Call path requires an explicit policy ENFORCE binding for the tool.
      options.guard.assertToolEnforced(policyToolName);
      // Policy argsSchema remains enforcement after discovery remirror; catalog inputSchema is not trusted.
      const approved = options.guard.validateToolCall(envelope, candidateArgs);
      assertNotTerminal();
      // Mutating calls never coalesce on payload alone. Reuse requires an explicit
      // idempotency key in _meta and a configured enforcer.
      const idempotencyKey = resolveGuwahIdempotencyKey(approved.params._meta);
      const enforcer = options.idempotencyEnforcer;
      if (
        idempotencyKey !== undefined &&
        enforcer !== undefined &&
        guwahMayCoalesceMutatingCall({
          idempotencyKey,
          enforcerConfigured: true,
        })
      ) {
        const reused = enforcer.tryReuse(idempotencyKey);
        if (reused !== undefined) {
          assertNotTerminal();
          return reused;
        }
      }
      // Forward only the frozen approved copy; never the original candidate object.
      const result = await options.afterApproval(approved, {
        signal: downstreamCancel.signal,
      });
      // Drop late success after a terminal outcome; never forward it upstream.
      assertNotTerminal();
      return result;
    } catch (error: unknown) {
      if (error instanceof GuwahSecurityViolation) {
        throw mapGuwahViolationToMcpError(error);
      }
      if (error instanceof McpError && isGuwahEmittedMcpError(error)) {
        throw error;
      }
      if (error instanceof McpError) {
        // Downstream or other untrusted MCP errors may embed secrets in message/data.
        throw mapGuwahDownstreamFailureToMcpError(error);
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
  const resolve: () => readonly GuwahMediatedTool[] = (() => {
    if (options?.resolveMediatedTools !== undefined) {
      return options.resolveMediatedTools;
    }
    const mediatedTools = options?.mediatedTools ?? [];
    return () => mediatedTools;
  })();
  return () => {
    const tools = resolve();
    // Startup/refresh collision check: shared gateway names fail closed.
    assertGuwahToolNamesUnique(tools);
    return tools;
  };
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
 * Constructs the official MCP SDK client for gateway-owned downstream mediation.
 * Used only by the gateway process. Validator and adapter modules must not import it.
 * Construction failure is fail-closed; never substitute an open-proxy client.
 */
export function createGuwahDownstreamClient(options?: {
  readonly name?: string;
  readonly version?: string;
}): Client {
  const name = options?.name ?? GUWAH_DOWNSTREAM_CLIENT_NAME;
  const version = options?.version ?? GUWAH_DOWNSTREAM_CLIENT_VERSION;
  if (typeof name !== "string" || name.trim().length === 0) {
    throw new Error("Downstream MCP client construction failed.");
  }
  if (typeof version !== "string" || version.trim().length === 0) {
    throw new Error("Downstream MCP client construction failed.");
  }
  try {
    return new Client({ name, version });
  } catch {
    // Fail closed: do not return a passthrough or unofficial substitute.
    throw new Error("Downstream MCP client construction failed.");
  }
}

/**
 * Forwards an approved tools/call to a downstream MCP client once.
 * Host cancel is propagated via AbortSignal → notifications/cancelled.
 * Never issues a second tools/call as a cancel substitute, and never retries
 * when cancel is unsupported or the request is aborted.
 * A result that arrives after the signal is aborted is discarded without logging
 * the body and is never returned as upstream success.
 * Timeout, reset, and error paths perform a single attempt only: tools are
 * mutating unless explicitly classified otherwise, and automatic retry is prohibited.
 */
export async function callGuwahDownstreamToolWithCancelPropagation(options: {
  readonly client: Pick<Client, "callTool">;
  readonly name: string;
  readonly arguments?: Record<string, unknown>;
  readonly signal: AbortSignal;
  /**
   * Optional mediated-tool classification. Omitted tools are mutating.
   * Does not enable automatic retry even when classified read-only.
   */
  readonly tool?: Pick<GuwahMediatedTool, "sideEffectClass">;
}): Promise<CallToolResult> {
  // Tools default to mutating; automatic retry is never performed (read-only retry out of scope).
  void classifyGuwahToolSideEffect(options.tool);
  const params: {
    name: string;
    arguments?: Record<string, unknown>;
  } = {
    name: options.name,
  };
  if (options.arguments !== undefined) {
    params.arguments = options.arguments;
  }
  try {
    // Single mutating dispatch. Abort uses protocol cancel notification only.
    const result = await options.client.callTool(params, undefined, {
      signal: options.signal,
    });
    // Late downstream success after terminal cancel/timeout: drop body, do not log it.
    if (options.signal.aborted) {
      throw new McpError(ErrorCode.InvalidRequest, "Tool call is no longer active.");
    }
    return result as CallToolResult;
  } catch (error: unknown) {
    if (options.signal.aborted) {
      throw new McpError(ErrorCode.InvalidRequest, "Tool call is no longer active.");
    }
    if (error instanceof McpError && isGuwahEmittedMcpError(error)) {
      throw error;
    }
    // Timeout, reset, or provider error: single attempt; never copy downstream text.
    throw mapGuwahDownstreamFailureToMcpError(error);
  }
}

/**
 * Local stdio spawn configuration for a downstream MCP server.
 * HTTP and SSE are not admitted. Cloud service catalogs are out of scope.
 */
export type GuwahDownstreamStdioTransportConfig = {
  readonly transport: "stdio";
  readonly command: string;
  readonly args?: readonly string[];
  readonly cwd?: string;
};

export type GuwahDownstreamTransportConfig = GuwahDownstreamStdioTransportConfig;

function failDownstreamTransportConfig(): never {
  throw new Error(GUWAH_DOWNSTREAM_TRANSPORT_CONFIG_ERROR);
}

function assertNonEmptyString(value: unknown): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    failDownstreamTransportConfig();
  }
  return value;
}

function parseDownstreamTransportConfig(raw: unknown): GuwahDownstreamTransportConfig {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    failDownstreamTransportConfig();
  }
  const record = raw as Record<string, unknown>;
  const keys = Object.keys(record);
  for (const key of keys) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") {
      failDownstreamTransportConfig();
    }
  }
  const allowed = new Set(["transport", "command", "args", "cwd"]);
  for (const key of keys) {
    if (!allowed.has(key)) {
      failDownstreamTransportConfig();
    }
  }
  if (record["transport"] !== "stdio") {
    // Only local stdio spawn is supported; do not invent an implicit localhost HTTP tool.
    failDownstreamTransportConfig();
  }
  const command = assertNonEmptyString(record["command"]);
  const config: {
    transport: "stdio";
    command: string;
    args?: readonly string[];
    cwd?: string;
  } = {
    transport: "stdio",
    command,
  };
  if (Object.prototype.hasOwnProperty.call(record, "args")) {
    const argsValue: unknown = record["args"];
    if (!Array.isArray(argsValue)) {
      failDownstreamTransportConfig();
    }
    const args: string[] = [];
    for (const entry of argsValue) {
      args.push(assertNonEmptyString(entry));
    }
    config.args = Object.freeze(args);
  }
  if (Object.prototype.hasOwnProperty.call(record, "cwd")) {
    config.cwd = assertNonEmptyString(record["cwd"]);
  }
  return Object.freeze(config);
}

/**
 * Loads and validates local downstream transport configuration from disk.
 * Missing files and invalid documents fail closed.
 */
export function loadGuwahDownstreamTransportConfig(
  configPath: string,
): GuwahDownstreamTransportConfig {
  if (typeof configPath !== "string" || configPath.trim().length === 0) {
    failDownstreamTransportConfig();
  }
  const resolved = path.resolve(configPath);
  let text: string;
  try {
    text = readFileSync(resolved, "utf8");
  } catch {
    failDownstreamTransportConfig();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    failDownstreamTransportConfig();
  }
  return parseDownstreamTransportConfig(parsed);
}

/**
 * Resolves optional downstream transport configuration.
 * Omitted path means deny-all: no downstream transport and no implicit localhost tool.
 * A provided path must load successfully or this throws.
 */
export function resolveGuwahDownstreamTransportConfig(options?: {
  readonly configPath?: string;
}): GuwahDownstreamTransportConfig | undefined {
  if (options?.configPath === undefined) {
    return undefined;
  }
  return loadGuwahDownstreamTransportConfig(options.configPath);
}

export type GuwahDownstreamConnection = {
  readonly client: Client;
  readonly transport: StdioClientTransport;
  readonly config: GuwahDownstreamTransportConfig;
  /**
   * False after process exit, EOF, or protocol death.
   * A stale (dead) connection must never be treated as healthy.
   */
  readonly isHealthy: () => boolean;
  /**
   * Fail closed for subsequent work when the downstream is dead.
   */
  readonly assertHealthy: () => void;
};

/**
 * Spawns/connects the official MCP downstream client using local transport config.
 * Connection failure is explicit and fail-closed. There is no automatic retry and no
 * silent success after a failed spawn or handshake.
 * After connect, exit/EOF/protocol death marks the connection dead fail-closed.
 * Automatic provider failover is not performed.
 * Downstream is a gateway-owned client only; it must not be bound as a second
 * host-visible MCP server on the gateway process stdio.
 */
export async function connectGuwahDownstream(
  config: GuwahDownstreamTransportConfig,
  options?: {
    readonly client?: Client;
    readonly onDead?: () => void;
  },
): Promise<GuwahDownstreamConnection> {
  if (config.transport !== "stdio") {
    throw new Error(GUWAH_DOWNSTREAM_CONNECTION_ERROR);
  }

  const client = options?.client ?? createGuwahDownstreamClient();
  const transportOptions: {
    command: string;
    args?: string[];
    cwd?: string;
    stderr: "pipe";
  } = {
    command: config.command,
    stderr: "pipe",
  };
  if (config.args !== undefined) {
    transportOptions.args = [...config.args];
  }
  if (config.cwd !== undefined) {
    transportOptions.cwd = config.cwd;
  }

  let transport: StdioClientTransport;
  try {
    transport = new StdioClientTransport(transportOptions);
  } catch {
    throw new Error(GUWAH_DOWNSTREAM_CONNECTION_ERROR);
  }

  try {
    // Single attempt only: non-mutating retries are not performed automatically.
    await client.connect(transport);
  } catch {
    try {
      await client.close();
    } catch {
      // Best-effort cleanup after an explicit connect failure.
    }
    try {
      await transport.close();
    } catch {
      // Best-effort cleanup after an explicit connect failure.
    }
    throw new Error(GUWAH_DOWNSTREAM_CONNECTION_ERROR);
  }

  let healthy = true;
  const markDead = (): void => {
    if (!healthy) {
      return;
    }
    // Exit, EOF, and protocol death all seal the connection; no failover reconnect.
    healthy = false;
    options?.onDead?.();
  };

  const priorOnClose = transport.onclose;
  transport.onclose = () => {
    // Child exit or stdin EOF closes the transport.
    markDead();
    priorOnClose?.();
  };
  const priorOnError = transport.onerror;
  transport.onerror = (error: Error) => {
    // Protocol death / transport fault.
    markDead();
    priorOnError?.(error);
  };

  return {
    client,
    transport,
    config,
    isHealthy: () => healthy,
    assertHealthy: () => {
      if (!healthy) {
        throw new Error(GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR);
      }
    },
  };
}

/**
 * Seals active request ids when reconnect begins.
 * Ambiguous in-flight work must not be reported as definitively unexecuted.
 * Does not dispatch a second mutating call.
 */
export function sealGuwahRequestsForFailClosedReconnect(
  activeRequests: GuwahActiveRequestRegistry,
): void {
  activeRequests.abortAllActive();
}

/**
 * Tracks an explicit reconnect window. While open, calls must fail closed.
 * Automatic failover is not performed; operators drive reconnect.
 */
export type GuwahDownstreamReconnectGate = {
  readonly isReconnecting: () => boolean;
  readonly assertNotReconnecting: () => void;
  readonly run: <T>(work: () => Promise<T>) => Promise<T>;
};

export function createGuwahDownstreamReconnectGate(): GuwahDownstreamReconnectGate {
  let reconnecting = false;
  return {
    isReconnecting: () => reconnecting,
    assertNotReconnecting: () => {
      if (reconnecting) {
        throw new Error(GUWAH_DOWNSTREAM_RECONNECTING_ERROR);
      }
    },
    run: async <T>(work: () => Promise<T>): Promise<T> => {
      if (reconnecting) {
        throw new Error(GUWAH_DOWNSTREAM_RECONNECTING_ERROR);
      }
      reconnecting = true;
      try {
        return await work();
      } finally {
        reconnecting = false;
      }
    },
  };
}

export type GuwahDownstreamReconnectResult = {
  readonly connection: GuwahDownstreamConnection;
  readonly discovered: readonly GuwahMediatedTool[];
  readonly mirrored: readonly GuwahMediatedTool[];
};

/**
 * Explicit fail-closed downstream reconnect.
 * Does not restore tools until connect, discovery, and policy intersection succeed.
 * Callers must clear the host catalog before invoking and assign `mirrored` only on success.
 * Does not retry in-flight mutating calls; seal active request ids separately first.
 * Automatic provider failover is not performed.
 */
export async function reconnectGuwahDownstreamFailClosed(options: {
  readonly config: GuwahDownstreamTransportConfig;
  readonly guard: GuwahGuard;
  readonly previousConnection?: GuwahDownstreamConnection;
}): Promise<GuwahDownstreamReconnectResult> {
  if (options.previousConnection !== undefined) {
    try {
      await options.previousConnection.client.close();
    } catch {
      // Best-effort close of the prior dead or stale connection.
    }
    try {
      await options.previousConnection.transport.close();
    } catch {
      // Best-effort close of the prior dead or stale connection.
    }
  }

  let connection: GuwahDownstreamConnection;
  try {
    connection = await connectGuwahDownstream(options.config);
  } catch {
    throw new Error(GUWAH_DOWNSTREAM_RECONNECT_FAILED_ERROR);
  }

  let discovered: readonly GuwahMediatedTool[];
  try {
    discovered = await discoverGuwahDownstreamTools(connection);
  } catch {
    try {
      await connection.client.close();
    } catch {
      // Best-effort cleanup after incomplete reconnect.
    }
    throw new Error(GUWAH_DOWNSTREAM_RECONNECT_FAILED_ERROR);
  }

  let mirrored: readonly GuwahMediatedTool[];
  try {
    // Tools restore only after discovery ∩ policy remirror succeeds.
    mirrored = remirrorGuwahToolsFromDiscovery(discovered, options.guard);
  } catch {
    try {
      await connection.client.close();
    } catch {
      // Best-effort cleanup after incomplete reconnect.
    }
    throw new Error(GUWAH_DOWNSTREAM_RECONNECT_FAILED_ERROR);
  }

  return Object.freeze({
    connection,
    discovered,
    mirrored,
  });
}

/**
 * Classifies whether a downstream dispatch may proceed or must fail closed.
 * Pre-dispatch unavailability is blocked locally.
 * Post-dispatch unavailability is outcome-unknown — never speculative success.
 * Does not claim provider-side rollback.
 */
export type GuwahDownstreamDispatchClassification =
  | "available"
  | "blocked-locally"
  | "outcome-unknown";

export function classifyGuwahDownstreamDispatchState(options: {
  readonly isHealthy: () => boolean;
  readonly isReconnecting?: () => boolean;
  readonly dispatchStarted: boolean;
}): GuwahDownstreamDispatchClassification {
  const reconnecting = options.isReconnecting?.() === true;
  const healthy = options.isHealthy();
  if (!options.dispatchStarted) {
    if (reconnecting || !healthy) {
      return "blocked-locally";
    }
    return "available";
  }
  if (reconnecting || !healthy) {
    return "outcome-unknown";
  }
  return "available";
}

export function mapGuwahDownstreamDispatchStateToMcpError(
  classification: Exclude<GuwahDownstreamDispatchClassification, "available">,
  options?: {
    readonly reconnecting?: boolean;
  },
): McpError {
  if (classification === "blocked-locally") {
    const message =
      options?.reconnecting === true
        ? GUWAH_DOWNSTREAM_RECONNECTING_ERROR
        : GUWAH_DOWNSTREAM_CONNECTION_DEAD_ERROR;
    return new McpError(ErrorCode.InternalError, message, {
      guwahCode: GUWAH_DOWNSTREAM_UNAVAILABLE_CODE,
    });
  }
  return new McpError(ErrorCode.InternalError, GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_ERROR, {
    guwahCode: GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_CODE,
  });
}

/**
 * Wraps afterApproval so unknown downstream state cannot produce speculative success.
 * Distinguishes blocked-locally (pre-dispatch) from outcome-unknown (post-dispatch).
 */
export function wrapGuwahAfterApprovalForDownstreamAmbiguity(options: {
  readonly afterApproval: GuwahAfterApprovalHandler;
  readonly isHealthy: () => boolean;
  readonly isReconnecting?: () => boolean;
}): GuwahAfterApprovalHandler {
  return async (approved, context) => {
    const reconnecting = options.isReconnecting?.() === true;
    const beforeState: {
      isHealthy: () => boolean;
      isReconnecting?: () => boolean;
      dispatchStarted: boolean;
    } = {
      isHealthy: options.isHealthy,
      dispatchStarted: false,
    };
    if (options.isReconnecting !== undefined) {
      beforeState.isReconnecting = options.isReconnecting;
    }
    const before = classifyGuwahDownstreamDispatchState(beforeState);
    if (before === "blocked-locally") {
      throw mapGuwahDownstreamDispatchStateToMcpError("blocked-locally", { reconnecting });
    }

    let dispatchStarted = false;
    try {
      dispatchStarted = true;
      const dispatchApproved = options.afterApproval;
      const result = await dispatchApproved(approved, context);
      const afterState: {
        isHealthy: () => boolean;
        isReconnecting?: () => boolean;
        dispatchStarted: boolean;
      } = {
        isHealthy: options.isHealthy,
        dispatchStarted: true,
      };
      if (options.isReconnecting !== undefined) {
        afterState.isReconnecting = options.isReconnecting;
      }
      const after = classifyGuwahDownstreamDispatchState(afterState);
      if (after !== "available") {
        // Disconnect or reconnect during/after dispatch: never speculative success.
        throw mapGuwahDownstreamDispatchStateToMcpError("outcome-unknown");
      }
      return result;
    } catch (error: unknown) {
      if (error instanceof McpError) {
        const data = error.data as { guwahCode?: unknown } | undefined;
        if (
          data?.guwahCode === GUWAH_DOWNSTREAM_OUTCOME_UNKNOWN_CODE ||
          data?.guwahCode === GUWAH_DOWNSTREAM_UNAVAILABLE_CODE ||
          data?.guwahCode === GUWAH_DOWNSTREAM_FAILURE_CODE
        ) {
          throw error;
        }
        if (isGuwahEmittedMcpError(error)) {
          throw error;
        }
        // Untrusted downstream MCP errors: never forward verbatim messages.
        throw mapGuwahDownstreamFailureToMcpError(error);
      }
      if (dispatchStarted) {
        const afterState: {
          isHealthy: () => boolean;
          isReconnecting?: () => boolean;
          dispatchStarted: boolean;
        } = {
          isHealthy: options.isHealthy,
          dispatchStarted: true,
        };
        if (options.isReconnecting !== undefined) {
          afterState.isReconnecting = options.isReconnecting;
        }
        const after = classifyGuwahDownstreamDispatchState(afterState);
        if (after === "outcome-unknown") {
          throw mapGuwahDownstreamDispatchStateToMcpError("outcome-unknown");
        }
      }
      // Non-MCP throws from dispatch are sanitized as downstream failures.
      throw mapGuwahDownstreamFailureToMcpError(error);
    }
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseDiscoveredTool(entry: unknown): GuwahMediatedTool | undefined {
  if (!isPlainObject(entry)) {
    return undefined;
  }
  if (typeof entry["name"] !== "string" || entry["name"].trim().length === 0) {
    return undefined;
  }
  if (!isPlainObject(entry["inputSchema"])) {
    return undefined;
  }
  // Catalog shape only. Downstream inputSchema is never trusted as policy.
  const tool: {
    name: string;
    description?: string;
    inputSchema: Tool["inputSchema"];
  } = {
    name: entry["name"],
    inputSchema: entry["inputSchema"] as Tool["inputSchema"],
  };
  if (typeof entry["description"] === "string") {
    tool.description = entry["description"];
  }
  return Object.freeze(tool);
}

/**
 * Runs tools/list against a healthy downstream connection.
 * Discovery errors and malformed list payloads yield an empty mediated set.
 * Never returns an unvalidated passthrough of downstream tool objects.
 * Downstream schemas are catalog metadata only and are not treated as policy.
 */
export async function discoverGuwahDownstreamTools(
  connection: Pick<GuwahDownstreamConnection, "client" | "isHealthy" | "assertHealthy">,
): Promise<readonly GuwahMediatedTool[]> {
  try {
    connection.assertHealthy();
  } catch {
    return Object.freeze([]);
  }
  if (!connection.isHealthy()) {
    return Object.freeze([]);
  }

  let listed: unknown;
  try {
    listed = await connection.client.listTools();
  } catch {
    // Discovery errors yield an empty mediated set, not passthrough.
    return Object.freeze([]);
  }

  if (!isPlainObject(listed) || !Object.prototype.hasOwnProperty.call(listed, "tools")) {
    return Object.freeze([]);
  }
  const toolsUnknown: unknown = listed["tools"];
  if (!Array.isArray(toolsUnknown)) {
    return Object.freeze([]);
  }

  const mediated: GuwahMediatedTool[] = [];
  for (const entry of toolsUnknown) {
    const parsed = parseDiscoveredTool(entry);
    if (parsed === undefined) {
      // Malformed list payloads are rejected entirely (no partial passthrough).
      return Object.freeze([]);
    }
    mediated.push(parsed);
  }
  return Object.freeze(mediated);
}

/**
 * Deterministic identity of a discovered tool for list-change detection.
 * Uses already-admitted mediated tool graphs only (not hostile runtime input).
 */
function fingerprintDiscoveredTool(tool: GuwahMediatedTool): string {
  return JSON.stringify({
    name: tool.name,
    description: tool.description ?? null,
    inputSchema: tool.inputSchema,
  });
}

/**
 * Stable fingerprint of a full discovery list.
 * Order-independent: tools are sorted by name before hashing.
 */
export function fingerprintGuwahDiscoveryList(
  tools: readonly GuwahMediatedTool[],
): string {
  const fingerprints = tools
    .map((tool) => ({ name: tool.name, fingerprint: fingerprintDiscoveredTool(tool) }))
    .sort((left, right) => {
      if (left.name < right.name) {
        return -1;
      }
      if (left.name > right.name) {
        return 1;
      }
      return 0;
    })
    .map((entry) => entry.fingerprint);
  return fingerprints.join("\n");
}

/**
 * Result of comparing two downstream discovery snapshots.
 * Detects list churn only; does not remirror under policy or update the gateway catalog.
 */
export type GuwahDiscoveryListChange = {
  readonly previous: readonly GuwahMediatedTool[];
  readonly current: readonly GuwahMediatedTool[];
  readonly changed: boolean;
  readonly addedNames: readonly string[];
  readonly removedNames: readonly string[];
  readonly changedSchemaNames: readonly string[];
  readonly previousFingerprint: string;
  readonly currentFingerprint: string;
};

/**
 * Compares two discovery snapshots for additions, removals, and retained-name schema drift.
 * Policy intersection and gateway catalog updates are out of scope.
 */
export function detectGuwahDiscoveryListChange(
  previous: readonly GuwahMediatedTool[],
  current: readonly GuwahMediatedTool[],
): GuwahDiscoveryListChange {
  const previousByName = new Map<string, GuwahMediatedTool>();
  for (const tool of previous) {
    previousByName.set(tool.name, tool);
  }
  const currentByName = new Map<string, GuwahMediatedTool>();
  for (const tool of current) {
    currentByName.set(tool.name, tool);
  }

  const addedNames: string[] = [];
  for (const name of currentByName.keys()) {
    if (!previousByName.has(name)) {
      addedNames.push(name);
    }
  }
  addedNames.sort();

  const removedNames: string[] = [];
  for (const name of previousByName.keys()) {
    if (!currentByName.has(name)) {
      removedNames.push(name);
    }
  }
  removedNames.sort();

  const changedSchemaNames: string[] = [];
  for (const [name, currentTool] of currentByName) {
    const previousTool = previousByName.get(name);
    if (
      previousTool !== undefined &&
      fingerprintDiscoveredTool(previousTool) !== fingerprintDiscoveredTool(currentTool)
    ) {
      changedSchemaNames.push(name);
    }
  }
  changedSchemaNames.sort();

  const previousFingerprint = fingerprintGuwahDiscoveryList(previous);
  const currentFingerprint = fingerprintGuwahDiscoveryList(current);

  return Object.freeze({
    previous: Object.freeze([...previous]),
    current: Object.freeze([...current]),
    changed: previousFingerprint !== currentFingerprint,
    addedNames: Object.freeze(addedNames),
    removedNames: Object.freeze(removedNames),
    changedSchemaNames: Object.freeze(changedSchemaNames),
    previousFingerprint,
    currentFingerprint,
  });
}

/**
 * Re-runs downstream tools/list and compares it to a previous discovery snapshot.
 * Establishes deterministic refresh detection for list churn.
 * Does not remirror authorized tools or widen the gateway allowlist.
 */
export async function pollGuwahDownstreamDiscovery(
  connection: Pick<GuwahDownstreamConnection, "client" | "isHealthy" | "assertHealthy">,
  previous: readonly GuwahMediatedTool[],
): Promise<GuwahDiscoveryListChange> {
  // Detection only: does not remirror authorized tools or update the gateway catalog.
  const current = await discoverGuwahDownstreamTools(connection);
  return detectGuwahDiscoveryListChange(previous, current);
}

/**
 * Intersects discovered downstream tools with local policy ENFORCE names.
 * Tools absent from policy are omitted from the gateway catalog (not advertised).
 * Does not auto-authorize newly discovered tools.
 * Catalog refresh must re-run this intersection; discovery churn alone cannot widen the allowlist.
 */
export function mirrorAuthorizedGuwahTools(
  discovered: readonly GuwahMediatedTool[],
  guard: GuwahGuard,
): readonly GuwahMediatedTool[] {
  let enforcedNames: ReadonlySet<string>;
  try {
    enforcedNames = new Set(guard.listEnforcedToolNames());
  } catch {
    // Policy load/parse failure → advertise nothing.
    return Object.freeze([]);
  }

  const mirrored: GuwahMediatedTool[] = [];
  for (const tool of discovered) {
    if (!enforcedNames.has(tool.name)) {
      // Extra downstream tools are omitted, not advertised.
      continue;
    }
    mirrored.push(tool);
  }
  return Object.freeze(mirrored);
}

/**
 * Recomputes the host-facing mirrored catalog from a discovery snapshot under policy.
 * Downstream inputSchema is catalog metadata only and is never treated as policy authority.
 */
export function remirrorGuwahToolsFromDiscovery(
  discovered: readonly GuwahMediatedTool[],
  guard: GuwahGuard,
): readonly GuwahMediatedTool[] {
  return applyGuwahToolNamespacing(mirrorAuthorizedGuwahTools(discovered, guard));
}

/**
 * Polls downstream tools/list and recomputes the mirrored set under local policy.
 * Removed tools disappear from the mirrored catalog.
 * Added tools remain omitted until human policy ENFORCE includes them.
 * Retained-name schema drift does not widen acceptance; policy argsSchema remains enforcement.
 */
export async function refreshGuwahMirroredToolsFromDiscovery(
  connection: Pick<GuwahDownstreamConnection, "client" | "isHealthy" | "assertHealthy">,
  previousDiscovery: readonly GuwahMediatedTool[],
  guard: GuwahGuard,
): Promise<{
  readonly change: GuwahDiscoveryListChange;
  readonly discovered: readonly GuwahMediatedTool[];
  readonly mirrored: readonly GuwahMediatedTool[];
}> {
  const change = await pollGuwahDownstreamDiscovery(connection, previousDiscovery);
  const discovered = change.current;
  const mirrored = remirrorGuwahToolsFromDiscovery(discovered, guard);
  return Object.freeze({
    change,
    discovered,
    mirrored,
  });
}

/**
 * Deterministic gateway tool naming algorithm:
 * 1. Downstream names must match `^[A-Za-z0-9][A-Za-z0-9_.-]*$`.
 * 2. Downstream names must not already begin with `guwah__` (ambiguous; rejected, not re-aliased).
 * 3. Gateway host name is exactly `guwah__` + downstream name.
 * The mapping is pure and stable: the same downstream name always yields the same gateway name.
 * Silent repair or operator rename UI is out of scope.
 */
export function namespaceGuwahToolName(downstreamName: string): string {
  if (typeof downstreamName !== "string" || downstreamName.trim().length === 0) {
    throw new Error(GUWAH_TOOL_NAMESPACE_ERROR);
  }
  if (downstreamName.startsWith(GUWAH_TOOL_NAMESPACE_PREFIX)) {
    // Already namespaced names are ambiguous in a host session; reject rather than alias silently.
    throw new Error(GUWAH_TOOL_NAMESPACE_ERROR);
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(downstreamName)) {
    throw new Error(GUWAH_TOOL_NAMESPACE_ERROR);
  }
  return `${GUWAH_TOOL_NAMESPACE_PREFIX}${downstreamName}`;
}

/**
 * Returns the raw downstream name when `gatewayName` uses the Guwah namespace prefix.
 */
export function parseGuwahGatewayToolName(gatewayName: string): string | undefined {
  if (typeof gatewayName !== "string" || !gatewayName.startsWith(GUWAH_TOOL_NAMESPACE_PREFIX)) {
    return undefined;
  }
  const downstreamName = gatewayName.slice(GUWAH_TOOL_NAMESPACE_PREFIX.length);
  if (downstreamName.length === 0) {
    return undefined;
  }
  return downstreamName;
}

/**
 * Applies deterministic host-facing namespacing to mirrored tools.
 * Rejects ambiguous downstream names instead of silently aliasing them.
 * Gateway `name` cannot equal the raw downstream name in the host session.
 * Duplicate gateway names fail closed with no merge and no automatic suffix repair.
 */
export function applyGuwahToolNamespacing(
  mirrored: readonly GuwahMediatedTool[],
): readonly GuwahMediatedTool[] {
  const namespaced: GuwahMediatedTool[] = [];
  const seenGatewayNames = new Set<string>();
  for (const tool of mirrored) {
    const downstreamName = tool.downstreamName ?? tool.name;
    const gatewayName = namespaceGuwahToolName(downstreamName);
    if (seenGatewayNames.has(gatewayName)) {
      // Collision is fail-closed; do not merge schemas or invent suffixes.
      throw new Error(GUWAH_TOOL_COLLISION_ERROR);
    }
    seenGatewayNames.add(gatewayName);
    const next: {
      name: string;
      downstreamName: string;
      description?: string;
      inputSchema: Tool["inputSchema"];
    } = {
      name: gatewayName,
      downstreamName,
      inputSchema: tool.inputSchema,
    };
    if (tool.description !== undefined) {
      next.description = tool.description;
    }
    namespaced.push(Object.freeze(next));
  }
  return Object.freeze(namespaced);
}

/**
 * Rejects catalogs where two tools share a host-facing gateway name.
 * Fail closed: no merged schema and no automatic suffixing.
 */
export function assertGuwahToolNamesUnique(tools: readonly GuwahMediatedTool[]): void {
  const seen = new Set<string>();
  for (const tool of tools) {
    if (typeof tool.name !== "string" || tool.name.trim().length === 0) {
      throw new Error(GUWAH_TOOL_COLLISION_ERROR);
    }
    if (seen.has(tool.name)) {
      throw new Error(GUWAH_TOOL_COLLISION_ERROR);
    }
    seen.add(tool.name);
  }
}

/**
 * Builds the MCP gateway server.
 * `initialize` and `initialized` are handled by the official SDK Server.
 * Advertised capabilities are limited to surfaces the gateway actually mediates.
 * tools/list returns only the authorized mediated set.
 * tools/call runs GuwahGuard.validateToolCall before any downstream send.
 * Only tools/call may execute tools; other methods must not smuggle dispatch.
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
  try {
    // Reject colliding gateway names at startup when the catalog can be resolved.
    resolveMediatedTools();
  } catch (error: unknown) {
    if (error instanceof Error && error.message === GUWAH_TOOL_COLLISION_ERROR) {
      throw error;
    }
    // Non-collision catalog failures remain deferred to list/call handlers.
  }
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
    beforeResolveMediatedTools?: () => void | Promise<void>;
    guard: GuwahGuard;
    afterApproval: GuwahAfterApprovalHandler;
    activeRequests: GuwahActiveRequestRegistry;
    requestTimeoutMs?: number;
    maxConcurrentCalls?: number;
    onActiveCountChange?: (activeCount: number) => void;
    isHandshakeComplete: () => boolean;
    idempotencyEnforcer?: GuwahIdempotencyEnforcer;
  } = {
    resolveMediatedTools,
    guard: resolveGuard(options),
    afterApproval: options?.afterApproval ?? defaultAfterApproval,
    activeRequests,
    isHandshakeComplete,
  };
  if (options?.beforeResolveMediatedTools !== undefined) {
    callOptions.beforeResolveMediatedTools = options.beforeResolveMediatedTools;
  }
  if (requestTimeoutMs !== undefined) {
    callOptions.requestTimeoutMs = requestTimeoutMs;
  }
  if (maxConcurrentCalls !== undefined) {
    callOptions.maxConcurrentCalls = maxConcurrentCalls;
  }
  if (options?.onActiveCountChange !== undefined) {
    callOptions.onActiveCountChange = options.onActiveCountChange;
  }
  if (options?.idempotencyEnforcer !== undefined) {
    callOptions.idempotencyEnforcer = options.idempotencyEnforcer;
  }
  const listOptions =
    options?.beforeResolveMediatedTools === undefined
      ? undefined
      : { beforeResolveMediatedTools: options.beforeResolveMediatedTools };
  registerGatewayToolsList(server, resolveMediatedTools, listOptions);
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
    beforeResolveMediatedTools?: () => void | Promise<void>;
    policyPath?: string;
    guard?: GuwahGuard;
    afterApproval?: GuwahAfterApprovalHandler;
    idempotencyEnforcer?: GuwahIdempotencyEnforcer;
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
  if (options.beforeResolveMediatedTools !== undefined) {
    serverOptions.beforeResolveMediatedTools = options.beforeResolveMediatedTools;
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
  if (options.idempotencyEnforcer !== undefined) {
    serverOptions.idempotencyEnforcer = options.idempotencyEnforcer;
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
): Promise<{
  readonly server: Server;
  readonly transport: StdioServerTransport;
  readonly downstream?: GuwahDownstreamConnection;
  /** Absolute path of the live active policy used by this gateway process. */
  readonly activePolicyPath?: string;
}> {
  // Reject invalid concurrency bounds before provisioning or connecting.
  const maxConcurrentCalls = resolveMaxConcurrentCalls(options?.maxConcurrentCalls);

  // Validate downstream transport config before provisioning so bad config fails closed
  // without touching the active policy path.
  const downstreamConfig =
    options?.downstreamTransportConfigPath !== undefined
      ? loadGuwahDownstreamTransportConfig(options.downstreamTransportConfigPath)
      : undefined;

  // Missing path => deny-all (no implicit localhost). Provided path must validate and connect.
  let downstreamConnection: GuwahDownstreamConnection | undefined;
  let lastDiscoveredTools: readonly GuwahMediatedTool[] | undefined;
  let mirroredMediatedTools: readonly GuwahMediatedTool[] | undefined;
  let discoveryGuard: GuwahGuard | undefined;
  let activePolicyPath: string | undefined;
  if (options?.guard !== undefined) {
    activePolicyPath = options.guard.getActivePolicyPath();
  } else {
    const liveOptions: {
      configBaseDir?: string;
      samplePolicyPath?: string;
      policyPath?: string;
    } = {};
    if (options?.configBaseDir !== undefined) {
      liveOptions.configBaseDir = options.configBaseDir;
    }
    if (options?.samplePolicyPath !== undefined) {
      liveOptions.samplePolicyPath = options.samplePolicyPath;
    }
    if (options?.policyPath !== undefined) {
      liveOptions.policyPath = options.policyPath;
    }
    // Stdio startup provisions and binds the active path, not the packaged sample.
    activePolicyPath = resolveGuwahLivePolicyPath(liveOptions);
  }
  if (downstreamConfig !== undefined) {
    // Failed connect must not proceed to a tool-exposing gateway server.
    downstreamConnection = await connectGuwahDownstream(downstreamConfig);
    discoveryGuard =
      options?.guard !== undefined
        ? options.guard
        : new GuwahGuard({
            policyPath: activePolicyPath,
          });
    const discovered = await discoverGuwahDownstreamTools(downstreamConnection);
    lastDiscoveredTools = discovered;
    // Gateway tools/list is policy ∩ discovery; extras are omitted, never auto-authorized.
    // Host-facing names are deterministically namespaced away from raw downstream names.
    mirroredMediatedTools = remirrorGuwahToolsFromDiscovery(discovered, discoveryGuard);
  }

  const refreshMirroredCatalogFromDiscovery = async (): Promise<void> => {
    if (
      downstreamConnection === undefined ||
      discoveryGuard === undefined ||
      lastDiscoveredTools === undefined
    ) {
      return;
    }
    const refreshed = await refreshGuwahMirroredToolsFromDiscovery(
      downstreamConnection,
      lastDiscoveredTools,
      discoveryGuard,
    );
    lastDiscoveredTools = refreshed.discovered;
    mirroredMediatedTools = refreshed.mirrored;
  };

  const stdinStream = options?.stdin ?? process.stdin;
  const stdoutStream = options?.stdout ?? process.stdout;
  const shutdownGraceMs = resolveShutdownGraceMs(options?.shutdownGraceMs);
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
  const guardedAfterApproval =
    downstreamConnection === undefined
      ? userAfterApproval
      : wrapGuwahAfterApprovalForDownstreamAmbiguity({
          afterApproval: userAfterApproval,
          isHealthy: () => downstreamConnection?.isHealthy() === true,
        });
  const serverOptions = buildServerOptionsFromStdio({
    ...options,
    ...(options?.guard === undefined && activePolicyPath !== undefined
      ? { policyPath: activePolicyPath }
      : {}),
    ...(mirroredMediatedTools !== undefined
      ? {
          resolveMediatedTools: () => mirroredMediatedTools ?? Object.freeze([]),
          beforeResolveMediatedTools: refreshMirroredCatalogFromDiscovery,
        }
      : {}),
    activeRequests,
    afterApproval: async (approved, context) => {
      if (!acceptingNewMessages) {
        throw new McpError(ErrorCode.InternalError, "Gateway is shutting down.");
      }
      activeDispatches += 1;
      try {
        // Re-check after booking the slot so shutdown cannot sneak a second dispatch.
        if (!acceptingNewMessages) {
          throw new McpError(ErrorCode.InternalError, "Gateway is shutting down.");
        }
        // Pre-dispatch unavailability is blocked locally; mid-dispatch death is outcome-unknown.
        return await guardedAfterApproval(approved, context);
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
    if (downstreamConnection !== undefined) {
      try {
        await downstreamConnection.client.close();
      } catch {
        // Cleanup must not throw into the transport loop.
      }
      try {
        await downstreamConnection.transport.close();
      } catch {
        // Cleanup must not throw into the transport loop.
      }
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

  if (downstreamConnection === undefined) {
    return activePolicyPath === undefined
      ? { server, transport }
      : { server, transport, activePolicyPath };
  }
  return activePolicyPath === undefined
    ? { server, transport, downstream: downstreamConnection }
    : { server, transport, downstream: downstreamConnection, activePolicyPath };
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
  // Host-facing entry starts only the gateway server on process stdio.
  // Downstream clients, when configured, are not registered as additional host servers.
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
