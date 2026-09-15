import { JSONRPC_VERSION } from "@modelcontextprotocol/sdk/types.js";
import {
  GuwahGuard,
  GuwahSecurityViolation,
  type McpToolCallPayload,
} from "./guwahGuard.js";

/**
 * Host-facing MCP `tools/call` adapter.
 * Every approval decision is made by `GuwahGuard`. This module must not
 * implement a parallel policy engine, skip validation, or open a downstream client.
 */
export class GuwahMcpAdapter {
  public constructor(private readonly guard: GuwahGuard) {
    if (JSONRPC_VERSION !== "2.0") {
      throw new GuwahSecurityViolation({
        code: "INTERNAL_VALIDATION_ERROR",
        message: "Protocol adapter cannot operate with an incompatible SDK.",
      });
    }
  }

  public approveToolCall(request: unknown): Readonly<McpToolCallPayload> {
    try {
      return this.guard.validateToolCall(request, candidateArguments(request));
    } catch (error: unknown) {
      if (error instanceof GuwahSecurityViolation) {
        throw error;
      }
      throw new GuwahSecurityViolation({
        code: "INTERNAL_VALIDATION_ERROR",
        message: "Protocol adapter terminated without approval.",
        cause: error instanceof Error ? error : undefined,
      });
    }
  }
}

function candidateArguments(request: unknown): unknown {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return {};
  }
  if (!Object.prototype.hasOwnProperty.call(request, "params")) {
    return {};
  }
  const params: unknown = Reflect.get(request, "params");
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    return {};
  }
  if (!Object.prototype.hasOwnProperty.call(params, "arguments")) {
    return {};
  }
  return Reflect.get(params, "arguments");
}
