# GUWAH Protocol Extension

**Gateway User-Whitelist Agent Hub**

Local, fail-closed policy enforcement for Model Context Protocol `tools/call` payloads.

---

## Purpose

Guwah is a local, client-side policy enforcement layer for Model Context Protocol tool execution. It intercepts the complete candidate `tools/call` envelope and the separately supplied arguments, then evaluates both against a fail-closed JSON Schema policy before an integrating runtime may serialize any network request. The primary threat model is Client-Runtime Payload Mutation: agent-generated or mutated arguments that would otherwise authorize an unintended transfer or destructive operation. Guwah does not transmit, sign, or settle transactions, and local validation does not eliminate financial liability.

| Property | Binding |
|---|---|
| Execution locus | Local process |
| Trust posture | Default deny |
| Transport | None in the core validator; stdio in the gateway entry |
| Provider coupling | None; MCP SDK agnostic |
| Financial units | Integer minor units (`amountMinor`) |
| Failure mode | Throw `GuwahSecurityViolation` |

---

## Execution Model

The core validator terminates at local approval or denial. The gateway entry speaks MCP over stdio and completes the official `initialize` / `initialized` handshake. Advertised capabilities stay limited to surfaces the gateway actually mediates; `tools/list` returns only the authorized mediated tool set. `tools/call` runs local Guwah validation before any downstream send. Unimplemented resources, prompts, and sampling are not claimed. Downstream tool execution is not configured by default.

```text
  [ Agent runtime ]
          |
          |  untrusted MCP tools/call payload
          |  + candidate arguments
          v
  +--------------------------------------------------+
  |                 GuwahGuard                       |
  |  1. JSON-compatible bounded graph validation     |
  |  2. Policy load, size check, structural bounds   |
  |  3. Tool resolution (default deny)               |
  |  4. Embedded vs candidate argument parity        |
  |  5. Ajv argument validation (no coercion)        |
  +----------------------+---------------------------+
                         |
          +--------------+--------------+
          |                             |
          v                             v
  GuwahSecurityViolation     Frozen approved envelope
  (blocked; do not send)     (defensive copy only)
                                        |
                                        |  integrator serializes
                                        |  the approved value only
                                        v
                         [ Integrator-owned transport ]
                                        |
                                        v
                         [ External tool server ]
```

`params._meta`, when present, is optional MCP protocol metadata. It is preserved in the approved copy, included in JSON-graph and resource-limit checks, and is not validated against the tool `argsSchema` or compared with candidate arguments.

Vendor APIs (for example, a Coinbase-named mock tool in the sample policy) are downstream of the integrator. The core validator does not import Stripe, Coinbase, or MCP vendor SDKs and does not open sockets. The protocol adapter imports the official MCP TypeScript SDK for host `tools/call` shaping only and still delegates every approval to `GuwahGuard`. The gateway entry uses the official SDK `Server` and stdio transport so a conforming client can complete `initialize` and `initialized`. `tools/call` is refused until that handshake completes successfully, so a malformed or failed initialize cannot reach downstream dispatch. Capability negotiation returns only registered surfaces. `tools/list` returns the gateway-mediated catalog only and never an unfiltered downstream tool dump. When downstream discovery is configured, host-facing tool names are deterministically namespaced as `guwah__` plus the raw downstream name so they cannot collide with raw downstream names in the host session; names that already use that prefix or fail the allowed character pattern are rejected rather than silently aliased. `tools/call` runs `GuwahGuard.validateToolCall` on the complete envelope and candidate arguments before any downstream send; rejected calls never dispatch. In-flight `tools/call` request ids are tracked explicitly; duplicate ids are rejected and completed ids are removed. MCP `notifications/cancelled` cancels in-flight work and suppresses late success responses without automatic retry. Optional per-request deadlines (`requestTimeoutMs`) expire fail-closed so expired calls do not dispatch after expiry and are not retried. Results that arrive after cancel, deadline expiry, or shutdown abort are dropped so a client never receives a success after a terminal error for the same request id. Optional `maxConcurrentCalls` rejects excess in-flight `tools/call` requests fail-closed without queuing. When that bound is set, the stdio gateway pauses stdin reading at saturation and resumes when a slot frees; framing intake is capped by `maxBufferSize` (10 MiB when omitted). Buffer overflow or stdin pause/resume failure closes fail-closed rather than dropping validations. Protocol and security failures return JSON-RPC error objects; each `GuwahSecurityViolation` code maps to a fixed sanitized MCP error with an operator `guwahCode`, and unexpected handler exceptions become a generic internal error without rejected values. JSON-RPC is read from stdin and written to stdout only; stdout is reserved for protocol frames during startup, list, call, and shutdown. Malformed stdio framing fails closed without dispatch. Clean shutdown stops accepting work, waits or times out in-flight approved dispatches, then closes transports without corrupting stdout. Stdin EOF and SIGINT/SIGTERM begin that ordered shutdown. Broken stdout (including EPIPE) is a terminal transport failure; further protocol writes are suppressed. Diagnostics use a redacted stderr logger that omits detail by default and never emits credentials, full payloads, or policy text. Transport failures terminate fail-closed. HTTP and SSE transports are not used.

---

## Quick Start and Verification

Requires Node.js `^20.19.0 || >=22.12.0`.

```bash
git clone <repository-url> guwah-mcp-extension
cd guwah-mcp-extension
npm ci
npm test
```

Implementation verification:

```bash
npm run typecheck
npm run build
npm test
```

The suite covers approved transfers, amount and destination policy failures, payload-mutation detection, JSON-compatibility rejection, MCP `_meta` handling, policy-load failures, resource limits, and immutability of approved envelopes. A passing suite is necessary for local development. It does not prove the implementation secure against every threat.

---

## Core Architecture

```text
src/guwahGuard.ts         Runtime validation engine
src/guwahMcpAdapter.ts    Host tools/call adapter; calls GuwahGuard
src/guwahGateway.ts       Node stdio gateway entry
test/guwahGuard.test.ts
test/guwahMcpAdapter.test.ts
test/guwahGateway.test.ts
guwah-policy.json         Local operator policy
package.json
tsconfig.json             Shared typecheck configuration
tsconfig.build.json       Production emit (src only)
vitest.config.ts
LICENSE
```

`npm run build` writes runtime artifacts under `dist/` (`guwahGuard.js`, `guwahMcpAdapter.js`, `guwahGateway.js`, and corresponding declarations and source maps). Test sources are not emitted. The package export remains the validator module. `npm run gateway` (or `node dist/guwahGateway.js`) starts the stdio gateway.

### Host deployment boundary

Intended deployment exposes only the Guwah gateway process to the host MCP client. Start that process with `npm run gateway` or `node dist/guwahGateway.js`. Configured downstream MCP servers are attached as gateway-owned clients over a separate transport and are not registered by this package as additional host-visible MCP servers. Pointing a host client at an unprotected downstream process bypasses Guwah and is outside the intended deployment.

### `src/guwahGuard.ts`

Runtime exports include `GuwahGuard`, `GuwahSecurityViolation`, and `DEFAULT_GUWAH_RESOURCE_LIMITS`. The module also exports TypeScript interfaces and violation-code types for integration. The public method accepts runtime-unknown values because agent and host objects cannot be trusted at the type boundary:

```ts
validateToolCall(
  payload: unknown,
  args: unknown,
): Readonly<McpToolCallPayload>
```

Before cloning, comparing, freezing, or invoking Ajv, both graphs must be JSON-compatible: `null`, booleans, strings, finite numbers, dense arrays, and plain objects. Accessors, symbol keys, sparse arrays, cycles, class instances, and non-finite numbers are rejected.

Contract after JSON-graph admission:

1. Require a plain MCP-compatible `tools/call` envelope.
2. Require plain-object candidate arguments.
3. Load `guwah-policy.json` from disk on every validation (SHA-256 cache identity only; not a signature).
4. Bound the parsed policy object graph, then validate the policy document and each tool `argsSchema`.
5. Reject unknown tools and tools not configured with `ENFORCE`.
6. Compare `payload.params.arguments` to `args` when embedded arguments exist.
7. Validate exact values with Ajv (`coerceTypes: false`, `useDefaults: false`, `removeAdditional: false`).
8. Return a deep-frozen defensive copy, or throw `GuwahSecurityViolation`.

Default policy path: `path.resolve(process.cwd(), "guwah-policy.json")`.

### Resource limits

Constructor overrides must be positive safe integers. Invalid overrides are rejected immediately.

| Limit | Default | Accounting |
|---|---|---|
| `maxPolicyBytes` | 1,048,576 | Policy file bytes actually read |
| `maxPolicyDepth` | 32 | Parsed policy graph depth |
| `maxPolicyNodes` | 10,000 | Parsed policy graph nodes |
| `maxPolicyArrayLength` | 1,000 | Arrays in the parsed policy |
| `maxPolicyObjectProperties` | 1,000 | Properties per policy object |
| `maxPatternLength` | 128 | `pattern` string length |
| `maxInputDepth` | 32 | Payload or argument graph depth |
| `maxInputNodes` | 10,000 | Payload or argument graph nodes |
| `maxInputBytes` | 1,048,576 | UTF-8 bytes of string values and object keys only |
| `maxArrayLength` | 10,000 | Arrays in payload or arguments |
| `maxObjectProperties` | 1,000 | Properties per input object |

`maxInputBytes` does not count JSON punctuation, numeric representations, booleans, null, or container overhead. Each of the payload graph and the candidate-argument graph is measured independently against the same limits.

### Schema patterns

String `pattern` values must be fully anchored. The sample policy uses:

- `^0x[0-9a-fA-F]{40}$`
- `^[A-Za-z0-9 .,_:-]+$`

Admitted forms are concatenations of literals and character classes. Groups, alternation, lookarounds, backreferences, wildcards, and arbitrary escapes are rejected. At most one variable-width quantifier is permitted. Multiple exact fixed-width quantifiers may be used.

### `guwah-policy.json`

Local constraint document. It is operator-editable and is not integrity-protected by this package.

Sample mapping for the example tool `coinbase_cdp_transfer`:

```json
{
  "version": "1.0.0",
  "posture": "default-deny",
  "tools": {
    "coinbase_cdp_transfer": {
      "action": "ENFORCE",
      "argsSchema": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "additionalProperties": false,
        "required": [
          "amountMinor",
          "assetId",
          "destinationAddress",
          "memo"
        ],
        "properties": {
          "amountMinor": {
            "type": "integer",
            "minimum": 1,
            "maximum": 5000
          },
          "assetId": {
            "type": "string",
            "enum": ["USDC"]
          },
          "destinationAddress": {
            "type": "string",
            "pattern": "^0x[0-9a-fA-F]{40}$",
            "enum": [
              "0x1111111111111111111111111111111111111111",
              "0x2222222222222222222222222222222222222222"
            ]
          },
          "memo": {
            "type": "string",
            "minLength": 1,
            "maxLength": 80,
            "pattern": "^[A-Za-z0-9 .,_:-]+$"
          }
        }
      }
    }
  }
}
```

---

## Package Scope and Integration

The published package export is the local validation engine (`GuwahGuard`). It is not a network proxy, wallet, or signing system. The gateway entry is the only host-facing MCP server this package starts; it does not ship a second host-visible server for unprotected downstream tools.

Integrators may wrap `GuwahGuard.validateToolCall` at an MCP client boundary. Any such wrapper must:

- pass the complete payload and the candidate arguments;
- serialize the approved return value, never the original candidate object;
- treat `GuwahSecurityViolation` as a denied execution, not as an HTTP status code, unless a real HTTP adapter exists.

Ajv compiles operator schemas to validators internally. Application source does not call `eval` or the `Function` constructor. That distinction is not a claim that the package executes no generated code at runtime.

---

## License

Apache License 2.0. See `LICENSE`.

The extension is designed to run in a local runtime. The core validation module performs no network requests and does not export telemetry. Operator policy and candidate arguments remain on the local host unless an integrator later transmits an approved payload.

Local enforcement reduces exposure to Client-Runtime Payload Mutation. It is not a wallet, custody system, payment processor, authorization server, or substitute for server-side authorization. It does not eliminate client-side or counterparty transaction liability.
