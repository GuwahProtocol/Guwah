import path from "node:path";
import { fileURLToPath } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const GATEWAY_NAME = "guwah";
const GATEWAY_VERSION = "0.1.0";

/**
 * Starts the local MCP gateway on process stdio.
 * Stdout is reserved for protocol frames. Startup failures must exit non-zero.
 */
export async function startGuwahStdioGateway(): Promise<void> {
  const server = new Server(
    { name: GATEWAY_NAME, version: GATEWAY_VERSION },
    { capabilities: {} },
  );
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

function isGatewayEntry(): boolean {
  const invoked = process.argv[1];
  if (invoked === undefined) {
    return false;
  }
  return path.resolve(fileURLToPath(import.meta.url)) === path.resolve(invoked);
}

function failStartup(): void {
  process.stderr.write("Guwah gateway failed to start.\n");
  process.exit(1);
}

if (isGatewayEntry()) {
  startGuwahStdioGateway().catch(() => {
    failStartup();
  });
}
