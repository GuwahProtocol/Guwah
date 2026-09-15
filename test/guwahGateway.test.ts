import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const GATEWAY_ENTRY = path.join(REPO_ROOT, "dist", "guwahGateway.js");
const VALIDATOR_ENTRY = path.join(REPO_ROOT, "dist", "guwahGuard.js");

type SpawnedGateway = {
  readonly child: ReturnType<typeof spawn>;
  readonly stdout: string[];
  readonly stderr: string[];
};

const live: SpawnedGateway[] = [];

function spawnGateway(entryPath: string): SpawnedGateway {
  const child = spawn(process.execPath, [entryPath], {
    cwd: REPO_ROOT,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  const spawned: SpawnedGateway = { child, stdout: [], stderr: [] };
  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => {
    spawned.stdout.push(chunk);
  });
  child.stderr?.on("data", (chunk: string) => {
    spawned.stderr.push(chunk);
  });
  live.push(spawned);
  return spawned;
}

async function waitForExit(child: ReturnType<typeof spawn>, timeoutMs: number): Promise<number | null> {
  if (child.exitCode !== null) {
    return child.exitCode;
  }
  return await new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.removeListener("exit", onExit);
      resolve(child.exitCode);
    }, timeoutMs);
    const onExit = (code: number | null): void => {
      clearTimeout(timer);
      resolve(code);
    };
    child.once("exit", onExit);
  });
}

async function waitForStdoutLine(spawned: SpawnedGateway, timeoutMs: number): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const combined = spawned.stdout.join("");
    const line = combined.split("\n").find((entry) => entry.trim().length > 0);
    if (line !== undefined) {
      return line.replace(/\r$/, "");
    }
    await new Promise((resolve) => {
      setTimeout(resolve, 25);
    });
  }
  throw new Error("gateway produced no stdout protocol line");
}

afterEach(() => {
  for (const spawned of live.splice(0, live.length)) {
    if (spawned.child.exitCode === null && spawned.child.killed === false) {
      spawned.child.kill();
    }
  }
});

describe("guwahGateway entry", () => {
  it("emits a compiled gateway distinct from the validator artifact", () => {
    expect(existsSync(VALIDATOR_ENTRY)).toBe(true);
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    expect(path.basename(GATEWAY_ENTRY)).not.toBe(path.basename(VALIDATOR_ENTRY));
  });

  it("fails when the compiled gateway entry is missing", async () => {
    const missing = path.join(REPO_ROOT, "dist", "guwahGateway.absent.js");
    expect(existsSync(missing)).toBe(false);
    const spawned = spawnGateway(missing);
    const code = await waitForExit(spawned.child, 5000);
    expect(code).not.toBe(0);
    expect(code).not.toBeNull();
  });

  it("starts a process that speaks MCP over stdio", async () => {
    expect(existsSync(GATEWAY_ENTRY)).toBe(true);
    const spawned = spawnGateway(GATEWAY_ENTRY);
    const stillRunning = await waitForExit(spawned.child, 250);
    expect(stillRunning).toBeNull();

    const initialize = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "guwah-process-start-test", version: "0.0.0" },
      },
    };
    spawned.child.stdin?.write(`${JSON.stringify(initialize)}\n`);
    const line = await waitForStdoutLine(spawned, 5000);
    const parsed: unknown = JSON.parse(line);
    expect(parsed).toMatchObject({ jsonrpc: "2.0", id: 1 });
    expect(parsed).toHaveProperty("result");
    expect(spawned.stderr.join("")).toBe("");
  });
});
