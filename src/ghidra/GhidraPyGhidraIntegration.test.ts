import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";

import type { JsonValue } from "../domain/jsonValue.js";
import { GhidraClient } from "./GhidraClient.js";
import {
  parseGhidraFunctionResult,
  type GhidraFunctionOperation,
} from "./GhidraFunctionValues.js";
import {
  parseGhidraInventoryResult,
  type GhidraInventoryOperation,
} from "./GhidraInventoryValues.js";
import { createGhidraLauncher } from "./GhidraLauncherFactory.js";
import { GhidraPyGhidraLauncher } from "./GhidraPyGhidraLauncher.js";

/**
 * Exercises the pyGhidra bridge through the production client and parsers, so
 * envelope, refinement and cross-field rules apply exactly as for the Java bridge.
 * Needs a Ghidra install, a pyghidra interpreter and a C compiler.
 */
const ENABLED =
  process.env.REA_TEST_PYGHIDRA === "1" &&
  process.platform !== "win32" &&
  process.env.GHIDRA_INSTALL_DIR !== undefined;

const INSTALL_DIR = process.env.GHIDRA_INSTALL_DIR ?? "";
const PYTHON = process.env.REA_PYGHIDRA_PYTHON ?? "python3";
const PROFILE_DIGEST = "b".repeat(64);
const STARTUP_TIMEOUT_MS = 600_000;
const FIXTURE_SOURCE = `
#include <stdio.h>
static int add(int a, int b) { return a + b; }
static int scale_by_three(int x) { return x * 3; }
int main(int argc, char **argv) {
  printf("%d\\n", add(argc, 2));
  return scale_by_three(argc);
}
`;

const ghidraVersion = (): string => {
  const properties = readFileSync(
    join(INSTALL_DIR, "Ghidra", "application.properties"),
    "utf8",
  );
  const match = /^application\.version=(.+)$/m.exec(properties);
  if (match?.[1] === undefined)
    throw new Error("Ghidra application.version is missing");
  return match[1].trim();
};

const procedureListSchema = z.array(
  z.object({
    address: z.string(),
    value: z.string(),
    procedure: z.object({ external: z.boolean() }),
  }),
);

const directories: string[] = [];

const buildTarget = (): string => {
  const directory = mkdtempSync(join(tmpdir(), "rea-pyghidra-it-"));
  directories.push(directory);
  const source = join(directory, "fixture.c");
  const binary = join(directory, "fixture");
  writeFileSync(source, FIXTURE_SOURCE);
  execFileSync("cc", ["-O0", "-no-pie", "-o", binary, source]);
  return binary;
};

const launcherFor = () =>
  createGhidraLauncher({ kind: "pyghidra", pythonPath: PYTHON }, INSTALL_DIR, {
    environment: process.env,
    analyzeHeadlessPath: join(INSTALL_DIR, "support", "analyzeHeadless"),
    configurationDirectoryName: null,
  });

const clientFor = (
  targetPath: string,
  targetSha256: string,
  startupTimeoutMs = STARTUP_TIMEOUT_MS,
): GhidraClient =>
  new GhidraClient({
    launcher: launcherFor(),
    targetPath,
    targetSha256,
    transport: "unix-socket",
    providerVersion: ghidraVersion(),
    profileDigest: PROFILE_DIGEST,
    startupTimeoutMs,
  });

const sha256 = (path: string): string =>
  createHash("sha256").update(readFileSync(path)).digest("hex");

afterAll(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

describe.skipIf(!ENABLED)("pyGhidra through GhidraClient", () => {
  let client: GhidraClient;
  let target: string;

  const call = async (
    operation: GhidraInventoryOperation | GhidraFunctionOperation,
    parameters: Record<string, JsonValue>,
  ): Promise<JsonValue> => {
    const result = await client.callTool(operation, parameters);
    if (!result.ok) throw result.error;
    return result.value;
  };

  const inventory = async (
    operation: GhidraInventoryOperation,
    parameters: Record<string, JsonValue>,
  ) => {
    const parsed = parseGhidraInventoryResult(
      operation,
      await call(operation, parameters),
    );
    if (!parsed.ok) throw parsed.error;
    return parsed.value.value;
  };

  const fn = async (
    operation: GhidraFunctionOperation,
    parameters: Record<string, JsonValue>,
  ) => {
    const parsed = parseGhidraFunctionResult(
      operation,
      await call(operation, parameters),
    );
    if (!parsed.ok) throw parsed.error;
    return parsed.value;
  };

  const addressOf = async (name: string): Promise<string> => {
    const procedures = procedureListSchema.parse(
      await inventory("list_procedures", { document: null }),
    );
    const found = procedures.find((entry) => entry.value === name);
    if (found === undefined) throw new Error(`no procedure named ${name}`);
    return found.address;
  };

  beforeAll(async () => {
    target = buildTarget();
    client = clientFor(target, sha256(target));
    const started = await client.start();
    if (!started.ok) throw started.error;
  }, STARTUP_TIMEOUT_MS);

  afterAll(async () => {
    await client?.close();
  });

  it("completes the production handshake with the committed profile", async () => {
    const info = await client.ping();
    if (!info.ok) throw info.error;
    expect(info.value.name).toBe("REA pyGhidra bridge");
    expect(info.value.profile_digest).toBe(PROFILE_DIGEST);
    expect(info.value.target.sha256).toBe(sha256(target));
  });

  it("list_procedures passes the inventory parser", async () => {
    const procedures = procedureListSchema.parse(
      await inventory("list_procedures", { document: null }),
    );
    expect(procedures.map((entry) => entry.value)).toEqual(
      expect.arrayContaining(["main", "add", "scale_by_three"]),
    );
    expect(procedures.some((entry) => entry.procedure.external)).toBe(true);
  });

  it("procedure_pseudo_code passes the function observation envelope parser", async () => {
    const result = await fn("procedure_pseudo_code", {
      document: null,
      procedure: await addressOf("add"),
    });
    expect(typeof result.value).toBe("string");
    expect(result.limitations.length).toBeGreaterThanOrEqual(0);
  });

  it("analyze_function reports relationship coverage and no cache policy on a live decompile", async () => {
    const result = await fn("analyze_function", {
      procedure: await addressOf("main"),
    });
    expect(result.cachePolicy).toBeUndefined();
    expect(result.relationshipCoverage).toBeDefined();
  });

  it("procedure_callers and procedure_callees return canonical address lists", async () => {
    const main = await addressOf("main");
    const add = await addressOf("add");
    const callees = await fn("procedure_callees", {
      document: null,
      procedure: main,
    });
    const callers = await fn("procedure_callers", {
      document: null,
      procedure: add,
    });
    expect(callees.value).toContain(add);
    expect(callers.value).toContain(main);
    expect(callers.relationshipCoverage).toBeDefined();
  });

  it("annotate_native_function passes the annotations schema with readback", async () => {
    const result = await fn("annotate_native_function", {
      procedure: await addressOf("scale_by_three"),
      name: "annotated_scale",
      comment: "REA plate comment",
    });
    expect(result.value).toMatchObject({
      annotations: { name: "annotated_scale", comment: "REA plate comment" },
      effects: { source_bytes_modified: false, persists_after_close: false },
    });
  });
});

describe.skipIf(!ENABLED)("pyGhidra backend lifecycle", () => {
  it("selects the pyGhidra launcher for the pyghidra backend", () => {
    expect(launcherFor()).toBeInstanceOf(GhidraPyGhidraLauncher);
  });

  it(
    "refuses a target whose digest differs from the committed digest",
    async () => {
      const target = buildTarget();
      const client = clientFor(target, "0".repeat(64));
      try {
        const started = await client.start();
        expect(started.ok).toBe(false);
      } finally {
        const closed = await client.close();
        expect(closed.ok).toBe(true);
      }
    },
    STARTUP_TIMEOUT_MS,
  );

  it(
    "closes cleanly and stops serving afterwards",
    async () => {
      const target = buildTarget();
      const client = clientFor(target, sha256(target));
      const started = await client.start();
      if (!started.ok) throw started.error;
      expect(client.isReady()).toBe(true);
      const closed = await client.close();
      expect(closed.ok).toBe(true);
      expect(client.isReady()).toBe(false);
    },
    STARTUP_TIMEOUT_MS,
  );
});
