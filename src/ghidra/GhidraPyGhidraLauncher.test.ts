import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import type {
  OwnedProviderProcessSpawnOptions,
  SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import {
  GhidraLaunchError,
  type GhidraLaunchSession,
} from "./GhidraLauncher.js";
import {
  GhidraPyGhidraLauncher,
  type GhidraPyGhidraLauncherOptions,
} from "./GhidraPyGhidraLauncher.js";

const posixOnly = it.skipIf(process.platform === "win32");

let runtimeRoot: string;
beforeEach(async () => {
  runtimeRoot = await mkdtemp(join(tmpdir(), "rea-pyghidra-launcher-"));
});
afterEach(async () => {
  await rm(runtimeRoot, { recursive: true, force: true });
});

const session = (): GhidraLaunchSession => ({
  runtimeRoot,
  transport: "unix-socket",
  endpointPath: join(runtimeRoot, "endpoint.sock"),
  token: "test-token",
  runId: "test-run",
  targetPath: join(runtimeRoot, "target.bin"),
  targetSha256: "0".repeat(64),
  providerVersion: "test",
  profileDigest: "test",
});

const fakeSpawned = (
  cleanup?: SpawnedOwnedProviderProcess["cleanup"],
): SpawnedOwnedProviderProcess =>
  ({
    process: { pid: 4242 },
    ownership: { leaderPid: 4242, processGroupId: 4242 },
    ...(cleanup === undefined ? {} : { cleanup }),
  }) as unknown as SpawnedOwnedProviderProcess;

const options = (
  overrides: Partial<GhidraPyGhidraLauncherOptions> = {},
): GhidraPyGhidraLauncherOptions => ({
  pythonPath: "/usr/bin/python3",
  bridgeScriptPath: "/bridge/pyghidra/__main__.py",
  ghidraInstallDir: "/opt/ghidra",
  javaHome: "/opt/jdk",
  environment: { PATH: "/usr/bin", LEAKED_SECRET: "x" },
  platform: "linux",
  ...overrides,
});

describe("GhidraPyGhidraLauncher", () => {
  it("constructs with required options", () => {
    expect(new GhidraPyGhidraLauncher(options())).toBeDefined();
  });

  it("returns cancelled without touching the runtime when already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    const spawnProcess = vi.fn();
    const result = await new GhidraPyGhidraLauncher(
      options({ spawnProcess }),
    ).launch(session(), { signal: controller.signal });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    expect(spawnProcess).not.toHaveBeenCalled();
  });

  posixOnly(
    "spawns the bridge with an isolated environment and descriptor",
    async () => {
      let captured: OwnedProviderProcessSpawnOptions | undefined;
      let descriptorAtSpawn = "";
      const spawnProcess = vi.fn(
        async (spawn: OwnedProviderProcessSpawnOptions) => {
          captured = spawn;
          descriptorAtSpawn = await readFile(spawn.arguments[1]!, "utf8");
          return fakeSpawned();
        },
      );
      const result = await new GhidraPyGhidraLauncher(
        options({
          spawnProcess,
          languageOverride: {
            languageId: "x86:LE:32:default",
            compilerSpecId: "borlandcpp",
          },
          disabledAnalyzers: ["Stack"],
          mipsSoftFloat: true,
        }),
      ).launch(session());

      expect(result.ok).toBe(true);
      expect(captured?.command).toBe("/usr/bin/python3");
      expect(captured?.arguments).toEqual([
        "/bridge/pyghidra/__main__.py",
        join(runtimeRoot, "session.json"),
        join(runtimeRoot, "target.bin"),
      ]);
      expect(captured?.hostEnvironment).toEqual({});
      expect(captured?.env).toMatchObject({
        HOME: join(runtimeRoot, "home"),
        TMPDIR: join(runtimeRoot, "tmp"),
        GHIDRA_INSTALL_DIR: "/opt/ghidra",
        JAVA_HOME: "/opt/jdk",
      });
      const descriptor = JSON.parse(descriptorAtSpawn) as Record<
        string,
        unknown
      >;
      expect(descriptor).toMatchObject({
        run_id: "test-run",
        language_id: "x86:LE:32:default",
        compiler_spec_id: "borlandcpp",
        disabled_analyzers: ["Stack"],
        mips_soft_float: true,
      });
      expect(descriptor).not.toHaveProperty("seed_paths");
      if (result.ok) {
        expect(result.value.ghidraLogPath).toBe(
          join(runtimeRoot, "ghidra.log"),
        );
        expect(result.value.scriptLogPath).toBe(
          join(runtimeRoot, "script.log"),
        );
      }
      const ownership = JSON.parse(
        await readFile(join(runtimeRoot, "ownership.json"), "utf8"),
      ) as Record<string, unknown>;
      expect(ownership).toMatchObject({ pid: 4242, run_id: "test-run" });
    },
  );

  posixOnly("reports a spawn failure as a launch error", async () => {
    const result = await new GhidraPyGhidraLauncher(
      options({
        spawnProcess: async () => Promise.reject(new Error("no python")),
      }),
    ).launch(session());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(GhidraLaunchError);
  });

  posixOnly("cleans up a process spawned before cancellation", async () => {
    const controller = new AbortController();
    const cleanup = vi.fn(async () => ({
      cleaned: true as const,
      signaled: true,
    }));
    const result = await new GhidraPyGhidraLauncher(
      options({
        spawnProcess: async () => {
          controller.abort(new Error("stop"));
          return fakeSpawned(cleanup);
        },
      }),
    ).launch(session(), { signal: controller.signal });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    expect(cleanup).toHaveBeenCalledOnce();
  });

  posixOnly(
    "retains the full launch when cancellation cleanup fails",
    async () => {
      const controller = new AbortController();
      const result = await new GhidraPyGhidraLauncher(
        options({
          spawnProcess: async () => {
            controller.abort(new Error("stop"));
            return fakeSpawned(() => Promise.reject(new Error("stuck")));
          },
        }),
      ).launch(session(), { signal: controller.signal });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(GhidraLaunchError);
        const error = result.error as GhidraLaunchError;
        expect(error.rollbackFailure?.kind).toBe("rejected");
        expect(error.partialLaunch?.process.pid).toBe(4242);
      }
    },
  );
});
