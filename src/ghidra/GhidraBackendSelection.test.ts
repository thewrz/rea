import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { ok } from "../domain/result.js";
import { silentLogger } from "../logger.js";
import type { GhidraJavaObservation } from "./GhidraJavaProbe.js";
import type { GhidraInstallationHost } from "./GhidraInstallation.js";
import type { GhidraLauncher } from "./GhidraLauncher.js";
import { GhidraHeadlessLauncher } from "./GhidraLauncher.js";
import { GhidraProvider, type PyGhidraProbe } from "./GhidraProvider.js";
import { GhidraPyGhidraLauncher } from "./GhidraPyGhidraLauncher.js";
import { GHIDRA_SESSION_BASELINE_CAPABILITIES } from "./GhidraSessionValues.js";
import { pyGhidraSupportsTarget } from "./PyGhidraBackend.js";

const INSTALL = "/opt/ghidra_12.1.4_PUBLIC";
const AVAILABLE = {
  available: true,
  version: "3.0.2",
  pythonPath: "/usr/bin/python3",
} as const;
const UNAVAILABLE = {
  available: false,
  reason: "pyGhidra not available via python3: No module named pyghidra",
} as const;

const host = (platform: NodeJS.Platform = "linux"): GhidraInstallationHost => ({
  platform,
  architecture: "x64",
  readText: () => "application.version=12.1.4\napplication.java.min=21\n",
  executable: () => true,
  probeJava: () =>
    ok<GhidraJavaObservation>({
      osArch: "amd64",
      osName: platform === "win32" ? "Windows 11" : "Linux",
      version: "21.0.11",
      major: 21,
      home: "/usr/lib/jvm/jdk-21",
      bits: 64,
      runtime: "jdk",
      vmName: "OpenJDK 64-Bit Server VM",
    }),
});

const sessionInfo = () => ({
  name: "REA Ghidra bridge" as const,
  run_id: "11111111-1111-4111-8111-111111111111",
  profile_digest: "a".repeat(64),
  provider: { id: "ghidra" as const, version: "12.1.4" },
  read_only: false as const,
  analysis_complete: true,
  analysis_timed_out: false,
  capabilities: [...GHIDRA_SESSION_BASELINE_CAPABILITIES],
  target: {
    name: "fixture",
    language_id: "x86:LE:64:default",
    compiler_spec_id: "gcc",
    image_base: "0x1000",
    default_address_space: "ram",
    sha256: "a".repeat(64),
  },
});

const elfTarget: BinaryTarget = {
  path: "/tmp/fixture",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
};

const rawTarget: BinaryTarget = {
  path: "/tmp/fixture.bin",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "raw-binary",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
  entryPoint: "0x1000",
  entryPointSource: "caller",
};

const pspTarget: BinaryTarget = {
  path: "/tmp/fixture.prx",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "mips",
  availableArchitectures: ["mips"],
  mips: {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    flags: 0x10a20001,
    gnuAttributes: null,
  },
};

const rig = (
  backend: "auto" | "java" | "pyghidra",
  availability: Awaited<ReturnType<PyGhidraProbe>>,
  platform: NodeJS.Platform = "linux",
) => {
  const parsed = parseConfig({
    GHIDRA_INSTALL_DIR: INSTALL,
    REA_GHIDRA_BACKEND: backend,
  });
  if (!parsed.ok) throw parsed.error;
  const launchers: GhidraLauncher[] = [];
  let probes = 0;
  const probe: PyGhidraProbe = () => {
    probes += 1;
    return Promise.resolve(availability);
  };
  const ghidra = new GhidraProvider(
    parsed.value,
    silentLogger,
    {},
    host(platform),
    (options) => {
      launchers.push(options.launcher);
      return {
        start: () => Promise.resolve(ok(sessionInfo())),
        callTool: () => Promise.resolve(ok(null)),
        close: () => Promise.resolve(ok(null)),
      };
    },
    probe,
  );
  return { ghidra, launchers, probes: () => probes };
};

const openLauncher = async (
  setup: ReturnType<typeof rig>,
  target: BinaryTarget,
) => {
  const resolved = await setup.ghidra.resolveAnalysisProfile(target);
  if (!resolved.ok) throw resolved.error;
  if (resolved.value.profile === null) throw new Error("expected a profile");
  const client = setup.ghidra.createClient(target, resolved.value.profile);
  await client.execute("health", {});
  return { launcher: setup.launchers[0], profile: resolved.value.profile };
};

describe("Ghidra backend selection", () => {
  it("selects Java when REA_GHIDRA_BACKEND=java without probing pyGhidra", async () => {
    const setup = rig("java", AVAILABLE);
    const { launcher, profile } = await openLauncher(setup, elfTarget);
    expect(launcher).toBeInstanceOf(GhidraHeadlessLauncher);
    expect(profile.parameters.analysis_backend).toBeUndefined();
    expect(setup.probes()).toBe(0);
  });

  it("selects pyGhidra when forced and available, committing its identity", async () => {
    const setup = rig("pyghidra", AVAILABLE);
    const { launcher, profile } = await openLauncher(setup, elfTarget);
    expect(launcher).toBeInstanceOf(GhidraPyGhidraLauncher);
    expect((launcher as GhidraPyGhidraLauncher).options.pythonPath).toBe(
      "/usr/bin/python3",
    );
    expect(profile.parameters.analysis_backend).toEqual({
      kind: "pyghidra",
      version: "3.0.2",
    });
  });

  it("selects pyGhidra under auto when it is available", async () => {
    const { launcher } = await openLauncher(rig("auto", AVAILABLE), elfTarget);
    expect(launcher).toBeInstanceOf(GhidraPyGhidraLauncher);
  });

  it("falls back to Java under auto when pyGhidra is unavailable", async () => {
    const { launcher } = await openLauncher(
      rig("auto", UNAVAILABLE),
      elfTarget,
    );
    expect(launcher).toBeInstanceOf(GhidraHeadlessLauncher);
  });

  it("fails profile resolution when forced pyGhidra is unavailable", async () => {
    const resolved = await rig(
      "pyghidra",
      UNAVAILABLE,
    ).ghidra.resolveAnalysisProfile(elfTarget);
    expect(resolved.ok).toBe(false);
  });

  it("always selects Java on Windows", async () => {
    const setup = rig("pyghidra", AVAILABLE, "win32");
    await setup.ghidra.resolveAnalysisProfile(elfTarget);
    expect(setup.probes()).toBe(0);
  });

  it("routes raw-binary targets to Java under auto without probing", async () => {
    const setup = rig("auto", AVAILABLE);
    const { launcher } = await openLauncher(setup, rawTarget);
    expect(launcher).toBeInstanceOf(GhidraHeadlessLauncher);
    expect(setup.probes()).toBe(0);
  });

  it("refuses an unsupported target under forced pyGhidra", async () => {
    const resolved = await rig(
      "pyghidra",
      AVAILABLE,
    ).ghidra.resolveAnalysisProfile(rawTarget);
    expect(resolved).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisUnsupportedTargetError" },
    });
  });

  it("probes once per provider instance", async () => {
    const setup = rig("auto", AVAILABLE);
    await setup.ghidra.resolveAnalysisProfile(elfTarget);
    await setup.ghidra.resolveAnalysisProfile(elfTarget);
    expect(setup.probes()).toBe(1);
  });
});

describe("pyGhidraSupportsTarget", () => {
  it.each([
    ["ELF", elfTarget, true],
    ["raw-binary", rawTarget, false],
    ["PSP", pspTarget, false],
    ["DOS MZ", { ...elfTarget, format: "dos-mz" } as BinaryTarget, false],
    ["DOS COM", { ...elfTarget, format: "dos-com" } as BinaryTarget, false],
  ])("%s -> %s", (_name, target, supported) => {
    expect(pyGhidraSupportsTarget(target)).toBe(supported);
  });
});
