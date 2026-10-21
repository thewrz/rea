import { chmod, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  inspectPyGhidraAvailability,
  resolveGhidraBackend,
  type PyGhidraAvailability,
} from "./PyGhidraBackend.js";

const AVAILABLE: PyGhidraAvailability = {
  available: true,
  version: "3.0.2",
  pythonPath: "/usr/bin/python3",
};
const UNAVAILABLE: PyGhidraAvailability = {
  available: false,
  reason: "pyGhidra not available via python3: No module named pyghidra",
};

/** A fake interpreter: phase 1 (`importlib`) prints a version, phase 2 (`start`) runs `startBody`. */
const fakePython = async (startBody: string): Promise<string> => {
  const root = await createTestTempDirectory("rea-pyghidra-probe-");
  const script = join(root, "python3");
  await writeFile(
    script,
    `#!/bin/sh\ncase "$2" in\n  *importlib*) echo "3.0.2" ;;\n  *start*) ${startBody} ;;\nesac\n`,
  );
  await chmod(script, 0o755);
  return script;
};

describe("inspectPyGhidraAvailability", () => {
  it("is available when the import and JVM start both succeed", async () => {
    const python = await fakePython("exit 0");
    await expect(
      inspectPyGhidraAvailability(python, "/opt/ghidra"),
    ).resolves.toEqual({
      available: true,
      version: "3.0.2",
      pythonPath: python,
    });
  });

  it("is unavailable when the JVM fails to start despite a successful import", async () => {
    const python = await fakePython('echo "JVM exploded" >&2; exit 1');
    const result = await inspectPyGhidraAvailability(python, "/opt/ghidra");
    expect(result).toMatchObject({ available: false });
    expect(!result.available && result.reason).toContain("JVM exploded");
  });

  it("starts the JVM against the selected Ghidra installation", async () => {
    const root = await createTestTempDirectory("rea-pyghidra-env-");
    const seen = join(root, "seen");
    const python = await fakePython(
      `printf %s "$GHIDRA_INSTALL_DIR" > ${seen}`,
    );
    await inspectPyGhidraAvailability(python, "/opt/ghidra_12");
    await expect(readFile(seen, "utf8")).resolves.toBe("/opt/ghidra_12");
  });

  it("is unavailable for a nonexistent interpreter", async () => {
    const result = await inspectPyGhidraAvailability(
      "/nonexistent/python3",
      "/opt/ghidra",
    );
    expect(result.available).toBe(false);
  });

  it("is unavailable when the version output is empty", async () => {
    const root = await createTestTempDirectory("rea-pyghidra-empty-");
    const python = join(root, "python3");
    await writeFile(python, "#!/bin/sh\nexit 0\n");
    await chmod(python, 0o755);
    const result = await inspectPyGhidraAvailability(python, "/opt/ghidra");
    expect(result).toEqual({
      available: false,
      reason: "pyGhidra reported an empty version",
    });
  });

  it("rethrows cancellation instead of reporting unavailability", async () => {
    const python = await fakePython("sleep 5");
    const controller = new AbortController();
    const reason = new Error("caller cancelled");
    const pending = inspectPyGhidraAvailability(
      python,
      "/opt/ghidra",
      controller.signal,
    );
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
  });

  it("rejects immediately when already cancelled", async () => {
    const reason = new Error("already cancelled");
    await expect(
      inspectPyGhidraAvailability(
        "python3",
        "/opt/ghidra",
        AbortSignal.abort(reason),
      ),
    ).rejects.toBe(reason);
  });
});

describe("resolveGhidraBackend", () => {
  it("always selects Java on Windows, even when pyghidra is forced", () => {
    expect(
      resolveGhidraBackend({ ghidraBackend: "pyghidra" }, AVAILABLE, "win32"),
    ).toEqual({ selected: "java", reason: "Windows excluded in Phase 1" });
  });

  it("selects Java when forced", () => {
    expect(
      resolveGhidraBackend({ ghidraBackend: "java" }, AVAILABLE, "linux"),
    ).toEqual({ selected: "java", reason: "REA_GHIDRA_BACKEND=java" });
  });

  it("selects pyGhidra when forced and available", () => {
    expect(
      resolveGhidraBackend({ ghidraBackend: "pyghidra" }, AVAILABLE, "linux"),
    ).toEqual({ selected: "pyghidra", pyghidraVersion: "3.0.2" });
  });

  it("fails loudly when pyGhidra is forced but unavailable", () => {
    expect(() =>
      resolveGhidraBackend({ ghidraBackend: "pyghidra" }, UNAVAILABLE, "linux"),
    ).toThrow(/pyGhidra backend required but unavailable.*No module named/u);
  });

  it("prefers pyGhidra under auto when available", () => {
    expect(
      resolveGhidraBackend({ ghidraBackend: "auto" }, AVAILABLE, "darwin"),
    ).toEqual({ selected: "pyghidra", pyghidraVersion: "3.0.2" });
  });

  it("falls back to Java under auto and carries the reason", () => {
    expect(
      resolveGhidraBackend({ ghidraBackend: "auto" }, UNAVAILABLE, "linux"),
    ).toEqual({ selected: "java", reason: UNAVAILABLE.reason });
  });
});
