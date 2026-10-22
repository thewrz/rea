import { execFileOutput } from "../process/ExecFileOutput.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { isGhidraPspTarget } from "./GhidraPspProfile.js";

/** Whether a pyGhidra interpreter can import pyghidra and start a JVM against the selected Ghidra. */
export type PyGhidraAvailability =
  | {
      readonly available: true;
      readonly version: string;
      readonly pythonPath: string;
    }
  | { readonly available: false; readonly reason: string };

/** The Ghidra backend a provider or doctor run commits to. */
export type GhidraBackendSelection =
  | { readonly selected: "java"; readonly reason: string }
  | { readonly selected: "pyghidra"; readonly pyghidraVersion: string };

const IMPORT_TIMEOUT_MS = 10_000;
const JVM_START_TIMEOUT_MS = 60_000;

const failureReason = (pythonPath: string, error: unknown): string => {
  const stderr: unknown =
    error instanceof Error ? Reflect.get(error, "stderr") : undefined;
  const lastLine =
    typeof stderr === "string"
      ? stderr
          .split("\n")
          .map((line) => line.trim())
          .filter((line) => line !== "")
          .at(-1)
      : undefined;
  const detail =
    lastLine ?? (error instanceof Error ? error.message : String(error));
  return `pyGhidra not available via ${pythonPath}: ${detail}`;
};

/**
 * Probe pyGhidra by importing it and starting its JVM against the installation
 * the provider will use, so JPype/JDK mismatches surface before selection.
 * Cancellation rethrows the caller's reason; it is never reported as unavailability.
 */
export const inspectPyGhidraAvailability = async (
  pythonPath: string,
  ghidraInstallDir: string,
  signal?: AbortSignal,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<PyGhidraAvailability> => {
  signal?.throwIfAborted();
  const env = { ...environment, GHIDRA_INSTALL_DIR: ghidraInstallDir };
  try {
    const { stdout } = await execFileOutput(
      pythonPath,
      [
        "-I",
        "-c",
        "import importlib.metadata as m; import pyghidra; print(m.version('pyghidra'))",
      ],
      { env, timeout: IMPORT_TIMEOUT_MS, ...(signal ? { signal } : {}) },
    );
    const version = stdout.trim();
    if (version === "")
      return { available: false, reason: "pyGhidra reported an empty version" };
    signal?.throwIfAborted();
    await execFileOutput(
      pythonPath,
      ["-I", "-c", "import pyghidra; pyghidra.start()"],
      { env, timeout: JVM_START_TIMEOUT_MS, ...(signal ? { signal } : {}) },
    );
    return { available: true, version, pythonPath };
  } catch (error) {
    if (signal?.aborted) throw signal.reason;
    return { available: false, reason: failureReason(pythonPath, error) };
  }
};

/**
 * Pure backend choice shared by doctor and provider so they never disagree.
 * Windows stays on Java in Phase 1; a forced pyGhidra that is unavailable throws.
 */
export const resolveGhidraBackend = (
  config: { readonly ghidraBackend: "auto" | "java" | "pyghidra" },
  availability: PyGhidraAvailability,
  platform: NodeJS.Platform,
): GhidraBackendSelection => {
  if (platform === "win32")
    return { selected: "java", reason: "Windows excluded in Phase 1" };
  if (config.ghidraBackend === "java")
    return { selected: "java", reason: "REA_GHIDRA_BACKEND=java" };
  if (availability.available)
    return { selected: "pyghidra", pyghidraVersion: availability.version };
  if (config.ghidraBackend === "pyghidra")
    throw new Error(
      `pyGhidra backend required but unavailable: ${availability.reason}`,
    );
  return { selected: "java", reason: availability.reason };
};

const JAVA_ONLY_FORMATS: ReadonlySet<string> = new Set([
  "dos-mz",
  "dos-com",
  "raw-binary",
]);

/** The pyGhidra bridge implements none of the PSP, DOS or raw-binary import modes in Phase 1. */
export const pyGhidraSupportsTarget = (target: BinaryTarget): boolean =>
  !isGhidraPspTarget(target) && !JAVA_ONLY_FORMATS.has(target.format);

export const PYGHIDRA_UNSUPPORTED_TARGET_REASON =
  "The pyGhidra backend does not support PSP, DOS MZ, DOS COM or raw-binary targets; set REA_GHIDRA_BACKEND=auto or java.";
