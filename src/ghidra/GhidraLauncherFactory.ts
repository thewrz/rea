import type { GhidraLauncher } from "./GhidraLauncher.js";
import {
  GhidraHeadlessLauncher,
  type GhidraHeadlessLauncherOptions,
} from "./GhidraLauncher.js";
import { GhidraPyGhidraLauncher } from "./GhidraPyGhidraLauncher.js";
import {
  javaBridgeScriptPath,
  pyGhidraBridgeScriptPath,
} from "./GhidraBridgeSources.js";

/** The launcher host a session commits to once its backend is selected. */
export type GhidraLauncherBackend =
  | { readonly kind: "java" }
  | { readonly kind: "pyghidra"; readonly pythonPath: string };

/**
 * Build the launcher for the selected backend from one option set. The Java-only
 * import modes (PSP, DOS, raw binary) are admitted before selection, so the
 * pyGhidra launcher deliberately receives none of them.
 */
export const createGhidraLauncher = (
  backend: GhidraLauncherBackend,
  installDir: string,
  options: Omit<GhidraHeadlessLauncherOptions, "bridgeScriptPath">,
): GhidraLauncher =>
  backend.kind === "java"
    ? new GhidraHeadlessLauncher({
        ...options,
        bridgeScriptPath: javaBridgeScriptPath(),
      })
    : new GhidraPyGhidraLauncher({
        pythonPath: backend.pythonPath,
        bridgeScriptPath: pyGhidraBridgeScriptPath(),
        ghidraInstallDir: installDir,
        environment: options.environment,
        ...(options.javaHome === undefined
          ? {}
          : { javaHome: options.javaHome }),
        ...(options.platform === undefined
          ? {}
          : { platform: options.platform }),
        ...(options.configurationDirectoryName === null
          ? {}
          : { configurationDirectoryName: options.configurationDirectoryName }),
        ...(options.languageOverride === undefined
          ? {}
          : { languageOverride: options.languageOverride }),
        ...(options.disabledAnalyzers === undefined
          ? {}
          : { disabledAnalyzers: options.disabledAnalyzers }),
        ...(options.analysisSeeds === undefined
          ? {}
          : { analysisSeeds: options.analysisSeeds }),
        ...(options.analysisExtensions === undefined
          ? {}
          : { analysisExtensions: options.analysisExtensions }),
        ...(options.mipsSoftFloat === undefined
          ? {}
          : { mipsSoftFloat: options.mipsSoftFloat }),
      });
