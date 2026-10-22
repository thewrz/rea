import { fileURLToPath } from "node:url";

/** Required packaged sources, selected by their runtime role rather than order. */
export const GHIDRA_BRIDGE_SOURCES = Object.freeze({
  bridge: "ReaGhidraBridge.java",
  bundleActivator: "ReaGhidraBundleActivator.java",
  extensions: "ReaGhidraExtensions.java",
  prepareCom: "ReaGhidraPrepareCom.java",
  prepareRaw: "ReaGhidraPrepareRaw.java",
  applySeeds: "ReaGhidraApplySeeds.java",
  analysisOptions: "ReaGhidraAnalysisOptions.java",
  noReturnFix: "ReaGhidraNoReturnFix.java",
  mipsSoftFloat: "ReaGhidraMipsSoftFloat.java",
} as const);

/** Entry module of the packaged pyGhidra bridge, run as `python <entry> <descriptor> <target>`. */
export const PYGHIDRA_BRIDGE_ENTRY = "__main__.py";

/** Absolute path of the packaged Java bridge script. */
export const javaBridgeScriptPath = (): string =>
  fileURLToPath(
    new URL(
      `../../bridge/ghidra/${GHIDRA_BRIDGE_SOURCES.bridge}`,
      import.meta.url,
    ),
  );

/** Absolute path of the packaged pyGhidra bridge entry. */
export const pyGhidraBridgeScriptPath = (): string =>
  fileURLToPath(
    new URL(`../../bridge/pyghidra/${PYGHIDRA_BRIDGE_ENTRY}`, import.meta.url),
  );
