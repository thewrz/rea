import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { analysisClientFailureForOperation } from "../providers/AnalysisClientFailure.js";
import type { RetainedResourceScope } from "../application/AnalysisProvider.js";
import type {
  DoctorProviderCheck,
  DoctorProviderInspection,
} from "../application/Doctor.js";
import { parseEnvironmentValues } from "../config/environment.js";
import { inspectWindowsNativeReadiness } from "../process/WindowsAuthority.js";
import {
  inspectGhidraInstallation,
  type GhidraInstallationCheck,
  type GhidraInstallationInspection,
} from "./GhidraInstallation.js";
import {
  inspectPyGhidraAvailability,
  resolveGhidraBackend,
  type PyGhidraAvailability,
} from "./PyGhidraBackend.js";

type GhidraBackendSetting = "auto" | "java" | "pyghidra";

/** Report the backend `resolveGhidraBackend` selects; a forced-but-unavailable pyGhidra fails. */
export const projectGhidraBackendCheck = (
  backend: GhidraBackendSetting,
  availability: PyGhidraAvailability,
  platform: NodeJS.Platform,
): DoctorProviderCheck => {
  try {
    const selection = resolveGhidraBackend(
      { ghidraBackend: backend },
      availability,
      platform,
    );
    return {
      name: "backend",
      ok: true,
      code: null,
      detail:
        selection.selected === "pyghidra"
          ? `Selected pyGhidra backend (pyghidra ${selection.pyghidraVersion}).`
          : `Selected Java backend: ${selection.reason}`,
      remediation: null,
      classification: "config_drift",
    };
  } catch (cause: unknown) {
    return {
      name: "backend",
      ok: false,
      code: "runtime_unavailable",
      detail: cause instanceof Error ? cause.message : String(cause),
      remediation:
        "Install pyGhidra in the interpreter named by REA_PYGHIDRA_PYTHON and confirm it can start against GHIDRA_INSTALL_DIR, or set REA_GHIDRA_BACKEND=auto or java.",
      classification: "runtime_failure",
    };
  }
};

const probeSkipped: PyGhidraAvailability = {
  available: false,
  reason: "no usable Ghidra installation to start pyGhidra against",
};

const inspectGhidraBackend = async (
  inspection: GhidraInstallationInspection,
  environment: Readonly<NodeJS.ProcessEnv>,
  signal: AbortSignal | undefined,
): Promise<DoctorProviderCheck | undefined> => {
  const settings = parseEnvironmentValues(environment);
  if (!settings.ok) return undefined;
  const backend = settings.value.REA_GHIDRA_BACKEND;
  const probe =
    backend !== "java" &&
    inspection.platform !== "win32" &&
    inspection.status === "available";
  const availability = probe
    ? await inspectPyGhidraAvailability(
        settings.value.REA_PYGHIDRA_PYTHON,
        inspection.installDir,
        signal,
        environment,
      )
    : probeSkipped;
  return projectGhidraBackendCheck(backend, availability, inspection.platform);
};

/** Project installation and runtime-authority facts into the doctor contract. */
export const projectGhidraDoctorInspection = (
  inspection: GhidraInstallationInspection,
): DoctorProviderInspection => {
  const readiness =
    inspection.status === "available" && inspection.platform === "win32"
      ? inspectWindowsNativeReadiness(inspection.platform)
      : undefined;
  const windowsAuthorityUnavailable = readiness?.available === false;
  return {
    id: "ghidra",
    configured: inspection.installDir !== null,
    available:
      inspection.status === "available" && !windowsAuthorityUnavailable,
    providerVersion: inspection.providerVersion,
    registrationEnvironment:
      inspection.status === "available"
        ? {
            GHIDRA_INSTALL_DIR: inspection.installDir,
            JAVA_HOME: inspection.javaHome,
          }
        : {},
    checks: [
      ...selectedChecks(inspection).map((check) =>
        projectCheck(
          check,
          inspection.installDir !== null,
          inspection.javaProbeFailure,
          inspection.nativeDecompilerHeaderFailure,
        ),
      ),
      ...(readiness !== undefined
        ? [
            {
              name: "native_authority",
              ok: !windowsAuthorityUnavailable,
              code: !readiness.available ? readiness.code : null,
              detail: !readiness.available
                ? readiness.reason
                : "Verified Windows native Job Object, private DACL, and reparse-safe handle controls; local NTFS only.",
              remediation: !readiness.available ? readiness.remediation : null,
              classification:
                !readiness.available && readiness.code === "runtime_unavailable"
                  ? ("runtime_failure" as const)
                  : !readiness.available && readiness.code === "runtime_missing"
                    ? ("missing_dependency" as const)
                    : ("unsupported_host" as const),
            },
          ]
        : []),
    ],
  };
};

/** Inspect the process-configured BYO Ghidra installation for `rea doctor`. */
export const inspectSystemGhidraProvider = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  resourceOwner: RetainedResourceScope,
  signal?: AbortSignal,
): Promise<DoctorProviderInspection> => {
  try {
    const installation = await inspectGhidraInstallation({
      environment,
      resourceOwner,
      ...(signal === undefined ? {} : { signal }),
      ...(environment.GHIDRA_INSTALL_DIR === undefined
        ? {}
        : { installDir: environment.GHIDRA_INSTALL_DIR }),
      ...(environment.JAVA_HOME === undefined
        ? {}
        : { javaHome: environment.JAVA_HOME }),
    });
    const projected = projectGhidraDoctorInspection(installation);
    const backendCheck = await inspectGhidraBackend(
      installation,
      environment,
      signal,
    );
    return backendCheck === undefined
      ? projected
      : { ...projected, checks: [...projected.checks, backendCheck] };
  } catch (cause: unknown) {
    throw analysisClientFailureForOperation(cause, "ghidra", "doctor");
  }
};

const selectedChecks = (
  inspection: GhidraInstallationInspection,
): readonly GhidraInstallationCheck[] => {
  const byName = new Map(
    inspection.checks.map((candidate) => [candidate.name, candidate]),
  );
  const configuration = byName.get("configuration");
  if (configuration === undefined) return [];
  if (configuration.status === "failed") return [configuration];
  const installation = byName.get("installation");
  return [
    configuration,
    byName.get("platform"),
    byName.get("architecture"),
    installation,
    ...(installation?.status === "passed"
      ? [
          byName.get("version"),
          byName.get("headless"),
          byName.get("native_decompiler"),
        ]
      : []),
    byName.get("java"),
  ].filter((candidate): candidate is GhidraInstallationCheck =>
    Boolean(candidate),
  );
};

const projectCheck = (
  check: GhidraInstallationCheck,
  configured: boolean,
  javaFailure: GhidraInstallationInspection["javaProbeFailure"],
  headerFailure: GhidraInstallationInspection["nativeDecompilerHeaderFailure"],
): DoctorProviderCheck => ({
  name: check.name,
  ok: check.status === "passed",
  code: check.status === "failed" ? check.code : null,
  detail: check.detail,
  ...(check.name === "java" && javaFailure?.output !== undefined
    ? {
        details: {
          output: { ...javaFailure.output },
          ...(javaFailure.processErrorCode === undefined
            ? {}
            : { process_error_code: javaFailure.processErrorCode }),
          ...(javaFailure.properties === undefined
            ? {}
            : { properties: { ...javaFailure.properties } }),
        },
      }
    : {}),
  ...(check.name === "native_decompiler" && headerFailure !== undefined
    ? { details: { header_failure: projectAnalysisError(headerFailure) } }
    : {}),
  remediation: check.status === "failed" ? check.remediation : null,
  classification:
    check.name === "platform" || check.name === "architecture"
      ? "unsupported_host"
      : check.name === "java" &&
          check.status === "failed" &&
          check.code === "runtime_missing"
        ? "missing_dependency"
        : check.name === "java" &&
            check.status === "failed" &&
            check.code === "runtime_unavailable"
          ? "runtime_failure"
          : configured
            ? "config_drift"
            : "missing_analysis_engine",
});
