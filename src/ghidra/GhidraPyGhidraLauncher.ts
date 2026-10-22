import { ghidraJavaEnvironment } from "./GhidraInstallation.js";
import {
  cleanupStartedProcess,
  createGhidraRuntimeDirectories,
  ghidraRuntimePaths,
  GhidraLaunchError,
  ownedGhidraLaunch,
  writeGhidraRuntimeFile,
  type GhidraLaunch,
  type GhidraLaunchRollbackFailure,
  type GhidraLaunchSession,
  type GhidraLauncher,
} from "./GhidraLauncher.js";
import { snapshotGhidraAnalysisSeeds } from "./GhidraAnalysisSeeds.js";
import {
  snapshotGhidraExtensions,
  type GhidraExtension,
} from "./extensions/GhidraExtensions.js";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { GhidraSeedCommitment } from "./GhidraAnalysisSeeds.js";
import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import {
  spawnOwnedProviderProcess,
  type SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";

export interface GhidraPyGhidraLauncherOptions {
  readonly pythonPath: string;
  readonly bridgeScriptPath: string;
  readonly ghidraInstallDir: string;
  readonly javaHome?: string;
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly platform?: NodeJS.Platform;
  /** Ghidra's per-release config directory name; absent leaves it to Ghidra. */
  readonly configurationDirectoryName?: string;
  readonly languageOverride?: GhidraLanguageOverride;
  readonly disabledAnalyzers?: readonly string[];
  readonly analysisSeeds?: GhidraSeedCommitment;
  readonly analysisExtensions?: readonly GhidraExtension[];
  readonly mipsSoftFloat?: true;
  readonly spawnProcess?: typeof spawnOwnedProviderProcess;
}

type LaunchOptions = {
  readonly signal?: AbortSignal;
  readonly resourceScope?: ArtifactResourceScope;
};

type LaunchResult = Result<
  GhidraLaunch,
  GhidraLaunchError | AnalysisCancelledError
>;

const isAborted = (signal?: AbortSignal): boolean => signal?.aborted === true;

const cancelled = (signal?: AbortSignal): AnalysisCancelledError =>
  new AnalysisCancelledError("open_binary", { cause: signal?.reason });

/** Starts the pyGhidra bridge in a private Python process instead of analyzeHeadless. */
export class GhidraPyGhidraLauncher implements GhidraLauncher {
  readonly options: GhidraPyGhidraLauncherOptions;

  constructor(options: GhidraPyGhidraLauncherOptions) {
    this.options = {
      ...options,
      environment: snapshotEnvironment(options.environment, options.platform),
    };
  }

  async launch(
    session: GhidraLaunchSession,
    options: LaunchOptions = {},
  ): Promise<LaunchResult> {
    if (isAborted(options.signal)) return err(cancelled(options.signal));
    const platform = this.options.platform ?? process.platform;
    const paths = ghidraRuntimePaths(session.runtimeRoot);
    let started: SpawnedOwnedProviderProcess | undefined;
    try {
      // Ghidra's framework creates JDK resolution and ghidra.properties here even under pyGhidra
      await createGhidraRuntimeDirectories(
        paths,
        platform,
        this.options.configurationDirectoryName ?? "",
      );
      const descriptor = await this.descriptor(session, options);
      await writeGhidraRuntimeFile(
        paths.descriptorPath,
        `${JSON.stringify(descriptor)}\n`,
        platform,
      );
      if (isAborted(options.signal)) return err(cancelled(options.signal));
      started = await (this.options.spawnProcess ?? spawnOwnedProviderProcess)({
        command: this.options.pythonPath,
        arguments: [
          "-I",
          this.options.bridgeScriptPath,
          paths.descriptorPath,
          session.targetPath,
        ],
        runId: session.runId,
        // The interpreter is not the bridge, so argv-prefix matching cannot apply.
        expectedCommand: null,
        platform,
        env: this.environment(paths, platform),
        hostEnvironment: {},
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      }).catch((cause: unknown) => {
        if (cause === options.signal?.reason && isAborted(options.signal))
          throw cancelled(options.signal);
        throw cause;
      });
      const launch = ownedGhidraLaunch(started, paths, platform, []);
      await writeGhidraRuntimeFile(
        paths.ownershipPath,
        `${JSON.stringify({
          run_id: session.runId,
          transport: session.transport,
          endpoint_path: session.endpointPath,
          pid: started.ownership.leaderPid,
          process_group_id: started.ownership.processGroupId,
          parent_pid: process.pid,
          ownership_kind:
            platform === "win32" ? "windows-job-object" : "posix-process-group",
          launcher: this.options.pythonPath,
          headless_script: this.options.bridgeScriptPath,
          created_at: new Date().toISOString(),
        })}\n`,
        platform,
      );
      if (isAborted(options.signal)) throw cancelled(options.signal);
      return ok(launch);
    } catch (cause: unknown) {
      return err(await this.failure(cause, started, paths, platform));
    }
  }

  private async descriptor(
    session: GhidraLaunchSession,
    options: LaunchOptions,
  ): Promise<Record<string, unknown>> {
    const { analysisSeeds, analysisExtensions } = this.options;
    const needsScope =
      analysisSeeds !== undefined || (analysisExtensions?.length ?? 0) > 0;
    if (needsScope && options.resourceScope === undefined)
      throw new GhidraLaunchError(
        "Configured Ghidra artifacts require a caller-owned resource scope.",
      );
    const scope = options.resourceScope;
    const seedPath =
      analysisSeeds === undefined || scope === undefined
        ? undefined
        : await snapshotGhidraAnalysisSeeds(
            analysisSeeds,
            session.runtimeRoot,
            scope,
            options.signal,
          );
    const extensions =
      scope === undefined
        ? []
        : await snapshotGhidraExtensions(
            analysisExtensions ?? [],
            session.runtimeRoot,
            scope,
            options.signal,
          );
    const override = this.options.languageOverride;
    const disabled = this.options.disabledAnalyzers ?? [];
    return {
      transport: session.transport,
      endpoint_path: session.endpointPath,
      token: session.token,
      run_id: session.runId,
      target_sha256: session.targetSha256,
      provider_version: session.providerVersion,
      profile_digest: session.profileDigest,
      ...(override === undefined ? {} : { language_id: override.languageId }),
      ...(override?.compilerSpecId === undefined
        ? {}
        : { compiler_spec_id: override.compilerSpecId }),
      ...(disabled.length === 0 ? {} : { disabled_analyzers: disabled }),
      ...(seedPath === undefined ? {} : { seed_paths: [seedPath] }),
      ...(extensions.length === 0 ? {} : { analysis_extensions: extensions }),
      ...(this.options.mipsSoftFloat === true ? { mips_soft_float: true } : {}),
    };
  }

  private environment(
    paths: ReturnType<typeof ghidraRuntimePaths>,
    platform: NodeJS.Platform,
  ): NodeJS.ProcessEnv {
    return {
      ...ghidraJavaEnvironment(
        this.options.javaHome,
        this.options.environment,
        platform,
      ),
      GHIDRA_INSTALL_DIR: this.options.ghidraInstallDir,
      HOME: paths.homeRoot,
      TMPDIR: paths.tempRoot,
      ...(platform === "win32"
        ? {
            USERPROFILE: paths.homeRoot,
            APPDATA: paths.configRoot,
            LOCALAPPDATA: paths.cacheRoot,
            TEMP: paths.tempRoot,
            TMP: paths.tempRoot,
          }
        : {}),
      XDG_CACHE_HOME: paths.cacheRoot,
      XDG_CONFIG_HOME: paths.configRoot,
      XDG_DATA_HOME: paths.dataRoot,
    };
  }

  private async failure(
    cause: unknown,
    started: SpawnedOwnedProviderProcess | undefined,
    paths: ReturnType<typeof ghidraRuntimePaths>,
    platform: NodeJS.Platform,
  ): Promise<GhidraLaunchError | AnalysisCancelledError> {
    if (cause instanceof AnalysisCancelledError && started === undefined)
      return cause;
    const cancellation =
      cause instanceof AnalysisCancelledError ? cause : undefined;
    const failure = new GhidraLaunchError("pyGhidra bridge launch failed", {
      cause,
      ...(cancellation === undefined ? {} : { primaryFailure: cancellation }),
    });
    if (started === undefined) return failure;
    const owner = started;
    const rollback = await Promise.resolve()
      .then(() => cleanupStartedProcess(owner, platform))
      .then(
        (result): Result<null, GhidraLaunchRollbackFailure> =>
          result.cleaned ? ok(null) : err({ kind: "incomplete", result }),
        (rejected: unknown): Result<null, GhidraLaunchRollbackFailure> =>
          err({ kind: "rejected", cause: rejected }),
      );
    if (rollback.ok) return cancellation ?? failure;
    return new GhidraLaunchError(
      `${cancellation?.message ?? `pyGhidra bridge launch failed: ${cause instanceof Error ? cause.message : String(cause)}`}; process cleanup remains incomplete`,
      {
        cause: new AggregateError(
          [
            failure,
            rollback.error.kind === "rejected"
              ? rollback.error.cause
              : rollback.error.result,
          ],
          "pyGhidra launch rollback did not release its process",
          { cause: failure },
        ),
        partialLaunch: ownedGhidraLaunch(started, paths, platform, []),
        rollbackFailure: rollback.error,
        ...(cancellation === undefined ? {} : { primaryFailure: cancellation }),
      },
    );
  }
}
