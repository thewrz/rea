import { expect, it } from "vitest";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  JAVA_BACKEND,
  resolveGhidraAnalysisProfile,
  type GhidraBackendIdentity,
} from "./GhidraAnalysisProfile.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";
import { GHIDRA_PROVIDER_IDENTITY } from "./GhidraProviderCapabilities.js";

const target: BinaryTarget = {
  path: "/fixture/app",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
};

const installation = (platform: NodeJS.Platform) =>
  ({
    status: "available",
    platform,
    providerVersion: "12.0.4",
  }) as unknown as GhidraInstallationInspection;

const resolve = async (
  platform: NodeJS.Platform,
  backend?: GhidraBackendIdentity,
) => {
  const resolved = await resolveGhidraAnalysisProfile(
    target,
    GHIDRA_PROVIDER_IDENTITY,
    installation(platform),
    new ArtifactResourceScope(),
    undefined,
    undefined,
    undefined,
    ...(backend === undefined ? [] : [backend]),
  );
  if (!resolved.ok || resolved.value.profile === null)
    throw new Error("expected a resolved profile");
  return resolved.value.profile;
};

it("keeps the Java backend profile free of backend fields", async () => {
  const profile = await resolve("linux", JAVA_BACKEND);
  expect(profile.parameters.process_launch).toBe(
    "inspected-jvm-launch-support-v1",
  );
  expect(profile.parameters).not.toHaveProperty("analysis_backend");
  expect((await resolve("linux")).digest).toBe(profile.digest);
});

it("commits the pyGhidra launch and version on POSIX", async () => {
  const profile = await resolve("linux", {
    kind: "pyghidra",
    version: "3.1.0",
  });
  expect(profile.parameters.process_launch).toBe("pyghidra-cpython-jpype-v1");
  expect(profile.parameters.analysis_backend).toEqual({
    kind: "pyghidra",
    version: "3.1.0",
  });
});

it("omits an unknown pyGhidra version instead of committing undefined", async () => {
  const profile = await resolve("linux", { kind: "pyghidra" });
  expect(profile.parameters.analysis_backend).toEqual({ kind: "pyghidra" });
});

it("produces distinct digests per backend and per pyGhidra version", async () => {
  const digests = await Promise.all([
    resolve("linux", JAVA_BACKEND),
    resolve("linux", { kind: "pyghidra", version: "3.1.0" }),
    resolve("linux", { kind: "pyghidra", version: "3.2.0" }),
    resolve("linux", { kind: "pyghidra" }),
  ]).then((profiles) => profiles.map((profile) => profile.digest));
  expect(new Set(digests).size).toBe(digests.length);
});

it("keeps the Windows launch value but still distinguishes pyGhidra", async () => {
  const java = await resolve("win32", JAVA_BACKEND);
  const pyghidra = await resolve("win32", {
    kind: "pyghidra",
    version: "3.1.0",
  });
  expect(pyghidra.parameters.process_launch).toBe(
    "official-headless-script-v1",
  );
  expect(pyghidra.digest).not.toBe(java.digest);
});
