import { ghidraSeedReportSchema } from "./GhidraAnalysisSeeds.js";
import { z } from "zod";

import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  GHIDRA_INVENTORY_OPERATIONS,
  GHIDRA_NAMING_OPERATIONS,
} from "./GhidraInventoryValues.js";
import { GHIDRA_FUNCTION_OPERATIONS } from "./GhidraFunctionValues.js";
import { ghidraExtensionResultSchema } from "./extensions/GhidraExtensions.js";
import { GHIDRA_MIPS_SOFT_FLOAT_STORAGE } from "./GhidraMipsProfile.js";

/** Methods every bridge must prove in its handshake after auto-analysis. */
export const GHIDRA_SESSION_BASELINE_CAPABILITIES = [
  "ping",
  "shutdown",
  ...GHIDRA_INVENTORY_OPERATIONS,
  ...GHIDRA_FUNCTION_OPERATIONS,
] as const;

/** Methods that edit the session database; read-only bridges omit them. */
export const GHIDRA_MUTATING_OPERATIONS: ReadonlySet<string> = new Set([
  "annotate_native_function",
  ...GHIDRA_NAMING_OPERATIONS,
]);

/** Baseline plus optional extended methods a bridge may additionally advertise. */
export const GHIDRA_ALL_KNOWN_CAPABILITIES: ReadonlySet<string> = new Set(GHIDRA_SESSION_BASELINE_CAPABILITIES);

// Shared wire budget: Java bounds the aggregate before serializing the handshake.
const PDB_ATTRIBUTE_UTF16_BUDGET = 4096;
const pdbAttributeSchema = z
  .string()
  .max(PDB_ATTRIBUTE_UTF16_BUDGET)
  .nullable();

const capabilitySchema = z
  .string()
  .refine((capability) => GHIDRA_ALL_KNOWN_CAPABILITIES.has(capability));

const BRIDGE_NAMES = ["REA Ghidra bridge", "REA pyGhidra bridge"] as const;

const sessionInfoSchema = z
  .object({
    name: z.enum(BRIDGE_NAMES),
    run_id: z.string().uuid(),
    profile_digest: z.string().regex(/^[a-f0-9]{64}$/u),
    provider: z
      .object({
        id: z.literal("ghidra"),
        version: z.string().min(1),
      })
      .strict(),
    read_only: z.boolean(),
    analysis_complete: z.boolean(),
    analysis_timed_out: z.boolean(),
    /** Program Information attributes; absent load state remains unknown. */
    pdb: z
      .strictObject({
        file: pdbAttributeSchema,
        guid: pdbAttributeSchema,
        /** Ghidra stores CodeView age as a hexadecimal string. */
        age: pdbAttributeSchema,
        signature: pdbAttributeSchema,
        version: pdbAttributeSchema,
        loaded: z.boolean().nullable(),
        resource_limit: z
          .strictObject({
            utf16_budget: z.literal(PDB_ATTRIBUTE_UTF16_BUDGET),
            omitted_attributes: z
              .array(z.enum(["file", "guid", "age", "signature", "version"]))
              .min(1)
              .max(5),
          })
          .optional(),
      })
      .refine(
        (pdb) =>
          [
            pdb.file,
            pdb.guid,
            pdb.age,
            pdb.signature,
            pdb.version,
          ].reduce<number>((sum, value) => sum + (value?.length ?? 0), 0) <=
          PDB_ATTRIBUTE_UTF16_BUDGET,
        "PDB attributes exceed the aggregate wire budget",
      )
      .optional(),
    analysis_extensions: z.array(ghidraExtensionResultSchema).optional(),
    analysis_seeds: ghidraSeedReportSchema.optional(),
    mips_soft_float_storage: z
      .object({
        policy: z.literal(GHIDRA_MIPS_SOFT_FLOAT_STORAGE),
        functions: z.number().int().nonnegative(),
        definitions: z.number().int().nonnegative(),
      })
      .strict()
      .optional(),
    capabilities: z.array(capabilitySchema),
    target: z
      .object({
        name: z.string().min(1),
        language_id: z.string().min(1),
        compiler_spec_id: z.string().min(1),
        image_base: z.string().regex(/^0x[0-9a-f]+$/u),
        default_address_space: z.string().min(1),
        sha256: z.string().regex(/^[a-f0-9]{64}$/u),
      })
      .strict(),
  })
  .strict();

/** Authenticated metadata produced after Ghidra finishes auto-analysis. */
export type GhidraSessionInfo = z.infer<typeof sessionInfoSchema>;

/** Describe missing PDB authority without claiming all names are generated. */
export const ghidraPdbLimitations = (
  pdb: GhidraSessionInfo["pdb"],
): readonly string[] => {
  if (pdb === undefined)
    return [
      "Ghidra did not report PDB attributes; debug-symbol coverage is unknown.",
    ];
  const limitations: string[] = [];
  if (pdb.resource_limit !== undefined)
    limitations.push(
      `PDB attributes ${pdb.resource_limit.omitted_attributes.join(", ")} were omitted because the handshake's ${pdb.resource_limit.utf16_budget}-UTF-16-unit PDB attribute budget was exhausted. Omitted values remain unknown; they were not truncated or reported as absent.`,
    );
  const hasReference = [
    pdb.file,
    pdb.guid,
    pdb.age,
    pdb.signature,
    pdb.version,
  ].some((value) => value !== null);
  const reference = hasReference
    ? `The Ghidra Program references PDB ${pdb.file ?? "(file unknown)"} (GUID ${pdb.guid ?? "unknown"}, age (hex) ${pdb.age ?? "unknown"}, signature ${pdb.signature ?? "unknown"}, version ${pdb.version ?? "unknown"}); `
    : "";
  if (pdb.loaded === true)
    return [
      ...limitations,
      `${reference}Ghidra reports a loaded PDB; this is not an independent PDB identity or complete symbol/type-coverage attestation. Original names and types may still be missing; an empty name search does not prove a procedure is absent. Use list_procedures and address-based analysis to inspect recovered functions.`,
    ];
  if (!hasReference) return limitations;
  const state = pdb.loaded === false ? "not loaded" : "load state unknown";
  return [
    ...limitations,
    `${reference}Ghidra reports ${state}. Original names and types may be missing; an empty name search does not prove a procedure is absent. Use list_procedures and address-based analysis to inspect recovered functions. REA does not admit a caller-selected PDB companion.`,
  ];
};

/** Mutation capabilities are forbidden on read-only bridges, required otherwise. */
const hasValidCapabilities = (
  advertised: readonly string[],
  readOnly: boolean,
): boolean => {
  const permitted = (capability: string): boolean =>
    !readOnly || !GHIDRA_MUTATING_OPERATIONS.has(capability);
  return (
    new Set(advertised).size === advertised.length &&
    advertised.every(
      (capability) =>
        GHIDRA_ALL_KNOWN_CAPABILITIES.has(capability) && permitted(capability),
    ) &&
    GHIDRA_SESSION_BASELINE_CAPABILITIES.filter(permitted).every((capability) =>
      advertised.includes(capability),
    )
  );
};

/** Require exact run, provider, and profile identity from the bridge. */
export const parseGhidraSessionInfo = (
  value: JsonValue,
  expected: {
    readonly runId: string;
    readonly providerVersion: string;
    readonly profileDigest: string;
    readonly targetSha256: string;
    readonly expectedReadOnly?: boolean;
    readonly expectedLanguageId?: string;
    readonly expectedCompilerSpecId?: string;
  },
): Result<GhidraSessionInfo, Error> => {
  const parsed = sessionInfoSchema.safeParse(value);
  const readOnly = expected.expectedReadOnly ?? false;
  if (
    !parsed.success ||
    parsed.data.run_id !== expected.runId ||
    parsed.data.read_only !== readOnly ||
    parsed.data.provider.version !== expected.providerVersion ||
    parsed.data.profile_digest !== expected.profileDigest ||
    parsed.data.target.sha256 !== expected.targetSha256 ||
    (expected.expectedLanguageId !== undefined &&
      parsed.data.target.language_id !== expected.expectedLanguageId) ||
    (expected.expectedCompilerSpecId !== undefined &&
      parsed.data.target.compiler_spec_id !==
        expected.expectedCompilerSpecId) ||
    !hasValidCapabilities(parsed.data.capabilities, readOnly) ||
    parsed.data.analysis_complete === parsed.data.analysis_timed_out
  )
    return err(new Error("Ghidra bridge handshake identity is invalid"));
  return ok(parsed.data);
};

/** Require acknowledgement that the private bridge loop has ended. */
export const isGhidraShutdownAcknowledgement = (value: JsonValue): boolean =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  value.shutdown === true &&
  value.project_ephemeral === true;
