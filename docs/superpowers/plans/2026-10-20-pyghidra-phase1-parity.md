# pyGhidra Phase 1: Parity Backend — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add pyGhidra as a protocol-compatible alternative Ghidra backend that implements all existing operations identically to the Java bridge, selectable via environment or auto-detected.

**Architecture:** A Python bridge process (`bridge/pyghidra/`) speaks the same newline-delimited JSON-over-socket wire protocol as `ReaGhidraBridge.java`. A new `GhidraPyGhidraLauncher` implements the `GhidraLauncher` interface, spawning Python instead of `analyzeHeadless`. The `GhidraProvider` selects the backend based on availability and configuration. The existing TS transport stack (`GhidraWire`, `GhidraResponseRouter`, `GhidraResponseBuffer`, `protocol.ts`) remains unchanged.

**Tech Stack:** Python 3.10+ / pyGhidra / JPype1 (bridge), TypeScript / Node.js / Zod / vitest (REA)

**Spec:** `docs/superpowers/specs/2026-10-20-pyghidra-integration-design.md`

## Global Constraints

- Python 3.10+ required for pyGhidra
- pyGhidra version must match the Ghidra installation version
- Unix-only in Phase 1 — Windows is excluded (uses TCP with `read_only: true`)
- The Java bridge path must remain fully functional; no regressions
- All Python bridge outputs must pass the same Zod schemas as Java bridge outputs
- Addresses use canonical format: `0x<hex>` for default space, `<encoded-space>:0x<hex>` for nondefault
- Ephemeral projects must be deleted on shutdown (pyGhidra does not auto-delete)
- Bridge files must be listed in `package.json` `files` array for npm distribution
- Follow `CONTRIBUTING.md` contribution scope: no target execution, script running, or archive mutation

## Review Focus

1. **Decompiler output divergence**: pyGhidra's DecompInterface may produce slightly different pseudocode formatting than the Java bridge for the same binary. A reviewer should verify that schema validation catches structural differences while tolerating cosmetic ones — run both backends against the same test binary and diff the `procedure_pseudo_code` results.
2. **Address space encoding edge cases**: Nondefault address spaces (`EXTERNAL`, segmented addresses like `1000:0x0042`) must be encoded identically to the Java bridge. Test with binaries that have relocations, external symbols, and segmented memory models.
3. **Startup timeout under slow JVM init**: pyGhidra starts a full JVM via JPype — if the system is under load, startup may exceed the default timeout. Verify the existing `DEFAULT_GHIDRA_STARTUP_TIMEOUT_MS` is adequate by measuring pyGhidra cold-start time.
4. **Descriptor field evolution**: If a future Java bridge version adds fields to the session descriptor, the Python bridge must tolerate unknown fields (ignore, not crash). Test by adding an unknown field to a descriptor and verifying the bridge starts normally.
5. **Concurrent shutdown race**: If `GhidraClient` sends `shutdown` while a long-running operation (e.g. `batch_decompile`) is in progress, the bridge must respond to shutdown after the in-flight operation completes or errors. Test by sending shutdown immediately after starting a slow operation.

---

### Task 1: Session Handshake Relaxation (`GhidraSessionValues.ts`)

**Files:**
- Modify: `src/ghidra/GhidraSessionValues.ts`
- Test: `src/ghidra/GhidraSessionValues.test.ts`

**Interfaces:**
- Consumes: existing `sessionInfoSchema`, `parseGhidraSessionInfo`, `GHIDRA_SESSION_CAPABILITIES`
- Produces: `GHIDRA_SESSION_BASELINE_CAPABILITIES` (the existing set, renamed), `GHIDRA_ALL_KNOWN_CAPABILITIES` (baseline + extended, as a `ReadonlySet<string>`), relaxed `sessionInfoSchema` accepting both bridge names, `parseGhidraSessionInfo` that validates baseline-required + extended-optional capabilities

- [ ] **Step 1: Write failing test for pyGhidra bridge name acceptance**

```typescript
// In GhidraSessionValues.test.ts
import { describe, it, expect } from "vitest";
import { parseGhidraSessionInfo } from "./GhidraSessionValues.js";

describe("parseGhidraSessionInfo", () => {
  it("accepts REA pyGhidra bridge name", () => {
    const sessionInfo = createValidSessionInfo({
      name: "REA pyGhidra bridge",
    });
    const result = parseGhidraSessionInfo(sessionInfo, validExpected());
    expect(result.ok).toBe(true);
  });

  it("still accepts REA Ghidra bridge name", () => {
    const sessionInfo = createValidSessionInfo({
      name: "REA Ghidra bridge",
    });
    const result = parseGhidraSessionInfo(sessionInfo, validExpected());
    expect(result.ok).toBe(true);
  });

  it("rejects unknown bridge name", () => {
    const sessionInfo = createValidSessionInfo({
      name: "Unknown bridge",
    });
    const result = parseGhidraSessionInfo(sessionInfo, validExpected());
    expect(result.ok).toBe(false);
  });
});
```

Use existing test fixtures in `GhidraSessionValues.test.ts` as a template for `createValidSessionInfo` and `validExpected` helpers. Read the file first to match the existing fixture pattern.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/ghidra/GhidraSessionValues.test.ts --reporter=verbose`
Expected: FAIL — `parseGhidraSessionInfo` rejects `"REA pyGhidra bridge"` because `sessionInfoSchema` has `z.literal("REA Ghidra bridge")`.

- [ ] **Step 3: Relax the session name schema**

In `src/ghidra/GhidraSessionValues.ts`, change the `name` field in `sessionInfoSchema` from:
```typescript
name: z.literal("REA Ghidra bridge"),
```
to:
```typescript
name: z.enum(["REA Ghidra bridge", "REA pyGhidra bridge"]),
```

- [ ] **Step 4: Write failing test for baseline/optional capability validation**

```typescript
it("accepts handshake with only baseline capabilities (Java bridge)", () => {
  const sessionInfo = createValidSessionInfo({
    capabilities: [...GHIDRA_SESSION_BASELINE_CAPABILITIES],
  });
  const result = parseGhidraSessionInfo(sessionInfo, validExpected());
  expect(result.ok).toBe(true);
});

it("rejects handshake missing a baseline capability", () => {
  const baseline = [...GHIDRA_SESSION_BASELINE_CAPABILITIES];
  baseline.pop(); // remove one
  const sessionInfo = createValidSessionInfo({ capabilities: baseline });
  const result = parseGhidraSessionInfo(sessionInfo, validExpected());
  expect(result.ok).toBe(false);
});

it("rejects handshake with unknown capability", () => {
  const sessionInfo = createValidSessionInfo({
    capabilities: [
      ...GHIDRA_SESSION_BASELINE_CAPABILITIES,
      "totally_unknown_op",
    ],
  });
  const result = parseGhidraSessionInfo(sessionInfo, validExpected());
  expect(result.ok).toBe(false);
});

it("accepts read-only handshake without mutation capabilities", () => {
  const readOnlyCapabilities = GHIDRA_SESSION_BASELINE_CAPABILITIES.filter(
    (cap) => !GHIDRA_MUTATING_OPERATIONS.has(cap),
  );
  const sessionInfo = createValidSessionInfo({
    capabilities: readOnlyCapabilities,
    read_only: true,
  });
  const result = parseGhidraSessionInfo(sessionInfo, {
    ...validExpected(),
    expectedReadOnly: true,
  });
  expect(result.ok).toBe(true);
});
```

- [ ] **Step 5: Run tests to verify failures**

Run: `npx vitest run src/ghidra/GhidraSessionValues.test.ts --reporter=verbose`
Expected: FAIL on the new tests.

- [ ] **Step 6: Implement baseline/optional capability split**

In `src/ghidra/GhidraSessionValues.ts`:

1. Rename `GHIDRA_SESSION_CAPABILITIES` to `GHIDRA_SESSION_BASELINE_CAPABILITIES` (keep the old name as a re-export alias to avoid breaking other files — search for all imports first).
2. Create `GHIDRA_ALL_KNOWN_CAPABILITIES`:
```typescript
export const GHIDRA_ALL_KNOWN_CAPABILITIES: ReadonlySet<string> = new Set([
  ...GHIDRA_SESSION_BASELINE_CAPABILITIES,
  // Phase 2 will add extended operations here
]);
```
3. Update `capabilitySchema` to accept all known capabilities.
4. Update `parseGhidraSessionInfo` validation: require all baseline capabilities present (accounting for read-only mode), permit only known capabilities, reject duplicates. Replace the existing exact-length + exact-membership check. The required set must exclude mutation capabilities when `expectedReadOnly` is true:
```typescript
const requiredBaseline = readOnly
  ? GHIDRA_SESSION_BASELINE_CAPABILITIES.filter(
      (cap) => !GHIDRA_MUTATING_OPERATIONS.has(cap),
    )
  : [...GHIDRA_SESSION_BASELINE_CAPABILITIES];
const hasAllRequired = requiredBaseline.every((cap) =>
  parsed.data.capabilities.includes(cap),
);
const allKnown = parsed.data.capabilities.every((cap) =>
  GHIDRA_ALL_KNOWN_CAPABILITIES.has(cap),
);
const noDuplicates =
  new Set(parsed.data.capabilities).size === parsed.data.capabilities.length;
```
This preserves the existing Windows test at `GhidraSessionValues.test.ts:156` which verifies read-only acceptance without mutations.

- [ ] **Step 7: Run all tests**

Run: `npx vitest run src/ghidra/GhidraSessionValues.test.ts --reporter=verbose`
Expected: All PASS — both old and new tests.

- [ ] **Step 8: Run the broader Ghidra test suite for regressions**

Run: `npx vitest run src/ghidra/ --reporter=verbose`
Run: `npm run test:focused -- tests/boundary/providers/ghidra/`
Expected: All existing tests PASS including boundary launcher/client tests. The Java bridge handshake still works because baseline capabilities are unchanged.

- [ ] **Step 9: Commit**

```bash
git add src/ghidra/GhidraSessionValues.ts src/ghidra/GhidraSessionValues.test.ts
git commit -m "feat(ghidra): relax session handshake for pyGhidra bridge name and optional capabilities"
```

---

### Task 2: Analysis Profile Backend Identity (`GhidraAnalysisProfile.ts`)

**Files:**
- Modify: `src/ghidra/GhidraAnalysisProfile.ts`
- Modify: `src/ghidra/GhidraProvider.ts` (thread backend kind to `resolveGhidraAnalysisProfile` call at ~line 386)
- Test: existing `GhidraAnalysisProfile` tests (if any), or add inline

**Interfaces:**
- Consumes: `resolveGhidraAnalysisProfile` function (called from `GhidraProvider.ts:386`, NOT `GhidraProviderClient.ts`), `createAnalysisProfile` from `src/domain/analysisProfile.ts`
- Produces: `process_launch` profile field now distinguishes `"pyghidra-cpython-jpype-v1"` from `"inspected-jvm-launch-support-v1"` / `"official-headless-script-v1"`, causing different profile digests per backend. Backend version (pyGhidra version string) is included in the profile commitment alongside backend kind.

- [ ] **Step 1: Identify current `process_launch` values**

Read `src/ghidra/GhidraAnalysisProfile.ts` to find all places `process_launch` is set. Currently:
- `"inspected-jvm-launch-support-v1"` for POSIX
- `"official-headless-script-v1"` for Windows

The caller is `GhidraProvider.ts` at ~line 386 (`resolveGhidraAnalysisProfile(target, GHIDRA_PROVIDER_IDENTITY, installation, ...)`).

- [ ] **Step 2: Add backend kind and version parameters**

```typescript
type GhidraBackendKind = "java" | "pyghidra";
type GhidraBackendIdentity = {
  readonly kind: GhidraBackendKind;
  readonly version?: string; // pyGhidra version string, e.g. "3.1.0"
};
```

Thread `GhidraBackendIdentity` through `GhidraProvider.ts` to `resolveGhidraAnalysisProfile`. The provider owns this call, not the client. When `backend.kind === "pyghidra"` and platform is not `"win32"`, use `"pyghidra-cpython-jpype-v1"` as the `process_launch` value. Include the backend version in the profile commitment so digests distinguish pyGhidra version changes.

- [ ] **Step 3: Verify profile digest changes**

Write a test (or add to existing profile tests) that creates two profiles identical except for `process_launch` and asserts their digests differ:

```typescript
it("pyghidra and java backends produce different profile digests", () => {
  const javaProfile = createAnalysisProfile(provider, {
    ...baseProfileParams,
    process_launch: "inspected-jvm-launch-support-v1",
  });
  const pyghidraProfile = createAnalysisProfile(provider, {
    ...baseProfileParams,
    process_launch: "pyghidra-cpython-jpype-v1",
  });
  expect(javaProfile.digest).not.toBe(pyghidraProfile.digest);
});
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/ghidra/ --reporter=verbose`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ghidra/GhidraAnalysisProfile.ts src/ghidra/GhidraProvider.ts
git commit -m "feat(ghidra): include backend identity in analysis profile for Evidence provenance"
```

---

### Task 3: pyGhidra Installation Inspection (`GhidraInstallation.ts`, `GhidraDoctor.ts`)

**Files:**
- Modify: `src/ghidra/GhidraInstallation.ts`
- Modify: `src/ghidra/GhidraDoctor.ts`
- Modify: `src/config/environment.ts` (add `REA_GHIDRA_BACKEND`, `REA_PYGHIDRA_PYTHON`)
- Modify: `src/config/types.ts` (add config fields)
- Test: `src/ghidra/GhidraInstallation.test.ts`

**Interfaces:**
- Consumes: `inspectGhidraInstallation` function, `AppConfig` type, environment schema
- Produces: `PyGhidraAvailability` type (`{ available: true, version: string, pythonPath: string } | { available: false, reason: string }`), `inspectPyGhidraAvailability(pythonPath: string, signal?: AbortSignal): Promise<PyGhidraAvailability>`, new config fields `ghidraBackend: "auto" | "java" | "pyghidra"` and `pyghidraPythonPath: string`

- [ ] **Step 1: Add environment variables to config schema**

In `src/config/environment.ts`, add:
```typescript
REA_GHIDRA_BACKEND: z.enum(["auto", "java", "pyghidra"]).default("auto"),
REA_PYGHIDRA_PYTHON: z.string().min(1).default("python3"),
```

In `src/config/types.ts`, add to `AppConfig`:
```typescript
readonly ghidraBackend: "auto" | "java" | "pyghidra";
readonly pyghidraPythonPath: string;
```

In `src/config/parseConfig.ts`, wire them through.

- [ ] **Step 2: Write failing test for pyGhidra availability probe**

```typescript
// In GhidraInstallation.test.ts
import { inspectPyGhidraAvailability } from "./GhidraInstallation.js";

describe("inspectPyGhidraAvailability", () => {
  it("returns available with version when pyghidra is importable", async () => {
    // This test only passes in environments with pyGhidra installed.
    // Gate with: if (!process.env.REA_TEST_PYGHIDRA) return;
    const result = await inspectPyGhidraAvailability("python3");
    if (process.env.REA_TEST_PYGHIDRA) {
      expect(result.available).toBe(true);
      if (result.available) {
        expect(result.version).toMatch(/^\d+\.\d+/);
      }
    }
  });

  it("returns unavailable for nonexistent interpreter", async () => {
    const result = await inspectPyGhidraAvailability(
      "/nonexistent/python3",
    );
    expect(result.available).toBe(false);
  });
});
```

- [ ] **Step 3: Run test to verify failure**

Run: `npx vitest run src/ghidra/GhidraInstallation.test.ts --reporter=verbose`
Expected: FAIL — `inspectPyGhidraAvailability` does not exist yet.

- [ ] **Step 4: Implement pyGhidra availability probe**

In `src/ghidra/GhidraInstallation.ts`, add:

```typescript
export type PyGhidraAvailability =
  | { readonly available: true; readonly version: string; readonly pythonPath: string }
  | { readonly available: false; readonly reason: string };

export const inspectPyGhidraAvailability = async (
  pythonPath: string,
  ghidraInstallDir: string,
  signal?: AbortSignal,
): Promise<PyGhidraAvailability> => {
  signal?.throwIfAborted();
  try {
    // Phase 1: verify pyghidra is importable and get version
    const { stdout: versionOut } = await execFileOutput(pythonPath, [
      "-c",
      "import pyghidra; print(pyghidra.__version__)",
    ], { signal, timeout: 10_000 });
    const version = versionOut.trim();
    if (!version) return { available: false, reason: "pyGhidra reported empty version" };

    // Phase 2: verify JVM startup against the selected Ghidra installation
    signal?.throwIfAborted();
    await execFileOutput(pythonPath, [
      "-c",
      "import pyghidra; pyghidra.start()",
    ], {
      signal,
      timeout: 60_000,
      env: { GHIDRA_INSTALL_DIR: ghidraInstallDir },
    });

    return { available: true, version, pythonPath };
  } catch (error) {
    if (signal?.aborted) throw signal.reason;
    return { available: false, reason: `pyGhidra not available via ${pythonPath}: ${error instanceof Error ? error.message : String(error)}` };
  }
};
```

Key differences from the naive version-only probe:
- Passes `GHIDRA_INSTALL_DIR` environment to the probe, matching the actual launch env
- Verifies JVM startup (not just importability) — catches JPype/JDK mismatches early
- Preserves cancellation as cancellation (rethrows `signal.reason`) instead of caching as unavailability
- Uses the same `execFileOutput` from `src/process/ExecFileOutput.ts` used for Java probes
- Cache the result per provider instance lifetime (aligns with existing scope-bound/shared inspection lifecycle in `GhidraProvider.ts:527`)

- [ ] **Step 5: Extract shared backend selection logic**

Create a pure function used by both `GhidraDoctor` and `GhidraProvider`:

```typescript
export type GhidraBackendSelection =
  | { readonly selected: "java"; readonly reason: string }
  | { readonly selected: "pyghidra"; readonly pyghidraVersion: string };

export const resolveGhidraBackend = (
  config: { readonly ghidraBackend: "auto" | "java" | "pyghidra" },
  pyghidraAvailability: PyGhidraAvailability,
  platform: NodeJS.Platform,
): GhidraBackendSelection => {
  if (platform === "win32")
    return { selected: "java", reason: "Windows excluded in Phase 1" };
  if (config.ghidraBackend === "java")
    return { selected: "java", reason: "REA_GHIDRA_BACKEND=java" };
  if (config.ghidraBackend === "pyghidra") {
    if (!pyghidraAvailability.available)
      throw new Error(`pyGhidra backend required but unavailable: ${pyghidraAvailability.reason}`);
    return { selected: "pyghidra", pyghidraVersion: pyghidraAvailability.version };
  }
  // auto
  if (pyghidraAvailability.available)
    return { selected: "pyghidra", pyghidraVersion: pyghidraAvailability.version };
  return { selected: "java", reason: pyghidraAvailability.reason };
};
```

- [ ] **Step 6: Add doctor diagnostics**

In `src/ghidra/GhidraDoctor.ts`, extend `inspectSystemGhidraProvider` to:
1. Call `inspectPyGhidraAvailability` with the installation's dir
2. Call `resolveGhidraBackend` to determine the selected backend
3. Report the result: selected backend, pyGhidra version if available, fallback reason if not
4. Add tests for: forced-backend failure, Windows exclusion, auto-fallback reporting

- [ ] **Step 7: Run tests**

Run: `npx vitest run src/ghidra/GhidraInstallation.test.ts --reporter=verbose`
Expected: PASS.

- [ ] **Step 8: Run typecheck**

Run: `npx turbo run typecheck`
Expected: PASS — new config fields are properly threaded.

- [ ] **Step 9: Commit**

```bash
git add src/ghidra/GhidraInstallation.ts src/ghidra/GhidraDoctor.ts \
  src/config/environment.ts src/config/types.ts src/config/parseConfig.ts \
  src/ghidra/GhidraInstallation.test.ts
git commit -m "feat(ghidra): add pyGhidra availability inspection and backend config"
```

---

### Task 4: Python Bridge — Protocol Handler and Inventory Operations

**Files:**
- Create: `bridge/pyghidra/__main__.py`
- Create: `bridge/pyghidra/rea_pyghidra_bridge.py`
- Create: `bridge/pyghidra/operations/__init__.py`
- Create: `bridge/pyghidra/operations/inventory.py`
- Create: `bridge/pyghidra/requirements.txt`
- Create: `bridge/pyghidra/test_bridge_protocol.py`
- Modify: `package.json` (`files` array, `test:python` script)

**Interfaces:**
- Consumes: session descriptor JSON (transport, endpoint_path, token, run_id, target_sha256, provider_version, profile_digest), target path via argv
- Produces: a running socket server that handles `ping`, `shutdown`, and all `GHIDRA_INVENTORY_OPERATIONS`: `read_binary_inventory_summary`, `inspect_native_load_image`, `read_bytes`, `search_bytes`, `address_to_file_offset`, `address_name`, `list_documents`, `list_names`, `list_procedures`, `list_segments`, `list_strings`, `procedure_address`, `resolve_containing_procedure`, `search_procedures`, `search_strings`, `set_address_name`, `set_addresses_names`

- [ ] **Step 1: Create `requirements.txt`**

```
pyghidra>=3.1.0
```

Version 3.1.0 is bundled with Ghidra 12.1.4 (the version REA verifies at `GhidraReleasePolicy.ts:2`). The revised API (`start()`, project-based import) arrived in pyGhidra 3.0; earlier versions lack required APIs. The pyGhidra version must be from the same Ghidra release line as the installation.

- [ ] **Step 2: Create `bridge/pyghidra/__main__.py`**

```python
"""REA pyGhidra bridge entry point.

Usage: python <path>/__main__.py <descriptor-path> <target-path>
"""
import json
import sys

def main():
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <descriptor-path> <target-path>",
            file=sys.stderr,
        )
        sys.exit(1)

    descriptor_path = sys.argv[1]
    target_path = sys.argv[2]

    with open(descriptor_path, "r") as f:
        descriptor = json.load(f)

    from rea_pyghidra_bridge import run_bridge
    run_bridge(descriptor, descriptor_path, target_path)

if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Create `bridge/pyghidra/rea_pyghidra_bridge.py` — protocol core**

This is the main bridge file. It handles:
1. pyGhidra JVM startup and program import
2. Socket server (Unix domain socket)
3. Request authentication and dispatch
4. Response framing
5. Shutdown and cleanup

Key implementation details:
- `run_bridge(descriptor, descriptor_path, target_path)` — receives all three from `__main__.py`
- Derive runtime root from `descriptor_path`: `os.path.dirname(descriptor_path)`
- Read the descriptor for transport, endpoint_path, token, run_id, target_sha256, provider_version, profile_digest, plus analysis config fields (see below)
- Start pyGhidra via `pyghidra.start()`, then import `ghidra` packages
- Create an ephemeral project inside the runtime root
- Import the target binary with language/compiler spec from descriptor if present
- **Apply analysis configuration for parity with Java launcher** (see `GhidraLauncher.ts:826`):
  1. Language/compiler-spec selection from descriptor `language_id`/`compiler_spec_id`
  2. Disabled analyzers from descriptor `disabled_analyzers` — apply via `AutoAnalysisManager` API
  3. Analysis seeds from descriptor `seed_paths` — apply seed data to program before analysis
  4. No-return fix extension from descriptor `analysis_extensions` — apply if present
  5. MIPS soft-float processing from descriptor `mips_soft_float` — apply if present
- Run Ghidra auto-analysis via `pyghidra.analyze()`
- **Verify imported binary identity**: after import, check `program.getExecutableSHA256()` matches `descriptor["target_sha256"]`. Fail with a clear error on mismatch — echoing an expected digest is not import attestation.
- Bind socket to `endpoint_path`
- **Authentication (Unix)**: accept one connection (matching Java's Unix path at `ReaGhidraBridge.java:360`). Validate token on each request. On wrong token, return an error response but do not disconnect (the connection is already established). Add wrong-token and silent-peer (no data sent) tests.
- Request loop: parse JSON line, verify token, dispatch method, write JSON response line
- `ping` returns session info matching `sessionInfoSchema`
- `shutdown` closes program, deletes project directory, responds, exits

The `ping` response must produce:
```python
{
    "name": "REA pyGhidra bridge",
    "run_id": descriptor["run_id"],
    "profile_digest": descriptor["profile_digest"],
    "provider": {"id": "ghidra", "version": ghidra_version},
    "read_only": False,
    "analysis_complete": True,
    "analysis_timed_out": False,
    "capabilities": [<all baseline capability names>],
    "target": {
        "name": program.getName(),
        "language_id": str(program.getLanguageID()),
        "compiler_spec_id": str(program.getCompilerSpec().getCompilerSpecID()),
        "image_base": format_address(program.getImageBase()),
        "default_address_space": program.getAddressFactory().getDefaultAddressSpace().getName(),
        "sha256": descriptor["target_sha256"],
    },
}
```

Address formatting helper — capture the program's default address space at bridge startup (matching `ReaGhidraBridge.java:203`), then compare with `space.equals()` (matching `ReaGhidraBridge.java:4510`). Do NOT call `isDefaultSpace()` (does not exist in Ghidra's AddressSpace API) or use the `"ram"` heuristic:

```python
# At bridge startup, after importing the program:
session_default_space = program.getAddressFactory().getDefaultAddressSpace()

def format_address(addr, session_default_space):
    """Format a Ghidra Address to canonical REA wire format."""
    space = addr.getAddressSpace()
    offset_hex = format(addr.getOffset() & 0xFFFFFFFFFFFFFFFF, 'x')
    if space.equals(session_default_space):
        return f"0x{offset_hex}"
    from urllib.parse import quote
    encoded_space = quote(space.getName(), safe="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-")
    return f"{encoded_space}:0x{offset_hex}"
```

- [ ] **Step 4: Create `bridge/pyghidra/operations/inventory.py`**

Implement each inventory operation as a function that receives `(program, flat_api, params)` and returns a JSON-serializable dict. The return shapes must match what the Java bridge produces (validated by the TS Zod schemas).

Key operations and their **exact** return shapes (from actual Zod schemas — the Python bridge MUST match these or validation fails):

- `list_procedures`: `[{"address": str, "value": str, "procedure": {"external": bool, "thunk": bool, "thunk_target": str|null}}, ...]` (from `GhidraInventoryValues.ts:procedureItem`)
- `list_segments`: `[{"name": str, "start": str, "end": str, "readable": bool, "writable": bool, "executable": bool, "permissions": {"available": true, "source": "ghidra-memory-block"}, "provenance": "ghidra-memory-block", "address_space": str, "image_base": str, "initialized": bool, "overlay": bool, "sections": [<nested memoryRegion array>]}, ...]` (from `GhidraInventoryValues.ts:segment` — note: `readable`/`writable`/`executable` not `read`/`write`/`execute`; includes `permissions`, `provenance`, `address_space`, `image_base`, `overlay`, `sections`)
- `list_strings`: `[{"address": str, "value": str, "string": {"encoding": str, "termination": "missing"|"present_or_not_required", "byte_length": int}}, ...]` (from `GhidraInventoryValues.ts:stringItem` — note: nested `string` facts, NOT flat `length`)
- `read_bytes`: `{"address": str, "requested_bytes": int, "returned_bytes": int, "bytes_hex": str, "complete": bool}` (from `nativeByteRead.ts:nativeByteReadSchema` — invariant: `returned_bytes * 2 === bytes_hex.length`, `complete === (returned_bytes === requested_bytes)`)
- `search_bytes`: `{"matches": [{"address": str, "segment": {"address": str, "name": str}|null, "procedure": {"address": str, "name": str}|null}, ...], "searched": {"blocks": [...], "bytes": int, "skipped_uninitialized": [...], "skipped_not_loaded": [...]}, "complete": bool, "next_cursor": str|null}` (from `bytePattern.ts` — invariant: `complete === (next_cursor === null)`, `searched.bytes === sum(blocks[*].bytes)`)
- `set_address_name` / `set_addresses_names`: see Transaction Semantics below

**Transaction semantics** (matching Java's behavior at `ReaGhidraBridge.java:1933`):
- `set_address_name`: open transaction, apply name, **readback the applied name before committing** — on mismatch, roll back. pyGhidra's `transaction()` auto-commits on normal exit, so the handler must explicitly check readback and `raise` to trigger rollback.
- `set_addresses_names`: use **per-address independent transactions** (matching Java's behavior at `ReaGhidraBridge.java:1952`). Handle alias conflicts. Preserve per-address partial success semantics — one failure does not roll back others.

Study `ReaGhidraBridge.java` dispatch at line 440+ for the exact response structure of each operation — the Python implementation must match.

- [ ] **Step 5: Write Python unit test for protocol conformance**

Create `bridge/pyghidra/test_bridge_protocol.py`:

```python
"""Protocol conformance tests for the pyGhidra bridge.

These tests require pyGhidra and Ghidra installed.
Run with: python3 -m unittest bridge/pyghidra/test_bridge_protocol.py -v
Gate: REA_TEST_PYGHIDRA=1
"""
import json
import os
import unittest

@unittest.skipUnless(
    os.environ.get("REA_TEST_PYGHIDRA") == "1",
    "pyGhidra tests require REA_TEST_PYGHIDRA=1",
)
class TestBridgeProtocol(unittest.TestCase):
    """Each test launches the bridge as a subprocess against a known binary,
    connects via Unix socket, sends a JSON request, and validates the response.

    Pattern for every test:
      1. Write a temp descriptor JSON + pick a test binary from fixtures/
      2. subprocess.Popen(["python3", BRIDGE_MAIN, descriptor_path, binary_path])
      3. Wait for socket file to appear, connect
      4. send_request(sock, {"id": 1, "token": TOKEN, "method": ..., "params": {}})
      5. response = read_response(sock)  # read until \\n, json.loads
      6. Assert keys, types, and values
      7. Send shutdown, wait for process exit, verify project dir deleted
    """

    def test_ping_response_shape(self):
        """Verify ping response has all required sessionInfoSchema fields."""
        response = self._send("ping", {})
        self.assertTrue(response["ok"])
        result = response["result"]
        self.assertEqual(result["name"], "REA pyGhidra bridge")
        self.assertIn("run_id", result)
        self.assertIn("profile_digest", result)
        self.assertIn("capabilities", result)
        self.assertIsInstance(result["target"], dict)
        for key in ("name", "language_id", "compiler_spec_id", "image_base",
                     "default_address_space", "sha256"):
            self.assertIn(key, result["target"])

    def test_list_procedures_response_shape(self):
        """Verify list_procedures returns the expected array shape."""
        response = self._send("list_procedures", {})
        self.assertTrue(response["ok"])
        for entry in response["result"]:
            self.assertIn("address", entry)
            self.assertIn("value", entry)
            self.assertIn("procedure", entry)
            proc = entry["procedure"]
            self.assertIn("external", proc)
            self.assertIn("thunk", proc)

    def test_shutdown_response(self):
        """Verify shutdown returns {shutdown: true, project_ephemeral: true}."""
        response = self._send("shutdown", {})
        self.assertTrue(response["ok"])
        self.assertTrue(response["result"]["shutdown"])
        self.assertTrue(response["result"]["project_ephemeral"])
```

Each test starts the bridge as a subprocess, connects via socket, sends a request, and validates the response JSON shape. Use a small known binary from the existing test fixtures.

- [ ] **Step 6: Add bridge files to `package.json`**

In `package.json`, add to the `files` array after the existing `bridge/ghidra/` entries:
```json
"bridge/pyghidra/__main__.py",
"bridge/pyghidra/rea_pyghidra_bridge.py",
"bridge/pyghidra/operations/__init__.py",
"bridge/pyghidra/operations/inventory.py",
"bridge/pyghidra/requirements.txt",
```

Add to the `test:python` script — run the pyGhidra tests unconditionally (the `@unittest.skipUnless` decorator inside the tests handles gating; the `|| true` shell pattern silently swallows real failures):
```
&& python3 -m unittest bridge/pyghidra/test_bridge_protocol.py -v
```

- [ ] **Step 7: Commit**

```bash
git add bridge/pyghidra/ package.json
git commit -m "feat(ghidra): add pyGhidra bridge with protocol handler and inventory operations"
```

---

### Task 5: Python Bridge — Function Operations

**Files:**
- Create: `bridge/pyghidra/operations/functions.py`
- Modify: `bridge/pyghidra/rea_pyghidra_bridge.py` (register function operations in dispatch)
- Modify: `bridge/pyghidra/test_bridge_protocol.py` (add function operation tests)

**Interfaces:**
- Consumes: `program` handle, `DecompInterface` from pyGhidra, `params` dict per operation
- Produces: handlers for all `GHIDRA_FUNCTION_OPERATIONS`: `annotate_native_function`, `inspect_native_data_type`, `inspect_native_instruction`, `resolve_native_call_targets`, `analyze_function`, `procedure_assembly`, `procedure_callees`, `procedure_callers`, `procedure_info`, `procedure_pseudo_code`, `read_function_instructions`, `procedure_references`, `xrefs`

- [ ] **Step 1: Create `bridge/pyghidra/operations/functions.py`**

Each function operation handler receives `(program, decompiler, flat_api, params)` and returns a JSON-serializable result.

**Observation envelopes**: Eight function operations (`analyze_function`, `procedure_assembly`, `procedure_callees`, `procedure_callers`, `procedure_info`, `procedure_pseudo_code`, `read_function_instructions`, `procedure_references`) are validated through `functionBoundaryObservationOperations` in `GhidraFunctionValues.ts:412`. These operations MUST return an observation envelope, not a raw value:

```python
{
    "value": <inner operation result>,
    "limitations": [<string array, may be empty>],
    # Optional fields (only on specific operations):
    # "cache_policy": "live"  — only on analyze_function
    # "relationship_coverage": {...}  — only on analyze_function, procedure_callers, procedure_callees
    # "selection": {"file_offset": int, "mapped_address": str, "procedure_address": str}  — only on procedure_pseudo_code
}
```

The TS client (`parseGhidraFunctionResult` at `GhidraFunctionValues.ts:461`) rejects responses without `{value, limitations}` before validating the inner value. This is NOT optional.

**Inner payload shapes** (from actual Zod schemas):

- `procedure_pseudo_code`: inner `value` is `string | null`. The Java dispatch name is `procedurePseudocode` (at `ReaGhidraBridge.java:447`).
- `analyze_function`: inner `value` is a function dossier matching `functionDossierSchema` — name, entry address, body ranges, signature, calling convention, local variables. Java dispatch: `analyzeFunctionObservation`.
- `procedure_callees` / `procedure_callers`: inner `value` is `string[]` — an array of canonical address strings (NOT `{address, name}` objects). Schema: `z.array(ghidraCanonicalAddressSchema)`.
- `xrefs`: returns `string[]` (canonical addresses). Java dispatch: `xrefs` at `ReaGhidraBridge.java:1401`. NOT wrapped in an observation envelope (not in `functionBoundaryObservationOperations`).
- `annotate_native_function`: returns `{annotations: {address: str, name: str, comment: str|null, inline_comment: str|null}, dossier: <functionDossierSchema>, effects: {scope: "session-analysis-database", source_bytes_modified: false, persists_after_close: false}}` (from `nativeFunctionAnnotationsSchema`). NOT wrapped in an observation envelope. Mutation — must invalidate decompiler cache before refreshed readback (matching `ReaGhidraBridge.java:1462`). Check readback matches applied annotations; raise to trigger rollback on mismatch.
- `inspect_native_data_type`, `inspect_native_instruction`, `resolve_native_call_targets`: NOT in `functionBoundaryObservationOperations` — return raw values, no envelope.

Study `ReaGhidraBridge.java` dispatch at line 440+ for exact implementations.

- [ ] **Step 2: Register function operations in the bridge dispatch**

In `rea_pyghidra_bridge.py`, add function operation handlers to the method dispatch dict alongside inventory operations.

- [ ] **Step 3: Add function operation tests**

Add tests in `test_bridge_protocol.py` for `procedure_pseudo_code`, `analyze_function`, `xrefs`, and `annotate_native_function` (mutation with readback).

- [ ] **Step 4: Run Python tests**

Run: `REA_TEST_PYGHIDRA=1 python3 -m unittest bridge/pyghidra/test_bridge_protocol.py -v`
Expected: PASS.

- [ ] **Step 5: Add `functions.py` to `package.json` `files` array**

Task 4 added inventory files but not function files. Add:
```json
"bridge/pyghidra/operations/functions.py",
```

Verify all bridge files are included in the package:
```bash
npm pack --dry-run 2>&1 | grep pyghidra
```
Expected: all `.py` files under `bridge/pyghidra/` are listed.

- [ ] **Step 6: Commit**

```bash
git add bridge/pyghidra/operations/functions.py bridge/pyghidra/rea_pyghidra_bridge.py \
  bridge/pyghidra/test_bridge_protocol.py package.json
git commit -m "feat(ghidra): add function operations to pyGhidra bridge"
```

---

### Task 6: `GhidraPyGhidraLauncher` (TypeScript)

**Files:**
- Create: `src/ghidra/GhidraPyGhidraLauncher.ts`
- Create: `src/ghidra/GhidraPyGhidraLauncher.test.ts`
- Modify: `src/ghidra/GhidraLauncher.ts` (export `ghidraRuntimePaths` — currently module-private at line 868)

**Interfaces:**
- Consumes: `GhidraLauncher` interface (from `GhidraLauncher.ts`), `GhidraLaunchSession`, `GhidraLaunch`, `GhidraLaunchError`, `GhidraLaunchRollbackFailure`, `spawnOwnedProviderProcess` (from `src/process/ProviderProcess.ts` — takes an `OwnedProviderProcessSpawnOptions` object, returns `Promise<SpawnedOwnedProviderProcess>`), `ghidraRuntimePaths` (must be exported from `GhidraLauncher.ts`), `PyGhidraAvailability` (from Task 3), `GhidraLanguageOverride` (from `src/config/ghidraLanguageOverride.ts` — `compilerSpecId` is optional)
- Produces: `GhidraPyGhidraLauncher` class implementing `GhidraLauncher`, `GhidraPyGhidraLauncherOptions` type

- [ ] **Step 1: Write failing test for launcher construction**

```typescript
import { describe, it, expect } from "vitest";
import { GhidraPyGhidraLauncher } from "./GhidraPyGhidraLauncher.js";

describe("GhidraPyGhidraLauncher", () => {
  it("constructs with required options", () => {
    const launcher = new GhidraPyGhidraLauncher({
      pythonPath: "/usr/bin/python3",
      bridgeScriptPath: "/path/to/bridge/pyghidra/__main__.py",
      ghidraInstallDir: "/path/to/ghidra",
      environment: {},
    });
    expect(launcher).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `npx vitest run src/ghidra/GhidraPyGhidraLauncher.test.ts --reporter=verbose`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Export `ghidraRuntimePaths`**

In `src/ghidra/GhidraLauncher.ts`, export `ghidraRuntimePaths` (currently `const` at line 868). The pyGhidra launcher needs the same directory layout.

- [ ] **Step 4: Implement `GhidraPyGhidraLauncher`**

Key implementation constraints (from codebase verification):

1. **`spawnOwnedProviderProcess` takes an options object** (`OwnedProviderProcessSpawnOptions`), not positional args. It returns `Promise<SpawnedOwnedProviderProcess>` and must be awaited.
2. **`ghidraRuntimePaths` is module-private** in `GhidraLauncher.ts` — must be exported (Step 3).
3. **`mkdir` from `node:fs/promises`** must be imported.
4. **`GhidraLanguageOverride`** (from `src/config/ghidraLanguageOverride.ts`) has `compilerSpecId` optional — use this type instead of a custom object.
5. **tsconfig has `exactOptionalPropertyTypes`** — never assign `undefined` to optional properties. Omit them instead.
6. **`GhidraLaunchError.partialLaunch`** must be a full `GhidraLaunch`, not just `{ projectRoot }`.
7. **Environment isolation** must match the Java launcher (`GhidraLauncher.ts:937`): isolate HOME, TMPDIR to runtime paths, pass inspected JDK through env, prevent ambient env leakage.
8. **Descriptor must include analysis config fields** for parity: `seed_paths`, `analysis_extensions`, `mips_soft_float`, `disabled_analyzers`, `language_id`, `compiler_spec_id`.

```typescript
import type { GhidraLauncher, GhidraLaunch, GhidraLaunchSession } from "./GhidraLauncher.js";
import { GhidraLaunchError, ghidraRuntimePaths } from "./GhidraLauncher.js";
import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import type { Result } from "../domain/result.js";
import { err, ok } from "../domain/result.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { spawnOwnedProviderProcess } from "../process/ProviderProcess.js";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import writeFileAtomic from "write-file-atomic";

export interface GhidraPyGhidraLauncherOptions {
  readonly pythonPath: string;
  readonly bridgeScriptPath: string;
  readonly ghidraInstallDir: string;
  readonly javaHome?: string;
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly platform?: NodeJS.Platform;
  readonly languageOverride?: GhidraLanguageOverride;
  readonly disabledAnalyzers?: readonly string[];
  readonly analysisSeeds?: readonly string[];
  readonly analysisExtensions?: readonly string[];
  readonly mipsSoftFloat?: boolean;
  readonly spawnProcess?: typeof spawnOwnedProviderProcess;
}
```

The `launch` method must:
1. Check cancellation via `signal?.throwIfAborted()`
2. Create runtime directories (reuse `ghidraRuntimePaths` + `mkdir`)
3. Build an isolated environment matching `ghidraLaunchEnvironment` pattern: `HOME` → `paths.homeRoot`, `TMPDIR` → `paths.tempRoot`, `GHIDRA_INSTALL_DIR`, and inspected `JAVA_HOME` if provided. Do NOT spread `process.env` — use only the snapshotted `environment`.
4. Write descriptor JSON including all analysis config fields (seeds, extensions, soft-float, disabled analyzers, language override)
5. Spawn via `await spawnOwnedProviderProcess({ command: pythonPath, arguments: [bridgeScriptPath, descriptorPath, targetPath], env, runId: session.runId, signal })` — **object form, awaited**
6. Write ownership manifest
7. Construct `GhidraLaunch` (omit `configuredMaxHeap` and `launchSupport` — do NOT assign `undefined`)
8. On post-spawn cancellation: attempt cleanup of spawned process, retain ownership through `GhidraLaunchError` with `partialLaunch` as a **full** `GhidraLaunch` (needs the process handle)
9. On spawn failure: retain cleanup info via `GhidraLaunchError.rollbackFailure` for retry
10. Set up log destinations at `paths.ghidraLogPath` and `paths.scriptLogPath` so `GhidraDiagnostics.ts:70` can report them

Key differences from `GhidraHeadlessLauncher`:
- Command: `[pythonPath, bridgeScriptPath, descriptorPath, targetPath]`
- No JVM launch support probes or headless argument construction
- No PSP/DOS/COM/raw-binary import mode handling (routed to Java in Task 7)
- Descriptor carries analysis config instead of CLI flags

- [ ] **Step 4: Write lifecycle tests**

Test startup cancellation:
```typescript
it("returns cancelled error when signal is already aborted", async () => {
  const controller = new AbortController();
  controller.abort();
  const launcher = new GhidraPyGhidraLauncher(validOptions());
  const result = await launcher.launch(validSession(), { signal: controller.signal });
  expect(result.ok).toBe(false);
});
```

Test descriptor writing (mock spawn to inspect what was written):
```typescript
it("writes session descriptor with correct fields", async () => {
  // Use spawnProcess mock that captures the descriptor file before the process starts
});
```

- [ ] **Step 5: Run tests**

Run: `npx vitest run src/ghidra/GhidraPyGhidraLauncher.test.ts --reporter=verbose`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ghidra/GhidraPyGhidraLauncher.ts src/ghidra/GhidraPyGhidraLauncher.test.ts
git commit -m "feat(ghidra): add GhidraPyGhidraLauncher implementing GhidraLauncher interface"
```

---

### Task 7: Backend Selection in `GhidraProvider` and `GhidraProviderClient`

**Files:**
- Modify: `src/ghidra/GhidraProvider.ts`
- Modify: `src/ghidra/GhidraProviderClient.ts`
- Modify: `src/ghidra/GhidraBridgeSources.ts` (add pyGhidra bridge path)
- Modify: `src/composition/binary.ts` (pass new config fields)
- Test: `src/ghidra/GhidraProvider.test.ts` (if exists, or inline)

**Interfaces:**
- Consumes: `GhidraPyGhidraLauncher` (Task 6), `PyGhidraAvailability` / `inspectPyGhidraAvailability` (Task 3), `AppConfig.ghidraBackend`, `AppConfig.pyghidraPythonPath`, `GhidraBackendKind` (Task 2)
- Produces: `GhidraProvider` that selects between Java and pyGhidra launchers, `GhidraProviderClient` that passes backend kind to profile resolution

- [ ] **Step 1: Add pyGhidra bridge script path to `GhidraBridgeSources.ts`**

```typescript
export const PYGHIDRA_BRIDGE_ENTRY = "__main__.py";
```

And a resolver that finds it relative to the package root (same pattern as the Java bridge script path resolution).

- [ ] **Step 2: Modify `GhidraProviderClient.ts` — launcher construction**

Find where `GhidraHeadlessLauncher` is constructed (around line 343). Add conditional construction of `GhidraPyGhidraLauncher` based on the backend selection. The `GhidraProviderClientFactory` receives the config and availability probe result.

```typescript
const launcher = backendKind === "pyghidra"
  ? new GhidraPyGhidraLauncher({ ... })
  : new GhidraHeadlessLauncher({ ... });
```

- [ ] **Step 3: Modify `GhidraProvider.ts` — backend selection logic with target guard**

In `GhidraProvider`, during `inspectAvailability` or construction:

1. If `config.ghidraBackend === "java"` → use Java, skip pyGhidra probe
2. If `config.ghidraBackend === "pyghidra"` → probe pyGhidra, fail if unavailable
3. If `config.ghidraBackend === "auto"` → probe pyGhidra, use if available, else Java
4. If `platform === "win32"` → always Java (Phase 1 scope)

**Target compatibility guard** (`pyGhidraSupportsTarget`): The Java launcher handles PSP, DOS MZ, DOS COM, and raw-binary import modes via specialized loader/language/base selection (`GhidraLauncher.ts:755`, `GhidraProviderClient.ts:361`). The pyGhidra bridge does not implement these in Phase 1. Add a guard function that checks the analysis profile's loader/language requirements:
- If the target requires PSP, DOS, COM, or raw-binary import mode → route to Java even under `auto`
- Under forced `pyghidra` mode → return a clear error explaining the unsupported target type
- The guard runs after profile resolution, before launcher construction

Cache the probe result on the provider instance.

**Injectable inspection seam**: The `pyGhidraAvailability` probe must be injectable (constructor parameter or factory option) so that:
- Existing Java-specific tests (`GhidraProvider.behavior.test.ts:81`) can force Java backend without depending on the developer's Python installation
- Tests at lines 231/240 that cast to `GhidraHeadlessLauncher` and read `.options.disabledAnalyzers` continue to work
- Each selection outcome (forced java, forced pyghidra, auto-with-python, auto-without-python, auto-with-unsupported-target) can be tested independently

- [ ] **Step 4: Thread config through `composition/binary.ts`**

The `GhidraProvider` constructor already receives `config` and `environment`. Ensure the new `ghidraBackend` and `pyghidraPythonPath` fields reach the provider.

- [ ] **Step 5: Write backend selection and target guard tests**

```typescript
it("selects Java launcher when REA_GHIDRA_BACKEND=java", () => { ... });
it("selects pyGhidra launcher when REA_GHIDRA_BACKEND=pyghidra and available", () => { ... });
it("falls back to Java when REA_GHIDRA_BACKEND=auto and pyGhidra unavailable", () => { ... });
it("always selects Java on Windows regardless of config", () => { ... });
it("routes PSP target to Java under auto mode even when pyGhidra available", () => { ... });
it("routes raw-binary target to Java under auto mode", () => { ... });
it("returns error for unsupported target under forced pyghidra mode", () => { ... });
it("existing Java-specific tests use injected unavailable pyGhidra", () => { ... });
```

Existing Java-specific fixtures (`GhidraProvider.behavior.test.ts`) must inject an `unavailable` pyGhidra probe to prevent auto-detection from changing their launcher type.

- [ ] **Step 6: Run full Ghidra test suite including boundary tests**

Run: `npx vitest run src/ghidra/ tests/boundary/providers/ghidra/ --reporter=verbose`
Expected: All PASS. Java bridge path unchanged. Boundary launcher/client tests unaffected.

- [ ] **Step 7: Run typecheck and lint**

Run: `npx turbo run typecheck lint:built`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/ghidra/GhidraProvider.ts src/ghidra/GhidraProviderClient.ts \
  src/ghidra/GhidraBridgeSources.ts src/composition/binary.ts
git commit -m "feat(ghidra): wire backend selection between Java and pyGhidra launchers"
```

---

### Task 8: Integration Test — Dual-Backend Verification

**Files:**
- Create: `bridge/pyghidra/test_dual_backend.py`
- Create: `src/ghidra/GhidraPyGhidraIntegration.test.ts` (TS-side integration through real client)
- Modify: `bridge/pyghidra/test_bridge_protocol.py` (expand with reference fixture comparison)

**Interfaces:**
- Consumes: running pyGhidra bridge (subprocess), running Java bridge (via REA CLI), same test binary, real `GhidraProviderClient` (for TS-side tests)
- Produces: test suite that verifies pyGhidra bridge output passes the same Zod validation as Java bridge output for inventory, function (with observation envelopes), and mutation operations

- [ ] **Step 1: Create dual-backend comparison test**

```python
"""Dual-backend comparison tests.

Run both bridges against the same binary, verify output schema compatibility.
Gate: REA_TEST_PYGHIDRA=1

Usage: REA_TEST_PYGHIDRA=1 python3 -m unittest bridge/pyghidra/test_dual_backend.py -v
"""
import json
import os
import subprocess
import unittest

@unittest.skipUnless(
    os.environ.get("REA_TEST_PYGHIDRA") == "1",
    "Dual-backend tests require REA_TEST_PYGHIDRA=1",
)
class TestDualBackend(unittest.TestCase):
    """Compare pyGhidra bridge output against Java bridge reference fixtures."""

    def test_list_procedures_schema_parity(self):
        """Both backends produce list_procedures with identical structure:
        [{address, value, procedure: {external, thunk, thunk_target}}]."""
        # 1. Load reference fixture (JSON captured from Java bridge)
        # 2. Start pyGhidra bridge against same binary
        # 3. Send list_procedures request
        # 4. Verify: same keys, same types, same address format (canonical)
        pass

    def test_procedure_pseudo_code_envelope_parity(self):
        """Both backends wrap procedure_pseudo_code in observation envelope:
        {value: string|null, limitations: [...]}."""
        # Must validate the observation envelope, not just the inner value.
        pass

    def test_analyze_function_envelope_parity(self):
        """Both backends return analyze_function with {value: <dossier>, limitations, cache_policy, relationship_coverage}."""
        pass

    def test_procedure_callers_envelope_parity(self):
        """Both backends return procedure_callers with {value: string[], limitations}."""
        # Inner value is string[] (canonical addresses), NOT {address, name} objects
        pass

    def test_ping_session_info_parity(self):
        """Both backends produce valid session info (differing only in name)."""
        pass

    def test_annotate_mutation_readback(self):
        """annotate_native_function returns {annotations, dossier, effects} after readback."""
        pass
```

- [ ] **Step 2: Add reference fixtures**

Extract reference JSON responses from Java bridge runs for the test binary. Store as `bridge/pyghidra/fixtures/java_bridge_*.json`. The dual-backend test loads these and compares structure (not exact values). Include at least: `ping`, `list_procedures`, `procedure_pseudo_code` (with envelope), `analyze_function` (with envelope), `xrefs`.

- [ ] **Step 3: Create TS-side integration test**

Create `src/ghidra/GhidraPyGhidraIntegration.test.ts` that exercises the pyGhidra backend through the **real** `GhidraProviderClient` and its production Zod parsers. This catches refinements, envelopes, provenance, and cross-field relationships that Python-side structural comparison misses:

```typescript
import { describe, it, expect } from "vitest";
// Gate: skip unless REA_TEST_PYGHIDRA=1

describe("pyGhidra through GhidraProviderClient", () => {
  it("list_procedures passes GhidraInventoryValues parser", async () => { ... });
  it("procedure_pseudo_code passes functionObservationEnvelope parser", async () => { ... });
  it("annotate_native_function passes nativeFunctionAnnotationsSchema", async () => { ... });
  it("launcher selection, profile commitment, and client cleanup lifecycle", async () => { ... });
});
```

- [ ] **Step 4: Update `test:python` in `package.json`**

Run dual-backend tests via `@unittest.skipUnless` gating inside Python — do NOT use the `|| true` shell pattern, which silently swallows assertion failures and crashes:
```
&& python3 -m unittest discover -s bridge/pyghidra -p 'test_*.py' -v
```

This runs all `test_*.py` files; the `@unittest.skipUnless` decorator handles gating when `REA_TEST_PYGHIDRA` is unset.

- [ ] **Step 5: Run full test suite including boundary tests**

Run: `npm run check:fast`
Expected: PASS (pyGhidra tests skipped without the gate).

Run: `npx vitest run src/ghidra/ tests/boundary/providers/ghidra/ --reporter=verbose`
Expected: All PASS.

Run: `REA_TEST_PYGHIDRA=1 python3 -m unittest discover -s bridge/pyghidra -p 'test_*.py' -v`
Expected: PASS (in environments with pyGhidra).

- [ ] **Step 5: Commit**

```bash
git add bridge/pyghidra/test_dual_backend.py bridge/pyghidra/fixtures/ package.json
git commit -m "test(ghidra): add dual-backend comparison tests for pyGhidra parity"
```

---

### Task 9: Final Verification and Documentation

**Files:**
- Modify: `README.md` (add pyGhidra backend section under provider setup)
- Modify: `bridge/pyghidra/test_bridge_protocol.py` (Review Focus items)

**Interfaces:**
- Consumes: everything from Tasks 1-8
- Produces: verified, documented, green build

- [ ] **Step 1: Add Review Focus tests**

Add the five Review Focus scenarios as explicit test cases:

```python
def test_decompiler_output_passes_schema_despite_formatting_differences(self):
    """Review Focus #1: decompiler divergence."""
    # Decompile a function with both backends, verify both pass schema
    pass

def test_nondefault_address_space_encoding(self):
    """Review Focus #2: address space encoding."""
    # Use a binary with EXTERNAL symbols, verify address format
    pass

def test_startup_timeout_respected(self):
    """Review Focus #3: slow JVM startup."""
    # Start bridge with very short timeout, verify clean error
    pass

def test_unknown_descriptor_field_tolerated(self):
    """Review Focus #4: descriptor field evolution."""
    # Add unknown field to descriptor, verify bridge starts
    pass

def test_shutdown_during_operation(self):
    """Review Focus #5: concurrent shutdown race."""
    # Start a long operation, send shutdown, verify clean exit
    pass
```

- [ ] **Step 2: Add README documentation**

In the Ghidra provider section of `README.md`, add:

```markdown
### pyGhidra Backend (experimental)

REA can use [pyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)
as an alternative Ghidra backend. When pyGhidra is installed, REA auto-selects
it. Override with `REA_GHIDRA_BACKEND`:

- `auto` (default) — use pyGhidra if available, fall back to Java
- `java` — always use the Java HeadlessScript bridge
- `pyghidra` — always use pyGhidra (fails if not installed)

Requirements: Python 3.10+, `pip install pyghidra`, Ghidra installation.
Set `REA_PYGHIDRA_PYTHON` to use a specific Python interpreter (default: `python3`).

Unix-only. Windows always uses the Java bridge.
```

- [ ] **Step 3: Run full verification**

Run: `npm run check:fast`
Expected: PASS.

Run: `npx vitest run src/ghidra/ tests/boundary/providers/ghidra/ --reporter=verbose`
Expected: All PASS including boundary launcher/client tests.

Run: `npm pack --dry-run 2>&1 | grep pyghidra`
Expected: All `bridge/pyghidra/` runtime files listed (including `operations/functions.py`).

Run: `npm run docs:check`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md bridge/pyghidra/test_bridge_protocol.py
git commit -m "docs(ghidra): add pyGhidra backend documentation and Review Focus tests"
```
