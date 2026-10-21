# pyGhidra Integration Design

REA's Ghidra backend currently talks to Ghidra through a custom Java
HeadlessScript (`ReaGhidraBridge.java`) that runs inside Ghidra's JVM and
communicates over a socket using newline-delimited JSON. This design adds
pyGhidra as a protocol-compatible alternative bridge process, expanding REA's
Ghidra capabilities without disrupting the existing Java bridge path.

Reviewed adversarially by Codex (gpt-6-astra, effort xhigh) against the actual
codebase. Twenty findings folded in; none dismissed.

## Goals

1. A Python bridge (`bridge/pyghidra/`) that speaks REA's existing Ghidra wire
   protocol, so the transport-layer TS files (`GhidraWire`, `GhidraResponseRouter`,
   `GhidraResponseBuffer`, `protocol.ts`) work unchanged.
2. New pyGhidra-only operations surface as new MCP tools: expanded mutation,
   batch decompilation, and program export. Script execution and
   archive/filesystem operations are deferred pending maintainer scope decision
   per CONTRIBUTING.md.
3. The `GhidraLauncher` gains a second launch mode that starts the Python
   bridge instead of `analyzeHeadless`. Backend selection is automatic
   (pyGhidra preferred when available) with manual override via environment.
4. The existing Java bridge path remains fully functional and is the fallback.

## Non-goals

- Replacing the Java bridge. Both backends coexist.
- Exposing pyGhidra's raw Java API passthrough to MCP callers (too broad an
  attack surface for an MCP tool).
- GUI mode. pyGhidra supports it; REA does not need it.
- Windows support in Phase 1. Windows Ghidra uses authenticated loopback TCP
  with `read_only: true` and explicitly rejects database mutation. The pyGhidra
  backend is Unix-only initially; Windows support requires a separate design
  pass that respects the Windows P0 authority boundary.

## Architecture

```
                          ┌──────────────────────┐
                          │   MCP Server / CLI    │
                          └──────────┬───────────┘
                                     │
                          ┌──────────▼───────────┐
                          │   GhidraProvider      │
                          │   (AnalysisProvider)   │
                          └──────────┬───────────┘
                                     │
                          ┌──────────▼───────────┐
                          │   GhidraClient        │
                          │   GhidraWire          │  ← transport unchanged
                          │   GhidraResponseRouter│
                          └──────────┬───────────┘
                                     │ JSON-over-socket
                     ┌───────────────┴───────────────┐
                     │                               │
          ┌──────────▼───────────┐       ┌───────────▼──────────┐
          │ ReaGhidraBridge.java │       │ rea_pyghidra_bridge  │
          │ (HeadlessScript)     │       │ (Python + pyGhidra)  │
          │                      │       │                      │
          │ inventory + function │       │ same ops + expanded  │
          │ + naming mutations   │       │ mutation + export    │
          └──────────────────────┘       └──────────────────────┘
```

## Wire Protocol

### Existing protocol (preserved exactly)

**Request**: `{"id": N, "token": "<secret>", "method": "<op>", "params": {...}}\n`

**Response (success)**: `{"id": N, "ok": true, "result": <value>}\n`

**Response (error)**: `{"id": N, "ok": false, "error": {"code": "<code>", "message": "<msg>"}}\n`

Response IDs are positive integers. The `responseSchema` in `protocol.ts` uses
`z.discriminatedUnion` on `ok` with `z.strictObject` — no extra fields allowed.
The Python bridge must produce responses that pass this exact schema.

### Handshake

The bridge responds to `ping` with a session-info object validated by
`sessionInfoSchema` in `GhidraSessionValues.ts`.

**Name field**: Relax from `z.literal("REA Ghidra bridge")` to:
```typescript
name: z.enum(["REA Ghidra bridge", "REA pyGhidra bridge"]),
```

**Capabilities validation**: `parseGhidraSessionInfo` currently requires the
capabilities array to have the exact length and membership of
`GHIDRA_SESSION_CAPABILITIES`. This is the critical change: the validation must
split into **baseline capabilities** (required — the existing set that both
bridges implement) and **extended capabilities** (optional — pyGhidra-only
operations that the Java bridge does not report). The check becomes:

```typescript
// All baseline capabilities must be present
const hasAllBaseline = GHIDRA_SESSION_BASELINE_CAPABILITIES.every(
  cap => parsed.data.capabilities.includes(cap)
);
// Extended capabilities are permitted but not required
const allKnown = parsed.data.capabilities.every(
  cap => GHIDRA_ALL_KNOWN_CAPABILITIES.has(cap)
);
// No duplicates
const noDuplicates = new Set(parsed.data.capabilities).size === parsed.data.capabilities.length;
```

This preserves the strict identity/authority checks (run_id, profile_digest,
target SHA, provider version, read_only) while allowing the Python bridge to
advertise additional capabilities without breaking the Java bridge handshake.

**Backend identity in profile**: The `GhidraAnalysisProfile` commitment must
include the backend implementation (java vs pyghidra) and its version, so that
Evidence provenance and snapshot cache keys distinguish observations produced by
different backends. A pyGhidra-produced observation cached under a Java profile
digest would be incorrect.

### How capabilities reach MCP tools

The spec's earlier draft incorrectly claimed that "the TS client already checks
capabilities per-session." In reality:

1. **`GhidraProviderCapabilities.ts`** builds a static frozen list of
   `CapabilityDescriptor` objects at provider construction time. MCP tool
   registration happens independently from that list via tool contracts in
   `src/contracts/`.
2. **`GhidraProviderClient.ts`** dispatches operations through a closed type
   (`GhidraOperation = GhidraInventoryOperation | GhidraFunctionOperation`)
   and selects input/output parsers from those same groups.
3. **`GhidraClient`** does not gate requests based on the handshake capabilities
   array — it starts the session and queues the operation.

Therefore, surfacing new operations requires changes at **four** layers:

1. **Operation type**: Extend `GhidraOperation` union to include extended ops.
2. **Provider client dispatch**: `GhidraProviderClient.ts` must recognize
   extended operations, route them through the wire, and parse results.
3. **Capability descriptors**: `GhidraProviderCapabilities.ts` must include
   extended operations, conditionally marked `available: true` only when the
   session handshake reported them. This requires the capability list to be
   built *after* the handshake, not statically at construction.
4. **MCP tool contracts**: New contracts in `src/contracts/` with strict schemas,
   effect declarations, and output schemas. Registered via the same mechanism
   as existing official tools.

### New operations (Phase 2 — pyGhidra bridge only)

| Operation | Purpose | Params |
|-----------|---------|--------|
| `modify_function_signature` | Transaction-safe: rename, retype return/params, set calling convention | `address`, `name?`, `return_type?`, `parameters?`, `calling_convention?` |
| `modify_data_type` | Define or redefine a data type at an address | `address`, `data_type_path`, `length?` |
| `set_native_comment` | Set any comment type on an address (renamed from `set_comment` to avoid conflict with existing Hopper `set_comment` tool) | `address`, `comment_type` (EOL/PRE/POST/PLATE/REPEATABLE), `text` |
| `create_native_bookmark` | Add analysis bookmark (renamed from `create_bookmark` to avoid semantic overlap with `set_bookmark`) | `address`, `category`, `description` |
| `batch_decompile_all` | Decompile all functions, return as streamed address → pseudocode pairs with per-function error/null handling | (none; operates on loaded program) |
| `export_program` | Export program database in a specified format (C headers, XML, etc.) to a bounded output path | `format`, `output_path` |

**Deferred operations** (require maintainer scope decision per CONTRIBUTING.md
contribution-scope rule for target execution and archive mutation):

| Operation | Reason for deferral |
|-----------|-------------------|
| `execute_ghidra_script` | Arbitrary code execution. Needs defined authority boundary, output bounds, cancellation, cleanup, and provenance model. Callers could bypass all safety through this. |
| `open_archive_filesystem` | Opens containers outside the single-binary session model. Needs session lifecycle design for multi-program handles. |
| `list_archive_entries` | Depends on `open_archive_filesystem`. |

### Mutation operations and `read_only`

The existing Java bridge already uses `startTransaction`/`endTransaction` for
its mutation operations (`set_address_name`, `set_addresses_names`,
`annotate_native_function`), with readback and conditional commit. The Python
bridge uses pyGhidra's `transaction()` context manager which provides
commit-on-success, rollback-on-exception semantics.

The Python bridge reports `read_only: false` on Unix (matching the Java bridge).
The `read_only` flag and its relationship to available mutation capabilities is
preserved: when `read_only` is true, mutation capabilities are omitted from the
handshake (existing behavior in `parseGhidraSessionInfo`).

New mutations must be added to `GHIDRA_MUTATING_OPERATIONS` so that:
- The snapshot cache correctly invalidates after mutation operations
- `BinarySession` performs pre-mutation invalidation
- Effect declarations in capability descriptors report `mutatesArtifact: true`
- Evidence provenance correctly reflects that the session was mutated

### Output schema compatibility

The Python bridge must produce outputs matching the exact Zod schemas the TS
client validates against. Specific shapes from the actual code:

- **`list_procedures`**: Returns `Array<{address: string, value: string, procedure: {external: boolean, thunk: boolean, thunk_target: string | null}}>` — not `{name, address, entry_point}` as initially claimed.
- **`procedure_pseudo_code`**: Returns a string-or-null value, optionally inside the observation envelope — not `{pseudo_code: string}`.
- **Addresses**: Canonical format preserves nondefault address spaces as `<encoded-space>:0x<hex>` (e.g. `EXTERNAL:0x00000001`). Plain `0x`-prefixed hex is only correct for the default address space. The Python bridge must replicate this encoding.

The Python bridge test suite validates outputs against reference fixtures
extracted from actual Java bridge sessions with known binaries.

## Python Bridge Implementation

### Directory structure

```
bridge/pyghidra/
├── __main__.py              # Entry: parse args + descriptor, start bridge
├── rea_pyghidra_bridge.py   # Protocol handler, socket server, operation dispatch
├── operations/
│   ├── __init__.py
│   ├── inventory.py         # list_procedures, list_segments, list_strings, etc.
│   ├── functions.py         # analyze_function, procedure_pseudo_code, xrefs, etc.
│   ├── mutation.py          # modify_function_signature, set_native_comment, etc.
│   └── export.py            # export_program, batch_decompile_all
└── requirements.txt         # pyghidra (which pulls JPype1)
```

### Package distribution

The bridge files must be included in REA's npm package. `package.json`'s `files`
array currently lists shipped bridge files explicitly — the pyghidra directory
must be added. The entry point must work via an installation-relative path
resolved by the TS launcher, not `python -m` which depends on Python's module
resolution finding REA's package root. The launcher passes the bridge script
path as an absolute argument:

```
<python> <rea-install-dir>/bridge/pyghidra/__main__.py <descriptor-path> <target-path>
```

### Startup sequence

1. Parse command-line arguments: descriptor path and **target path** (the
   descriptor does not contain the target path — the Java bridge receives it
   via the `-import` flag, not the descriptor).
2. Read session descriptor JSON (transport, endpoint_path, token, run_id,
   target_sha256, provider_version, profile_digest, and optionally
   analysis_extensions and language/compiler overrides).
3. Start pyGhidra headlessly via `pyghidra.start()`.
4. Create an ephemeral project in the runtime root directory (not beside the
   binary — `open_program`'s default). Use `pyghidra.open_project()` with an
   explicit project location inside the runtime root, then
   `program_loader()` to import the target.
5. Apply analysis configuration matching what the Java launcher does:
   - Language/compiler-spec selection (from descriptor or auto-detect)
   - Disabled analyzers (from descriptor)
   - Analysis seeds (from descriptor seed path)
   - MIPS soft-float processing (from descriptor)
   - No-return fix extension (from descriptor analysis_extensions)
6. Run Ghidra auto-analysis via `pyghidra.analyze()`.
7. Open socket listener. For Unix domain sockets: bind to `endpoint_path` from
   the descriptor. Publish the endpoint (for TCP: write the compact
   `{"host":"127.0.0.1","port":N}\n` JSON file to `endpoint_path` matching the
   format `GhidraTransport.ts` expects).
8. Accept exactly one connection. Authenticate: the first request must contain
   the correct token. Reject unauthenticated peers without consuming the
   session. Apply the same authentication deadline behavior as the Java bridge.
9. Enter request loop: read newline-delimited JSON, validate token on each
   request, dispatch method, write response.
10. On `shutdown` method: close the program, **delete the ephemeral project
    directory** (pyGhidra's `open_program` saves-and-closes but does not
    delete; explicit cleanup required), respond with
    `{"shutdown": true, "project_ephemeral": true}`, exit.

### Error handling and lifecycle

The Python bridge must implement equivalent lifecycle behavior to the Java
bridge:

- **Cancellation**: Monitor for socket close / broken pipe as cancellation
  signal. In-flight operations are interrupted and return error responses.
- **Cleanup on crash**: If the Python process dies, the TS side handles it
  through the existing `ProviderProcessSupervisor` — the process exit is
  detected, cleanup of the runtime root proceeds, and `GhidraLaunchError`
  retains any partial launch for cleanup retry.
- **Log output**: Write structured logs to the log paths provided in the launch
  session, matching the Java bridge's log location conventions so diagnostic
  collection works.

## TypeScript Changes

### `GhidraSessionValues.ts`

1. Relax `name` literal to enum as shown above.
2. Split `GHIDRA_SESSION_CAPABILITIES` into baseline (required) and extended
   (optional) sets.
3. Update `parseGhidraSessionInfo` validation to accept extended capabilities.
4. Add new mutation operation names to `GHIDRA_MUTATING_OPERATIONS`.

### New file: `src/ghidra/GhidraExtendedOperations.ts`

Defines pyGhidra-only operations, their input/output Zod schemas, and
validation. Follows the pattern of `GhidraInventoryValues.ts` and
`GhidraFunctionValues.ts`. Extends `GhidraOperation` union type.

### `GhidraProviderCapabilities.ts`

Capabilities become session-aware: the base set is always advertised. Extended
operations are advertised conditionally based on session handshake. This
requires capabilities to be built after session establishment, not at provider
construction. The provider can build a "maximum" capability set at construction
(for availability inspection) and refine it per-session.

### `GhidraProviderClient.ts`

Extend the dispatch logic to recognize extended operations. Add input/output
parser selection for new operation types. This file also contains launcher
construction — the pyGhidra launcher wiring goes here alongside the existing
`GhidraHeadlessLauncher` construction.

### New file: `src/ghidra/GhidraPyGhidraLauncher.ts`

Implements `GhidraLauncher` interface. Key differences from Java launcher:

- Spawns Python instead of `analyzeHeadless`
- Passes target path as a command-line argument (not via `-import`)
- Passes `GHIDRA_INSTALL_DIR` via environment
- Writes the same session descriptor file
- Sets up the same transport endpoint
- Returns a `GhidraLaunch` with process handle, project root, and log paths
- Implements equivalent process-lifetime ownership, cancellation handling, and
  failed cleanup retention through `GhidraLaunchError` with partial launch

### `GhidraProvider.ts`

Launcher selection (Unix only in Phase 1):

1. If `REA_GHIDRA_BACKEND=java`, use `GhidraHeadlessLauncher`.
2. If `REA_GHIDRA_BACKEND=pyghidra`, use `GhidraPyGhidraLauncher`, fail if
   unavailable.
3. If `REA_GHIDRA_BACKEND=auto` (default): use the pyGhidra availability probe
   result. Fall back to Java.
4. On Windows: always use Java launcher regardless of `REA_GHIDRA_BACKEND`
   (Phase 1 scope exclusion).

### `GhidraAnalysisProfile.ts`

Include backend identity (java/pyghidra) and backend version in the profile
commitment. This ensures:
- Evidence provenance distinguishes backends
- Snapshot cache keys are backend-specific
- Profile digest changes when switching backends (correct: results may differ)

### `GhidraInstallation.ts` / `GhidraDoctor.ts`

Add pyGhidra availability inspection:
- Resolve interpreter from `REA_PYGHIDRA_PYTHON` env (default: `python3`)
- Probe: `<python> -c "import pyghidra; print(pyghidra.__version__)"`
- Verify pyGhidra version is compatible with the detected Ghidra version
  (pyGhidra ships with Ghidra; version must match the installation)
- Probe JVM startup: `<python> -c "import pyghidra; pyghidra.start()"`
  (cached, not per-request — done during installation inspection)
- Report findings in doctor diagnostics
- Cache result per provider instance lifetime (aligns with existing
  scope-bound/shared inspection lifecycle in `GhidraProvider`)

### New MCP tool contracts

New contracts for Phase 2 operations in `src/contracts/`, following existing
patterns. Each has:
- Descriptive name and documentation
- Strict Zod input/output schemas
- Effect declarations (`mutatesArtifact`, `launchesProcess`, etc.)
- `cachePolicy` respecting mutation semantics (mutating ops are non-cacheable)
- Registration through the same mechanism as existing official tools

## Configuration

### Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `REA_GHIDRA_BACKEND` | `auto` | `auto`, `java`, or `pyghidra`. Ignored on Windows (always `java`). |
| `REA_PYGHIDRA_PYTHON` | `python3` | Python interpreter path. Used for both probing and launching. |

### Installation requirements

pyGhidra requires:
- Python 3.10+
- `pip install pyghidra` (which installs JPype1)
- A Ghidra installation (same one REA already uses)
- pyGhidra version matching the Ghidra installation version (pyGhidra is
  part of Ghidra's source tree and tracks its releases)

The launcher passes `GHIDRA_INSTALL_DIR` from REA's existing
`ghidraInstallDir` config to the Python process environment.

## Testing Strategy

### Python bridge tests

- Unit tests per operation module against a real pyGhidra session with known
  test binaries (same fixtures as Java bridge tests).
- **Protocol conformance**: Feed the Python bridge the same requests the Java
  bridge handles; validate output shapes against the actual Zod schemas (not
  example shapes). Schema validation, not byte equality — decompiler output
  may differ between backends.
- **Handshake conformance**: Session-info response passes
  `parseGhidraSessionInfo` with both baseline and extended capabilities.
- **Mutation rollback**: Verify that exceptions during mutation operations
  produce rollback, and that partial-success semantics match the Java bridge's
  per-address transaction model for bulk naming.

### TypeScript tests

- Existing tests pass unchanged (no regressions in Java bridge path).
- New tests for `GhidraPyGhidraLauncher`:
  - Successful launch and handshake
  - Startup cancellation
  - Failed cleanup with partial launch retention
  - Process exit during operation
- New tests for extended operation input/output validation.
- New tests for capability negotiation: baseline-only handshake (Java bridge)
  vs baseline+extended handshake (pyGhidra bridge).
- Backend selection tests: auto-detection, explicit override, Windows exclusion.
- Profile commitment tests: verify backend identity in profile digest.

### Integration tests

- End-to-end: launch pyGhidra bridge, connect, run representative operations
  from each group (inventory, function, mutation), verify responses.
- **Dual-backend comparison**: Run the same operation set against both backends
  with the same binary; verify schema-compatible outputs.
- Gate behind `REA_TEST_PYGHIDRA=1` for environments with Ghidra + pyGhidra.
- Python bridge tests run in `test:python` alongside existing Python tests.

## Rollout

### Phase 1: Parity backend (this design)

Python bridge + launcher + handshake relaxation. The bridge implements all
existing operations (same set as Java bridge). Backend selection defaults to
`auto`. No new MCP tools — just a protocol-compatible alternative backend.
Unix-only.

**Deliverables**: `bridge/pyghidra/`, `GhidraPyGhidraLauncher`,
`sessionInfoSchema` relaxation, profile backend identity, installation
inspection, doctor integration, dual-backend tests.

### Phase 2: Extended mutations and export

New pyGhidra-only operations: `modify_function_signature`, `modify_data_type`,
`set_native_comment`, `create_native_bookmark`, `batch_decompile_all`,
`export_program`. These are mutation/read operations that stay within the
single-binary session model and do not involve target execution.

**Deliverables**: `GhidraExtendedOperations`, extended capability negotiation,
new MCP tool contracts, `GhidraProviderClient` dispatch, mutation
classification, operation handler implementations.

### Phase 3: Script execution and archive analysis (pending scope decision)

`execute_ghidra_script`, `open_archive_filesystem`, `list_archive_entries`.
These involve arbitrary code execution and multi-program session handles.
Requires maintainer scope decision per CONTRIBUTING.md before design.

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| pyGhidra decompiler output differs from Java bridge | Schema-based validation, not string matching. Document known differences. Profile digest distinguishes backends so cached results don't cross-contaminate. |
| JPype JVM startup latency | Comparable to Ghidra headless startup. Existing startup timeout applies. |
| pyGhidra version incompatibility with Ghidra | Version match check during installation inspection. Doctor reports mismatches. Probe includes actual JVM startup, not just import. |
| Python dependency management | `requirements.txt` with pinned versions. Works in a venv. |
| Analysis configuration parity | Python bridge must replicate all Java launcher analysis customizations (language/compiler selection, disabled analyzers, seeds, MIPS soft-float, no-return fix). Missing any of these silently changes results. Test against the same binaries with both backends. |
| `batch_decompile_all` unbounded output | Streamed response with per-function entries. Response buffer handles large single-line payloads; consider chunked protocol extension if output exceeds buffer capacity. Per-function error/null handling (decompilation can fail for individual functions). |
| Ephemeral project cleanup | Explicit directory deletion on shutdown. pyGhidra's `open_program` saves but does not delete. Runtime root cleanup by TS side is the backstop. |
