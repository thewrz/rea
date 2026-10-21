"""The ping response: session identity plus what the bridge measured about the Program."""
import json

PDB_ATTRIBUTE_UTF16_BUDGET = 4096
BRIDGE_NAME = "REA pyGhidra bridge"
_SEEDS_OPTION = "REA analysis seeds"
_SOFT_FLOAT_OPTION = "REA MIPS soft-float storage"


def _utf16_length(text):
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def pdb_observation(program):
    """Read loader/analyzer-owned PDB facts without searching for or applying companions."""
    from ghidra.app.util.bin.format.pdb import PdbParserConstants as Pdb
    from ghidra.program.model.listing import Program

    info = program.getOptions(Program.PROGRAM_INFO)
    attributes = {
        "file": Pdb.PDB_FILE,
        "guid": Pdb.PDB_GUID,
        "age": Pdb.PDB_AGE,
        "signature": Pdb.PDB_SIGNATURE,
        "version": Pdb.PDB_VERSION,
    }
    remaining = PDB_ATTRIBUTE_UTF16_BUDGET
    omitted = []
    pdb = {}
    for name, attribute in attributes.items():
        raw = info.getString(attribute, None)
        value = None if raw is None else str(raw)
        if value is not None and _utf16_length(value) > remaining:
            omitted.append(name)
            pdb[name] = None
            continue
        pdb[name] = value
        if value is not None:
            remaining -= _utf16_length(value)
    if omitted:
        pdb["resource_limit"] = {
            "utf16_budget": PDB_ATTRIBUTE_UTF16_BUDGET,
            "omitted_attributes": omitted,
        }
    pdb["loaded"] = (
        bool(info.getBoolean(Pdb.PDB_LOADED, False)) if info.contains(Pdb.PDB_LOADED) else None
    )
    return pdb


def _recorded_report(program, option):
    from ghidra.program.model.listing import Program

    text = program.getOptions(Program.PROGRAM_INFO).getString(option, None)
    return None if text is None else json.loads(str(text))


def session_info(session, descriptor, provider_version, capabilities):
    program = session.program
    addresses = session.addresses
    info = {
        "name": BRIDGE_NAME,
        "run_id": descriptor.run_id,
        "profile_digest": descriptor.profile_digest,
        "provider": {"id": "ghidra", "version": provider_version},
        "read_only": False,
        "analysis_complete": True,
        "analysis_timed_out": False,
        "capabilities": list(capabilities),
        "target": {
            "name": str(program.getName()),
            "language_id": str(program.getLanguageID().getIdAsString()),
            "compiler_spec_id": str(program.getCompilerSpec().getCompilerSpecID().getIdAsString()),
            "image_base": addresses.format(program.getImageBase()),
            "default_address_space": str(addresses.default_space.getName()),
            "sha256": descriptor.target_sha256,
        },
        "pdb": pdb_observation(program),
    }
    extensions = session.extensions.reports()
    if extensions:
        info["analysis_extensions"] = extensions
    # Written by the pre-analysis seed pass; REA checks it against the committed profile.
    seeds = _recorded_report(program, _SEEDS_OPTION)
    if seeds is not None:
        info["analysis_seeds"] = seeds
    # Written after analysis; REA requires it exactly when the profile declares soft-float storage.
    soft_float = _recorded_report(program, _SOFT_FLOAT_OPTION)
    if soft_float is not None:
        info["mips_soft_float_storage"] = soft_float
    return info
