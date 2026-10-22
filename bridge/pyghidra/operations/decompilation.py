"""Decompiler runs and decompile-specific procedure selection (names, addresses, file offsets)."""
import re

from rea_protocol import MAX_SAFE_INTEGER, RequestFailure

from operations.identity import function_at_or_containing
from operations.inventory import resolve_procedure
from operations.memory import is_target_source

FILE_OFFSET_PREFIX = "file-offset:"
_HEX_COORDINATE = re.compile(r"0x[0-9a-fA-F]+")
_LINE_BREAKS = re.compile(r"[\r\n]+")


def diagnostic_message(value):
    if value is None or not str(value).strip():
        return "native decompiler returned no detail"
    return _LINE_BREAKS.sub(" ", str(value))


def decompile(session, function):
    """Decompiler results, or None for functions Ghidra does not decompile."""
    if function.isExternal() or function.getBody().isEmpty():
        return None
    results = session.decompiler.decompileFunction(function, 0, session.monitor)
    if results.isCancelled():
        raise RequestFailure("decompile_cancelled", "Ghidra decompilation was cancelled")
    if not results.decompileCompleted():
        raise RequestFailure(
            "decompile_failed",
            "Ghidra decompilation failed: " + diagnostic_message(results.getErrorMessage()),
        )
    return results


def decompiled_text(results):
    if results is None:
        return None
    value = results.getDecompiledFunction()
    return None if value is None else str(value.getC())


def _mapped_addresses(session, offset):
    mapped = {}
    for block in session.program.getMemory().getBlocks():
        for source in block.getSourceInfos():
            session.monitor.checkCancelled()
            backing = source.getFileBytes()
            if backing.isEmpty() or not is_target_source(session, backing.get()):
                continue
            address = source.locateAddressForFileOffset(offset)
            if address is not None:
                mapped.setdefault(session.addresses.format(address), address)
    return list(mapped.values())


def _offset_failure(session, coordinate, candidates):
    if len(candidates) > 1:
        listed = ", ".join(session.addresses.format(address) for address in candidates)
        return RequestFailure(
            "ambiguous",
            f"File offset {coordinate} has multiple loaded mappings: [{listed}]; "
            "select an explicit analysis address",
        )
    return RequestFailure(
        "not_found",
        f"File offset {coordinate} has no loaded source mapping for the admitted target file; "
        f"Ghidra image base: {session.addresses.format(session.program.getImageBase())}. "
        "Inspect mappings with rea inspect-native-load-image <path> --provider ghidra --json "
        "or MCP inspect_native_load_image.",
    )


def _function_at_file_offset(session, coordinate):
    if not _HEX_COORDINATE.fullmatch(coordinate):
        raise RequestFailure(
            "invalid_request", "File offsets require hexadecimal file-offset:0x... syntax"
        )
    offset = int(coordinate[2:], 16)
    if offset > MAX_SAFE_INTEGER:
        raise RequestFailure(
            "invalid_request", "File offset exceeds the exact JSON integer range"
        )
    session.monitor.checkCancelled()
    candidates = _mapped_addresses(session, offset)
    if len(candidates) != 1:
        raise _offset_failure(session, coordinate, candidates)
    mapped = candidates[0]
    function = function_at_or_containing(session, mapped)
    if function is None:
        raise RequestFailure(
            "not_found",
            f"File offset {coordinate} maps to analysis address {session.addresses.format(mapped)}, "
            "but no procedure starts at or contains that address in the current Ghidra analysis. "
            "Choose an observed procedure with CLI rea search <path> . --kind procedures "
            "--mode regex --provider ghidra --json or MCP list_procedures.",
        )
    selection = {
        "file_offset": offset,
        "mapped_address": session.addresses.format(mapped),
        "procedure_address": session.addresses.format(function.getEntryPoint()),
    }
    return function, selection


def resolve_decompile_procedure(session, selector):
    """(function, selection) where selection records a file-offset mapping, else None."""
    explicit = selector.startswith(FILE_OFFSET_PREFIX)
    if not explicit:
        try:
            return resolve_procedure(session, selector), None
        except RequestFailure as failure:
            # Existing names/addresses win; only an unresolved numeric input falls back to
            # source coordinates, and ambiguity never does.
            if failure.code != "not_found" or not _HEX_COORDINATE.fullmatch(selector):
                raise
    coordinate = selector[len(FILE_OFFSET_PREFIX):] if explicit else selector
    return _function_at_file_offset(session, coordinate)
