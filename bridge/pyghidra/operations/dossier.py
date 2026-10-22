"""The function dossier and the session-scoped function annotation that returns it."""
from rea_protocol import RequestFailure, require_keys, require_string

from operations.decompilation import decompile, decompiled_text
from operations.function_facts import (
    basic_block_values,
    comments,
    function_locals,
    procedure_signature,
    referenced_names,
    referenced_strings,
    render_assembly_lines,
    swift_program,
)
from operations.identity import procedure_identity, procedure_name
from operations.inventory import resolve_procedure
from operations.native_flow import (
    native_api_boundary,
    native_value_flow,
    unavailable_native_api_boundary,
    unavailable_native_value_flow,
)
from operations.naming import symbol_leaf_name, validate_annotation_text
from operations.references import (
    body_instructions,
    call_boundary_observation,
    call_relationship_coverage,
    collect_references,
    count_unrepresented_callers,
    procedure_identities,
    reference_edges,
)

ANNOTATION_FIELDS = ("name", "comment", "inline_comment")
BASE_LIMITATIONS = [
    "Unresolved computed or indirect flows without target addresses are not represented as "
    "reference edges.",
    "Thunk and external classifications are Ghidra FunctionManager observations; they do not "
    "resolve targetless calls.",
    "Pseudocode and assembly are Ghidra-specific representations, not original source or "
    "Hopper-equivalent text.",
    "Synthetic Ghidra entry-point references without actionable memory sources are omitted.",
]
SWIFT_LIMITATION = (
    "Swift String literal decoding is not implemented by the pyGhidra backend; no Swift "
    "literals were decoded."
)
LISTING_FACTS_NOTE = (
    "Pseudocode, the native API boundary and p-code value flow are unavailable for this "
    "procedure; assembly, comments, callers, callees, references, strings, names and basic "
    "blocks come from the Ghidra program listing and were still collected."
)


def _facet(available, reason=None):
    return {"available": True} if available else {"available": False, "reason": reason}


def _pseudocode_unavailable_reason(function, failure):
    if failure is not None:
        return failure
    if function.isExternal():
        return "Ghidra does not decompile external functions."
    if function.getBody().isEmpty():
        return "Ghidra has no function body to decompile."
    return "Ghidra completed decompilation without returning pseudocode."


def _decompile_for_dossier(session, function):
    """(results, failure message); the listing facts do not depend on the decompiler."""
    try:
        return decompile(session, function), None
    except RequestFailure as failure:
        if failure.code != "decompile_failed":
            raise
        return None, failure.message.strip()


def _decompiler_limitations(decompilation, failure):
    limitations = []
    message = None if decompilation is None else decompilation.getErrorMessage()
    if message is not None and str(message).strip():
        limitations.append(f"Ghidra decompiler diagnostic: {message}")
    if failure is not None:
        separator = " " if failure.endswith(".") else ". "
        limitations.append(failure + separator + LISTING_FACTS_NOTE)
    return limitations


def _native_facets(session, function, decompilation, failure):
    if failure is not None:
        return (
            unavailable_native_api_boundary(failure),
            unavailable_native_value_flow(failure),
        )
    return native_api_boundary(function, decompilation), native_value_flow(session, decompilation)


def _dossier_body(session, function, instructions, decompilation, failure):
    pseudocode = decompiled_text(decompilation)
    incoming_all = collect_references(session, function, "incoming")
    body = function.getBody()
    incoming = [item for item in incoming_all if not body.contains(item.getFromAddress())]
    outgoing = collect_references(session, function, "outgoing")
    callers = list(function.getCallingFunctions(session.monitor))
    callees = list(function.getCalledFunctions(session.monitor))
    native_api, value_flow = _native_facets(session, function, decompilation, failure)
    procedure = {
        **procedure_identity(session, function),
        "signature": procedure_signature(function),
        "locals": function_locals(function),
    }
    availability = {
        "pseudocode": _facet(
            pseudocode is not None, _pseudocode_unavailable_reason(function, failure)
        ),
        **{
            facet: _facet(True)
            for facet in ("comments", "callers", "callees", "references", "strings_names", "cfg")
        },
        "assembly": _facet(True),
    }
    dossier = {
        "procedure": procedure,
        "pseudocode": "" if pseudocode is None else pseudocode,
        "assembly": render_assembly_lines(session, instructions),
        "comments": comments(session, function),
        "callers": procedure_identities(session, callers),
        "callees": procedure_identities(session, callees),
        "incoming_references": reference_edges(session, incoming),
        "outgoing_references": reference_edges(session, outgoing),
        "referenced_strings": referenced_strings(session, outgoing),
        "referenced_names": referenced_names(session, outgoing),
        "basic_blocks": basic_block_values(session, function),
        "native_api": native_api,
        "native_value_flow": value_flow,
        "facet_availability": availability,
    }
    return dossier, incoming_all, outgoing, callers, callees


def analyze_function_observation(session, params):
    require_keys(params, {"procedure"})
    function = resolve_procedure(session, require_string(params, "procedure"))
    instructions = body_instructions(session, function)
    decompilation, failure = _decompile_for_dossier(session, function)
    dossier, incoming_all, outgoing, callers, callees = _dossier_body(
        session, function, instructions, decompilation, failure
    )
    calls = call_boundary_observation(session, function, instructions, callees, True, outgoing)
    limitations = list(BASE_LIMITATIONS)
    if swift_program(session):
        limitations.append(SWIFT_LIMITATION)
    limitations += calls["limitations"] + _decompiler_limitations(decompilation, failure)
    dossier["unresolved_calls"] = calls["unresolved_calls"]
    dossier["limitations"] = limitations
    session.monitor.checkCancelled()
    missing = count_unrepresented_callers(session, incoming_all, callers)
    return {
        "dossier": dossier,
        "limitations": calls["limitations"],
        "relationship_coverage": call_relationship_coverage(calls, missing),
        "decompiler_failed": failure is not None,
    }


def analyze_function(session, params):
    observation = analyze_function_observation(session, params)
    result = {
        "value": observation["dossier"],
        "limitations": observation["limitations"],
        "relationship_coverage": observation["relationship_coverage"],
    }
    if observation["decompiler_failed"]:
        result["cache_policy"] = "live"
    return result


def _annotation_text(params, field):
    value = params.get(field)
    if not isinstance(value, str):
        raise RequestFailure("invalid_request", f"Annotation {field} must be text")
    return value


def _annotation_readback(session, function):
    from ghidra.program.model.listing import CommentType

    entry = function.getEntryPoint()
    listing = session.program.getListing()
    comment, inline = listing.getComment(CommentType.PRE, entry), listing.getComment(CommentType.EOL, entry)
    return {
        "address": session.addresses.format(entry),
        "name": procedure_name(function),
        "comment": None if comment is None else str(comment),
        "inline_comment": None if inline is None else str(inline),
    }


def _write_annotations(session, function, params, leaf_name):
    from ghidra.program.model.listing import CommentType
    from ghidra.program.model.symbol import SourceType

    entry = function.getEntryPoint()
    listing = session.program.getListing()
    for field, comment_type in (("comment", CommentType.PRE), ("inline_comment", CommentType.EOL)):
        if field in params:
            text = _annotation_text(params, field)
            listing.setComment(entry, comment_type, text if text else None)
    if "name" in params:
        function.setName(leaf_name, SourceType.USER_DEFINED)


def _verify_readback(session, function, params, leaf_name, readback):
    entry = session.addresses.format(function.getEntryPoint())
    for field in ANNOTATION_FIELDS:
        if field not in params:
            continue
        requested = _annotation_text(params, field)
        if field == "name":
            expected, observed = leaf_name, str(function.getName())
        else:
            expected, observed = (requested or None), readback[field]
        if expected != observed:
            raise RequestFailure(
                "annotation_readback_mismatch",
                f"Annotation readback differs for {field} at {entry}",
            )


def _validated_function(session, params):
    if not set(params) <= {"procedure", *ANNOTATION_FIELDS}:
        raise RequestFailure("invalid_request", "Unknown function annotation field")
    if not any(field in params for field in ANNOTATION_FIELDS):
        raise RequestFailure("invalid_request", "Supply at least one annotation change")
    function = resolve_procedure(session, require_string(params, "procedure"))
    entry = function.getEntryPoint()
    if function.isExternal() or not session.program.getMemory().contains(entry):
        raise RequestFailure(
            "invalid_request",
            f"Annotations require a local function entry: {session.addresses.format(entry)}",
        )
    for field in ANNOTATION_FIELDS:
        if field in params:
            validate_annotation_text(_annotation_text(params, field), field)
    return function


def _java_message(exception):
    message = exception.getMessage()
    return "operation failed" if message is None or not str(message).strip() else str(message)


def annotate_native_function(session, params):
    """Edit the session database, read the edit back, and commit only if it matches."""
    from ghidra.util.exception import DuplicateNameException, InvalidInputException

    function = _validated_function(session, params)
    entry = session.addresses.format(function.getEntryPoint())
    transaction = session.program.startTransaction("REA function annotations")
    committed = False
    try:
        leaf_name = (
            symbol_leaf_name(function.getSymbol(), require_string(params, "name"))
            if "name" in params
            else None
        )
        _write_annotations(session, function, params, leaf_name)
        session.monitor.checkCancelled()
        session.invalidate_caches()
        readback = _annotation_readback(session, function)
        _verify_readback(session, function, params, leaf_name, readback)
        dossier = analyze_function_observation(session, {"procedure": entry})["dossier"]
        session.monitor.checkCancelled()
        committed = True
        return {
            "annotations": readback,
            "dossier": dossier,
            "effects": {
                "scope": "session-analysis-database",
                "source_bytes_modified": False,
                "persists_after_close": False,
            },
        }
    except (InvalidInputException, DuplicateNameException) as exception:
        raise RequestFailure(
            "invalid_function_name",
            f"Invalid function name at {entry}: {_java_message(exception)}",
        ) from exception
    finally:
        session.program.endTransaction(transaction, committed)
        session.invalidate_caches()
