"""Function operations. Eight answer with {value, limitations} observation envelopes."""
from rea_protocol import RequestFailure, require_keys, require_string
from rea_session import address_order

from operations.decompilation import decompile, decompiled_text, resolve_decompile_procedure
from operations.dossier import analyze_function, annotate_native_function
from operations.function_facts import basic_blocks, function_locals, procedure_signature, render_assembly_lines
from operations.identity import function_body, function_classification, procedure_identity, procedure_name
from operations.inventory import require_document, resolve_procedure
from operations.native_inspect import (
    inspect_native_data_type,
    inspect_native_instruction,
    resolve_native_call_targets,
    xrefs,
)
from operations.references import (
    body_instructions,
    call_boundary_observation,
    call_relationship_coverage,
    collect_references,
    count_unrepresented_callers,
    function_boundary_limitations,
    reference_edges,
    visit_references,
)

INSTRUCTION_LIMITATIONS = [
    "Instruction text and ordering are Ghidra-specific representations.",
    "The fast path does not invoke the decompiler or scan whole-program names and strings.",
]


def _envelope(value, limitations, **extra):
    return {"value": value, "limitations": list(limitations), **extra}


def _procedure(session, params):
    require_keys(params, {"document", "procedure"})
    require_document(session, params)
    return resolve_procedure(session, require_string(params, "procedure"))


def procedure_pseudo_code(session, params):
    require_keys(params, {"document", "procedure"})
    require_document(session, params)
    selector = require_string(params, "procedure")
    function, selection = resolve_decompile_procedure(session, selector)
    try:
        value = decompiled_text(decompile(session, function))
    except RequestFailure as failure:
        if selection is None:
            raise
        raise RequestFailure(
            failure.code,
            f"Selector {selector} mapped to analysis address {selection['mapped_address']} and "
            f"procedure {session.addresses.format(function.getEntryPoint())}; {failure.message}",
        ) from failure
    limitations = function_boundary_limitations(session, function, body_instructions(session, function))
    extra = {} if selection is None else {"selection": selection}
    return _envelope(value, limitations, **extra)


def procedure_assembly(session, params):
    function = _procedure(session, params)
    instructions = body_instructions(session, function)
    lines = render_assembly_lines(session, instructions)
    return _envelope(
        "\n".join(lines), function_boundary_limitations(session, function, instructions)
    )


def read_function_instructions(session, params):
    function = _procedure(session, params)
    instructions = body_instructions(session, function)
    boundary = function_boundary_limitations(session, function, instructions)
    value = {
        "procedure": procedure_identity(session, function),
        "instructions": render_assembly_lines(session, instructions),
        "limitations": [*INSTRUCTION_LIMITATIONS, *boundary],
    }
    return _envelope(value, boundary)


def _ordered_entries(session, functions):
    ordered = sorted(functions, key=lambda function: address_order(function.getEntryPoint()))
    return [session.addresses.format(function.getEntryPoint()) for function in ordered]


def procedure_callers(session, params):
    function = _procedure(session, params)
    callers = list(function.getCallingFunctions(session.monitor))
    instructions = body_instructions(session, function)
    incoming = list(visit_references(session, function, "incoming"))
    missing = count_unrepresented_callers(session, incoming, callers)
    session.monitor.checkCancelled()
    return _envelope(
        _ordered_entries(session, callers),
        function_boundary_limitations(session, function, instructions),
        relationship_coverage=call_relationship_coverage(None, missing),
    )


def procedure_callees(session, params):
    function = _procedure(session, params)
    callees = list(function.getCalledFunctions(session.monitor))
    instructions = body_instructions(session, function)
    calls = call_boundary_observation(session, function, instructions, callees, False, None)
    session.monitor.checkCancelled()
    return _envelope(
        _ordered_entries(session, callees),
        calls["limitations"],
        relationship_coverage=call_relationship_coverage(calls, None),
    )


def procedure_info(session, params):
    function = _procedure(session, params)
    body = function_body(session, function)
    value = {
        "name": procedure_name(function),
        "entrypoint": session.addresses.format(function.getEntryPoint()),
        "basicblock_count": len(basic_blocks(session, function)),
        "length": body["total_bytes"],
        "body": body,
        "signature": procedure_signature(function),
        "locals": function_locals(function),
        "classification": function_classification(session, function),
    }
    limitations = function_boundary_limitations(session, function, body_instructions(session, function))
    return _envelope(value, limitations)


def procedure_references(session, params):
    require_keys(params, {"document", "procedure", "direction"})
    require_document(session, params)
    function = resolve_procedure(session, require_string(params, "procedure"))
    direction = require_string(params, "direction")
    if direction not in ("incoming", "outgoing"):
        raise RequestFailure("invalid_request", "direction must be incoming or outgoing")
    references = collect_references(session, function, direction)
    instructions = body_instructions(session, function)
    unresolved = []
    if direction == "outgoing":
        calls = call_boundary_observation(session, function, instructions, None, True, references)
        unresolved, limitations = calls["unresolved_calls"], calls["limitations"]
    else:
        limitations = function_boundary_limitations(session, function, instructions)
    value = {
        "procedure": procedure_identity(session, function),
        "direction": direction,
        "references": reference_edges(session, references),
        "reference_kinds_available": True,
        "unresolved_calls": unresolved,
    }
    return _envelope(value, limitations)


FUNCTION_OPERATIONS = {
    "analyze_function": analyze_function,
    "annotate_native_function": annotate_native_function,
    "inspect_native_data_type": inspect_native_data_type,
    "inspect_native_instruction": inspect_native_instruction,
    "procedure_assembly": procedure_assembly,
    "procedure_callees": procedure_callees,
    "procedure_callers": procedure_callers,
    "procedure_info": procedure_info,
    "procedure_pseudo_code": procedure_pseudo_code,
    "procedure_references": procedure_references,
    "read_function_instructions": read_function_instructions,
    "resolve_native_call_targets": resolve_native_call_targets,
    "xrefs": xrefs,
}
