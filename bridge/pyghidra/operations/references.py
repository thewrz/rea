"""Reference-manager observations and the call/boundary limitations derived from them."""
import functools
import re

from rea_session import address_order, iterate, utf16_order

from operations.identity import function_at_or_containing, procedure_identity, procedure_name

ALL_CALLS_DIAGNOSTIC = (
    "Only resolved Ghidra call references are returned; unresolved computed or indirect calls "
    "remain unknown, while function classifications distinguish thunks and externals."
)
_SIZE_PREFIX = re.compile(r"\b(?:byte|word|dword|qword)\s+ptr\s+", re.IGNORECASE | re.ASCII)
_WHITESPACE = re.compile(r"\s+", re.ASCII)


def observation_scope(function):
    from ghidra.program.model.address import AddressSet

    scope = AddressSet(function.getBody())
    scope.add(function.getEntryPoint())
    return scope


def visit_references(session, function, direction):
    """References owned by the function's body (and entry), minus synthetic entry-point refs."""
    manager = session.program.getReferenceManager()
    scope = observation_scope(function)
    outgoing = direction == "outgoing"
    addresses = (
        manager.getReferenceSourceIterator(scope, True)
        if outgoing
        else manager.getReferenceDestinationIterator(scope, True)
    )
    for address in iterate(addresses):
        found = (
            manager.getReferencesFrom(address)
            if outgoing
            else iterate(manager.getReferencesTo(address))
        )
        for reference in found:
            if not reference.isEntryPointReference():
                yield reference


def references_to(session, address):
    manager = session.program.getReferenceManager()
    return [
        reference
        for reference in iterate(manager.getReferencesTo(address))
        if not reference.isEntryPointReference()
    ]


def _reference_key(session, reference):
    return (
        session.addresses.format(reference.getFromAddress()),
        session.addresses.format(reference.getToAddress()),
        str(reference.getReferenceType().getName()),
        int(reference.getOperandIndex()),
        bool(reference.isPrimary()),
    )


def _compare_references(left, right):
    for order in (
        left.getFromAddress().compareTo(right.getFromAddress()),
        left.getToAddress().compareTo(right.getToAddress()),
    ):
        if order:
            return order
    left_type = utf16_order(str(left.getReferenceType().getName()))
    right_type = utf16_order(str(right.getReferenceType().getName()))
    if left_type != right_type:
        return -1 if left_type < right_type else 1
    left_tail = (int(left.getOperandIndex()), bool(left.isPrimary()))
    right_tail = (int(right.getOperandIndex()), bool(right.isPrimary()))
    return (left_tail > right_tail) - (left_tail < right_tail)


reference_order = functools.cmp_to_key(_compare_references)


def distinct_references(session, references):
    observed = {}
    for reference in references:
        observed.setdefault(_reference_key(session, reference), reference)
    return sorted(observed.values(), key=reference_order)


def collect_references(session, function, direction):
    return distinct_references(session, visit_references(session, function, direction))


def reference_kind(reference):
    kind = reference.getReferenceType()
    return {
        "available": True,
        "provenance": "ghidra-reference-manager",
        "type": str(kind.getName()),
        "flow": bool(kind.isFlow()),
        "call": bool(kind.isCall()),
        "jump": bool(kind.isJump()),
        "data": bool(kind.isData()),
        "read": bool(kind.isRead()),
        "write": bool(kind.isWrite()),
        "indirect": bool(kind.isIndirect()),
        "computed": bool(kind.isComputed()),
        "conditional": bool(kind.isConditional()),
        "terminal": bool(kind.isTerminal()),
        "primary": bool(reference.isPrimary()),
        "operand_index": int(reference.getOperandIndex()),
        "external": bool(reference.isExternalReference()),
    }


def _owner_identity(session, address):
    owner = function_at_or_containing(session, address)
    return None if owner is None else procedure_identity(session, owner)


def reference_edge(session, reference):
    source, target = reference.getFromAddress(), reference.getToAddress()
    return {
        "source_address": session.addresses.format(source),
        "target_address": session.addresses.format(target),
        "source_procedure": _owner_identity(session, source),
        "target_procedure": _owner_identity(session, target),
        "kind": reference_kind(reference),
    }


def reference_edges(session, references):
    return [reference_edge(session, reference) for reference in references]


def procedure_identities(session, functions):
    ordered = sorted(functions, key=lambda function: address_order(function.getEntryPoint()))
    return [procedure_identity(session, function) for function in ordered]


def _immediately_precedes(first, second):
    fall_through = first.getFallThrough()
    return fall_through is not None and bool(fall_through.equals(second.getAddress()))


def _normalized_fs_operand(instruction):
    text = str(instruction.getDefaultOperandRepresentation(0))
    text = _WHITESPACE.sub("", _SIZE_PREFIX.sub("", text))
    return text if text[:3].lower() == "fs:" and "[" in text else None


def _same_fs_operand(first, second):
    left, right = _normalized_fs_operand(first), _normalized_fs_operand(second)
    return left is not None and right is not None and left.lower() == right.lower()


def _has_register_operand(instruction, operand, name):
    from ghidra.program.model.lang import Register

    return any(
        isinstance(item, Register) and str(item.getName()).lower() == name.lower()
        for item in instruction.getOpObjects(operand)
    )


def _is_push_of_one_operand(instruction):
    return str(instruction.getMnemonicString()).lower() == "push" and instruction.getNumOperands() == 1


def _seh_handler_limitation(session, function, handler_push, frame_push, frame_link):
    from ghidra.program.model.scalar import Scalar

    if not (
        _immediately_precedes(handler_push, frame_push)
        and _immediately_precedes(frame_push, frame_link)
        and _is_push_of_one_operand(handler_push)
        and _is_push_of_one_operand(frame_push)
        and str(frame_link.getMnemonicString()).lower() == "mov"
        and frame_link.getNumOperands() == 2
        and _same_fs_operand(frame_push, frame_link)
        and _has_register_operand(frame_link, 1, "ESP")
    ):
        return None
    operand = list(handler_push.getOpObjects(0))
    if len(operand) != 1 or not isinstance(operand[0], Scalar) or operand[0].bitLength() != 32:
        return None
    space = session.program.getAddressFactory().getDefaultAddressSpace()
    handler = space.getAddress(operand[0].getUnsignedValue())
    if function.getBody().contains(handler):
        return None
    handler_text = session.addresses.format(handler)
    return (
        "Ghidra Listing shows a Borland/Delphi-style SEH frame registration at "
        f"{session.addresses.format(frame_link.getAddress())} (push {handler_text} followed by "
        f"fs-segment stack chaining); handler {handler_text} lies outside this procedure's body, "
        "so callees, strings, and cross-references may omit the handler region."
    )


def _terminal_call_limitation(session, instruction):
    flow = instruction.getFlowType()
    if not (flow.isCall() and flow.isTerminal()):
        return None
    manager = session.program.getFunctionManager()
    destinations = list(instruction.getFlows())
    text = "Ghidra Listing reports a terminal call at " + session.addresses.format(
        instruction.getAddress()
    )
    if not destinations:
        return text + " with no resolved callee; its no-return basis is unknown."
    described = []
    for destination in destinations:
        target = manager.getFunctionAt(destination)
        label = session.addresses.format(destination)
        if target is None:
            described.append(f"{label} (callee identity unknown)")
        else:
            described.append(
                f"{label} {procedure_name(target)} (external={_java_bool(target.isExternal())}, "
                f"thunk={_java_bool(target.isThunk())}, hasNoReturn={_java_bool(target.hasNoReturn())})"
            )
    text += " to " + ", ".join(described) + "; fallthrough is excluded by Ghidra's flow model."
    only = manager.getFunctionAt(destinations[0]) if len(destinations) == 1 else None
    if only is not None and only.hasNoReturn():
        return text + (
            " This records Ghidra's FunctionManager flag, not an independent verification "
            "that the callee cannot return."
        )
    return text + " The reason for the terminal flow is not established by this observation."


def _java_bool(value):
    return "true" if value else "false"


def function_boundary_limitations(session, function, instructions):
    limitations = []
    before_previous = previous = None
    for instruction in instructions:
        session.monitor.checkCancelled()
        terminal = _terminal_call_limitation(session, instruction)
        if terminal is not None:
            limitations.append(terminal)
        if before_previous is not None and previous is not None:
            seh = _seh_handler_limitation(session, function, before_previous, previous, instruction)
            if seh is not None:
                limitations.append(seh)
        before_previous, previous = previous, instruction
    return limitations


def body_instructions(session, function):
    return list(iterate(session.program.getListing().getInstructions(function.getBody(), True)))


def call_boundary_observation(
    session, function, instructions, returned_callees, include_unresolved_sites, references
):
    """Limitations plus the callee calls Ghidra's inventory cannot represent.

    `unrepresented` is None when no callee inventory was supplied; `unresolved` is None
    unless unresolved sites were requested.
    """
    observed = visit_references(session, function, "outgoing") if references is None else references
    callee_entries = (
        None
        if returned_callees is None
        else {session.addresses.format(callee.getEntryPoint()) for callee in returned_callees}
    )
    unrepresented = 0
    unresolved = {}
    for reference in observed:
        session.monitor.checkCancelled()
        if not reference.getReferenceType().isCall():
            continue
        target = function_at_or_containing(session, reference.getToAddress())
        if callee_entries is not None and (
            target is None or session.addresses.format(target.getEntryPoint()) not in callee_entries
        ):
            unrepresented += 1
        if target is None:
            _note_unresolved(
                session, unresolved, reference.getFromAddress(),
                "A call destination has no known containing Ghidra procedure",
            )
    for instruction in instructions:
        if not instruction.getFlowType().isCall():
            continue
        if any(item.getReferenceType().isCall() for item in instruction.getReferencesFrom()):
            continue
        unrepresented += 1
        _note_unresolved(
            session, unresolved, instruction.getAddress(),
            "Instruction decoder identifies a call but ReferenceManager supplies no call destination",
        )
    limitations = function_boundary_limitations(session, function, instructions)
    sites = None
    if include_unresolved_sites:
        ordered = sorted(unresolved.values(), key=lambda item: address_order(item[0]))
        sites = [
            {"address": session.addresses.format(address), "reason": reason}
            for address, reason in ordered
        ]
    return {
        "limitations": limitations,
        "unrepresented": None if returned_callees is None else unrepresented,
        "unresolved_calls": sites,
    }


def _note_unresolved(session, unresolved, address, reason):
    unresolved[session.addresses.format(address)] = (address, reason)


def _complete_coverage():
    return {"status": "complete", "diagnostics": [ALL_CALLS_DIAGNOSTIC]}


def call_relationship_coverage(calls, missing_callers):
    """Whether the caller/callee inventories account for every observed call."""
    coverage = _complete_coverage()
    omitted = None if calls is None else calls["unrepresented"]
    directions = []
    caller_limitation = None
    if missing_callers is not None and missing_callers > 0:
        directions.append("callers")
        caller_limitation = (
            f"Ghidra's caller inventory omits sources of {missing_callers} "
            "call reference(s) into this function's body."
        )
    if (calls is not None and omitted is None) or (calls is None and missing_callers is None):
        reason = (
            "No call inventory was examined."
            if calls is None
            else "The callee inventory was not examined alongside decoded call targets."
        )
        if calls is None and missing_callers is None:
            directions.append("callers")
        directions.append("callees")
        return {
            **coverage,
            "status": "unknown",
            "reason": reason + ("" if caller_limitation is None else " " + caller_limitation),
            "limited_directions": directions,
        }
    limitations = [] if caller_limitation is None else [caller_limitation]
    if omitted is not None and omitted > 0:
        limitations.append(
            f"Ghidra's callee inventory omits targets of {omitted} call reference(s) "
            "or decoded call(s) without destinations."
        )
        directions.append("callees")
    if limitations:
        return {**coverage, "status": "partial", "limitations": limitations, "limited_directions": directions}
    return coverage


def unrepresented_caller(session, reference, callers):
    if not reference.getReferenceType().isCall():
        return False
    owner = function_at_or_containing(session, reference.getFromAddress())
    return owner is None or session.addresses.format(owner.getEntryPoint()) not in callers


def caller_entry_set(session, callers):
    return {session.addresses.format(caller.getEntryPoint()) for caller in callers}


def count_unrepresented_callers(session, references, callers):
    entries = caller_entry_set(session, callers)
    count = 0
    for reference in references:
        session.monitor.checkCancelled()
        if unrepresented_caller(session, reference, entries):
            count += 1
    return count
