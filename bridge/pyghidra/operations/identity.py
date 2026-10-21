"""Function identity facts shared by inventory and function operations."""
from rea_addresses import unsigned_offset
from rea_session import iterate

MAX_BODY_BYTES = 9007199254740991


def procedure_name(function):
    symbol = function.getSymbol()
    return str(function.getName() if symbol is None else symbol.getName(True))


def procedure_facts(session, function):
    target = function.getThunkedFunction(False) if function.isThunk() else None
    return {
        "external": bool(function.isExternal()),
        "thunk": bool(function.isThunk()),
        "thunk_target": None
        if target is None
        else session.addresses.format(target.getEntryPoint()),
    }


def function_classification(session, function):
    return {**procedure_facts(session, function), "provenance": "ghidra-function-manager"}


def _safe_byte_count(value):
    if value < 0 or value > MAX_BODY_BYTES:
        raise OverflowError("Function body byte coverage exceeds exact JSON integer range")
    return value


def function_body(session, function):
    """Observe the whole AddressSet; range endpoints are inclusive."""
    ranges = []
    total = 0
    first = last = space = None
    multiple_spaces = False
    for address_range in iterate(function.getBody().getAddressRanges(True)):
        start = address_range.getMinAddress()
        end = address_range.getMaxAddress()
        if start.getAddressSpace().getAddressableUnitSize() != 1:
            raise ValueError("Function body byte coverage requires a byte-addressed space")
        ranges.append(
            {"start": session.addresses.format(start), "end": session.addresses.format(end)}
        )
        total += unsigned_offset(end) - unsigned_offset(start) + 1
        if first is None:
            first, space = start, start.getAddressSpace()
        elif not space.equals(start.getAddressSpace()):
            multiple_spaces = True
        last = end
    span = (
        None
        if multiple_spaces
        else 0
        if first is None
        else unsigned_offset(last) - unsigned_offset(first) + 1
    )
    return {
        "available": True,
        "provenance": "ghidra-function-body-address-set",
        "ranges": ranges,
        "total_bytes": _safe_byte_count(total),
        "span_bytes": None if span is None else _safe_byte_count(span),
        "non_contiguous": len(ranges) > 1,
        "contains_entry": bool(function.getBody().contains(function.getEntryPoint())),
    }


def procedure_identity(session, function):
    return {
        "address": session.addresses.format(function.getEntryPoint()),
        "name": procedure_name(function),
        "classification": function_classification(session, function),
        "body": function_body(session, function),
    }


def function_at_or_containing(session, address):
    manager = session.program.getFunctionManager()
    function = manager.getFunctionAt(address)
    if function is None and address.isMemoryAddress():
        function = manager.getFunctionContaining(address)
    return function
