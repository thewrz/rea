"""Whole-Program inventories: names, procedures, strings, segments and searches."""
import functools
import json
import re

from rea_addresses import is_explicit_address, unsigned_offset
from rea_protocol import (
    RequestFailure,
    optional_string,
    require_boolean,
    require_keys,
    require_string,
)
from rea_session import address_order, iterate, utf16_order

from operations.identity import (
    function_at_or_containing,
    procedure_facts,
    procedure_identity,
    procedure_name,
)


def require_document(session, params):
    document = optional_string(params, "document")
    program_name = str(session.program.getName())
    if document is not None and document != program_name:
        raise RequestFailure(
            "not_found",
            f"Unknown Ghidra Program identity: {document}; active program: {program_name}",
        )


def _compare_items(left, right):
    order = left["_address"].compareTo(right["_address"])
    if order:
        return order
    left_value, right_value = utf16_order(left["value"]), utf16_order(right["value"])
    if left_value != right_value:
        return -1 if left_value < right_value else 1
    left_facts = json.dumps(left["facts"], separators=(",", ":"))
    right_facts = json.dumps(right["facts"], separators=(",", ":"))
    return (left_facts > right_facts) - (left_facts < right_facts)


def _sorted_items(items):
    return sorted(items, key=functools.cmp_to_key(_compare_items))


def _normalized_symbol_type(symbol):
    text = re.sub(r"[^a-z0-9]+", "_", str(symbol.getSymbolType()).lower()).strip("_")
    return text or "unknown"


def names(session):
    def build():
        items = []
        for symbol in iterate(session.program.getSymbolTable().getAllSymbols(True)):
            address = symbol.getAddress()
            if not address.isMemoryAddress() and not address.isExternalAddress():
                continue
            facts = {
                "primary": bool(symbol.isPrimary()),
                "dynamic": bool(symbol.isDynamic()),
                "external": bool(symbol.isExternal()),
                "type": _normalized_symbol_type(symbol),
                "source": str(symbol.getSource().name()).lower(),
            }
            items.append(
                {"_address": address, "value": str(symbol.getName(True)), "facts": facts}
            )
        return _sorted_items(items)

    return session.cached("names", build)


def procedures(session):
    """Local and external functions, each with its inventory item."""

    def build():
        manager = session.program.getFunctionManager()
        entries, seen = [], set()
        for iterator in (manager.getFunctions(True), manager.getExternalFunctions()):
            for function in iterate(iterator):
                entry = function.getEntryPoint()
                key = session.addresses.format(entry)
                if key in seen:
                    continue
                seen.add(key)
                item = {
                    "_address": entry,
                    "value": procedure_name(function),
                    "facts": procedure_facts(session, function),
                }
                entries.append((function, item))
        entries.sort(key=functools.cmp_to_key(lambda a, b: _compare_items(a[1], b[1])))
        return entries

    return session.cached("procedures", build)


def strings(session):
    def build():
        from ghidra.program.model.data import StringDataInstance

        items = []
        for data in iterate(session.program.getListing().getDefinedData(True)):
            if not data.hasStringValue():
                continue
            instance = StringDataInstance.getStringDataInstance(data)
            value = instance.getStringValue()
            if value is None:
                continue
            charset = instance.getCharsetName()
            facts = {
                "encoding": str(charset) if charset else "unknown",
                "termination": "missing"
                if instance.isMissingNullTerminator()
                else "present_or_not_required",
                "byte_length": max(0, int(data.getLength())),
            }
            items.append({"_address": data.getAddress(), "value": str(value), "facts": facts})
        return _sorted_items(items)

    return session.cached("strings", build)


def _result_item(session, item, facts_name=None):
    result = {"address": session.addresses.format(item["_address"]), "value": item["value"]}
    if facts_name is not None:
        result[facts_name] = dict(item["facts"])
    return result


def _inventory(session, items, facts_name):
    return [_result_item(session, item, facts_name) for item in items]


def _filter_address(session, items, requested):
    if requested is None:
        return items
    address = session.addresses.parse(requested)
    return [item for item in items if item["_address"].equals(address)]


def list_documents(session, params):
    require_keys(params, set())
    return [str(session.program.getName())]


def _exclusive_end(session, block):
    following = block.getEnd().next()
    space = block.getStart().getAddressSpace()
    if following is not None and following.getAddressSpace().equals(space):
        return session.addresses.format(following)
    return session.addresses.format_offset(
        space, unsigned_offset(block.getStart()) + int(block.getSize())
    )


def memory_region(session, block, image_base):
    return {
        "name": str(block.getName()),
        "start": session.addresses.format(block.getStart()),
        "end": _exclusive_end(session, block),
        "readable": bool(block.isRead()),
        "writable": bool(block.isWrite()),
        "executable": bool(block.isExecute()),
        "permissions": {"available": True, "source": "ghidra-memory-block"},
        "provenance": "ghidra-memory-block",
        "address_space": str(block.getStart().getAddressSpace().getName()),
        "image_base": image_base,
        "initialized": bool(block.isInitialized()),
        "overlay": bool(block.isOverlay()),
    }


def ordered_blocks(session):
    blocks = list(session.program.getMemory().getBlocks())
    return sorted(blocks, key=lambda block: address_order(block.getStart()))


def segments(session):
    image_base = session.addresses.format(session.program.getImageBase())
    return [
        {**memory_region(session, block, image_base), "sections": []}
        for block in ordered_blocks(session)
    ]


def list_segments(session, params):
    require_keys(params, {"document"})
    require_document(session, params)
    return segments(session)


def read_binary_inventory_summary(session, params):
    require_keys(params, set())
    return {
        "document": str(session.program.getName()),
        "segments": segments(session),
        "procedure_count": len(procedures(session)),
        "string_count": len(strings(session)),
    }


def list_names(session, params):
    require_keys(params, {"document", "address"})
    require_document(session, params)
    items = _filter_address(session, names(session), optional_string(params, "address"))
    return _inventory(session, items, "symbol")


def list_procedures(session, params):
    require_keys(params, {"document"})
    require_document(session, params)
    return _inventory(session, [item for _, item in procedures(session)], "procedure")


def list_strings(session, params):
    require_keys(params, {"document", "address"})
    require_document(session, params)
    items = _filter_address(session, strings(session), optional_string(params, "address"))
    return _inventory(session, items, "string")


def _matches_entry_symbol(session, function, value):
    symbols = session.program.getSymbolTable().getSymbols(function.getEntryPoint())
    return any(
        str(symbol.getName()) == value or str(symbol.getName(True)) == value
        for symbol in symbols
    )


def _named_procedures(session, value):
    matches = []
    for function, _ in procedures(session):
        symbol = function.getSymbol()
        qualified = str(function.getName() if symbol is None else symbol.getName(True))
        # Imported labels can share a function entry without being its primary symbol.
        if (
            str(function.getName()) == value
            or qualified == value
            or _matches_entry_symbol(session, function, value)
        ):
            matches.append(function)
    return matches


def resolve_procedure(session, value):
    """An explicit address wins; otherwise an exact symbol name, then legacy bare hex."""
    explicit = is_explicit_address(value)
    if not explicit:
        matches = _named_procedures(session, value)
        if len(matches) > 1:
            entries = ", ".join(session.addresses.format(match.getEntryPoint()) for match in matches)
            raise RequestFailure(
                "ambiguous",
                f"Ghidra procedure name is ambiguous: {value}; select an exact entry address from [{entries}]",
            )
        if matches:
            return matches[0]
    address = session.addresses.parse(value) if explicit else session.addresses.try_parse(value)
    if address is None:
        raise RequestFailure("not_found", f"Unknown Ghidra procedure name or address: {value}")
    function = function_at_or_containing(session, address)
    if function is None:
        raise RequestFailure(
            "not_found",
            f"No procedure exists at the requested address: {value}; Ghidra image base: "
            f"{session.addresses.format(session.program.getImageBase())}. Choose an observed "
            "analysis address with list_procedures, and inspect the loaded base with "
            "binary_overview and inspect_native_load_image.",
        )
    return function


def procedure_address(session, params):
    require_keys(params, {"document", "procedure"})
    require_document(session, params)
    function = resolve_procedure(session, require_string(params, "procedure"))
    return session.addresses.format(function.getEntryPoint())


def resolve_containing_procedure(session, params):
    require_keys(params, {"document", "address"})
    require_document(session, params)
    query = session.addresses.parse(require_string(params, "address"))
    function = function_at_or_containing(session, query)
    result = {"query_address": session.addresses.format(query)}
    if function is not None:
        return {**result, "found": True, "procedure": procedure_identity(session, function)}
    inside = query.isMemoryAddress() and session.program.getMemory().contains(query)
    return {
        **result,
        "found": False,
        "procedure": None,
        "reason": "not_in_procedure" if inside else "outside_segments",
    }


def _literal_matcher(pattern, case_sensitive):
    needle = pattern if case_sensitive else pattern.lower()
    return lambda value: needle in (value if case_sensitive else value.lower())


def _stack_exhausted(expression, stage):
    return RequestFailure(
        "regex_stack_exhausted",
        f"Ghidra's Java regex engine exhausted its stack while {stage} pattern {expression}. "
        "Use literal mode or simplify the regex; the session remains usable.",
    )


def _regex_matcher(expression, case_sensitive):
    """Java Pattern semantics, as the capability limitations promise."""
    from java.lang import StackOverflowError
    from java.util.regex import Pattern, PatternSyntaxException

    flags = 0 if case_sensitive else Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
    try:
        pattern = Pattern.compile(expression, flags)
    except PatternSyntaxException as exception:
        description = str(exception.getDescription())
        if description == "Stack overflow during pattern compilation":
            raise _stack_exhausted(expression, "compiling") from exception
        raise RequestFailure(
            "invalid_request",
            f"Invalid regex pattern {expression}: {description} at index {exception.getIndex()}",
        ) from exception
    except StackOverflowError as exception:
        raise _stack_exhausted(expression, "compiling") from exception

    def matches(value):
        try:
            return bool(pattern.matcher(value).find())
        except StackOverflowError as exception:
            raise _stack_exhausted(expression, "matching") from exception

    return matches


def _search(session, params, items):
    require_keys(params, {"pattern", "mode", "case_sensitive", "document"})
    require_document(session, params)
    expression = require_string(params, "pattern")
    mode = require_string(params, "mode")
    if mode not in ("literal", "regex"):
        raise RequestFailure("invalid_request", "mode must be literal or regex")
    case_sensitive = require_boolean(params, "case_sensitive")
    matcher = (
        _literal_matcher(expression, case_sensitive)
        if mode == "literal"
        else _regex_matcher(expression, case_sensitive)
    )
    return [_result_item(session, item) for item in items if matcher(item["value"])]


def search_procedures(session, params):
    return _search(session, params, [item for _, item in procedures(session)])


def search_strings(session, params):
    return _search(session, params, strings(session))
