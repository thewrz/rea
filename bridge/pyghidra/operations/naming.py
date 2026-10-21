"""Analyst naming: a function entry renames the function, other addresses get a primary label."""
from rea_protocol import RequestFailure, require_keys, require_string

from operations.inventory import require_document


def validate_annotation_text(text, field):
    """Reject NUL and unpaired surrogates, reporting UTF-16 indexes as Ghidra callers see them."""
    units = text.encode("utf-16-le", "surrogatepass")
    code_units = [int.from_bytes(units[i:i + 2], "little") for i in range(0, len(units), 2)]
    index = 0
    while index < len(code_units):
        unit = code_units[index]
        if unit == 0:
            raise RequestFailure(
                "invalid_request",
                f"Annotation {field} contains NUL at UTF-16 index {index}; "
                "Ghidra's decompiler cannot marshal NUL text",
            )
        is_high = 0xD800 <= unit <= 0xDBFF
        if is_high and index + 1 < len(code_units) and 0xDC00 <= code_units[index + 1] <= 0xDFFF:
            index += 2
            continue
        if 0xD800 <= unit <= 0xDFFF:
            raise RequestFailure(
                "invalid_request",
                f"Annotation {field} contains an unpaired Unicode surrogate at UTF-16 index "
                f"{index}; Ghidra cannot preserve it as annotation text",
            )
        index += 1


def symbol_leaf_name(symbol, requested):
    """A fully qualified readback is accepted as an idempotent rename input."""
    from ghidra.util.exception import InvalidInputException

    if requested == str(symbol.getName(True)):
        return str(symbol.getName())
    parent = symbol.getParentNamespace()
    namespace = "" if parent.isGlobal() else str(parent.getName(True))
    prefix = namespace + "::"
    if namespace and requested.startswith(prefix):
        leaf = requested[len(prefix):]
        if leaf:
            return leaf
        raise InvalidInputException(
            f"Symbol name has an empty leaf within namespace {namespace} at "
            f"{symbol.getAddress()}: {requested}"
        )
    return requested


def address_name(session, params):
    require_keys(params, {"document", "address"})
    require_document(session, params)
    address = session.addresses.parse(require_string(params, "address"))
    symbol = session.program.getSymbolTable().getPrimarySymbol(address)
    return None if symbol is None else str(symbol.getName(True))


def _rename(session, address, name):
    """Apply one name; True only when the primary symbol reads back as requested."""
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.exception import DuplicateNameException, InvalidInputException

    program = session.program
    if not program.getMemory().contains(address):
        raise RequestFailure(
            "invalid_request", f"Address is not mapped: {session.addresses.format(address)}"
        )
    validate_annotation_text(name, "name")
    transaction = program.startTransaction("REA address name")
    commit = False
    try:
        function = program.getFunctionManager().getFunctionAt(address)
        table = program.getSymbolTable()
        primary = table.getPrimarySymbol(address) if function is None else function.getSymbol()
        namespace = (
            program.getGlobalNamespace() if primary is None else primary.getParentNamespace()
        )
        expected = name if primary is None else symbol_leaf_name(primary, name)
        for symbol in table.getLabelOrFunctionSymbols(expected, namespace):
            if not address.equals(symbol.getAddress()):
                return False
        if function is not None:
            function.setName(expected, SourceType.USER_DEFINED)
        elif primary is not None and not primary.isDynamic():
            primary.setName(expected, SourceType.USER_DEFINED)
        else:
            table.createLabel(address, expected, SourceType.USER_DEFINED).setPrimary()
        session.invalidate_caches()
        readback = program.getSymbolTable().getPrimarySymbol(address)
        commit = readback is not None and str(readback.getName()) == expected
        return commit
    except (InvalidInputException, DuplicateNameException):
        return False
    finally:
        program.endTransaction(transaction, commit)


def set_address_name(session, params):
    require_keys(params, {"document", "address", "name"})
    require_document(session, params)
    address = session.addresses.parse(require_string(params, "address"))
    return _rename(session, address, require_string(params, "name"))


def set_addresses_names(session, params):
    require_keys(params, {"document", "names"})
    require_document(session, params)
    names = params.get("names")
    if not isinstance(names, dict):
        raise RequestFailure("invalid_request", "names must be an object of address -> name")
    result = {}
    requests_by_address = {}
    for text, name in names.items():
        if not isinstance(name, str):
            raise RequestFailure("invalid_request", "names must be an object of address -> name")
        try:
            address = session.addresses.parse(text)
        except RequestFailure:
            result[text] = False
            continue
        key = session.addresses.format(address)
        requests_by_address.setdefault(key, (address, []))[1].append((text, name))
    for address, requests in requests_by_address.values():
        name = requests[0][1]
        success = False
        if all(candidate == name for _, candidate in requests):
            try:
                success = _rename(session, address, name)
            except RequestFailure:
                # One address's failure never rolls back or hides the others.
                success = False
        for text, _ in requests:
            result[text] = success
    return result
