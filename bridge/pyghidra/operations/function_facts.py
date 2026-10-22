"""Listing and database facts that make up a function dossier."""
from rea_addresses import unsigned_offset
from rea_session import address_order, iterate, utf16_order

from operations.references import observation_scope


def procedure_signature(function):
    return str(function.getPrototypeString(False, True))


def function_locals(function):
    ordered = sorted(
        function.getLocalVariables(),
        key=lambda variable: (
            utf16_order(str(variable.getName())),
            utf16_order(str(variable.getVariableStorage().toString())),
        ),
    )
    return [
        {
            "description": f"{variable.getDataType().getDisplayName()} {variable.getName()}"
            f" @ {variable.getVariableStorage()}",
            "provenance": "ghidra-function-database",
        }
        for variable in ordered
    ]


def render_assembly_lines(session, instructions):
    lines = []
    for instruction in instructions:
        operands = [
            str(instruction.getDefaultOperandRepresentation(index))
            for index in range(instruction.getNumOperands())
        ]
        text = f"{session.addresses.format(instruction.getAddress())}: {instruction.getMnemonicString()}"
        lines.append(text + (" " + ", ".join(operands) if operands else ""))
    return lines


def basic_blocks(session, function):
    from ghidra.program.model.block import BasicBlockModel

    model = BasicBlockModel(session.program, False)
    blocks = list(iterate(model.getCodeBlocksContaining(function.getBody(), session.monitor)))
    return sorted(blocks, key=lambda block: address_order(block.getFirstStartAddress()))


def _exclusive_address(session, inclusive):
    space = inclusive.getAddressSpace()
    return session.addresses.format_offset(space, unsigned_offset(inclusive) + 1)


def _block_successors(session, function, block):
    body = function.getBody()
    successors = {}
    for destination in iterate(block.getDestinations(session.monitor)):
        target = destination.getDestinationBlock()
        if target is None:
            continue
        address = target.getFirstStartAddress()
        if not destination.getFlowType().isCall() and body.contains(address):
            successors[session.addresses.format(address)] = address
    ordered = sorted(successors.values(), key=address_order)
    return [session.addresses.format(address) for address in ordered]


def basic_block_values(session, function):
    return [
        {
            "start": session.addresses.format(block.getFirstStartAddress()),
            "end": _exclusive_address(session, block.getMaxAddress()),
            "successors": _block_successors(session, function, block),
        }
        for block in basic_blocks(session, function)
    ]


def _ordered_unique(entries):
    """Entries are (sort key, item); the last duplicate wins, as in a keyed map."""
    keyed = {}
    for key, item in entries:
        keyed[key] = item
    return [keyed[key] for key in sorted(keyed, key=utf16_order)]


def comments(session, function):
    from ghidra.program.model.listing import CommentType

    listing = session.program.getListing()
    entries = []
    for address in iterate(listing.getCommentAddressIterator(observation_scope(function), True)):
        session.monitor.checkCancelled()
        text_address = session.addresses.format(address)
        for comment_type in CommentType.values():
            text = listing.getComment(comment_type, address)
            if text is None or str(text) == "":
                continue
            kind = "inline" if comment_type == CommentType.EOL else "comment"
            key = "\0".join((text_address, kind, str(comment_type.name()), str(text)))
            entries.append((key, {"address": text_address, "kind": kind, "text": str(text)}))
    return _ordered_unique(entries)


def referenced_strings(session, references):
    from ghidra.program.model.data import StringDataInstance

    listing = session.program.getListing()
    entries = []
    for reference in references:
        data = listing.getDefinedDataContaining(reference.getToAddress())
        if data is None or not data.hasStringValue():
            continue
        value = StringDataInstance.getStringDataInstance(data).getStringValue()
        if value is None:
            continue
        address = session.addresses.format(data.getAddress())
        source = session.addresses.format(reference.getFromAddress())
        entries.append(
            (
                "\0".join((address, str(value), source)),
                {"address": address, "value": str(value), "source_address": source},
            )
        )
    return _ordered_unique(entries)


def referenced_names(session, references):
    table = session.program.getSymbolTable()
    entries = []
    for reference in references:
        symbol = table.getPrimarySymbol(reference.getToAddress())
        if symbol is None:
            continue
        address = session.addresses.format(reference.getToAddress())
        name = str(symbol.getName(True))
        source = session.addresses.format(reference.getFromAddress())
        entries.append(
            (
                "\0".join((address, name, source)),
                {"address": address, "value": name, "source_address": source},
            )
        )
    return _ordered_unique(entries)


def swift_program(session):
    return any(
        str(block.getName()).startswith(("__swift5_", "swift5_"))
        for block in session.program.getMemory().getBlocks()
    )
