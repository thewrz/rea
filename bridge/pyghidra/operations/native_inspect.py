"""Instruction, data-type and cross-reference inspection (answers are raw values, not envelopes)."""
from rea_protocol import RequestFailure, optional_string, require_keys, require_string
from rea_session import address_order, utf16_order

from operations.inventory import require_document
from operations.references import distinct_references, reference_kind, references_to

MAX_TYPE_FIELDS = 20_000
INSTRUCTION_REFERENCE_FIELDS = (
    "type", "call", "jump", "indirect", "computed", "operand_index", "data", "read", "write",
    "primary", "provenance",
)
INSTRUCTION_LIMITATION = (
    "Operand components are Ghidra Listing decoder tokens; effective memory base/index/"
    "displacement roles and per-instruction context mode are unavailable. The mode field is the "
    "program language variant."
)
TERMINAL_LIMITATION = (
    "No RETURN operation was observed in the provider's instruction p-code; terminal "
    "classification remains generic."
)
CALL_TARGET_LIMITATIONS = [
    "Targets are static Ghidra ReferenceManager call-reference observations. Computed calls "
    "without call references remain unresolved; a resolved reference is not proof of runtime "
    "execution.",
    "Objective-C, Swift, vtable and closure mechanisms are not identified by this reference-only "
    "boundary.",
]
TYPE_LIMITATIONS = [
    "Layouts are Ghidra data-type database observations; original debug/source authority and "
    "flexible-tail semantics are not inferred. Nested and recursive types retain category-path "
    "identities for separate inspection.",
    "At most 20000 fields or enum members are serialized per type to bound provider output. "
    "total_fields and truncated report omissions. Enum values preserve Ghidra's signed long "
    "representation.",
]
UNAVAILABLE_TYPE_REASON = "No exact database type or defined typed data exists at the selected identity"


def _instruction_reference(session, reference):
    kind = reference_kind(reference)
    item = {
        "source_address": session.addresses.format(reference.getFromAddress()),
        "target_address": session.addresses.format(reference.getToAddress()),
    }
    item.update({field: kind[field] for field in INSTRUCTION_REFERENCE_FIELDS})
    item["source"] = str(reference.getSource().name()).lower()
    return item


def _decoder_context(session, address):
    register = session.program.getRegister("ISA_MODE")
    if register is None:
        return []
    value = session.program.getProgramContext().getValue(register, address, False)
    return [
        {
            "register": str(register.getName()),
            "value": None if value is None else str(value),
            "source": "ghidra-program-context",
        }
    ]


def _operand_component(session, item):
    from ghidra.program.model.address import Address
    from ghidra.program.model.lang import Register
    from ghidra.program.model.scalar import Scalar

    component = {"text": str(item.toString()), "value": None, "bit_width": None}
    if isinstance(item, Register):
        component.update(kind="register", value=str(item.getName()), bit_width=int(item.getBitLength()))
    elif isinstance(item, Scalar):
        unsigned = int(item.getUnsignedValue()) & 0xFFFFFFFFFFFFFFFF
        component.update(kind="immediate", value=f"0x{unsigned:x}", bit_width=int(item.bitLength()))
    elif isinstance(item, Address):
        component.update(kind="address", value=session.addresses.format(item))
    else:
        component["kind"] = "unknown"
    return component


def _operands(session, instruction):
    return [
        {
            "index": index,
            "raw": str(instruction.getDefaultOperandRepresentation(index)),
            "provider_type": int(instruction.getOperandType(index)),
            "memory_addressing": "unavailable",
            "components": [
                _operand_component(session, item) for item in instruction.getOpObjects(index)
            ],
        }
        for index in range(instruction.getNumOperands())
    ]


def _undecoded_status(session, address):
    listing = session.program.getListing()
    if not session.program.getMemory().contains(address):
        return "outside-memory"
    if listing.getInstructionContaining(address) is not None:
        return "not-instruction-boundary"
    return "data" if listing.getDefinedDataContaining(address) is not None else "undecodable"


def _flow_kind(flow_type, decoded_return):
    if flow_type.isCall():
        return "call"
    if flow_type.isJump():
        return "jump"
    if decoded_return:
        return "return"
    return "terminal" if flow_type.isTerminal() else "fallthrough"


def _decoded_instruction(session, instruction, result, flow):
    from ghidra.program.model.pcode import PcodeOp

    flow_type = instruction.getFlowType()
    evidence = [{"source": "ghidra-listing-flow-type", "value": str(flow_type.getName())}]
    decoded_return = False
    for operation in instruction.getPcode():
        if operation.getOpcode() == PcodeOp.RETURN:
            decoded_return = True
            evidence.append(
                {"source": "ghidra-instruction-pcode", "value": str(operation.getMnemonic())}
            )
    result.update(
        status="decoded",
        bytes=bytes(value & 0xFF for value in instruction.getBytes()).hex(),
        length=int(instruction.getLength()),
        mnemonic=str(instruction.getMnemonicString()),
        raw_disassembly=str(instruction.toString()),
    )
    flow.update(
        kind=_flow_kind(flow_type, decoded_return),
        conditional=bool(flow_type.isConditional()),
        computed=bool(flow_type.isComputed()),
        classification_evidence=evidence,
    )
    if not flow_type.isComputed():
        flow["direct_destinations"] = [
            session.addresses.format(target) for target in instruction.getFlows()
        ]
    result["references"] = [
        _instruction_reference(session, reference) for reference in instruction.getReferencesFrom()
    ]
    result["operands"] = _operands(session, instruction)


def inspect_instruction(session, params, include_incoming):
    require_keys(params, {"document", "address"})
    require_document(session, params)
    address = session.addresses.parse(require_string(params, "address"))
    instruction = session.program.getListing().getInstructionAt(address)
    function = session.program.getFunctionManager().getFunctionContaining(address)
    language_id = str(session.program.getLanguageID().getIdAsString())
    result = {
        "address": session.addresses.format(address),
        "procedure": None
        if function is None
        else session.addresses.format(function.getEntryPoint()),
        "architecture": language_id,
        "mode": str(session.program.getLanguage().getLanguageDescription().getVariant()),
    }
    if language_id.startswith("MIPS:"):
        result["decoder_context"] = _decoder_context(session, address)
    flow = {
        "kind": "unavailable",
        "conditional": False,
        "computed": False,
        "direct_destinations": [],
        "classification_evidence": [],
    }
    result.update(references=[], operands=[])
    if instruction is None:
        result["status"] = _undecoded_status(session, address)
        result.update(bytes=None, length=None, mnemonic=None, raw_disassembly=None)
    else:
        _decoded_instruction(session, instruction, result, flow)
    result["flow"] = flow
    if include_incoming:
        incoming = distinct_references(session, references_to(session, address))
        result["incoming_references"] = [
            _instruction_reference(session, reference) for reference in incoming
        ]
    limitations = [INSTRUCTION_LIMITATION]
    if flow["kind"] == "terminal":
        limitations.append(TERMINAL_LIMITATION)
    result["limitations"] = limitations
    return result


def inspect_native_instruction(session, params):
    return inspect_instruction(session, params, True)


def _call_targets(instruction):
    by_target = {}
    if instruction["flow"]["kind"] == "call":
        for reference in instruction["references"]:
            if reference["call"]:
                by_target.setdefault(reference["target_address"], []).append(reference)
    return by_target


def _call_target(session, target_address, references, status):
    address = session.addresses.try_parse(target_address)
    function = None if address is None else session.program.getFunctionManager().getFunctionAt(address)
    return {
        "address": target_address,
        "procedure": None if function is None else session.addresses.format(function.getEntryPoint()),
        "status": status,
        "basis": "provider-reference",
        "references": references,
    }


def _call_status(decoded, call, ambiguous, targets, computed):
    if not decoded:
        return "unavailable"
    if not call:
        return "not-call"
    if ambiguous:
        return "ambiguous"
    if not targets:
        return "unresolved"
    return "resolved-indirect" if computed else "direct"


def resolve_native_call_targets(session, params):
    instruction = inspect_instruction(session, params, False)
    flow = instruction["flow"]
    decoded = instruction["status"] == "decoded"
    call = flow["kind"] == "call"
    computed = flow["computed"]
    by_target = _call_targets(instruction)
    ambiguous = len(by_target) > 1
    target_status = "candidate" if ambiguous else "resolved-indirect" if computed else "direct"
    targets = [
        _call_target(session, key, by_target[key], target_status)
        for key in sorted(by_target, key=utf16_order)
    ]
    return {
        "call_site": instruction["address"],
        "procedure": instruction["procedure"],
        "targets": targets,
        "status": _call_status(decoded, call, ambiguous, targets, computed),
        "mechanism": "unavailable" if not call else "computed" if computed else "direct",
        "limitations": list(CALL_TARGET_LIMITATIONS),
    }


def xrefs(session, params):
    require_keys(params, {"document", "address"})
    require_document(session, params)
    address = session.addresses.parse(require_string(params, "address"))
    sources = {
        session.addresses.format(reference.getFromAddress()): reference.getFromAddress()
        for reference in references_to(session, address)
    }
    return [session.addresses.format(source) for source in sorted(sources.values(), key=address_order)]


def _type_kind(data_type):
    from ghidra.program.model.data import Array as GhidraArray
    from ghidra.program.model.data import BuiltInDataType, Pointer, Structure, TypeDef, Union
    from ghidra.program.model.data import Enum as GhidraEnum

    for kind, candidate in (
        ("struct", Structure), ("union", Union), ("enum", GhidraEnum), ("pointer", Pointer),
        ("array", GhidraArray), ("typedef", TypeDef), ("scalar", BuiltInDataType),
    ):
        if isinstance(data_type, candidate):
            return kind
    return "unsupported"


def _composite_fields(session, composite):
    from ghidra.program.model.data import BitFieldDataType

    components = list(composite.getComponents())
    fields = []
    for component in components[:MAX_TYPE_FIELDS]:
        session.monitor.checkCancelled()
        name = component.getFieldName()
        length = int(component.getLength())
        field = {
            "ordinal": int(component.getOrdinal()),
            "name": None if name is None else str(name),
            "offset_bytes": int(component.getOffset()),
            "size_bytes": None if length < 0 else length,
            "type_id": str(component.getDataType().getPathName()),
            "bit_size": None,
            "bit_offset": None,
        }
        if isinstance(component.getDataType(), BitFieldDataType):
            field["bit_size"] = int(component.getDataType().getBitSize())
            field["bit_offset"] = int(component.getDataType().getBitOffset())
        field.update(status="observed", flexible_tail="unknown")
        fields.append(field)
    return fields, len(components)


def _enum_members(session, enumeration):
    names = sorted((str(name) for name in enumeration.getNames()), key=utf16_order)
    members = []
    for name in names[:MAX_TYPE_FIELDS]:
        session.monitor.checkCancelled()
        members.append({"name": name, "value": str(int(enumeration.getValue(name)))})
    return members, len(names)


def _describe_type(session, data_type, result):
    """Fill the type-specific facts; returns (fields, members, total_fields)."""
    from ghidra.program.model.data import Array as GhidraArray
    from ghidra.program.model.data import Composite, Pointer, TypeDef
    from ghidra.program.model.data import Enum as GhidraEnum

    result.update(id=str(data_type.getPathName()), name=str(data_type.getName()))
    archive = data_type.getSourceArchive()
    if archive is not None:
        result["source_archive"] = str(archive.getName())
    if data_type.getLength() >= 0:
        result["size_bytes"] = int(data_type.getLength())
    if data_type.getAlignment() > 0:
        result["alignment_bytes"] = int(data_type.getAlignment())
    result["kind"] = _type_kind(data_type)
    fields, members, total = [], [], 0
    if isinstance(data_type, Composite):
        result["packing_enabled"] = bool(data_type.isPackingEnabled())
        fields, total = _composite_fields(session, data_type)
    elif isinstance(data_type, GhidraEnum):
        members, total = _enum_members(session, data_type)
    elif isinstance(data_type, Pointer):
        if data_type.getDataType() is not None:
            result["referenced_type"] = str(data_type.getDataType().getPathName())
    elif isinstance(data_type, GhidraArray):
        result.update(
            referenced_type=str(data_type.getDataType().getPathName()),
            array_count=int(data_type.getNumElements()),
            array_stride_bytes=int(data_type.getElementLength()),
        )
    elif isinstance(data_type, TypeDef):
        result["referenced_type"] = str(data_type.getDataType().getPathName())
    return fields, members, total


def inspect_native_data_type(session, params):
    require_keys(params, {"document", "type", "address"})
    require_document(session, params)
    type_text = optional_string(params, "type")
    address_text = optional_string(params, "address")
    if (type_text is None) == (address_text is None):
        raise RequestFailure("invalid_request", "Supply exactly one of type or address")
    address = None
    if type_text is not None:
        data_type = session.program.getDataTypeManager().getDataType(type_text)
    else:
        address = session.addresses.parse(address_text)
        data = session.program.getListing().getDefinedDataAt(address)
        data_type = None if data is None else data.getDataType()
    result = {
        "status": "unavailable" if data_type is None else "available",
        "reason": UNAVAILABLE_TYPE_REASON if data_type is None else None,
        "address": None if address is None else session.addresses.format(address),
        "source": "analysis-database",
        "kind": "unavailable",
    }
    result.update(
        {
            key: None
            for key in (
                "id", "name", "source_archive", "size_bytes", "alignment_bytes", "packing_enabled",
                "referenced_type", "array_count", "array_stride_bytes",
            )
        }
    )
    fields, members, total = [], [], 0
    if data_type is not None:
        fields, members, total = _describe_type(session, data_type, result)
    result.update(
        fields=fields,
        members=members,
        total_fields=total,
        truncated=total > MAX_TYPE_FIELDS,
        limitations=list(TYPE_LIMITATIONS),
    )
    if data_type is not None:
        metadata = session.extensions.inspect_data_type(
            session.program, data_type, address, session.monitor
        )
        if metadata is not None:
            result["metadata_recovery"] = metadata
    return result
