"""MIPS o32 soft-float storage.

Ghidra's MIPS32 compiler specifications model only hard-float o32, so every typed float
prototype would read $f12/$f14/$f0. Derive a program-specific prototype model from the
default o32 model with its floating-point entries and rules removed, install it as a
specification extension, and assign it to every callable whose formal types use floats.
"""
import re
import sys
from xml.dom import minidom

from rea_session import iterate

REPORT_KEY = "REA MIPS soft-float storage"
POLICY = "o32-soft-float-prototype-v1"
PROTOTYPE = "__rea_soft_float"
_FPU_REGISTER = re.compile(r"f\d+(_\d+)?")


def _collect(nodes, attribute, value, ancestor, selected):
    """Select matching elements, or their nearest `ancestor` element when one is named."""
    for element in nodes:
        if element.getAttribute(attribute) != value:
            continue
        target = element
        while ancestor is not None and target is not None and target.nodeName != ancestor:
            target = target.parentNode
        if target is not None and target not in selected:
            selected.append(target)


def _soft_float_prototype(base, spec):
    from ghidra.program.model.pcode import XmlEncode

    encoder = XmlEncode()
    base.encode(encoder, spec.getPcodeInjectLibrary())
    encoded = str(encoder.toString())
    # Ghidra's own encoding of the Program's spec; refusing a DOCTYPE closes entity expansion.
    if "<!DOCTYPE" in encoded:
        raise ValueError("Unexpected default prototype encoding with a document type")
    root = minidom.parseString(encoded).documentElement
    if root.tagName != "prototype":
        raise ValueError(f"Unexpected default prototype encoding {root.tagName}")
    root.setAttribute("name", PROTOTYPE)
    removed = []
    _collect(root.getElementsByTagName("pentry"), "metatype", "float", None, removed)
    _collect(root.getElementsByTagName("consume"), "storage", "float", "rule", removed)
    if not removed:
        raise ValueError("Default prototype has no floating-point entries to remove")
    for node in removed:
        node.parentNode.removeChild(node)
    return root.toxml()


def _require_integer_storage(storages, owner):
    for storage in storages:
        if storage.isBadStorage() or storage.isUnassignedStorage():
            raise ValueError(f"REA soft-float storage unresolved for {owner}")
        registers = storage.getRegisters()
        if registers is None:
            continue
        for register in registers:
            if _FPU_REGISTER.fullmatch(str(register.getName())):
                raise ValueError(
                    f"REA soft-float storage still uses {register.getName()} for {owner}"
                )


def _is_float(data_type):
    from ghidra.program.model.data import AbstractFloatDataType, TypeDef

    current = data_type
    while isinstance(current, TypeDef):
        current = current.getBaseDataType()
    return isinstance(current, AbstractFloatDataType)


def _function_uses_float(function):
    return _is_float(function.getReturn().getFormalDataType()) or any(
        _is_float(parameter.getFormalDataType()) for parameter in function.getParameters()
    )


def _definition_uses_float(definition):
    return _is_float(definition.getReturnType()) or any(
        _is_float(argument.getDataType()) for argument in definition.getArguments()
    )


def _install_prototype(program, monitor):
    import jpype
    from ghidra.program.database import SpecExtension
    from ghidra.program.model.data import (
        DataType,
        DoubleDataType,
        FloatDataType,
        IntegerDataType,
    )

    spec = program.getCompilerSpec()
    prototype = _soft_float_prototype(spec.getDefaultCallingConvention(), spec)
    SpecExtension(program).addReplaceCompilerSpecExtension(prototype, monitor)
    soft = program.getCompilerSpec().getCallingConvention(PROTOTYPE)
    if soft is None:
        raise ValueError("REA soft-float prototype was not installed")
    probe = jpype.JArray(DataType)(
        [
            FloatDataType.dataType, IntegerDataType.dataType, DoubleDataType.dataType,
            FloatDataType.dataType, DoubleDataType.dataType,
        ]
    )
    _require_integer_storage(
        soft.getStorageLocations(program, probe, False), "soft-float prototype self-check"
    )


def _assign_functions(program):
    manager = program.getFunctionManager()
    callables = list(iterate(manager.getFunctions(True))) + list(
        iterate(manager.getExternalFunctions())
    )
    count = 0
    for function in callables:
        # A thunk's signature is its target's; the target is in this list.
        if function.isThunk() or not _function_uses_float(function):
            continue
        if function.hasCustomVariableStorage():
            function.setCustomVariableStorage(False)
        function.setCallingConvention(PROTOTYPE)
        storages = [function.getReturn().getVariableStorage()]
        storages += [parameter.getVariableStorage() for parameter in function.getParameters()]
        _require_integer_storage(storages, str(function.getName(True)))
        count += 1
    return count


def _assign_definitions(program):
    from ghidra.program.model.data import FunctionDefinition

    count = 0
    for data_type in iterate(program.getDataTypeManager().getAllDataTypes()):
        if isinstance(data_type, FunctionDefinition) and _definition_uses_float(data_type):
            data_type.setCallingConvention(PROTOTYPE)
            count += 1
    return count


def apply_soft_float(program, monitor):
    import pyghidra
    from ghidra.program.model.listing import Program

    processor = str(program.getLanguage().getProcessor())
    if processor != "MIPS" or program.getDefaultPointerSize() != 4:
        raise ValueError(f"REA soft-float storage requires a 32-bit MIPS program, not {processor}")
    with pyghidra.transaction(program, "REA MIPS soft-float storage"):
        _install_prototype(program, monitor)
        functions = _assign_functions(program)
        definitions = _assign_definitions(program)
        # Written last: any failure above leaves no report, and REA refuses the session.
        program.getOptions(Program.PROGRAM_INFO).setString(
            REPORT_KEY,
            f'{{"policy":"{POLICY}","functions":{functions},"definitions":{definitions}}}',
        )
    print(
        f"REA MIPS soft-float prototype: functions={functions} definitions={definitions}",
        file=sys.stderr,
    )
