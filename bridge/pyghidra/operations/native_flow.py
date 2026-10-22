"""Decompiler-derived dossier facets: the native API boundary and high p-code value flow."""
from rea_session import iterate

MAX_HIGH_PCODE_OPS = 3000
MAX_HIGH_PCODE_INPUTS_PER_OP = 64
MAX_HIGH_PCODE_DEF_USE_EDGES = 12000
UNSIGNED_64 = 0xFFFFFFFFFFFFFFFF

BOUNDARY_LIMITATIONS = [
    "Types and calling conventions are Ghidra decompiler observations, not source declarations.",
    "Register variables, compiler-generated blocks, and pointer arithmetic remain decompiler artifacts.",
    "Pseudocode is neither original source nor guaranteed to compile.",
]
VALUE_FLOW_LIMITATIONS = [
    "High p-code is decompiler-derived, not original source or runtime behavior. is_dead preserves "
    "the Java AST flag; decoded block members can retain that flag, so block_membership separately "
    "reports actual syntax-tree membership.",
    "Def-use links do not cross function boundaries and may omit memory aliasing, call side "
    "effects, or unresolved indirect flow.",
    "Memory read/write effects include stack and temporary memory operations; they do not identify "
    "persistent state or business meaning.",
    "Operation, input, and def-use limits can truncate large functions; inspect truncation, omitted "
    "lower bounds, and known omitted counts before drawing conclusions.",
    "Known omitted-edge counts cover links omitted from retained operations; omitted operations may "
    "contain additional uncounted links.",
]
JUMP_TABLE_UNAVAILABLE_REASON = (
    "The pyGhidra backend does not yet recover jump-table case mappings, and this procedure's "
    "decompilation contains a jump table; use the Java backend for its native API boundary"
)


def unavailable_native_value_flow(reason):
    return {
        "available": False,
        "reason": reason,
        "limitations": [
            "No p-code operations or def-use relationships were recovered for this procedure."
        ],
    }


def unavailable_native_api_boundary(reason):
    return {
        "available": False,
        "reason": reason,
        "residual_unknowns": [
            "Return and parameter boundary types are unavailable.",
            "Jump-table mappings are unavailable.",
        ],
    }


def _evidence(kind, source, detail):
    return {"kind": kind, "source": source, "detail": detail}


def _inference_confidence(signature_source, type_locked):
    if type_locked or signature_source in ("user_defined", "imported"):
        return "high"
    return "medium" if signature_source == "analysis" else "low"


def _boundary_type(role, ordinal, name, data_type, storage, type_locked, signature_source):
    display = str(data_type.getDisplayName())
    length = int(data_type.getLength())
    evidence = [
        _evidence(
            "signature-source",
            "ghidra-function-manager",
            f"Function signature source is {signature_source}.",
        ),
        _evidence(
            "decompiler-type",
            "ghidra-high-function",
            f"HighFunction recovered data type {display}.",
        ),
    ]
    if type_locked:
        evidence.append(
            _evidence(
                "type-lock",
                "ghidra-high-symbol",
                "The decompiler marks this parameter type as locked.",
            )
        )
    artifacts = ["recovered-signature"]
    if storage.strip():
        artifacts.append("register-or-stack-storage")
    if name is not None and name.startswith(("param_", "unaff_")):
        artifacts.append("compiler-generated-variable")
    return {
        "role": role,
        "ordinal": ordinal,
        "name": name if name is not None and name.strip() else None,
        "data_type": display,
        "size_bytes": None if length < 0 else length,
        "storage": None if not storage.strip() else storage,
        "confidence": _inference_confidence(signature_source, type_locked),
        "evidence": evidence,
        "decompiler_artifacts": artifacts,
    }


def _boundary_parameters(prototype, signature_source):
    parameters = []
    for index in range(prototype.getNumParams()):
        parameter = prototype.getParam(index)
        if parameter is None:
            continue
        parameters.append(
            _boundary_type(
                "parameter",
                index,
                str(parameter.getName()),
                parameter.getDataType(),
                str(parameter.getStorage().toString()),
                bool(parameter.isTypeLocked()),
                signature_source,
            )
        )
    return parameters


def native_api_boundary(function, decompilation):
    high = None if decompilation is None else decompilation.getHighFunction()
    if high is None:
        return unavailable_native_api_boundary(
            "Ghidra has no HighFunction model for an external or bodyless procedure"
        )
    jump_tables = high.getJumpTables()
    if jump_tables is not None and len(jump_tables) > 0:
        return unavailable_native_api_boundary(JUMP_TABLE_UNAVAILABLE_REASON)
    prototype = high.getFunctionPrototype()
    signature_source = str(function.getSignatureSource().name()).lower()
    model = prototype.getModelName()
    return {
        "available": True,
        "provenance": "ghidra-high-function",
        "signature_source": signature_source,
        "calling_convention": "unknown" if model is None or not str(model).strip() else str(model),
        "return_type": _boundary_type(
            "return",
            None,
            None,
            prototype.getReturnType(),
            str(prototype.getReturnStorage().toString()),
            False,
            signature_source,
        ),
        "parameters": _boundary_parameters(prototype, signature_source),
        "jump_tables": [],
        "pseudocode": {"classification": "decompiler-generated-non-source", "compilable": False},
        "decompiler_artifacts": [
            "recovered-signature",
            "register-and-stack-variables",
            "compiler-generated-control-flow",
            "pointer-arithmetic",
            "pseudocode",
        ],
        "limitations": list(BOUNDARY_LIMITATIONS),
    }


def _varnode_value(session, varnode):
    if varnode.isConstant():
        kind = "constant"
    elif varnode.isAddress():
        kind = "address"
    elif varnode.isRegister():
        kind = "register"
    else:
        kind = "unique" if varnode.isUnique() else "other"
    constant = bool(varnode.isConstant())
    return {
        "kind": kind,
        "size_bytes": int(varnode.getSize()),
        "location": None if constant else session.addresses.format(varnode.getAddress()),
        "constant_hex": f"{int(varnode.getOffset()) & UNSIGNED_64:x}" if constant else None,
    }


def _effect_shape(opcode):
    from ghidra.program.model.pcode import PcodeOp

    shapes = {
        PcodeOp.LOAD: ("memory_read", 1, None),
        PcodeOp.STORE: ("memory_write", 1, 2),
        PcodeOp.CBRANCH: ("conditional_branch", None, 1),
        PcodeOp.BRANCHIND: ("indirect_branch", 0, None),
        PcodeOp.CALL: ("direct_call", 0, None),
        PcodeOp.CALLIND: ("indirect_call", 0, None),
    }
    return shapes.get(int(opcode))


def _operation_id(session, operation):
    seqnum = operation.getSeqnum()
    return f"{session.addresses.format(seqnum.getTarget())}#{int(seqnum.getTime())}"


def _selected_operations(session, high):
    selected, omitted_lower_bound = [], 0
    for operation in iterate(high.getPcodeOps()):
        session.monitor.checkCancelled()
        if len(selected) >= MAX_HIGH_PCODE_OPS:
            omitted_lower_bound = 1
            break
        selected.append(operation)
    return selected, omitted_lower_bound


def _parameter_values(prototype):
    values = []
    for ordinal in range(prototype.getNumParams()):
        parameter = prototype.getParam(ordinal)
        if parameter is None:
            continue
        values.append(
            {
                "ordinal": ordinal,
                "name": str(parameter.getName()),
                "data_type": str(parameter.getDataType().getPathName()),
            }
        )
    return values


class _FlowAccumulator:
    def __init__(self, session, operation_ids):
        self.session = session
        self.operation_ids = operation_ids
        self.def_use = []
        self.parameter_uses = []
        self.omitted_inputs = 0
        self.omitted_edges = 0

    def _link_parameter(self, ast_input, operation_id, input_index):
        from ghidra.program.model.pcode import HighParam

        high_variable = ast_input.getHigh()
        if not isinstance(high_variable, HighParam):
            return
        if len(self.parameter_uses) >= MAX_HIGH_PCODE_DEF_USE_EDGES:
            self.omitted_edges += 1
            return
        self.parameter_uses.append(
            {"ordinal": int(high_variable.getSlot()), "use": operation_id, "input_index": input_index}
        )

    def _link_definition(self, ast_input, operation_id, input_index):
        from ghidra.program.model.pcode import PcodeOpAST

        definition = ast_input.getDef()
        if not isinstance(definition, PcodeOpAST):
            return
        definition_id = self.operation_ids.get(definition)
        if definition_id is None or len(self.def_use) >= MAX_HIGH_PCODE_DEF_USE_EDGES:
            self.omitted_edges += 1
            return
        self.def_use.append(
            {"definition": definition_id, "use": operation_id, "input_index": input_index}
        )

    def inputs(self, operation, operation_id):
        from ghidra.program.model.pcode import VarnodeAST

        count = int(operation.getNumInputs())
        captured = min(count, MAX_HIGH_PCODE_INPUTS_PER_OP)
        values = []
        for index in range(captured):
            varnode = operation.getInput(index)
            values.append(_varnode_value(self.session, varnode))
            if isinstance(varnode, VarnodeAST):
                self._link_parameter(varnode, operation_id, index)
                self._link_definition(varnode, operation_id, index)
        self.omitted_inputs += count - captured
        return values


def native_value_flow(session, decompilation):
    high = None if decompilation is None else decompilation.getHighFunction()
    if high is None:
        return unavailable_native_value_flow(
            "Ghidra has no HighFunction p-code model for this procedure"
        )
    selected, omitted_lower_bound = _selected_operations(session, high)
    operation_ids = {operation: _operation_id(session, operation) for operation in selected}
    flow = _FlowAccumulator(session, operation_ids)
    operations, effects = [], []
    for operation in selected:
        session.monitor.checkCancelled()
        operation_id = operation_ids[operation]
        seqnum = operation.getSeqnum()
        output = operation.getOutput()
        operations.append(
            {
                "id": operation_id,
                "address": session.addresses.format(seqnum.getTarget()),
                "sequence": int(seqnum.getTime()),
                "opcode": str(operation.getMnemonic()),
                "is_dead": bool(operation.isDead()),
                "block_membership": "detached" if operation.getParent() is None else "member",
                "inputs": flow.inputs(operation, operation_id),
                "output": None if output is None else _varnode_value(session, output),
            }
        )
        shape = _effect_shape(operation.getOpcode())
        if shape is not None:
            kind, operand_input, value_input = shape
            effects.append(
                {
                    "operation": operation_id,
                    "kind": kind,
                    "operand_input": operand_input,
                    "value_input": value_input,
                }
            )
    return {
        "available": True,
        "provenance": "ghidra-high-pcode",
        "operations": operations,
        "def_use": flow.def_use,
        "parameters": _parameter_values(high.getFunctionPrototype()),
        "parameter_uses": flow.parameter_uses,
        "effects": effects,
        "truncated": omitted_lower_bound > 0 or flow.omitted_inputs > 0 or flow.omitted_edges > 0,
        "omitted_operations_lower_bound": omitted_lower_bound,
        "known_omitted_inputs": flow.omitted_inputs,
        "known_omitted_edges": flow.omitted_edges,
        "limitations": list(VALUE_FLOW_LIMITATIONS),
    }
