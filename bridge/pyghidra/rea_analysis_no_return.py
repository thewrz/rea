"""Undo wrong no-return flags left by auto-analysis.

A function flagged no-return that contains a real RET is an ordinary function, and known
returning libc/TLS imports have no body to inspect, so their flags clear by exact external
ABI name. Callers that treated the call as a terminator are re-disassembled and refit.
"""
import sys
from collections import deque

from rea_session import address_order, iterate

RETURNING_IMPORTS = frozenset(
    {"malloc", "__tls_get_addr", "memcpy", "memset", "strlen", "__errno_location"}
)


def _external_abi_name(program, function):
    name = str(function.getName())
    # Mach-O stores C-linkage symbols with one object-format underscore prefix.
    if "Mach-O" in str(program.getExecutableFormat()) and name.startswith("_"):
        return name[1:]
    return name


def _clear_decoded_return(function, listing):
    from ghidra.program.model.pcode import PcodeOp

    if not function.hasNoReturn() or function.isThunk():
        return False
    for instruction in iterate(listing.getInstructions(function.getBody(), True)):
        flow = instruction.getFlowType()
        if flow.isJump() or flow.isCall():
            continue
        if any(op.getOpcode() == PcodeOp.RETURN for op in instruction.getPcode()):
            function.setNoReturn(False)
            return True
    return False


class _Repair:
    def __init__(self, program, monitor):
        from ghidra.program.flatapi import FlatProgramAPI

        self.program = program
        self.monitor = monitor
        self.flat = FlatProgramAPI(program, monitor)
        self.manager = program.getFunctionManager()
        self.listing = program.getListing()
        self.cleared = set()
        self.pending = deque()
        self.redone = 0
        self.owners = set()

    def enqueue_returning(self, function):
        entries = [function.getEntryPoint()]
        # A thunk inherits the flag of the function it forwards to, including through other thunks.
        thunks = function.getFunctionThunkAddresses(True)
        entries += [] if thunks is None else list(thunks)
        for entry in entries:
            if entry not in self.cleared:
                self.cleared.add(entry)
                self.pending.append(entry)

    def clear_flags(self):
        for function in iterate(self.manager.getExternalFunctions()):
            # Import-name assumptions never apply to local functions or arbitrary externals.
            name = _external_abi_name(self.program, function)
            if function.hasNoReturn() and name in RETURNING_IMPORTS:
                function.setNoReturn(False)
                self.enqueue_returning(function)
        for function in iterate(self.manager.getFunctions(True)):
            if _clear_decoded_return(function, self.listing):
                self.enqueue_returning(function)

    def _call_sites(self, target):
        # Collect before redisassembly mutates the reference table.
        references = self.program.getReferenceManager().getReferencesTo(target)
        sites = {reference.getFromAddress() for reference in iterate(references)}
        return sorted(sites, key=address_order)

    def _repair_site(self, site, target):
        from ghidra.app.cmd.function import CreateFunctionCmd

        instruction = self.listing.getInstructionAt(site)
        if instruction is None:
            return
        flow = instruction.getFlowType()
        if not (flow.isCall() and flow.isTerminal()):
            return
        if not any(destination.equals(target) for destination in instruction.getFlows()):
            return
        following = instruction.getMaxAddress().add(1)
        # Never redisassemble into an independently identified function.
        if self.manager.getFunctionAt(following) is not None:
            return
        if not self.program.getMemory().contains(following):
            return
        owner = self.manager.getFunctionContaining(site)
        usable = owner is not None and not owner.isThunk()
        if usable:
            self.owners.add(owner.getEntryPoint())
        self.flat.clearListing(instruction.getMinAddress(), instruction.getMaxAddress())
        self.flat.disassemble(site)
        self.redone += 1
        if usable:
            # Refit in place so the name, signature and calling convention survive.
            CreateFunctionCmd.fixupFunctionBody(self.program, owner, self.monitor)
            # The truncated caller's RET is visible only now; repair its callers too.
            if _clear_decoded_return(owner, self.listing):
                self.enqueue_returning(owner)

    def run(self):
        self.clear_flags()
        while self.pending:
            target = self.pending.popleft()
            for site in self._call_sites(target):
                self._repair_site(site, target)
        print(
            f"REA no-return fix: cleared={len(self.cleared)} sites={self.redone} "
            f"refit={len(self.owners)}",
            file=sys.stderr,
        )


def fix_no_return(program, monitor):
    import pyghidra

    with pyghidra.transaction(program, "REA no-return fix"):
        _Repair(program, monitor).run()
