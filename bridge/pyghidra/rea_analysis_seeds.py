"""Apply caller-declared analysis seeds before default auto-analysis.

The snapshot holds one line per seed: 0x<hex>, a tab, function|code|label, and an optional
tab and name. Functions apply first, then code, then labels; the outcome is stored as a
Program Information option that the handshake reports.
"""
import hashlib
import json
import os
import stat
import sys

from rea_addresses import is_hexadecimal

REPORT_OPTION = "REA analysis seeds"
FORMAT = "rea-ghidra-seeds-v1"
_PASSES = ("function", "code", "label")
_MAX_ADDRESS = 1 << 64


def _read_snapshot(path):
    status = os.lstat(path)
    if not stat.S_ISREG(status.st_mode):
        raise ValueError("REA seed file is not a regular file")
    with open(path, "rb") as handle:
        return handle.read()


def _parse(data, space):
    from ghidra.program.model.address import AddressOutOfBoundsException

    seeds = []
    for line in data.decode("utf-8").split("\n"):
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) not in (2, 3) or not fields[0].startswith("0x"):
            raise ValueError("REA seed snapshot is malformed")
        digits = fields[0][2:]
        offset = int(digits, 16) if is_hexadecimal(digits) else _MAX_ADDRESS
        if offset >= _MAX_ADDRESS:
            raise ValueError("REA seed snapshot is malformed")
        signed = offset - _MAX_ADDRESS if offset >= _MAX_ADDRESS // 2 else offset
        try:
            address = space.getAddress(signed)
        except AddressOutOfBoundsException:
            address = None
        seeds.append((address, fields[1], fields[2] if len(fields) == 3 else None))
    # Highest address first: a body computed before analysis stops at an existing entry.
    mapped = sorted(
        (seed for seed in seeds if seed[0] is not None),
        key=lambda seed: int(seed[0].getOffset()) & (_MAX_ADDRESS - 1),
        reverse=True,
    )
    return mapped + [seed for seed in seeds if seed[0] is None]


class _Applier:
    def __init__(self, program, monitor):
        from ghidra.program.flatapi import FlatProgramAPI

        self.program = program
        self.flat = FlatProgramAPI(program, monitor)
        self.counts = dict.fromkeys(
            (
                "function_created", "function_existing", "function_failed",
                "code_decoded", "code_failed", "label_applied", "label_failed", "unmapped",
            ),
            0,
        )
        self.logged = 0

    def _log(self, message):
        if self.logged < 20:
            print(f"REA seed failed: {message}", file=sys.stderr)
        self.logged += 1

    def _decoded(self, address):
        flat = self.flat
        if flat.getInstructionAt(address) is not None:
            return True
        if flat.getDataAt(address) is not None or flat.getInstructionContaining(address) is not None:
            return False
        flat.disassemble(address)
        return flat.getInstructionAt(address) is not None

    def _function(self, address, name):
        from ghidra.program.model.symbol import SourceType

        existing = self.flat.getFunctionAt(address)
        if existing is not None:
            self.counts["function_existing"] += 1
            if name is not None:
                existing.setName(name, SourceType.USER_DEFINED)
        elif self._decoded(address) and self.flat.createFunction(address, name) is not None:
            self.counts["function_created"] += 1
        else:
            self.counts["function_failed"] += 1
            self._log(f"function {address}")

    def _code(self, address):
        if self._decoded(address):
            self.counts["code_decoded"] += 1
        else:
            self.counts["code_failed"] += 1
            self._log(f"code {address}")

    def _label(self, address, name):
        from ghidra.program.model.symbol import SourceType

        try:
            self.flat.createLabel(address, name, True, SourceType.USER_DEFINED)
            self.counts["label_applied"] += 1
        except Exception:
            self.counts["label_failed"] += 1

    def apply(self, seeds):
        memory = self.program.getMemory()
        for current in _PASSES:
            for address, kind, name in seeds:
                if kind != current:
                    continue
                block = None if address is None else memory.getBlock(address)
                if block is None or (current != "label" and not block.isInitialized()):
                    self.counts["unmapped"] += 1
                elif current == "function":
                    self._function(address, name)
                elif current == "code":
                    self._code(address)
                else:
                    self._label(address, name)


def apply_seeds(program, monitor, seed_path):
    import pyghidra
    from ghidra.program.model.listing import Program

    data = _read_snapshot(seed_path)
    seeds = _parse(data, program.getAddressFactory().getDefaultAddressSpace())
    applier = _Applier(program, monitor)
    with pyghidra.transaction(program, "REA analysis seeds"):
        applier.apply(seeds)
    report = {
        "format": FORMAT,
        "sha256": hashlib.sha256(data).hexdigest(),
        "entries": len(seeds),
        **applier.counts,
    }
    with pyghidra.transaction(program, "REA analysis seeds report"):
        program.getOptions(Program.PROGRAM_INFO).setString(
            REPORT_OPTION, json.dumps(report, separators=(",", ":"))
        )
    print(f"REA seeds applied: {report}", file=sys.stderr)
