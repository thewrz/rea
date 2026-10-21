"""Memory-facing operations: byte reads and searches, file offsets and load-image facts."""
import hashlib
import hmac
import json
import re

from rea_protocol import (
    MAX_SAFE_INTEGER,
    RequestFailure,
    optional_string,
    require_bounded_integer,
    require_keys,
    require_string,
)
from rea_session import address_order, iterate

from operations.inventory import ordered_blocks, require_document

CHUNK_BYTES = 65536
# Java's [\s\p{Z}﻿]: ASCII whitespace plus the Unicode separator categories.
_PATTERN_SPACE = re.compile(
    "[ \t\n\x0b\f\r   -     　﻿]"
)
_HEX_PAIR = re.compile(r"[0-9a-fA-F]{2}")


def _byte_buffer(size_or_data):
    import jpype

    return jpype.JArray(jpype.JByte)(size_or_data)


def _hash_chunks(read, length):
    digest = hashlib.sha256()
    buffer = _byte_buffer(CHUNK_BYTES)
    offset = 0
    while offset < length:
        count = min(CHUNK_BYTES, length - offset)
        read_count = int(read(offset, buffer, count))
        if read_count != count:
            raise OSError(f"Incomplete read at {offset}")
        digest.update(bytes(buffer[:read_count]))
        offset += read_count
    return digest.hexdigest()


def hash_file_bytes(file_bytes, modified):
    read = file_bytes.getModifiedBytes if modified else file_bytes.getOriginalBytes
    return _hash_chunks(lambda offset, buffer, count: read(offset, buffer, 0, count), int(file_bytes.getSize()))


def hash_memory(session, start, length):
    memory = session.program.getMemory()
    return _hash_chunks(
        lambda offset, buffer, count: memory.getBytes(start.add(offset), buffer, 0, count),
        length,
    )


def _is_target_source(session, file_bytes):
    """Only an unshifted copy of the admitted target can establish original file offsets."""
    for known, matched in session.target_sources:
        if known == file_bytes:
            return matched
    matched = int(file_bytes.getFileOffset()) == 0 and hmac.compare_digest(
        hash_file_bytes(file_bytes, False), session.target_sha256
    )
    session.target_sources.append((file_bytes, matched))
    return matched


def target_file_offset(session, block, address):
    """Return (offset or None, authoritative mapping count) for one block address."""
    offset, mappings = None, 0
    for source in block.getSourceInfos():
        backing = source.getFileBytes()
        if not source.contains(address) or backing.isEmpty():
            continue
        if not _is_target_source(session, backing.get()):
            continue
        candidate = int(source.getFileBytesOffset(address))
        if candidate < 0:
            continue
        offset, mappings = candidate, mappings + 1
    safe = mappings == 1 and offset <= MAX_SAFE_INTEGER
    return (offset if safe else None), mappings


def read_bytes(session, params):
    require_keys(params, {"document", "address", "length"})
    require_document(session, params)
    start = session.addresses.parse(require_string(params, "address"))
    length = params.get("length")
    if type(length) is not int or length < 1 or length > MAX_SAFE_INTEGER:
        raise RequestFailure("invalid_request", "Byte length must be a positive safe integer")
    memory = session.program.getMemory()
    collected = bytearray()
    buffer = _byte_buffer(CHUNK_BYTES)
    offset = 0
    while offset < length:
        try:
            at = start.addNoWrap(offset)
        except Exception:
            break
        block = memory.getBlock(at)
        if block is None or not block.isInitialized():
            break
        count = min(CHUNK_BYTES, length - offset, int(block.getEnd().subtract(at)) + 1)
        read = int(memory.getBytes(at, buffer, 0, count))
        collected += bytes(buffer[:read])
        if read != count:
            break
        offset += read
    return {
        "address": session.addresses.format(start),
        "requested_bytes": length,
        "returned_bytes": len(collected),
        "bytes_hex": collected.hex(),
        "complete": len(collected) == length,
    }


def address_to_file_offset(session, params):
    require_keys(params, {"document", "address"})
    require_document(session, params)
    address = session.addresses.parse(require_string(params, "address"))
    text = session.addresses.format(address)
    block = session.program.getMemory().getBlock(address)
    if block is None or not block.isInitialized():
        raise RequestFailure(
            "invalid_request", f"Address has no initialized file-backed memory: {text}"
        )
    offset, mappings = target_file_offset(session, block, address)
    if mappings != 1:
        raise RequestFailure(
            "invalid_request",
            f"Address has {mappings} authoritative target-file mappings: {text}",
        )
    if offset is None:
        raise RequestFailure("invalid_request", f"Address lacks a safe file offset: {text}")
    return {"address": text, "file_offset": offset}


def _coverage(session, block, low, high):
    return {
        "segment": str(block.getName()),
        "start": session.addresses.format(low),
        "end": session.addresses.format(high),
        "bytes": int(high.subtract(low)) + 1,
    }


class _BytePattern:
    def __init__(self, params):
        pattern = _PATTERN_SPACE.sub("", require_string(params, "pattern"))
        mask = params.get("mask")
        if mask is not None:
            mask = _PATTERN_SPACE.sub("", require_string(params, "mask"))
        if not pattern or len(pattern) % 2 or (mask is not None and len(mask) != len(pattern)):
            raise RequestFailure(
                "invalid_request", "Mask length must equal a nonempty byte pattern length"
            )
        values, masks = bytearray(), bytearray()
        for index in range(0, len(pattern), 2):
            pair = pattern[index:index + 2]
            wildcard = pair == "??"
            mask_pair = None if mask is None else mask[index:index + 2]
            if (not wildcard and not _HEX_PAIR.fullmatch(pair)) or (
                mask_pair is not None and not _HEX_PAIR.fullmatch(mask_pair)
            ):
                raise RequestFailure("invalid_request", "Use hexadecimal byte pairs or ?? wildcards")
            selected = 255 if mask_pair is None else int(mask_pair, 16)
            values.append(0 if wildcard else int(pair, 16))
            masks.append(0 if wildcard else selected)
        if not any(masks):
            raise RequestFailure("invalid_request", "Pattern must constrain at least one bit")
        self.values, self.masks = bytes(values), bytes(masks)


def _cursor_binding(session, pattern, start_text, end_text, document):
    identity = [
        session.target_sha256,
        session.profile_digest,
        pattern.values.hex(),
        pattern.masks.hex(),
        start_text,
        end_text,
        document,
    ]
    encoded = json.dumps(identity, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _resume_address(session, cursor, binding, start, end):
    if not cursor.startswith(binding + ":"):
        raise RequestFailure(
            "invalid_request", "Byte search cursor does not match the target and query"
        )
    resume = session.addresses.parse(cursor[len(binding) + 1:])
    block = session.program.getMemory().getBlock(resume)
    bound = start if start is not None else end
    if (
        block is None
        or not block.isInitialized()
        or (bound is not None and not bound.getAddressSpace().equals(resume.getAddressSpace()))
        or (start is not None and resume.compareTo(start) < 0)
        or (end is not None and resume.compareTo(end) > 0)
    ):
        raise RequestFailure(
            "invalid_request", "Byte search cursor lies outside initialized query memory"
        )
    return resume


def _scan_block(session, block, low, high, pattern, limit, matches):
    """Append matches in [low, high]; return (examined end, next cursor address or None)."""
    memory = session.program.getMemory()
    length = len(pattern.values)
    values, masks = _byte_buffer(pattern.values), _byte_buffer(pattern.masks)
    at, examined_end = low, high
    while at is not None and at.compareTo(high) <= 0 and int(high.subtract(at)) >= length - 1:
        found = memory.findBytes(at, high.subtract(length - 1), values, masks, True, session.monitor)
        if found is None or int(high.subtract(found)) < length - 1:
            break
        if len(matches) == limit:
            return found.addNoWrap(length - 1), found
        function = session.program.getFunctionManager().getFunctionContaining(found)
        offset, _ = target_file_offset(session, block, found)
        matches.append(
            {
                "address": session.addresses.format(found),
                "segment": str(block.getName()),
                "file_offset": offset,
                "procedure": None
                if function is None
                else {
                    "address": session.addresses.format(function.getEntryPoint()),
                    "name": str(function.getName(True)),
                },
            }
        )
        at = found.next()
    return examined_end, None


def search_bytes(session, params):
    keys = set(params)
    if not {"document", "pattern", "limit"} <= keys or not keys <= {
        "document", "pattern", "mask", "start", "end", "limit", "cursor"
    }:
        raise RequestFailure("invalid_request", "Bridge request fields are invalid")
    require_document(session, params)
    pattern = _BytePattern(params)
    limit = require_bounded_integer(params, "limit", 1, 1000)
    start = session.addresses.parse(require_string(params, "start")) if "start" in params else None
    end = session.addresses.parse(require_string(params, "end")) if "end" in params else None
    if start is not None and end is not None and (
        not start.getAddressSpace().equals(end.getAddressSpace()) or start.compareTo(end) > 0
    ):
        raise RequestFailure(
            "invalid_request", "Search bounds must be ordered in one address space"
        )
    binding = _cursor_binding(
        session,
        pattern,
        "" if start is None else session.addresses.format(start),
        "" if end is None else session.addresses.format(end),
        optional_string(params, "document"),
    )
    resume = (
        _resume_address(session, require_string(params, "cursor"), binding, start, end)
        if "cursor" in params
        else None
    )
    bound = start if start is not None else end
    matches, blocks, skipped, not_loaded = [], [], [], []
    next_cursor = None
    for block in ordered_blocks(session):
        low, high = block.getStart(), block.getEnd()
        if bound is not None and not bound.getAddressSpace().equals(low.getAddressSpace()):
            continue
        # Unbounded searches cover loaded memory only; overlays and non-loaded file parts need bounds.
        if bound is None and (not block.isLoaded() or block.isOverlay()):
            not_loaded.append(_coverage(session, block, low, high))
            continue
        if start is not None and low.compareTo(start) < 0:
            low = start
        if end is not None and high.compareTo(end) > 0:
            high = end
        if low.compareTo(high) > 0:
            continue
        if not block.isInitialized():
            skipped.append(_coverage(session, block, low, high))
            continue
        if next_cursor is not None:
            continue
        if resume is not None and low.compareTo(resume) < 0:
            low = resume
        if low.compareTo(high) > 0 or not low.getAddressSpace().equals(high.getAddressSpace()):
            continue
        examined_end, paused_at = _scan_block(session, block, low, high, pattern, limit, matches)
        if paused_at is not None:
            next_cursor = f"{binding}:{session.addresses.format(paused_at)}"
        blocks.append(_coverage(session, block, low, examined_end))
    return {
        "matches": matches,
        "searched": {
            "blocks": blocks,
            "bytes": sum(block["bytes"] for block in blocks),
            "skipped_uninitialized": skipped,
            "skipped_not_loaded": not_loaded,
        },
        "complete": next_cursor is None,
        "next_cursor": next_cursor,
    }


def _source_files(session, files):
    return [
        {
            "name": str(file.getFilename()),
            "size": int(file.getSize()),
            "original_sha256": hash_file_bytes(file, False),
            "modified_sha256": hash_file_bytes(file, True),
        }
        for file in files
    ]


def _mappings(session, files):
    result = []
    for block in session.program.getMemory().getBlocks():
        for source in block.getSourceInfos():
            backing = source.getFileBytes()
            index = -1 if backing.isEmpty() else int(files.indexOf(backing.get()))
            file_offset = int(source.getFileBytesOffset())
            start = source.getMinAddress()
            result.append(
                {
                    "block": str(block.getName()),
                    "start": session.addresses.format(start),
                    "end": session.addresses.format(source.getMaxAddress()),
                    "address_space": str(start.getAddressSpace().getName()),
                    "initialized": bool(block.isInitialized()),
                    "loaded": bool(block.isLoaded()),
                    "overlay": bool(block.isOverlay()),
                    "length": int(source.getLength()),
                    "source_file_index": None if index < 0 else index,
                    "file_offset": None if file_offset < 0 else file_offset,
                    "sha256": hash_memory(session, start, int(source.getLength()))
                    if block.isInitialized()
                    else None,
                }
            )
    return result


def _relocations(session):
    from ghidra.program.model.address import SegmentedAddress

    memory = session.program.getMemory()
    rows = []
    for relocation in iterate(session.program.getRelocationTable().getRelocations()):
        location = relocation.getAddress()
        segmented = isinstance(location, SegmentedAddress)
        original = relocation.getBytes()
        original_hex = None if original is None else bytes(original).hex()
        memory_hex = None
        if original is not None and len(original) > 0:
            buffer = _byte_buffer(len(original))
            if int(memory.getBytes(location, buffer)) == len(original):
                memory_hex = bytes(buffer).hex()
        values = relocation.getValues()
        rows.append(
            {
                "address": session.addresses.format(location),
                "segment": int(location.getSegment()) if segmented else None,
                "offset": int(location.getSegmentOffset()) if segmented else None,
                "status": str(relocation.getStatus().toString()),
                "type": int(relocation.getType()),
                "values": [] if values is None else [int(value) for value in values],
                "original_bytes_hex": original_hex,
                "memory_bytes_hex": memory_hex,
            }
        )
    return rows


def _entry_contexts(session, entries):
    context = session.program.getProgramContext()
    result = []
    for entry in entries:
        registers = []
        for name in ("CS", "DS", "ES", "SS"):
            register = session.program.getRegister(name)
            if register is None:
                continue
            value = context.getValue(register, entry, False)
            registers.append(
                {"name": name, "value_hex": None if value is None else "0x" + str(value.toString(16))}
            )
        result.append({"address": session.addresses.format(entry), "registers": registers})
    return result


def inspect_native_load_image(session, params):
    require_keys(params, set())
    program = session.program
    files = program.getMemory().getAllFileBytes()
    entries = sorted(
        iterate(program.getSymbolTable().getExternalEntryPointIterator()), key=address_order
    )
    result = {}
    recovery = session.extensions.inspect_image()
    if recovery:
        result["metadata_recovery"] = recovery
    result.update(
        {
            "executable_format": str(program.getExecutableFormat()),
            "language_id": str(program.getLanguageID().getIdAsString()),
            "compiler_spec_id": str(program.getCompilerSpec().getCompilerSpecID().getIdAsString()),
            "image_base": session.addresses.format(program.getImageBase()),
            "default_address_space": str(session.addresses.default_space.getName()),
            "source_files": _source_files(session, files),
            "mappings": _mappings(session, files),
            "relocations": _relocations(session),
            "entry_points": [session.addresses.format(entry) for entry in entries],
            "entry_context": _entry_contexts(session, entries),
        }
    )
    return result
